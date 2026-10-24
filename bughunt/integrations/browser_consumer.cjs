'use strict';

// Network-none consumer. Only the host can turn a selected request into traffic.
const fs = require('node:fs');
const crypto = require('node:crypto');
const os = require('node:os');
const {execFileSync} = require('node:child_process');
const DRIVER_SHA256 = '954be1e183d0ddb9748fe0d2d08b0b66a9210c74dd75c397aeb70303b9f08a00';
const hash = value => crypto.createHash('sha256').update(value).digest('hex');
const pause = milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds));
let sequence = 0;

function readJSON(path, maximum) {
  if (fs.lstatSync(path).isSymbolicLink() || fs.statSync(path).size > maximum)
    throw new Error('input-bound');
  const raw = fs.readFileSync(path);
  if (raw.length > maximum) throw new Error('input-growth');
  return JSON.parse(raw);
}

function writeJSON(path, value) {
  const raw = JSON.stringify(value);
  if (Buffer.byteLength(raw) > 200000) throw new Error('output-bound');
  fs.writeFileSync(path + '.tmp', raw, {mode: 0o600, flag: 'wx'});
  fs.renameSync(path + '.tmp', path);
}

function driver() {
  const archive = fs.readFileSync('/bughunt/driver.tgz');
  if (archive.length > 8000000 || hash(archive) !== DRIVER_SHA256) throw new Error('driver-drift');
  execFileSync('/usr/bin/tar', ['-xzf', '/bughunt/driver.tgz', '-C', '/runtime']);
  const metadata = readJSON('/runtime/package/package.json', 100000);
  if (metadata.version !== '1.62.1') throw new Error('driver-version');
  return require('/runtime/package').chromium;
}

function configuration() {
  const value = readJSON('/bughunt/input/browser.json', 100000);
  if (!/^[0-9a-f-]{36}$/.test(value.job_id) || !/^[0-9a-f-]{36}$/.test(value.actor_revision)
      || !/^[a-z][a-z0-9_-]{0,63}$/.test(value.actor) || !Array.isArray(value.urls)
      || value.urls.length < 1 || value.urls.length > 32 || value.seconds <= 0 || value.seconds > 300)
    throw new Error('input-schema');
  return value;
}

async function reply(request, deadline) {
  sequence += 1;
  if (sequence > 128) throw new Error('rpc-count');
  const key = String(sequence).padStart(6, '0');
  const raw = {sequence: key, method: request.method(), url: request.url(), headers: {}};
  const headers = await request.allHeaders();
  for (const name of ['accept', 'accept-language', 'cache-control'])
    if (headers[name]) raw.headers[name] = headers[name];
  if (Buffer.byteLength(JSON.stringify(raw)) > 32768) throw new Error('request-bound');
  writeJSON('/proof/rpc/' + key + '.req', raw);
  const path = '/proof/rpc/' + key + '.resp';
  while (!fs.existsSync(path)) {
    if (Date.now() >= deadline || fs.existsSync('/proof/rpc/STOP')) throw new Error('stopped');
    await pause(20);
  }
  return readJSON(path, 100000);
}

async function routeRequest(route, deadline) {
  const result = await reply(route.request(), deadline);
  if (result.denied) {
    await route.abort('blockedbyclient');
    return;
  }
  if (result.fatal) throw new Error('host-stopped');
  const body = Buffer.from(result.body, 'base64');
  if (body.length > 65536 || !Number.isInteger(result.status) || result.status < 100 || result.status > 599)
    throw new Error('response-schema');
  await route.fulfill({status: result.status, headers: result.headers, body});
}

function rendererState() {
  const result = [];
  for (const pid of fs.readdirSync('/proc').filter(value => /^\d+$/.test(value))) {
    try {
      const command = fs.readFileSync('/proc/' + pid + '/cmdline', 'utf8');
      if (!command.includes('--type=renderer')) continue;
      const status = fs.readFileSync('/proc/' + pid + '/status', 'utf8');
      result.push({no_sandbox_flag: command.includes('--no-sandbox'),
        seccomp: Number(status.match(/^Seccomp:\s+(\d+)/m)?.[1]),
        no_new_privileges: Number(status.match(/^NoNewPrivs:\s+(\d+)/m)?.[1])});
    } catch (_) { /* Process exit/namespace privacy does not create an attestation. */ }
  }
  return result;
}

async function observe(context, page, maximum) {
  const text = await page.locator('body').innerText({timeout: 1000});
  const storage = JSON.stringify(await context.storageState());
  if (Buffer.byteLength(text) > maximum || Buffer.byteLength(storage) > maximum)
    throw new Error('observation-bound');
  return {body_sha256: hash(text), storage_sha256: hash(storage),
    final_url: page.url(), renderers: rendererState()};
}

async function main() {
  const input = configuration();
  const interfaces = Object.keys(os.networkInterfaces()).sort();
  if (JSON.stringify(interfaces) !== '["lo"]') throw new Error('network-namespace-drift');
  const chromium = driver();
  const profile = '/profiles/' + input.job_id + '/' + input.actor_revision;
  fs.mkdirSync(profile, {recursive: true, mode: 0o700});
  fs.chmodSync(profile, 0o700);
  const context = await chromium.launchPersistentContext(profile, {headless: true,
    chromiumSandbox: true, serviceWorkers: 'block', timeout: 8000,
    args: ['--no-proxy-server', '--disable-quic', '--force-webrtc-ip-handling-policy=disable_non_proxied_udp']});
  const deadline = Date.now() + input.seconds * 1000;
  let timer, chain = Promise.resolve(), routeError = null, blockedSockets = 0;
  try {
    const initial = await context.storageState();
    const empty = initial.cookies.length === 0 && initial.origins.length === 0;
    if (!empty) throw new Error('profile-not-empty');
    await context.routeWebSocket('**/*', () => { blockedSockets += 1; });
    await context.route('**/*', route => {
      chain = chain.then(() => routeRequest(route, deadline)).catch(async error => {
        routeError = error.name;
        try { await route.abort('blockedbyclient'); } catch (_) { }
      });
      return chain;
    });
    writeJSON('/proof/rpc/READY', {job_id: input.job_id, actor: input.actor,
      actor_revision: input.actor_revision, driver_version: '1.62.1',
      chromium_version: context.browser().version(), sandbox_enabled: true,
      network_interfaces: interfaces,
      profile_directory: profile, profile_mode: fs.statSync(profile).mode & 0o777,
      initial_storage_empty: empty});
    timer = setInterval(() => {
      if (Date.now() >= deadline || fs.existsSync('/proof/rpc/STOP')) context.close().catch(() => {});
    }, 20);
    const page = context.pages()[0] || await context.newPage();
    await page.goto(input.urls[0], {waitUntil: 'networkidle', timeout: Math.min(15000, input.seconds * 1000)});
    await chain;
    if (routeError) throw new Error('route-error');
    const observed = await observe(context, page, input.max_bytes);
    writeJSON('/proof/browser-result.json', {...observed, job_id: input.job_id,
      actor: input.actor, initial_storage_empty: empty, generated_requests: sequence,
      blocked_websockets: blockedSockets, complete: true});
  } finally {
    clearInterval(timer);
    await context.close();
  }
}

main().catch(error => {console.error('browser-consumer: ' + error.name); process.exitCode = 1;});
