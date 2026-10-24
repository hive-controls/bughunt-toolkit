# Bughunt manual

**Version 2.15.0** — an authorized HTTP/HTTPS toolkit. Bughunt maps hosts, keeps an
engagement workspace, and runs its recon, capture, test, and intel modules from one
console.

Only run Bughunt against systems you own or have **written permission** to test.
Unauthorized port scanning and web probing can be illegal.

**Jump to:** [Safety model](#safety-model) · [Install](#install) ·
[Running Bughunt](#running-bughunt) · [Modules](#modules) ·
[Workspace files](#workspace-files) · [Snare](#log-the-browser-with-snare) ·
[Console](#console) · [Intel modules](#intel-modules) · [Scanner](#scanner)

## Safety model

Bughunt is built so that nothing reaches the network until you have said what is in
bounds and the mission policy permits it. The same gate guards the scanner, the
modules, and the reference tools.

- **Scope.** An allow-list of hosts, domains, `*.domains`, and CIDRs in the
  workspace's `scope.txt`. Loopback is always allowed; every other host needs an
  entry. A domain entry includes its subdomains; `*.example.com` is subdomains only.
  Out-of-scope targets are rejected before any DNS lookup or TCP connect.
- **Mission policy.** `bughunt policy` imports and verifies a dated JSON profile that
  authorizes sends. The profile lists exact asset origins (scheme/host/port), the
  operations allowed on each (`passive`, `manual`, `crawl`, `fuzz`, `active_scan`,
  `dns`, `process`, `callback`), the HTTP methods, and rate/concurrency limits. A
  missing, stale, draft, or disallowed profile blocks the request. Credentials never
  live in the policy.
- **The egress gate.** Every outbound request is authorized at one chokepoint against
  the resolved target, operation, and method. A grant for `HTTPS:443` does not permit
  `HTTP:443`; each redirect and proxy hop is re-checked. Inherited HTTP proxy
  environment variables are ignored; an explicit `--proxy` is used only when you set
  it.
- **Evidence and redaction.** Guarded exchanges and raw actions are recorded under the
  workspace `runs/<id>/` with hashes and metadata. Console output, exports, and
  reports redact credential headers, URL/proxy credentials, and private-key blocks.
  Private originals stay in the ignored workspace. Chroma, Lantern deep, and URLscan
  provider credentials are removed before their evidence is written. Those captures
  are marked `sanitized_at_rest`; their hashes describe the stored sanitized bytes.
- **Labs are loopback-only.** The higher-risk Labs modules (`race`, `desync`, `ws`)
  and the owned active engine jobs run only against a lab you own on `127.0.0.1`,
  named by a mission you verified first.

Scan defaults stay small on purpose:

- common web ports only (80, 443, 8080, 8443, …); no full 1–65535 sweep unless you
  pass `--all --authorized`
- a port list longer than 4096, or a CIDR larger than `/24`, also requires
  `--authorized`
- hard cap of 1024 expanded CIDR hosts
- discover / mutate / params that would explode past 400 paths require `--authorized`

`--i-own-this` is accepted as an alias for `--authorized`.

## Install

Python 3.12 or newer. Python 3.12 is the CI baseline; see the
[CI workflow](../.github/workflows/ci.yml) for the tested platforms and versions.
Run these commands from the source checkout.

**Bash (macOS/Linux):**

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-hardened.txt
python -m pip install -e .
bughunt doctor
```

**Windows PowerShell:**

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements-hardened.txt
python -m pip install -e .
bughunt doctor
```

The full distribution is the complete source checkout with its `addons/` directory,
installed editable inside a virtual environment using the hardened requirements,
matching `bughunt setup` and CI. Keep that checkout in place so addon discovery can
resolve the shipped programs. The core wheel is a secondary artifact containing
native modules and integration helpers; it does not bundle addon source and cannot
replace this full installation. The editable install registers `bughunt` in the venv. Activate the environment in
each new shell; no global launcher is installed. You can skip activation and call
`.venv/bin/python -m bughunt doctor` on macOS/Linux or
`.\.venv\Scripts\python.exe -m bughunt doctor` in PowerShell. The latter also works
when PowerShell's execution policy blocks `Activate.ps1`. `python -m bughunt`
requires the same environment and dependencies as the installed command.

Two feature sets are optional extras:

```bash
python -m pip install -e ".[screenshots]"    # Playwright, for scan --screenshots
python -m pip install -e ".[tor]"            # socksio, for tcurl over Tor
playwright install chromium        # browser download for screenshots
```

For the optional native mitmproxy flow reader, use a Python 3.14 virtual
environment and install the pinned version with
`python -m pip install -c requirements-hardened.txt mitmproxy==12.2.3`.
This combination conflicts on Python 3.12 because mitmproxy's conditional
`typing-extensions` cap is below the hardened pin. Run `python -m pip check`
after installing.

`bughunt doctor` reports your Python version, the installed packages, whether
`socksio` is present (the SOCKS5 support `tcurl` needs), and whether a `tor` program
is on `PATH`. Each module tells you when an optional dependency it needs is missing.

Bughunt includes an optional in-process route gate. Configure it with `bughunt route init`; protected console and proxy-scan entry points fail closed when that configuration is invalid or verification fails. With no configuration the route gate is inactive. `BUGHUNT_ALLOW_NO_ROUTE=1` explicitly disables this route check, warns and records an audit event before continuing; audit failure blocks the operation. Scope and mission-policy checks still apply. Bughunt does not create a VPN or provide a continuous kill switch; routing can change after a check.

## Running Bughunt

For a first run against a loopback server you own, this command works in Bash and
PowerShell after installation:

```text
bughunt 127.0.0.1 --ports 8000 --http-only --fast --authorized --dry-run
```

The preview sends no target traffic. `--fast --authorized` adds the targets to
scope and writes a verified mission policy for the exact planned origins, including
on a dry run. Remove `--dry-run` to scan your server on port 8000. The scope and
policy gates still apply. Fast mode refuses to overwrite a manually authored
policy; for an existing engagement, import and verify its policy instead. Running
`bughunt scope init` alone does not satisfy the policy gate.

Fast policy expires after 24 hours. Scope entries remain until explicitly removed
with `bughunt scope remove`; stale policy still blocks network actions. Generated
method grants include GET (also used by connection checks) plus the selected
`--method`. Fast mode does not grant DNS operations or third-party service origins.
It warns for `--dns`, `--ct`, and DNS enrichment enabled by `--intel`; import an
explicit policy for that enrichment. Other intel analysis can still run.

Bughunt reads its first argument to decide what to do:

```bash
bughunt 127.0.0.1 --ports 80,443      # a host or scan flag runs the scanner
bughunt silk http://127.0.0.1:8080/   # a module name runs that module once
bughunt                               # no arguments, in a terminal, opens the console
```

With no arguments on an attached terminal, Bughunt opens the interactive console (the
menu picker if your terminal supports it, otherwise the typed console). Piped or
redirected with no arguments, it prints usage instead. `bughunt console` always opens
the console; `bughunt console --text` forces the typed console over the picker.

Inside the console the same module is `use`, then `run`:

```text
Bughunt > use silk
Bughunt silk > run http://127.0.0.1:8080/
```

Help is available everywhere:

- `bughunt help` — the command guide; `bughunt help scan` prints every scan flag.
- `bughunt <module> --help` — one module's flags (or `run --help` in the console).
- `bughunt examples` — copy-paste command lines.
- `bughunt modules` — the phases; `bughunt modules Recon` prints one phase.
- `bughunt catalog` — the whole catalog as JSON, for other front-ends.
- `bughunt guide` — a step-by-step walkthrough from your current engagement state.

A host whose name matches a command needs an explicit scan: `bughunt scan modules` or
`bughunt -- pulse`. A positional argument that is an existing file is not treated as a
hostname; put host lists on `-l`.

## Python, JSON and pipelines

`bughunt.run_module(module_id, operation=..., options=..., dry_run=...)` returns a
`Result`. Module aliases normalize to stable catalog IDs. Option keys are the
existing parser destinations, with the same required fields, types, choices and
mutual exclusions. Unknown options fail closed. The API does not invoke an editor
or parse terminal output. Calls are synchronous; use a worker thread when embedding
them in an asynchronous application.

```python
import bughunt

result = bughunt.run_module("scope", operation="list")
document = result.to_dict()
capabilities = bughunt.catalog()
plan = bughunt.load_pipeline("owned-chain.json")
preview = bughunt.run_pipeline(plan, execute=False)
```

`bughunt --json dns example.test` and `bughunt --json recon dns example.test`
produce one JSON result followed by a newline. The global switch must precede
the command. A module's own `--json FILE` after its command keeps its legacy
meaning. `--` still marks a scanner target that happens to match a command name.
Help, catalog, guide, doctor and schema also have structured output. Interactive
console transports report their explicit noninteractive equivalents.

Result schema version 1 includes status, exit code, timestamps, typed artifacts,
sanitized errors/warnings, evidence references, policy receipt and metrics.
Success/planned exit 0; partial/failed exit 1; blocked/invalid/unsupported exit 2;
cancelled exits 130. Domain classifications such as negative, inconclusive and
hypothesis remain in artifacts. They are not promoted to confirmed findings.
Legacy commands retain their existing exits.

Artifacts carry producer identity and a hash of their canonical sanitized payload.
Raw captures remain in the private workspace. Ledger evidence includes a run ID,
content hash and representation label; logical HTTP evidence is not a wire capture.
`requests_admitted` counts admission decisions, not arrival at a remote server.
`bytes_retained` measures recorded evidence files; repeated writes to the same file
use its latest measured size in a module receipt. A failed child admission channel
or unmetered raw scanner probe reports an unknown count. A local-only operation has no policy receipt; a run that
uses multiple authorities cannot claim a single receipt covers them all.

Inspect contracts with `bughunt schema result`, `bughunt schema pipeline` and
`bughunt schema artifact urls`. Schema validation describes structural contracts;
loading results additionally verifies artifact hashes, chronological timestamps
and typed handoff eligibility. A syntactically valid artifact never grants scope
or permission by itself.

### An owned chain

This example assumes a verified mission named `owned-demo`, an owned server on
port 8080, exact policy grants for its GET/manual and GET/fuzz operations, and a
bodyless `owned-request.http` whose relative request target matches the URL
selected from robots. Import is inert evidence; it does not claim a live capture.

```json
{
  "schema_version": 1,
  "mission": "owned-demo",
  "limits": {"requests": 20, "seconds": 60, "concurrency": 1,
             "requests_per_second": 1, "bytes": 1048576},
  "steps": [
    {"id": "recon", "module": "robots",
     "options": {"fetch": "http://127.0.0.1:8080/robots.txt", "no_workspace": true}},
    {"id": "capture", "module": "exchange", "operation": "import-raw",
     "options": {"request": "owned-request.http", "source_id": "owned-demo"},
     "inputs": {"url": {"step": "recon", "artifact": "urls", "index": 0}}},
    {"id": "test", "module": "discover",
     "options": {"header": ["X-Owned-Candidate"], "requests": 10},
     "inputs": {"exchange_id": {"step": "capture", "artifact": "exchanges", "index": 0}}}
  ]
}
```

```text
bughunt pipeline validate owned-chain.json
bughunt pipeline dry-run owned-chain.json
bughunt pipeline run owned-chain.json --execute
bughunt pipeline status PIPELINE_ID
bughunt pipeline cancel PIPELINE_ID
bughunt pipeline resume PIPELINE_ID --execute
```

`chain` aliases `pipeline`. JSON is always available. YAML plans require
`python -m pip install -e ".[pipeline-yaml]"`; aliases, tags, merges, duplicate
keys and unbounded/deep documents are rejected. Plans contain 1–32 ordered steps
and only backward typed references. Scalar destinations require an explicit
`index`; list destinations use `indices` with 1–32 unique selections. There is no
implicit fan-out, expression evaluation, shell execution or arbitrary import.
Observation text cannot become a URL, file or command. File inputs are copied and
hashed before execution, including bounded lists of files; stdin is not immutable.

Root and per-step limits, known native caps and policy bounds intersect. The
whole chain shares its remaining request budget, deadline and retained-byte cap;
later steps do not get fresh budgets. This cap covers immutable inputs, captured
evidence and result receipts; control journals have separate size bounds.
Shared concurrency is one. Preview validates
available input data without sends or writes, and identifies deferred references.
It never grants authority for later execution. Policy, scope and actor changes
block a running or resumed chain.

Execution persists under workspace `jobs/PIPELINE_ID`, with an OS lock, durable
intent, events and per-step results. Resume verifies the plan, immutable inputs,
authority and linked evidence. Completed steps are reused. An interrupted unsafe
intent is indeterminate and requires a new run; it is never automatically replayed,
even for GET. Cancellation prevents new admissions while in-flight I/O settles;
it does not roll back remote effects.

Pipeline eligibility is narrower than standalone API support. Configuration
mutations, interactive editors, unbounded watches/listeners and binary downloads
are excluded. Scanner raw probes and snare capture are also excluded until their
full dispatch and deadline behavior is governed. Race requires concurrent workers;
replay/IDOR switch actors; the Burp child transport cannot synchronously enforce
the shared admission cap. Managed engine jobs and lab operations with unmetered
retained files are excluded as identified by their catalog reason. These
operations therefore remain standalone. Consult catalog operation reasons and
validate the actual plan, since option-dependent restrictions also apply.

For pipelines, robots and silk require `no_workspace: true`. File-output flags
that bypass the retained-evidence cap are rejected. Feed caches are disabled
during pipeline execution. Finite addon watches require an explicit `polls`
bound, and their waits check the shared deadline and cancellation.

Standalone Snare automation uses `snare capture --seconds 30 --max-exchanges 10`;
it finishes at the time or connection bound and returns retained exchange IDs.
The interactive listener remains a separate console operation. Chroma automation
uses the one-shot operations listed in its catalog instead of starting a REPL.

## Modules

Modules are grouped into seven phases that follow a hunt in order: **Engagement →
Recon → Capture → Test → Labs → Engines → Intel**. Each phase is also a command
namespace, so `bughunt recon` lists that phase and `bughunt recon scan 127.0.0.1`
runs a module within it. Every name also works flat (`bughunt scan`, `use silk`),
which is the form scripts use.

### Engagement — set up the hunt and keep its state

These share the `./.bughunt` workspace (or `$BUGHUNT_SCOPE`).

| Module | What it does | Example |
| --- | --- | --- |
| `scope` | Allow-list of in-scope hosts and the shared URL list | `bughunt scope add app.internal` |
| `policy` | Import and verify the mission policy that authorizes sends | `bughunt policy status` |
| `identity` | Select owned account or anonymous profiles bound to exact origins | `bughunt identity list` |
| `session` | Store a Cookie or Authorization you already hold | `bughunt session show` |
| `verify` | Configure and run a bounded server-side actor identity probe | `bughunt verify show owner` |
| `ledger` | Inspect run provenance and export sanitized evidence | `bughunt ledger --help` |
| `roost` | Counts, scope entries, and saved hosts outside scope | `bughunt roost` |
| `route` | Check that traffic would leave through your tunnel | `bughunt route status` |

### Recon — map hosts, endpoints, DNS, and certificates

| Module | What it does | Example |
| --- | --- | --- |
| `scan` | Map HTTP and HTTPS on a host | `bughunt 127.0.0.1` |
| `silk` | Spider one site, including robots and sitemaps | `bughunt silk http://127.0.0.1:8080/` |
| `ct` | Certificate-transparency names | `bughunt ct app.internal -c` |
| `dns` | A, AAAA, CNAME, MX, TXT, and NS | `bughunt dns app.internal` |
| `whois` | Registrar, dates, and nameservers | `bughunt whois app.internal` |
| `mail` | MX, SPF, DMARC, and named DKIM selectors | `bughunt mail app.internal --selector s1` |
| `cert` | Read the TLS certificate | `bughunt cert https://app.internal` |
| `vhost` | One address, once per Host name | `bughunt vhost http://127.0.0.1:8080/ app.internal` |
| `redirect` | Follow a redirect chain and stop at the scope edge | `bughunt redirect http://127.0.0.1:8080/start` |
| `robots` | Turn a robots.txt or sitemap into URLs | `bughunt robots robots.txt --base https://app.internal` |
| `pulse` | Check which URLs are live | `bughunt pulse .bughunt/urls.txt` |

### Capture — record traffic and keep notes

| Module | What it does | Example |
| --- | --- | --- |
| `snare` | Localhost proxy; stays up beside the console | `bughunt snare` |
| `clutch` | List saved requests, or print one with secrets blanked | `bughunt clutch` |
| `exchange` | Import/export inert raw HTTP and HAR with provenance | `bughunt exchange --help` |
| `carve` | Pull links out of a HAR, raw HTTP, or a proxy dump | `bughunt carve capture.har --unique` |
| `blaze` | Label a URL that is already in the list | `bughunt blaze add login https://app.internal/login` |
| `quill` | Timestamped notes | `bughunt quill add checked the login form` |

### Test — probe and compare requests by hand

| Module | What it does | Example |
| --- | --- | --- |
| `repeater` | Edit a saved request and send that copy | `bughunt repeater captured.http --print` |
| `replay` | Compare owner, lower-privilege, and anonymous for one baseline | `bughunt replay --help` |
| `discover` | Probe explicit hidden inputs with bounded budgets and controls | `bughunt discover --help` |
| `forms` | List form fields and query parameters | `bughunt forms page.html --base https://app.internal` |
| `diff` | Compare two saved responses, or two in-scope URLs | `bughunt diff before.http after.http` |
| `jwt` | Decode a token you already have | `bughunt jwt --session` |
| `decode` | Print a page with non-image base64 shown as text | `bughunt decode http://127.0.0.1:8080/` |
| `skiff` | Replace `FUZZ` from a wordlist | `bughunt skiff -u http://127.0.0.1/FUZZ -w words.txt --dry-run` |

### Labs — higher-risk techniques in an owned loopback lab

Each runs only against an explicitly owned, named loopback lab you set up first.

| Module | What it does | Example |
| --- | --- | --- |
| `race` | Bounded concurrent requests in an owned loopback lab | `bughunt race --help` |
| `desync` | Compare HTTP/1.1 parser views in an owned loopback lab | `bughunt desync --help` |
| `ws` | Capture/replay bounded WebSocket text in an owned loopback lab | `bughunt ws --help` |

### Engines — integrated engines and callbacks

| Module | What it does | Example |
| --- | --- | --- |
| `engine` | List curated engine capabilities and manage bounded jobs | `bughunt engine list` |
| `zap` | Import passive ZAP evidence, or run one guarded owned active lab | `bughunt zap --help` |
| `oast` | Correlate approved out-of-band callbacks with initiating runs | `bughunt oast --help` |

### Intel — look things up in external feeds

| Module | What it does | Example |
| --- | --- | --- |
| `phish` | Phishunt feed, campaigns, and a passive URL score | `bughunt phish --help` |
| `ioc` | TweetFeed indicators (IOCaw) | `bughunt ioc --help` |
| `chroma` | abuse.ch lookups (chromahaus) | `bughunt chroma --help` |
| `urlscan` | urlscan.io lookup | `bughunt urlscan --help` |
| `tcurl` | Fetch one URL over Tor, scope and policy enforced | `bughunt tcurl example.com -I` |

`phish deep` and `chroma download` stay hidden until you select that subcommand.

## Workspace files

Scope, URLs, and saved traffic live in `./.bughunt`. Set `BUGHUNT_SCOPE` to put that
directory elsewhere; keep any override outside tracked data.

| Path | What it holds |
| --- | --- |
| `scope.txt` | Hosts, domains, `*.domains`, and CIDRs. Created by `scope init`. |
| `urls.txt` | The shared URL list. |
| `session.txt` | Cookie and Authorization. Hidden by roost; blanked by `clutch show`. |
| `identities/` | Named identity profiles and credentials; private workspace data. |
| `identities/verification/` | Private identity-probe configuration. |
| `policy.json` | The imported mission policy. |
| `runs/<id>/` | Per-run request/response captures, manifests, and hashes. |
| `requests/` | Raw requests. `clutch` lists these; `repeater` sends one. |
| `responses/` | Responses from snare. `diff` reads these. |
| `marks.txt` | `blaze` labels. |
| `notes.txt` | `quill` notes. |
| `snare/ca.crt` | CA certificate for the test browser. |

```bash
bughunt scope init
bughunt scope add app.internal '*.lab.internal' 10.1.0.0/16
bughunt scope import-urls found.txt
bughunt scope urls
```

`scope init` creates the directory and does not wipe an existing scope file.
`import-urls` keeps lines that contain `://` whose host is in scope. `scope urls`
prints the list; point `pulse` at it with `bughunt pulse .bughunt/urls.txt`.

## Log the browser with snare

Snare is a local logging proxy. From the console it stays up and the prompt returns:

```text
Bughunt > snare
Bughunt [snare:8080] >
```

Point the test browser at `127.0.0.1:8080`. To read HTTPS inside scope, trust the
certificate from `snare ca` (this needs `openssl` on `PATH`):

```bash
bughunt snare ca
```

Each in-scope exchange is saved twice under one name:

```text
.bughunt/requests/example.com-snare-0001.http
.bughunt/responses/example.com-snare-0001.http
```

The count restarts for each host, so a long list sorts by site. Tab completion on
`clutch show` and `diff` fills the name in, so you do not type the directory:

```text
Bughunt > clutch
Bughunt > clutch show example.com-snare-0001.http
Bughunt > diff example.com-snare-0001.http example.com-snare-0002.http
Bughunt > snare status
Bughunt > snare stop
```

`clutch show` prints the request with Cookie and Authorization replaced by `[blank]`;
the saved file keeps them so `repeater` can resend it. A host outside scope is
forwarded and not written; with no scope file, only loopback is kept. A saved body
over 1 MB is marked `truncated`, though the browser still receives the full body (up
to 8 MB). A shell `bughunt snare` holds that terminal until Ctrl-C; open the console
when you want the proxy and the other modules together.

## Console

`bughunt` in a terminal prints a banner and a short command list, then a prompt.
`banner` picks a different banner; `help` prints the longer guide. On a color
terminal `Bughunt` is magenta, the module name cyan, and `>` green; while snare is
listening, `[snare:8080]` is yellow.

```text
Bughunt > use pulse
Bughunt pulse > show options
Bughunt pulse > set FILE urls.txt
Bughunt pulse > set FOLLOW_REDIRECTS true
Bughunt pulse > run
Bughunt pulse > back
Bughunt > exit
```

Option names are the argument destination in uppercase. `set FILE=urls.txt` is the
same as `set FILE urls.txt`. `true`, `yes`, `on`, and `1` turn a switch on. `unset
FILE` forgets one value; `unset all` clears the selected module. Saved values persist
across `back` and fill whatever you leave off the next `run`; arguments typed on `run`
win. Typing the module name runs it once (`pulse urls.txt`). Ctrl-C stops the running
module and returns to the prompt. `exit` leaves, and stops snare if it is up.

Tab completes commands, modules, options, choices, group names, and paths, leaving a
trailing slash on directories so the path can continue. Up and down recall history,
stored at `~/.local/share/bughunt/history` (`BUGHUNT_HISTORY` overrides it); a line
that contains a token, password, secret, cookie, API key, or JWT is left out.
`search spider` lists modules whose name or description matches, naming the group.

Shell completion for the command name and scan flags:

```bash
bughunt completion bash > ~/.local/share/bash-completion/completions/bughunt
bughunt completion zsh > ~/.zsh/completions/_bughunt
```

## Module notes

The newer modules print a small banner on a color terminal; `--plain` skips it, and
pipes stay plain.

- **route.** An opt-in check that traffic would leave through your VPN or tunnel. It
  reads the operating system's routing table and sends no packets. Nothing is checked
  until a config exists: `route init --interface NAME` (repeat the flag for several)
  writes a validated `route.json` into the workspace, or to `--path FILE`; it refuses
  to replace an existing file without `--force`. `NAME` is matched case-insensitively
  against each interface's name and description, so copy a real name from
  `route status`. Set `BUGHUNT_ROUTE_CONFIG=FILE` to use a config kept outside the
  workspace; that variable wins, and a missing or unreadable file blocks rather than
  silently turning the gate off. `route status [--json]` prints which config won, the
  protected points, the probe backend, and each interface with whether it is up,
  matches your names, and carries the probe route; it exits 2 if the config is invalid.
  `route check [HOST] [--json]` runs the gate by hand: with no `HOST` it checks the
  probe address (default `1.1.1.1`, a routing-table lookup only); with a `HOST` it
  must be in scope before it is resolved, and every address it resolves to must egress
  through the tunnel. Exit 0 means pass, 2 means block, including an invalid config,
  an unavailable backend, or no config at all. When a config exists, `bughunt doctor`
  adds one optional `route gate` row; it never fails the doctor and never evaluates the
  live route.
- **identity.** Create an owned named profile for exact HTTP(S) origins, then select
  it with `identity use NAME`. `identity show` and `identity list` never print secret
  values. `identity clear NAME` removes its credentials without deleting the profile.
  A request under a named identity requires one of its exact origins.
- **companion headers.** `identity companion NAME header...` declares an allowlist (at
  most 8, names only — never values) of exact request-header names the actor may carry
  for a site's CSRF/XSRF companion header. The allowlist excludes the four canonical
  credential headers (Cookie, Authorization, X-API-Key, Auth-Key) but, by design, does
  permit other credential-named headers such as `x-auth-token` or `proxy-authorization`:
  the trust rests on the operator's declaration that the actor and its origins are theirs
  to test. The mechanism is actor-bound (the allowlist lives on one named profile) and
  origin-bound (a value is only ever supplied to the actor's own origins). On `verify
  check NAME` each allowlisted header is privately filled from the matching cookie in
  that actor's stored session — a double-submit XSRF value, the leading `x-` optional
  when matching the cookie name — and that value is redacted from all output. The
  `default` actor supplies nothing.
- **verify.** Configure one exact server-side identity probe per named actor, select
  that actor, then run `verify check NAME`. The probe uses one GET with size/time
  limits, no redirects, and the policy gate. Expected principal and role values are
  never printed by `verify show`.
- **session.** Under the `default` identity, `session set` writes `session.txt`. With
  a named identity selected, it updates that profile. silk, forms, vhost, redirect,
  diff, and decode send the saved Cookie and Authorization; a flag on one run replaces
  the saved value, and an empty flag omits the header. Repeater does not add them.
- **replay.** Sends one captured request as three named profiles — `owner`,
  `lower_privilege`, and `anonymous` — and compares status, Content-Type, Location,
  and body hashes. A match is a review lead, never an automatic finding. Each actor
  needs a bounded identity check; `--dry-run` validates everything without traffic.
- **repeater.** `--print` writes the edited request without connecting. The host it
  would contact must be in scope, including `--connect`. `--edit` opens `$VISUAL` or
  `$EDITOR`; `--save-request NAME` stores it under `requests/`.
- **discover.** Tests explicit candidate names (not a wordlist) against complete
  bodyless GET/HEAD exchanges, with baselines and negative controls. Needs `fuzz`
  permission. The default budget is 30 attempts / 60 seconds (caps 100 / 300).
  Repeatable differences are review leads only.
- **forms.** One GET, or a local file. Marks review names (`id`, `user`, `search`,
  `sort`, `order`, `filter`, `*_id`) plus hidden, password, and disabled fields.
  Password values are blanked in anything it writes. `--save` writes raw requests for
  repeater; `--limit` defaults to 20. It never sends a modified request.
- **silk.** Stays on the scheme, host, and port you give it. Robots paths are listed,
  not fetched. Defaults are depth 2 and 40 fetches. One URL per line to stdout.
- **vhost.** One connection, one GET per Host name. Names outside an active scope file
  are skipped; redirects are left as they are.
- **cert.** One handshake: subject, names, issuer, and dates.
- **redirect.** Stops before a hop that leaves the original hostname or scope.
- **diff.** A path that exists is read from disk; a bare name is read from
  `responses/`; a URL is one GET, and only when that host is in scope. Cookies received
  on the left side do not carry into the right side; supplied credentials still apply.
- **dns.** Six record types, no name guessing. `--resolver` is an IP address; replies
  must come from the selected resolver address and port.
- **pulse.** A policy denial stops retries and marks the check `EXCLUDED`, separately
  from a down host. JSON and CSV include `excluded`; an earlier redirect response is
  retained when a later hop is denied. Any excluded check makes the command exit 2.
- **ct.** Policy-denied probes are `BLOCKED`, appear with `--show-dead`, and do not
  trigger an HTTP fallback after an HTTPS denial.
- **whois.** One in-scope domain. `--server` is an IP and is the only server queried;
  without it, Bughunt asks IANA for one referral, then queries that registry once.
- **jwt.** Prints the header and claims; the signature is not checked. `--session`
  reads the saved Authorization value and strips a leading `Bearer`.
- **mail.** MX, SPF, `_dmarc`, and only the DKIM selectors you pass. It does not guess
  selectors or look up the mail hosts.
- **decode.** Image data and short unmarked blocks stay encoded; `--min` changes the
  64-character floor.
- **roost.** Read-only; secret values stay hidden.
- **clutch.** `show` takes the file name, not a path. Nothing is sent.
- **blaze.** The URL must already be in `urls.txt`; a label is a short lowercase word.
  Writing marks does not turn scope on.
- **quill.** Each line starts with a UTC timestamp, `YYYY-MM-DD HH:MM:SSZ`.
- **exchange.** Imports raw HTTP, HAR 1.2, or hash-checked ledger exchanges into
  private, content-addressed records. Import never sends requests. Default exports are
  sanitized derivatives; `--private` exports original bytes (keep those out of tracked
  files).
- **engine / zap / oast.** The Engines phase manages integrated engines (ZAP and a
  read-only Burp Community intake) and out-of-band callbacks. `engine list` shows what
  is available; previews and imports use files only, never DNS, sockets, or child
  processes; active engine jobs are bounded, owned-loopback, and policy-gated. Run
  `bughunt engine --help`, `bughunt zap --help`, and `bughunt oast --help` for the
  current commands, or `bughunt engine list` for the live capability map.
- **skiff.** `--dry-run` prints the requests without connecting. Target and every
  redirect hop must be in scope and policy-granted; `-t`/`--rps`/`--delay` only tighten
  the policy's own rate cap, never loosen it.

## Intel modules

The Intel modules query public threat-intelligence services. Each talks to one fixed
set of hosts and nothing else, so you always know where a lookup goes:

| Module | Where it connects |
| --- | --- |
| `phish` | Talks only to `phishunt.io`. `analyze` and `deep` submit the URL, so the URL must be in scope and confirmed (prompt, or `--yes`) and the policy must grant `active_scan` on its origin. |
| `ioc` | Talks only to `api.tweetfeed.live` and the GitHub raw file `/v1/year` redirects to. |
| `chroma` | Talks only to `*.abuse.ch`; its Auth-Key never leaves those hosts. `download` keeps `--i-understand` and always writes to `<workspace>/samples/`. |
| `urlscan` | Talks only to `urlscan.io`. `scan` makes urlscan visit the URL, so it must be in scope and confirmed; `--visibility` defaults to `private`. |
| `tcurl` | Fetches one URL over Tor; the target, every redirect hop, the Tor SOCKS endpoint, and the exit-check host must each be in scope or policy-granted. See [Tor routing](#tor-routing-tcurl). |

Alias names: `crt-scout` is `ct`, `flowcarve` is `carve`, `lanternjaw` is `phish`,
`iocaw` is `ioc`, `chromahaus` is `chroma`. The programs ship under `addons/`. Bughunt
looks in `$BUGHUNT_ADDONS` first, then `./addons`, then `../addons`.

### Tor routing (tcurl)

`tcurl` fetches one URL over Tor, but Tor is only the route: every request it makes
(the exit check, the fetch, each redirect hop) passes the same scope and mission-policy
checks as any other Bughunt request, and nothing is sent when a check fails. Three
grants are needed:

1. **The target.** A `scope.txt` line (`bughunt scope add example.com`) and a policy
   asset for its exact origin allowing operation `manual` and the method used. A
   `.onion` target is an ordinary origin.
2. **The Tor SOCKS endpoint.** A policy asset whose origin is `http://HOST:PORT` of
   your Tor listener (default `http://127.0.0.1:9050`; Tor Browser uses 9150), path
   `/`, method `GET`, operations `manual` and `passive`. This row is the opt-in:
   without it `tcurl` routes nowhere.
3. **The exit check.** A policy asset for `https://check.torproject.org` with path
   `/api/ip`, operation `passive`, method `GET`. `--no-exit-check` skips it.

`bughunt tcurl URL --dry-run` prints the scope and policy decisions for all three and
sends nothing.

What this does and does not tell you:

- DNS is resolved inside Tor (SOCKS5, remote resolution); the machine never looks up
  the target.
- There is no direct fallback. If the SOCKS endpoint is down, `tcurl` exits 1 with
  `tor-unreachable`.
- The target sees a Tor exit relay address. Bughunt cannot verify how your Tor daemon
  connects; each run prints that disclosure, and every ledger manifest records the
  route so a Tor capture is not mistaken for a direct one.
- Granting the SOCKS row is your statement that this mission permits Tor; many programs
  forbid it and block exit addresses.
- Plain `http://` to a clearnet host over Tor can be read and altered by the exit
  relay; `tcurl` warns.

Output is `--json` friendly (`schema_version` 1). Exit codes: 0 (any HTTP status),
1 (Tor unreachable or not a Tor exit), 2 (usage or block), 3 (Tor reached, request
failed), 130 (interrupted). The full flag list and JSON shape are in
`addons/tcurl/README.md`.

### Optional integration readiness

Check each integration at the level you intend to use. A successful dependency or
configuration check alone does not establish a live connection.

| Integration | Local readiness check | Requirements for live use |
|---|---|---|
| Formic | Run its `doctor` from this checkout, then select Bughunt in the interactive launcher. | Windows Terminal must be discoverable by the launcher. Verify the new tab starts in this checkout and reaches the Bughunt console. Keep the profile's health command relative to the repository: the installed Formic does not expand `{repo}` in health arguments. |
| Chromium | Launch and close the installed browser with the browser runtime. | An authorized browser job with the required scope and policy. |
| ZAP | Run the pinned Docker consumer's offline, network-disabled integration test. | Docker must be running; live work requires the applicable engine job and policy grants. |
| Burp MCP | The profile doctor validates the configured artifact versions and fingerprints. | Start Burp with its MCP extension, configure `.bughunt/burp-mcp.json` with the actual loopback listener and pinned artifacts, then verify the transport handshake. Installed JARs alone are insufficient. |
| Tor | Confirm a SOCKS listener exists, then inspect `tcurl --dry-run` decisions. | Start Tor or Tor Browser, configure its actual port, and satisfy the three grants above. A dry run sends nothing and cannot verify the Tor exit. |

### Integration verification

The default suite retains explicit gates for external tools. CI enables the owned
native wire cases on Windows and Linux, runs the native mitmproxy reader in its
own dependency job, and runs the live route smoke on macOS. The
[Docker integration workflow](../.github/workflows/integrations.yml) provisions
the pinned browser/ZAP inputs and runs their real consumers sequentially. It also
supports manual dispatch. Burp approval checks remain attended Windows tests.

On Windows, completion and TLS fixture tests also need Git Bash and OpenSSL on
the test process's PATH. For a default Git for Windows installation, set this in
the PowerShell session before running pytest (adjust for your installation):

```powershell
$env:PATH = 'C:/Program Files/Git/bin;C:/Program Files/Git/usr/bin;' + $env:PATH
```

Missing prerequisites cause skips; check `pytest -ra` before treating a green run
as complete integration coverage.

For the contained browser and ZAP consumers, use Docker's containerd image store.
The runtime checks bind both the image and the container to the pinned identity.
On Linux, run these tests as UID 1000 with access to Docker: private input and
result directories must remain owner-only and readable by the container's UID
1000. The workflow demonstrates an isolated workspace without changing those
permissions. Host Playwright Chromium installation alone does not supply the
contained browser's driver archive or seccomp file; the workflow downloads and
verifies both against `bughunt/integrations/browser_actor.py`.

To verify the optional native flow reader in the active venv:

```powershell
python -m pip install -c requirements-hardened.txt mitmproxy==12.2.3
python -m pip check
mitmdump --version
python -m pytest tests/test_flowcarve_characterization.py -q -rs
```

Mitmproxy remains an addon dependency. These four dependency-gated reader tests
must execute when it is installed; a skipped test is not integration proof.

For attended Burp verification, start a temporary Community project with the
supported MCP extension and a loopback-only listener. Keep project-data approval
enabled. Capture one synthetic GET to `/whk010/fixture` on an owned loopback
server, then use Burp's native **Save items** with Base64 encoding. Set these
variables in the test shell, using absolute local paths:

```powershell
$env:BUGHUNT_BURP_INTEGRATION = '1'
$env:BUGHUNT_BURP_PROFILE = (Resolve-Path .bughunt/burp-mcp.json).Path
$env:BUGHUNT_BURP_XML_FIXTURE = (Resolve-Path .bughunt/validation/integration-completion/burp-owned.xml).Path
python -m pytest tests/test_burp_consumer.py -q -s
```

The suite first proves the handshake without reading history. Its denial case
requires clicking **Deny**; its final import case requires **Allow once** for the
single selected history item. A timeout does not prove denial. Do not enable
permanent history access to make these tests unattended. The separate saved-export
test in `tests/test_burp.py` always runs against the repository's genuine synthetic
capture in `tests/fixtures/burp_2026_9_2_owned.xml`, including its exact digest,
timestamp and redaction checks. Git preserves that export's original bytes.

The workbench's `configured-no-use` variant requires the same fingerprint-valid
Burp profile but deliberately makes no Burp calls. The Linux Docker lane permits
only that named skip; verify the variant on the configured Windows machine.
Keep local profiles, raw captures, and private job evidence under ignored
`.bughunt/`; upload only sanitized test receipts.

## Scanner

The scanner is the HTTP/HTTPS mapper. `bughunt 127.0.0.1` runs it; `bughunt scan
--help` prints the same flags. Closed ports never get an HTTP request unless you pass
`--skip-tcp`.

```bash
bughunt doctor
bughunt 127.0.0.1
bughunt 127.0.0.1 localhost --ports 80,443,8080,8443
bughunt scan -l targets.txt --output-dir ./bughunt-out
bughunt 127.0.0.1 --ports 80,443 --delay 0.3-1.0 --intel --md report.md
```

### How a scan works

1. Resolve each host and label addresses as loopback / private / public.
2. Asynchronous TCP connect scan of the selected ports (unless `--skip-tcp`).
3. For every open port, send the chosen method over HTTP and/or HTTPS for each path.
4. Classify the response: status, `Server` / `X-Powered-By`, HTML title, body snippet,
   tags.
5. On HTTPS, pull TLS version, subject, issuer, and expiry.
6. Optional intel: artifacts, params, headers, cookies, `security.txt`, favicon, JS,
   DNS, CT, banners.
7. Stream artifacts to disk and optionally write JSON / CSV / Markdown.

### Recon extras (opt-in)

These do **not** run unless you pass the flag (or `--intel`).

- **`--intel`** turns on `--discover --score-headers --extract-js --favicon --dns` in
  one switch. Add `--cors`, `--ct`, `--banners`, `--md` yourself.
- **`--discover`** requests sensitive artifact paths (`/robots.txt`, `/.git/HEAD`,
  `/.git/config`, `/.env`, `/.htpasswd`, `/backup.zip`, `/server-status`, …). A
  **200/206** on a sensitive path is raised as a high finding; a 404 is just a 404.
- **`--mutate-paths` / `--mutate-ext`** also request backup-style suffixes (`.bak`,
  `.old`, `.orig`, `.zip`, `.tar.gz`, `.sql`, `.log`, `.swp`, `~`, plus your own).
- **`--params` / `--params-file`** append common query names (`debug`, `admin`,
  `redirect`, `token`, `file`, …) on `/` and endpoint-like paths.
- **`--score-headers`** flags missing security headers (HSTS, CSP, X-Frame-Options,
  X-Content-Type-Options, Referrer-Policy, Permissions-Policy) and cookie problems
  (missing `Secure`/`HttpOnly`/`SameSite`, `SameSite=None` without `Secure`). It runs
  on `/` and HTML responses so a discover sweep does not repeat itself.
- **`security.txt`** (RFC 9116) is parsed when `/.well-known/security.txt` or
  `/security.txt` returns a body: info for a valid Contact/unexpired Expires, low if
  missing, medium if Expires is in the past. Bughunt reads a target's file; it does
  not ship one.
- **`--favicon`** fetches `/favicon.ico` and computes the Shodan-style mmh3 hash,
  matching 60+ common products from a built-in table. Unknown hashes still print.
- **`--extract-js`** pulls `script src`, `fetch(`, axios/jQuery calls, absolute URLs,
  and `/api` paths. Key-like assignments (`api_key=`, `secret=`, `token=`) become high
  findings with the value redacted.
- **`--cors`** sends `OPTIONS` with a foreign and a loopback `Origin`: `*` is medium, a
  reflected foreign origin is high.
- **`--dns`** enumerates records over DNS-over-HTTPS (Cloudflare); **`--ct`** pulls
  certificate-transparency names from crt.sh, capped.
- **`--banners`** reads the first bytes from TCP-open ports that did not speak HTTP.
- **`--screenshots DIR`** captures live pages with headless Chromium via Playwright,
  every browser request scope-checked. Needs `pip install ".[screenshots]"` then
  `playwright install chromium`.

### Scanner reference

**Targets and ports**

| Flag | Meaning |
| --- | --- |
| `targets` | IPs, hostnames, URLs, or CIDR |
| `-l FILE` / `--targets-file` | Extra targets, one per line |
| `--common` | Built-in web ports (default) |
| `--ports SPEC` | `80,443,8000-8010` |
| `--range START-END` | Inclusive range |
| `--all` | 1–65535; requires `--authorized` |
| `--ports-file FILE` | Port specs, one per line |
| `--exclude-ports SPEC` | Drop ports |
| `--authorized` | Wide-sweep acknowledgement. Alias: `--i-own-this` |
| `--skip-tcp` | HTTP(S) every selected port, no TCP connect scan |

**Request shape**

| Flag | Meaning |
| --- | --- |
| `--paths SPEC` / `--paths-file FILE` | Comma list or a file; a missing `/` is prepended |
| `--method GET\|HEAD\|OPTIONS\|POST` | Default `GET` |
| `--http-only` / `--https-only` | Restrict scheme |
| `--follow-redirects` | Follow 3xx |
| `--insecure` | Skip TLS verification |
| `--no-cert` | Skip certificate metadata |
| `--host-header NAME` | Force `Host` |
| `-H HEADER` / `--headers-file FILE` | `Name: value` (repeatable), or a headers file |
| `--auth USER:PASS` | HTTP Basic |
| `--user-agent STR` / `--user-agents-file FILE` | UA string or a file of UAs |
| `--random-agent` / `--rotate-agent` | One UA for the scan, or a new UA per request |
| `--proxy URL` | Outbound / intercepting proxy. With a route gate on `proxy_scan`, the proxy host is verified once at start; use an IP-literal proxy so a later DNS change cannot move it off the tunnel |
| `--concurrency N` | Default 256 |
| `--connect-timeout S` / `--http-timeout S` | Timeouts |
| `--retries N` | Retry timeout/connect failures |
| `--delay S` | `0.4`, or jitter range `0.5-2.0` |
| `--max-body N` | Max saved body bytes (default 256 KiB) |

**Recon, filters, and output**

| Flag | Meaning |
| --- | --- |
| `--discover` `--mutate-paths` `--mutate-ext` `--params` `--params-file` | Artifact, backup-suffix, and query-parameter probes |
| `--score-headers` `--cors` `--extract-js` `--favicon` `--dns` `--ct` `--banners` | Recon extras (above) |
| `--intel` | discover + score-headers + extract-js + favicon + dns |
| `--status` `--grep` `--only-live` | Filter the results |
| `--save-urls FILE` | Unique live URLs, appended one per line |
| `--save-source DIR` / `--save-headers DIR` | Response bodies / interesting headers |
| `--screenshots DIR` | PNG captures of live pages |
| `--json FILE` `--csv FILE` `--md FILE` | Machine report / one row per hit / grouped human report |
| `--output-dir DIR` | All of the above with default names |
| `--quiet` `--version` | Quiet output / print version |

### List file formats

Blank lines and `#` comments are ignored.

```
# targets.txt            # paths.txt       # params.txt
127.0.0.1                /                 debug
localhost                robots.txt        verbose
app.internal.example     admin             reset
```

`admin` in a paths file becomes `/admin`. A user-agents file is one UA per line; a
headers file is `Name: value` per line.

### Examples

```bash
# Quiet lab box, dump everything
bughunt 127.0.0.1 --ports 80,443,8080 --output-dir ./bughunt-out

# Authorized recon pack
bughunt app.internal --ports 80,443 --https-only --insecure \
    --delay 0.4-1.2 --intel --cors --ct --banners --md bughunt.md

# Custom lists
bughunt 127.0.0.1 --http-only --ports 8765 \
    --user-agent examples/agents.example.txt --rotate-agent \
    --paths examples/paths.example.txt \
    --headers-file examples/headers.example.txt \
    --mutate-paths --params

# Skip the TCP scan, HTTP only
bughunt 127.0.0.1 --ports 80,443,8080 --skip-tcp --only-live

# Full-port sweep you own
bughunt 127.0.0.1 --all --authorized --only-live --save-urls live.txt
```

### Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Finished |
| 2 | Bad arguments / safety rail tripped |
| 130 | Interrupted |

A DNS failure on one host does not abort the rest of the list.

### Limitations

- The scanner checks for an HTTP speaker first; it is not a general-purpose port
  scanner.
- `--all`, and `--discover` + `--mutate-paths` + `--params`, get loud. Stay in scope.
- Favicon hints are a lookup table, not a guarantee.
- `security.txt` parsing is RFC 9116 field extraction, not a compliance audit.
- Cookie scoring looks at `Set-Cookie` attributes only; it does not replay sessions.
- Page source is a single path, truncated to `--max-body`, not a crawl.

## License / use

Provided as-is for defensive and authorized testing. You are responsible for staying
inside your scope and local law.
