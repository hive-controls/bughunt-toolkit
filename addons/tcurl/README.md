# tcurl

Fetch one URL over Tor and see which exit address fetched it. tcurl is a Bughunt addon: the request
goes through the same scope and mission-policy gate as every other Bughunt request. Tor is only the
route, not a way around the rules.

```bash
bughunt tcurl example.com
bughunt tcurl example.com -I
bughunt tcurl example.com -L -H 'Accept: application/json'
bughunt tcurl http://<56-character-address>.onion/ --json
bughunt tcurl example.com --dry-run
```

## What it does

1. Checks the target against `scope.txt` and the mission policy, and checks the policy for the Tor
   SOCKS listener and the exit-check host. If any grant is missing nothing is sent, and every missing
   grant is listed at once.
2. Asks `check.torproject.org` whether the exit is a Tor exit (the exit check), through the same
   Tor circuit it then uses for the fetch.
3. Fetches the URL once (or hop by hop with `-L`), re-checking scope and policy before every hop.
4. Prints the exit address, the route, the request, the status and the body, or one JSON document
   with `--json`.

There is no direct fallback. If the Tor endpoint cannot be reached, tcurl stops; it never retries
without Tor, with another proxy, or with a local DNS lookup. Host names are sent to Tor and resolved
inside Tor (SOCKS5 with remote DNS).

## Requirements

| Piece | Version | Notes |
| --- | --- | --- |
| Python | 3.10 or newer | |
| `bughunt` | this repository | tcurl imports `bughunt.core` for scope, policy and the guarded client |
| `httpx` | `==0.28.1` | pinned by Bughunt's egress layer |
| `socksio` | `==1.0.0` | SOCKS5 for httpx; install with `pip install "bughunt[tor]"` |
| `rich` | `>=13.7.0` | output |
| a Tor daemon | any current release | **you run it**; Bughunt does not bundle or start one |

Run Tor yourself and leave its SOCKS listener on the default `127.0.0.1:9050`:

- Linux: `sudo apt install tor` (or your distribution's package), then start the service.
- macOS: `brew install tor`, then `brew services start tor`.
- Windows: run the `tor.exe` from the Tor Expert Bundle, or start Tor Browser, which listens on
  `127.0.0.1:9150` (use `--socks 127.0.0.1:9150`).

`bughunt doctor` reports whether `socksio` is installed and whether a `tor` program is on `PATH`. It
does not probe the network.

## Quick start

tcurl needs three things on top of an ordinary Bughunt workspace.

```bash
bughunt scope init
bughunt scope add example.com
bughunt policy import --file policy.json
bughunt tcurl example.com
```

The policy must grant three origins. Policy rows are exact origins, so the scheme and port matter.

```json
{"id": "tor-target", "origin": "https://example.com", "paths": ["/"], "operations": ["manual"], "methods": ["GET", "HEAD"]},
{"id": "tor-socks",  "origin": "http://127.0.0.1:9050", "paths": ["/"], "operations": ["manual", "passive"], "methods": ["GET"]},
{"id": "tor-check",  "origin": "https://check.torproject.org", "paths": ["/api/ip"], "operations": ["passive"], "methods": ["GET"]}
```

- **The target** (`manual`) is granted like any other target, with the methods you will use.
- **The SOCKS hop** is the Tor listener written as the endpoint identifier `http://HOST:PORT`. Its
  methods must include `GET` whatever method the request uses, and its operations must include every
  operation tcurl uses (`manual` for the fetch, `passive` for the exit check). Granting this row is
  how you opt a mission into Tor; without it tcurl will not route anywhere.
- **The exit check** (`passive`, `GET /api/ip` on `check.torproject.org`) can be skipped with
  `--no-exit-check`, in which case the exit is reported as unverified.

From the console:

```
Bughunt > use tcurl
Bughunt tcurl > set URL example.com
Bughunt tcurl > set HEADER 'Accept: application/json'
Bughunt tcurl > run
```

## Onion services

A `.onion` URL is an ordinary exact origin. Add its address to `scope.txt` and grant
`http://<address>.onion` (or `https://`) in the policy. Only v3 addresses (56 characters) are
accepted; the retired 16-character v2 form is refused. A bare onion address defaults to `http://`,
because onion transport is already end-to-end encrypted. A scope line such as `onion` matches every
onion service, but the policy still has to grant the exact origin, so it authorizes nothing by itself.

## Reading the output

On a terminal tcurl prints a short banner (`exit`, `route`, `request`, `status`, and `final`,
`saved` or `error` when they apply) and then the response. When stdout is piped the banner goes to
stderr and only the body goes to stdout. Long responses open in `less` when it is installed; use
`--no-pager` to print everything. HTML, JSON and CSS/JS bodies are highlighted on a terminal.
Binary bodies are not printed; save them with `-o FILE`.

Every text run also prints this disclosure, because Tor changes what the target sees:

> Route: Tor (SOCKS5, remote DNS) via HOST:PORT. The target sees a Tor exit relay address, not your
> VPN address. Bughunt's VPN route check does not cover this request, and Bughunt cannot verify how
> your Tor daemon itself connects. Scope and policy were enforced before sending.

Plain `http://` to a clearnet host over Tor adds a warning: the exit relay can read and alter that
traffic.

## `--json`

`--json` prints exactly one document to stdout and nothing else (`schema_version` 1):

| Key | Contents |
| --- | --- |
| `outcome` | `ok`, `tor-unreachable`, `exit-not-tor`, `blocked`, `transport-error`, `invalid-input` or `interrupted` |
| `error` | `null`, or `{kind, message}` (never contains the SOCKS credential) |
| `route` | `class`, `scheme`, `endpoint`, `dns`, `isolation`, `vpn_attribution`, `disclosure` |
| `exit` | `state` (`confirmed`, `not-tor`, `unverified`, `skipped`), `ip`, `is_tor`, `check_url`, `check_run_id` |
| `request` | `method`, `url`, `onion`, `header_names` (names only), `body_bytes`, `actor` |
| `policy` | `mission`, `policy_version`, `operation`, `target_decision`, `hop_decision`, `check_decision`, `run_id` |
| `redirects` | one `{from, to, status, followed, note}` per redirect seen with `-L` |
| `response` | `status`, `reason`, `http_version`, `final_url`, `content_type`, `headers`, `elapsed_ms`, `body` |
| `exit_code` | the process exit code |

`response.body` holds `bytes`, `truncated`, `sha256` (over the kept bytes), `saved_to`, `text` (null
for binary or saved bodies) and `encoding`. The `run_id` values name the evidence in the run
ledger (`bughunt ledger`); each ledger manifest also records the route (`kind`, `endpoint`, never
credentials), so a capture made through Tor is never mistaken for one attributed to your VPN.

`--dry-run` evaluates scope and policy, prints the same document, and sends nothing.

## Options

| Flag | Default | Meaning |
| --- | --- | --- |
| `url` | required | one URL; a bare host means `https://`, a bare `.onion` means `http://` |
| `-X`, `--request METHOD` | GET | HTTP method (`CONNECT` is refused) |
| `-I`, `--head` | off | send HEAD and show the headers |
| `-H`, `--header "Name: value"` | none | extra request header; repeatable |
| `-d`, `--data TEXT` | none | request body text, joined with `&` when repeated; implies POST. `@file` is literal text, never a file read |
| `-A`, `--user-agent` | none | accepted, but the policy's User-Agent replaces it on the wire |
| `-L`, `--location` | off | follow redirects, one request per hop |
| `--max-redirs N` | `10` | most redirects to follow |
| `-k`, `--insecure` | off | skip TLS verification for the fetch |
| `-m`, `--max-time SEC` | `60` | time limit for each phase (check, fetch) |
| `--connect-timeout SEC` | `30` | time limit for reaching the SOCKS port |
| `--max-body BYTES` | `8388608` | most response bytes kept |
| `--socks HOST:PORT` | `127.0.0.1:9050` | Tor SOCKS5 endpoint; also `BUGHUNT_TOR_SOCKS`. Still needs its policy row |
| `--no-exit-check` | off | skip the exit check |
| `--dry-run` | off | decide only; send nothing |
| `-i`, `--include` | off | show response headers above the body |
| `-o`, `--output PATH` | none | save the body (`-` for stdout) |
| `-v`, `--verbose` | off | summarize request and response headers on stderr |
| `--json` | off | print only the JSON document |
| `--no-pager`, `--raw` | off | never open a pager |
| `--no-color` / `--color` | auto | disable colour / force it when piped |

tcurl no longer wraps curl. Options that would change the route or read local files (`-x`/`--proxy`,
`--resolve`, `-K`, `-T`, `-F`, `-b`, `-c`, `--netrc`, and the rest of curl's flags) are not accepted;
any unsupported flag stops the run with exit status 2 before anything is sent.

## Redirects

Without `-L` a redirect response is shown as it is. With `-L` tcurl asks before every hop whether the
hop is in scope and permitted by policy for the method it will use (301/302 turn a POST into a GET,
303 turns anything but HEAD into a GET, 307/308 keep the method). A hop that fails either check is
not followed: the run ends with the redirect response, the `redirects` list says `followed: false`
and gives the reason, and the exit code stays 0. Credentials (`Authorization`, `Cookie`) are dropped
when a hop changes origin.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | a response was received (any HTTP status), or `--dry-run` found every grant |
| 1 | Tor unreachable, the exit is not a Tor exit, or the SOCKS endpoint did not speak SOCKS5 |
| 2 | usage error, invalid input, an unsupported flag, or a scope/policy block |
| 3 | Tor was reached but the request failed (target refused, exit-side DNS failure, TLS error, timeout) |
| 130 | interrupted |

## What the gate cannot do

- It cannot prove the endpoint you named is really Tor. The exit check can, and it travels over that
  same endpoint. An inconclusive check proceeds as `unverified`; only a definite "not a Tor exit"
  or an unreachable endpoint stops the run.
- It cannot see how the Tor daemon itself connects, for example whether it goes out through your VPN.
- It cannot stop an operator from granting a non-Tor SOCKS proxy as the hop.
- The policy has no field saying whether a program allows Tor, and Tor exits are shared and often
  blocked. Granting the SOCKS row is the operator's statement that the program permits this.
- Pacing is local dispatch pacing, not per exit.

## Known limitations

- `--max-time` bounds the exchange but not the SOCKS handshake itself: httpcore 1.0.9 reads the
  handshake reply without a timeout, so a listener that accepts the connection and never answers
  can hold the run until you interrupt it (exit 130). A real Tor daemon always answers.
- Stream isolation (one circuit per run) relies on Tor's default behaviour of isolating by SOCKS
  credential. It was not exercised against a live Tor daemon in the tests.
- The exit check parses `check.torproject.org/api/ip` (`IsTor`, `IP`). Its live response format was
  not available when this was written.
