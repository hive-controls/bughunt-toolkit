# chromahaus

A command-line client for the [abuse.ch](https://abuse.ch) community threat feeds. Give it a URL,
host, IP, hash, tag or malware family and it asks URLhaus, MalwareBazaar and ThreatFox what they
know; it also lists the newest entries of each service, prints the Feodo Tracker and SSL
blacklist feeds, follows URLhaus for new URLs, and can save a malware sample ZIP inside the
workspace. It never unpacks, executes or analyzes a sample.

Inside Bughunt it is the `chroma` reference addon (`chromahaus` is an alias):

```
bughunt chroma hunt 8.8.8.8
bughunt chromahaus -n 50 recent
python addons/chromahaus/chromahaus.py --key YOUR_KEY recent     # also works as a plain script
```

## Requirements

- Python 3.10 or newer.
- `httpx==0.28.1`, the same pin the Bughunt project uses (`pip install -r addons/chromahaus/requirements.txt`).
- The `bughunt.core` modules (the policy-gated HTTP client and the workspace helper). Run from a
  Bughunt checkout; the script adds the repository root to `sys.path` itself when started directly.
- A free abuse.ch Auth-Key from <https://auth.abuse.ch/>. Every subcommand needs one, including
  `feodo`, `sslbl` and `download`.

## Auth-Key

Looked up in this order; the first non-empty value wins and is stripped of whitespace:

1. `--key KEY`
2. the `ABUSECH_AUTH_KEY` environment variable
3. the `ABUSE_CH_KEY` environment variable
4. a file holding only the key: `~/.config/chromahaus/auth.key`, then `~/.chromahaus.key`, then `./.chromahaus.key`

With no key the tool prints how to get one and exits with code 2, before any banner or request.
The key is sent only as the `Auth-Key` request header; it is never printed or put in a URL or body.

## Usage

**Global options go before the subcommand.** argparse does not accept them after it, so
`chromahaus recent -n 15` is a usage error (exit 2); write `chromahaus -n 15 recent`.

| Option | Meaning |
| --- | --- |
| `--key KEY` | Auth-Key for this run |
| `--no-color` | never print ANSI colors |
| `--json` | print the raw API JSON instead of the formatted view |
| `--out FILE` | save the last listing to `FILE`: `.json` (any case) gives a JSON array, any other name gives CSV |
| `-n`, `--limit N` | row cap / API limit for list commands (default 25) |
| `-V`, `--version` | print `CHROMAHAUS 1.1.0` |

| Subcommand | What it does |
| --- | --- |
| `repl` | interactive prompt (also what you get with no subcommand) |
| `hunt INDICATOR` | detect the kind (URL, hash, IP, host or free term) and query every feed that fits |
| `url URL` / `host HOST` | URLhaus lookup of a URL / a host or IP |
| `hash DIGEST` | a 32-character (MD5) or 64-character (SHA-256) digest across URLhaus, MalwareBazaar and ThreatFox |
| `tag TAG` / `family NAME` | URLhaus and MalwareBazaar by tag / URLhaus, ThreatFox and MalwareBazaar by signature |
| `fox TERM` | ThreatFox IOC search |
| `recent` / `payloads` / `bazaar` | latest URLhaus URLs / URLhaus payloads / MalwareBazaar samples |
| `iocs [--days D]` | recent ThreatFox IOCs; `D` is clamped to 1-7 (default 1) |
| `feodo` / `sslbl` | the Feodo Tracker recommended C2 blocklist / the SSL certificate blacklist |
| `watch [--interval S]` | poll URLhaus recent URLs and print only new ones; sleeps at least 15 s between polls (default 30); Ctrl-C stops it |
| `download SHA256 [--dest DIR] --i-understand` | save a sample ZIP, see below |

```
chromahaus hunt evil.example
chromahaus -n 100 --out urls.csv recent
chromahaus --out bazaar.json bazaar
chromahaus --json url http://example.test/x.exe
chromahaus family Emotet
chromahaus watch --interval 60
```

A 40-character SHA-1 is not a supported lookup key: it is treated as a SHA-256 and sent to URLhaus
as `sha256_hash`, so only MD5 (32) and SHA-256 (64) digests give reliable answers.

### Output

Human-readable output goes to stdout; errors go to stderr as `  ! message`. Color is used only on a
terminal and is off when `--no-color` is given or the `NO_COLOR` environment variable is set.

`--json` prints each API response as an indented JSON document, but the stream is **not a single
JSON document**: the banner comes first, commands that query several feeds (`hunt`, `hash`, `tag`,
`family`) print one document per feed separated by blank lines, and `hunt` adds a heading. Do not
pipe it straight into `jq`; extract the documents first, or use `--out` for machine-readable rows.

`--out` saves what the command listed: `recent`, `payloads` (their rows), `url` (the whole
response), `host` (its URLs), `iocs`, `fox`, `bazaar` (their `data`), and for `tag` only the
MalwareBazaar half. `hunt`, `hash`, `family`, `feodo`, `sslbl`, `watch` and `download` export
nothing, and `--out` is silently ignored for them. An empty listing writes no file. CSV uses the union
of keys as its header and stores list or object values as JSON text.

### Interactive prompt

`chromahaus` with no subcommand starts a prompt. Commands: `hunt`, `url`, `host`, `hash`, `tag`,
`family` (aliases `sig`, `signature`), `fox`, `recent [n]`, `payloads [n]`, `bazaar [n]`,
`iocs [days]`, `feodo`, `sslbl`, `watch [seconds]`, `export FILE`, `raw` (toggle raw JSON), `help`,
`quit`. A bare URL, IP, host or hash is treated as `hunt`. `export` saves the rows of the last
`url`, `host`, `recent`, `payloads`, `iocs`, `fox` or `bazaar`. The prompt's `download` always
refuses (it cannot carry the confirmation flag) and then ends the session; use the one-shot
subcommand. Bare indicators typed at the prompt are queried in lower case.

### download

`download SHA256 --i-understand` fetches the sample from URLhaus (falling back to MalwareBazaar
when URLhaus has no usable copy) and writes the raw ZIP to
`<workspace>/samples/<dest>/<sha256>.zip`. The ZIP is password-protected with `infected`.

- `--i-understand` is required. Without it the tool prints the live-malware warning and refuses
  before any request is made.
- The digest must be exactly 64 hex characters.
- `--dest` is a sub-folder of `<workspace>/samples` (default: that folder itself). Absolute paths
  and anything that resolves outside the samples folder (`..`, `../..`) are refused. Files never
  land in the current directory.
- An existing file of the same name is overwritten. The sample is not checked, unpacked or executed.

The workspace is `$BUGHUNT_SCOPE` when set, otherwise `./.bughunt`.

## Egress and policy

Everything goes through Bughunt's policy-gated HTTP client as operation `passive`; there is no
other network path (no raw sockets, subprocesses or browser). The client ignores proxy
environment variables, always verifies TLS and never follows redirects on its own. Requests are
limited to `abuse.ch` and its subdomains, and redirects on GET are followed by hand (at most 5
hops), each hop re-checked, so the Auth-Key can never be sent to another host.

The workspace `policy.json` must be verified, permit `passive`, and list each exact origin
(an `abuse.ch` apex grant does not cover the subdomains):

| Origin | Methods | Used by |
| --- | --- | --- |
| `https://urlhaus-api.abuse.ch` | GET, POST | URLhaus lookups, recent lists, sample download |
| `https://mb-api.abuse.ch` | POST | MalwareBazaar lookups and the download fallback |
| `https://threatfox-api.abuse.ch` | POST | ThreatFox searches |
| `https://feodotracker.abuse.ch` | GET | `feodo` |
| `https://sslbl.abuse.ch` | GET | `sslbl` |

A denied request fails with exit code 1 and a `network error talking to <url>: <reason>` message
(for example `asset-unknown`). There is no pre-flight check, so commands that query several feeds
print the earlier feeds before the denied one fails.

## Third parties and disclosure

- **abuse.ch is a third party.** Every indicator you type (a URL, IP, hash, tag or name, possibly
  an engagement target) is sent to abuse.ch as typed, together with your Auth-Key. The tool does
  not check the engagement scope and does not ask for confirmation, unlike the active addons.
  Decide whether a lookup is acceptable before you run it, and follow abuse.ch's terms of use.
- Every request is recorded by the egress layer under `<workspace>/runs/`. The recorded request
  contains the `Auth-Key` header in plain text, so treat the workspace as sensitive.
- This addon is an independent client and is not affiliated with or endorsed by abuse.ch.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | success (including "no hit"), `--help`, `--version`, leaving the prompt, stopping `watch` |
| 1 | a request or export failed: network, policy or host-guard error, 401, 429, any HTTP status of 400 or more, an unwritable `--out` file; every refusal by `download` |
| 2 | no Auth-Key, or a command-line usage error |
