# urlscan

A command-line client for [urlscan.io](https://urlscan.io), shipped as a Bughunt reference addon in
the Intel phase. It searches past scans, submits new ones, fetches results, downloads screenshots
and DOM snapshots, and reports API quotas and account details.

```
bughunt urlscan search page.domain:example.com AND date:>now-7d
bughunt urlscan scan https://app.example.org/ --wait
bughunt urlscan result 0196d976-07f6-7aae-8a57-aa019145f31c
```

## Requirements

- Python 3.10 or newer.
- The `bughunt` package, importable. Running through `bughunt urlscan ...` guarantees it; to run
  `python urlscan.py ...` directly, install Bughunt (`pip install -e .` from the repository root) or
  put the repository root on `PYTHONPATH`.
- `httpx==0.28.1` and `rich>=13.7.0` (see `requirements.txt`; they are already part of a Bughunt
  install).

## Safety model

urlscan only ever talks to `urlscan.io` (and its `*.urlscan.io` subdomains, when a redirect points
there). It never contacts the engagement target itself. Every request goes through Bughunt's guarded
API client: no ambient proxy, TLS always verified, redirects followed by hand (at most 5 hops) with
each hop re-checked against the host allow-list and the egress policy.

**Policy grants.** The workspace `policy.json` must allow:

| What | Policy requirement |
| --- | --- |
| Any command that calls the API | an asset for origin `https://urlscan.io`, path `/`, operation `passive`, method `GET` |
| `scan` (submitting) | the same asset must also list method `POST` |
| `scan` (target check) | an asset for the target's own origin that permits the `active_scan` operation |

With the policy missing, invalid, or lacking a grant, the command stops before sending anything and
reports `HTTP 0: network error: <reason>` (or the reason alone, for the scan target check).
`fields` is offline and needs no policy.

**`scan` is the only active capability.** It makes urlscan.io's scanners visit a URL on your behalf,
so before anything is submitted the URL must be:

1. in the workspace scope (`bughunt scope add <host>`), and
2. authorised for `active_scan` by the policy, and
3. confirmed: you are asked `Continue? [y/N]`, or you pass `--yes`. Without a terminal and without
   `--yes` the scan is not submitted.

An API key is required for `scan` (checked first, before the scope check). Submissions default to
`--visibility private`; `unlisted` and `public` must be asked for explicitly, and `public` publishes
the URL and its result on urlscan.io.

**Confidentiality.** The passive subcommands are not scope-gated: you can look up any URL, domain or
scan id. The text of every `search` query and the URL of every `scan` is disclosed to urlscan.io, and
those often name the engagement target. Keep that in mind before searching for client names, and use
private scans for anything sensitive.

## Authentication

The first non-empty source wins:

1. `--api-key KEY`
2. the `URLSCAN_API_KEY` environment variable
3. the first line of `~/.config/urlscan/api_key`
4. the first line of `~/.urlscan_api_key`

The key is sent only in the `API-Key` header and is never printed. `scan` and `whoami` refuse to run
without a key. The others try without one; urlscan.io may answer 401 or 403, and the error line says
how to fix it.

## Usage

Global options come before the subcommand; after it they are rejected.

| Option | Meaning |
| --- | --- |
| `--api-key KEY` | API key (see above) |
| `--timeout SECONDS` | HTTP timeout, default 30 |
| `--json` | print the API response as JSON instead of the formatted view |
| `--no-color` | never use ANSI colors (also honoured: `NO_COLOR`; `FORCE_COLOR` forces color) |
| `--save FILE` | also write the JSON response to FILE (search, scan and result only) |

| Subcommand | What it does |
| --- | --- |
| `search QUERY...` | search finished scans. `--size N` (default 20), `--after CURSOR`, `--datasource scans\|hostnames\|incidents\|notifications\|certificates`. A pasted URL is rewritten into a domain/URL field query. |
| `scan URL` | submit a scan (see Safety model). `--visibility public\|unlisted\|private` (default private), `--yes`, `--country CC`, `--tag TAG` (repeatable), `--user-agent UA`, `--referer URL`, `--override-safety`, `--wait` |
| `result UUID` | show a finished scan: verdict, page and network details, indicators, links. `--wait` polls until it exists |
| `screenshot UUID` | save the screenshot, to `-o FILE` or `<uuid>.png` in the current directory |
| `dom UUID` | print the DOM snapshot, or save it with `-o FILE` |
| `quotas` | show rate limits and usage per action and window |
| `whoami` | show the account behind the API key |
| `fields` | print the searchable fields and example queries (offline) |

Scan ids are validated (8-4-4-4-12 hex) before they are put in a request path.

### Waiting for a scan

`scan --wait` and `result --wait` poll until the result exists. `scan` waits 10 seconds before the
first poll and `result` waits 2 seconds; after that both poll every 3 seconds (`--initial-delay`,
`--interval`) until `--wait-timeout` (default 120 seconds) runs out. A progress ticker is drawn on
stderr only when stderr is a terminal.

### Search paging

A page ends with `next page:  --after '<cursor>'`; pass that cursor to `--after` with the same query
to continue. `bughunt urlscan fields` lists the field names and a few example queries.

## Output and scripting

- `--json` prints the response body as indented JSON on stdout. Non-object bodies are wrapped as
  `{"raw": ...}`; `dom --json` prints `{"uuid": ..., "dom": ...}`.
- Errors and diagnostics go to stderr as a single `error: ...` line.
- `--save FILE` writes the JSON (ASCII-escaped) and prints `  saved FILE` on stdout.
- `screenshot` and `dom` ignore `--save`; `quotas`, `whoami` and `fields` do too.

```
bughunt urlscan --json result 0196d976-07f6-7aae-8a57-aa019145f31c | jq .verdicts.overall
```

## Exit status

| Code | Meaning |
| --- | --- |
| 0 | success |
| 1 | API or network error, refusal (scope, policy, missing key, not confirmed), invalid input |
| 2 | command-line error (unknown option, missing argument, global option after the subcommand) |
| 130 | interrupted with Ctrl-C |

## Known quirks

These describe current behaviour and may change:

- `--wait-timeout` shares its setting with the global `--timeout`: for `scan` and `result`, its value
  (default 120) is also the HTTP timeout for that run, replacing any global `--timeout`.
- With `--json`, stdout can carry extra lines besides the JSON: the `saved FILE` notice, a leading
  blank line before `scan --wait` output, and the confirmation prompt when it is shown.
- `--save` and `-o` write wherever you point them and do not confine output to the workspace; an
  unwritable destination ends in a Python traceback rather than an `error:` line.
- On a console that cannot encode the box and warning glyphs (for example a Windows code page
  other than UTF-8), formatted output can fail with `UnicodeEncodeError`; set `PYTHONUTF8=1`.
- A `result --wait` that times out reports "not ready yet ... re-run with --wait".
- The scan id returned by a submission is not re-validated before polling.
- A non-ASCII API key is rejected by the HTTP layer with a traceback.
