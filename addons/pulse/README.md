# pulse

Check which URLs in a list are live. pulse reads URLs from a file (or stdin), sends one
`GET` per URL, sorts the answers into status families (2xx, 3xx, 4xx, 5xx, unreachable),
prints a table per family plus a summary, and can write the full results as JSON or CSV.

pulse is a Bughunt addon, not a stand-alone scanner. It only contacts URLs that are in the
active scope and permitted by the active mission policy (see [Scope and policy](#scope-and-policy)).
Every in-scope URL receives a live request, so it is an active check, not a passive one.

## Requirements

| Piece | Version | Notes |
| --- | --- | --- |
| Python | 3.10 or newer | |
| `bughunt` | this repository | pulse imports `bughunt.core` for scope, policy and the guarded HTTP client; it must be importable |
| `httpx` | `==0.28.1` | pinned by Bughunt's egress layer |
| `rich` | `>=13.7.0` | tables, panels and the progress bar |
| `h2` | `>=4.1` | **optional**; enables HTTP/2 when installed |

`pip install -e .` from the repository root installs `bughunt`, `httpx` and `rich`.
`addons/pulse/requirements.txt` lists the same pins for a separate environment.

## Quick start

```bash
bughunt scope init
bughunt scope add app.example.com
bughunt policy import --file policy.json     # a verified policy that grants app.example.com
bughunt pulse urls.txt
```

From the Bughunt console, option names are the flag names in upper case:

```
Bughunt > use pulse
Bughunt pulse > set FILE urls.txt
Bughunt pulse > set FOLLOW_REDIRECTS true
Bughunt pulse > run
```

`bughunt scope import-urls found.txt` keeps the in-scope URLs from a list and
`bughunt scope urls` prints them, so `bughunt pulse .bughunt/urls.txt` checks everything you
have collected.

Running `python addons/pulse/pulse.py urls.txt` directly works only where the `bughunt`
package is importable (for example after `pip install -e .`); otherwise it stops with
`ModuleNotFoundError: No module named 'bughunt'`. Use `bughunt pulse` instead.

## Scope and policy

Two independent checks stand between a URL and the network.

1. **Scope.** A URL whose host is not covered by the workspace `scope.txt` is never contacted.
   Its row is reported as unreachable with the note `outside scope, not contacted`, it is not
   retried, and it counts as a failure for the exit code. Loopback is always in scope; a
   scoped domain includes its subdomains; ports are ignored. With no scope file nothing but
   loopback is in scope.
2. **Policy.** Every request is checked against the mission policy (`policy.json`) for the
   operation `crawl` with method `GET`, and is paced and recorded in the workspace run ledger
   like every other guarded request. Policy grants are per origin, so the scheme and port
   matter: a grant for `https://app.example.com` does not cover `http://app.example.com` or
   `https://app.example.com:8443`. A missing, invalid or stale policy, an ungranted origin, or an
   invalid target (non-HTTP scheme, credentials in the URL, trailing-dot host) does not stop the
   run; that URL becomes an unreachable row carrying the policy's reason, for example
   `asset-unknown; no outbound action ran`. Preview a decision with
   `bughunt policy check <url> --operation crawl --method GET`.

The policy profile also sets the real request rate and concurrency, regardless of `-c`, and it
supplies the `User-Agent` and any required identity headers on the wire. That means `-A` only
changes the value pulse asks for; under an active policy the profile's user agent is what the
server sees. The built-in default for `-A` is `Mozilla/5.0 (compatible; BughuntPulse/1.0)`.

pulse ignores proxy environment variables (`HTTP_PROXY`, `HTTPS_PROXY`, ...); there is no proxy
option.

## Input

One URL per line, from a file or from stdin (`-`).

- Blank lines and lines whose first non-blank character is `#` are skipped.
- A `#` later in a line is **not** a comment: `example.com/a # note` becomes one (invalid) URL.
- A line with no scheme gets `https://` in front. A scheme is left exactly as written, and
  host case is not changed.
- A schemeless `host:port` such as `example.com:8080` is read as if `example.com` were the
  scheme, so it is **not** prefixed and the policy rejects it as an invalid target. Write
  `https://example.com:8080` instead.
- Exact duplicates (after the steps above) are dropped; the first occurrence keeps its place.
  Comparison is case-sensitive.
- The file is read as UTF-8; undecodable bytes are replaced.
- There is no limit on the number of URLs. Concurrency is bounded by `-c` and, below that, by
  the policy's pacing.

## Options

| Flag | Default | Meaning |
| --- | --- | --- |
| `file` | required | text file with one URL per line, or `-` for stdin |
| `-f`, `--follow-redirects` | off | follow in-scope 3xx hops and report the final answer |
| `--show-redirects` | off | add the redirect chain to rows that followed one |
| `-c`, `--concurrency N` | `20` | most URLs checked at the same time |
| `-t`, `--timeout SEC` | `10.0` | per-request timeout in seconds (the connect phase is capped at 10 s) |
| `-r`, `--retries N` | `1` | extra attempts after a network failure |
| `-A`, `--user-agent` | built-in string | User-Agent to request (see [Scope and policy](#scope-and-policy)) |
| `-k`, `--insecure` | off | skip TLS certificate verification, on every request and redirect hop |
| `--only FAMILIES` | all | comma-separated list of tables to show (see below) |
| `--json PATH` | none | write every result to a JSON file |
| `--csv PATH` | none | write every result to a CSV file |

`--concurrency` must be at least 1, `--timeout` greater than 0 and `--retries` not negative;
otherwise pulse prints a message and exits with status 2 before reading any input.

### `--only`

`--only` changes what is **displayed**. It never changes the summary, the exit code or the
exports.

- Family names (`2xx`, `3xx`, `4xx`, `5xx`, `error`) choose which tables appear. They are
  case-sensitive, and the tables always keep the order above.
- A number in the list does not choose a table; it only narrows the chosen tables to rows with
  exactly that status code. `--only 4xx,404` shows the 4xx table with just the 404 rows.
- A list with no family name (for example `--only 404,500`) selects nothing, and pulse prints
  `No results matched the current filter.` Name the family too: `--only 4xx,5xx`.

## Redirects

By default pulse does not follow redirects: a 301 or 302 is reported as a 3xx row and counts as
live. With `-f` it walks the chain itself, one request per hop:

- Only `301`, `302`, `303`, `307` and `308` with a non-empty `Location` are followed. Relative
  locations resolve against the current URL.
- Every hop target must be in scope and permitted by policy **before** it is requested. A hop
  to an out-of-scope host is not followed; the row keeps the redirect response and the note
  `redirect to <host> is outside scope, not followed`.
- At most 10 hops are followed (so at most 11 requests per URL). If the 11th response is still
  a redirect, the row keeps that 3xx response with the note `stopped after 10 redirects`. A
  chain that reaches a final answer on the 11th request is accepted.
- A hop that is in scope but refused by policy turns the whole URL into an error row, even
  though earlier hops answered; the earlier answer is not kept.
- A followed chain that ends on a 3xx (scope edge or the cap) is not "live" in the summary but is
  not a hard failure either.
- Moving from `https` to `http` inside scope is followed.

The `Final / Info` column shows the final URL when it differs from the one you listed.
`--show-redirects` also prints the whole chain.

## Reading the results

Each URL ends up in exactly one family:

| Family | Table title | Meaning |
| --- | --- | --- |
| `2xx` | LIVE | status 200-299 |
| `3xx` | REDIRECT | status 300-399 |
| `4xx` | CLIENT ERROR | status 400-499 |
| `5xx` | SERVER ERROR | status 500-599 |
| `error` | UNREACHABLE | no usable answer: out of scope, policy block, timeout, connection or TLS failure, or a status outside 200-599 (such rows keep their numeric status and an empty error text) |

A row counts as **live** (`ok`) when it is 2xx, or 3xx without `-f`. The summary shows live
and down totals, the count per family, the average time of the rows that were timed, and
the wall-clock time of the run. A time of `-` means the row has no timing (error rows, or a
response faster than a millisecond).

Failure messages in the `error` column and in the exports:

| Situation | Message |
| --- | --- |
| timeout (connect, read, write or pool) | `timeout` |
| TLS or certificate problem | `tls error: <detail>` |
| other connection failure | `connection failed: <detail>` |
| too many redirects (from the HTTP client) | `too many redirects` |
| unsupported protocol | `unsupported protocol` |
| other HTTP-client error, including a policy block | the error text |
| anything else | `<ExceptionName>: <detail>` |

HTTP statuses are never retried. Network failures, and policy refusals, are retried up to `-r`
times with a growing pause (0.4 s, then 0.8 s, ...). A retried URL walks its redirect chain again
from the start. The reported time covers only the attempt that succeeded.

## Exports

Both exports are written after the tables and summary, JSON first, and always hold **every**
result in input order, whatever `--only` says. A path whose directory does not exist is an
error (see limitations).

- **JSON** (`--json`): an object with `generated_at` (UTC, ISO 8601 with offset), `count` and
  `results`. Non-ASCII text is escaped as `\uXXXX`.
- **CSV** (`--csv`): UTF-8 with a header row and CRLF line endings.

Both use the same ten fields per result, in this order:

`url, ok, status, reason, family, elapsed_ms, final_url, content_type, error, redirects`

`status` is `null` (JSON) or empty (CSV) when there was no response. `content_type` has any
`;parameters` removed. `redirects` is the chain of requested URLs joined with ` -> ` (empty when
no redirect was followed). `url` is the normalised input URL.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | no row is `error` or `5xx` (2xx, any 3xx and 4xx rows alone give 0) |
| `1` | at least one `error` or `5xx` row, **including** out-of-scope and policy-blocked URLs; also input file not found, no URLs in the input, or an unexpected failure (for example the input path is a directory or an export path cannot be written) |
| `2` | command-line usage error, or an invalid `-c`, `-t` or `-r` value |
| `130` | interrupted with Ctrl-C (nothing is rendered or exported) |

## HTTP/2

pulse switches HTTP/2 on only if the optional `h2` package can be imported when a run starts, and
says nothing either way. Without `h2` it uses HTTP/1.1 and works normally. HTTP/2 applies only to
HTTPS servers that negotiate it. The result rows do not record which protocol was used.

## Known limitations

- `-A` does not change what the server sees while a policy profile is active.
- A `#` after a URL on the same line is not treated as a comment, and a schemeless `host:port`
  is rejected (see [Input](#input)).
- A policy refusal on a redirect hop discards the earlier answer, and policy refusals are
  retried like network failures.
- `--only` needs a family name; bare status codes select nothing.
- An input path that is a directory, or an export path that cannot be written, ends in an
  unhandled error (exit 1). When an export fails the tables have already been printed, but nothing
  is saved.
- File names in the "not found" and "no URLs" messages are printed through rich markup, so
  bracketed text such as `[bold]` in a file name is swallowed.
- `--show-redirects` draws its chain with a non-ASCII arrow, so it needs a UTF-8 terminal; on a
  console limited to a legacy code page (such as cp1252) printing the table fails.
- Real DNS and TLS failure texts, and HTTP/2 against a live server with `h2` installed, have not
  been verified here; the offline tests use mock transports.
