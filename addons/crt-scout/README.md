# crt-scout

Subdomain discovery for a single apex domain, using the certificate-transparency search service
at **crt.name** (this is not crt.sh; the scanner's separate `--ct` option is the crt.sh one). It
can also check which of the discovered names answer over HTTP(S) and export their name prefixes
as a wordlist.

crt-scout is a **scope- and policy-gated capability**, not a passive offline reference. Even a
plain lookup sends a request to a third party (crt.name), and `-c` sends GET requests to every
discovered host. Both are allowed only when the mission scope and policy say so.

## Running it

Use it through the toolkit; `crt-scout` is an alias for `ct`:

```
bughunt ct example.com
bughunt crt-scout example.com -c --show-dead
```

The toolkit finds the program through `$BUGHUNT_ADDONS` first. If `bughunt ct` reports that the
program was not found, point `BUGHUNT_ADDONS` at the repository's `addons` folder. Running
`python crt-scout.py <domain>` directly also works, but only when the `bughunt` package is
already importable (for example with the repository root on `PYTHONPATH`).

## Requirements

- Python 3.10 or newer.
- `httpx==0.28.1`, the same pin as the rest of Bughunt (`pip install -r requirements.txt`). The
  egress layer relies on httpx 0.28.1 internals, so other versions are not supported.
- The `bughunt` package, which supplies scope checks, the policy engine, and the guarded HTTP
  clients.

## Scope and policy requirements

1. **Scope.** The domain must be covered by the active scope file (`bughunt scope add <domain>`).
   An out-of-scope domain is refused before any request is made.
2. **Policy, always.** The mission policy must list the apex domain as an asset with the
   `passive` operation permitted, and must list `https://crt.name` with `passive` permitted.
   Without the apex grant the run stops at a preflight check; without the crt.name grant the
   lookup is refused and nothing is sent.
3. **Policy, with `-c`.** Each probed URL needs a `crawl` grant for that host and scheme. A host
   that is in scope but has no grant is never contacted and is reported as dead.

Every request goes through `bughunt.core.egress`: no proxy from the environment, no automatic
redirects, and one policy decision per request. Redirects are followed one hop at a time, and a
hop to a host outside scope is not requested; the status of the redirect that pointed there is
what gets reported. Probes follow at most ten redirects.

Privacy: crt.name learns which domain you are researching. Use the tool only where that
disclosure is acceptable for the engagement.

## What gets kept

crt.name returns one name per line. crt-scout keeps a name only if it is a plain hostname
(no wildcards, underscores, or IP addresses), equals the domain or ends in `.<domain>`, and is in
scope. Everything else is counted in a "skipped" notice on stderr and discarded.

## Options

| Option | Meaning |
| --- | --- |
| `domain` | Apex domain to enumerate (required). |
| `-c`, `--check` | Probe every kept name, HTTPS first and then HTTP, and report the ones that answer. Any HTTP status counts as live. |
| `--https-only` | With `-c`, skip the HTTP attempt. |
| `-k`, `--insecure` | Do not verify TLS certificates on probes. The crt.name lookup is always verified. |
| `--ua STRING` | User-Agent to request. When a policy profile is active, the profile's User-Agent is what goes on the wire. |
| `-o`, `--output FILE` | With `-c`, write the result lines to FILE instead of stdout. Ignored without `-c`. |
| `-w`, `--wordlist FILE` | Write the unique subdomain prefixes (labels left of the domain) to FILE, one per line, sorted. Common labels (`www`, `mail`, `ftp`, `blog`, `shop`) are left out. |
| `-d`, `--dates` | Ask crt.name to include dates in its listing. The dates are not shown in the output. |
| `--timeout SECONDS` | Probe connect timeout (default 5); the total per-request timeout is this plus 3. |
| `--workers N` | Maximum hosts probed at once (default 50). Use at least 1. |
| `--show-dead` | With `-c`, also list the hosts that did not answer. |
| `-q`, `--quiet` | Hide the progress counter. Other stderr messages remain. |

## Output

stdout carries the results; stderr carries notices and progress.

- Without `-c`: the kept names, sorted, one per line.
- With `-c`: one line per live host, then (with `--show-dead`) one line per dead host.

  ```
  [LIVE] https://www.example.com  ->  HTTP 200
  [DEAD] old.example.com
  ```

  The arrow in the real output is the single character U+2192. Live lines are ordered by scheme
  and then status. Live lines are green and dead lines are red, using ANSI escapes that are
  emitted even when stdout is piped.
- With `-c -o FILE`: the same lines, without color, go to FILE and stdout stays empty. A summary
  with the first 20 live URLs is printed to stderr.
- `-w FILE` is independent of `-c` and is built from every kept name, live or not. A failure to
  write is reported but does not stop the run.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | The run completed. This includes a crt.name error, a timeout, an empty result, and zero live hosts; those are reported on stderr. |
| 1 | The domain is not a valid domain name (or an unexpected error when run directly). |
| 2 | Bad command-line arguments, a domain outside scope, or (through `bughunt ct`) a policy block at preflight. |
| 130 | Interrupted with Ctrl-C when run directly. |

## Known limitations

- `-o` has no effect without `-c`, and `-d` does not change what is printed.
- `--workers 0` never finishes and a negative value raises an error; keep it at 1 or higher.
- Result and wordlist files are always written as UTF-8, but with the platform's newline
  convention, so on Windows they use CRLF line endings.
- A host that is in scope but not covered by the policy is reported as dead rather than
  distinguished from one that did not answer.
- There is no cap on the size of the crt.name response or the number of names probed.
