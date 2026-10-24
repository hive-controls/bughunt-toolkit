# skiff

A request-position fuzzer: it substitutes the placeholder `FUZZ` -- in a URL, a raw request
file, a header, a cookie, or the body -- with entries from a wordlist file you supply, sends
each resulting request, and reports hits by response filter. skiff ships no wordlists or attack
payloads of its own; point it at a file you already have.

## Gating (read this first)

Every request skiff sends, including each redirect hop when `--follow-redirects` is given, goes
through `bughunt.core.egress.async_client(operation="fuzz")`. That means:

- The target (and every redirect hop) must be in scope and must have a mission-policy grant for
  the `fuzz` operation. A request that is not permitted is never sent; skiff cannot construct a
  request that bypasses this, because the check runs inside the egress transport, not in skiff's
  own code.
- The policy's `requests_per_second` / `concurrency` is a mandatory, workspace-wide cap enforced
  by egress itself. skiff's own `-t`/`--rps`/`--delay` are **advisory** and may only tighten that
  cap, never loosen it -- the effective pacing is always the slower of the two.
- `--authorized` is a no-op confirmation echo. It does not gate anything; `egress.authorize()` is
  the only real check, so there is exactly one source of truth for whether a request may go out.
- TLS certificate verification is **on by default**. Pass `--ignore-ssl` to relax it.
- A proxy given with `-p`/`--proxy` is policy-checked the same way the target is.

## Usage

```
skiff -u https://allowed.example/item?id=FUZZ -w ids.txt
skiff -u https://allowed.example/FUZZ -w paths.txt -mc 200,301-302
skiff --request-file req.txt -w ids.txt --follow-redirects -o hits.json -of json
```

Run it through the console (`use skiff`, `set ...`, `run`) or directly as
`python addons/skiff/skiff.py`.

### Target

One of:

- `-u`/`--url URL` -- the target; put `FUZZ` wherever a payload belongs.
- `--request-file FILE` -- a raw HTTP request (start line, headers, blank line, optional body)
  with `FUZZ` placeholder(s); `--scheme` picks `http`/`https` when the request line's path is
  relative (default `https`).

Always required: `-w`/`--wordlist FILE` -- a path to a wordlist, or `-` to read it from stdin.
Lines are deduplicated and blank/`#`-comment lines are skipped by default; `--no-dedup` and
`--keep-comments` turn that off.

`FUZZ` may appear in the URL, in any `-H`/`--header` value, any `-c`/`--cookie` value, or the
`-d`/`--data` body. With more than one `FUZZ` position, `--multi-fuzz same` (default) sends the
same wordlist entry to every position in each request; `--multi-fuzz combo` sends the full
cartesian product across positions.

### Payload shaping

`--transform {none,upper,lower}`, `--prefix`, `--suffix`, and the encoding selector
(`--encoding {url,none,base64}`, or the shorthand `--base64`/`--no-encode`) are applied to every
wordlist entry before it is substituted. `-x`/`--extensions` (repeatable) also sends each entry
with the given suffix appended, in addition to the bare entry. `--randomize` shuffles the order;
`--seed` makes that (and `--auto-calibrate`'s probes) reproducible.

### Pacing

`-t`/`--threads` (advisory concurrency), `--rps` (advisory rate), `--delay` (advisory minimum
spacing) -- see Gating above: these only ever make a run slower than the policy's own cap, never
faster. `--timeout` is the per-request timeout. `--follow-redirects` follows redirects, with each
hop authorized the same way the first request is.

### Filters

`-mc`/`-fc` (status codes), `-ms`/`-fs` (response size in bytes), `-mw`/`-fw` (word count),
`-ml`/`-fl` (line count) each take a comma-separated list of values and/or `lo-hi` ranges.
`--match-regex`/`--filter-regex` match against the response body; `--match-header NAME:REGEX`
matches one response header. A `match` option keeps only responses that satisfy **all** given
match criteria; a `filter` option drops a response that satisfies **any** given filter criterion.
`--auto-calibrate` sends a few throwaway (non-wordlist) payloads first; if they all come back with
the same status and size, that combination is treated as noise and filtered from the real run.

Every sent request still appears in the result's `outcomes`, marked `"hit"` or `"filtered"` --
filtering changes classification, not whether the attempt is recorded.

### Output

By default skiff prints a summary panel and a table of hits (`-v`/`--verbose` shows filtered
rows too; `--silent` prints nothing but errors). `-o FILE` additionally writes the full typed
result; `-of {txt,json,jsonl,csv}` picks the format (default `txt`, which lists hits only).

The JSON/JSONL forms carry the typed result described below. `--dry-run` prints the plan
(target, FUZZ positions, planned request count) and exits without sending anything.

## Result shape

```json
{
  "schema_version": 1,
  "run": {
    "run_id": "...", "tool": "skiff", "operation": "fuzz", "actor": "...",
    "policy_version": "...", "target": "...", "method": "GET",
    "started_at": "...", "finished_at": "...",
    "requests_planned": 0, "requests_sent": 0, "requests_per_second_effective": 0.0
  },
  "outcomes": [
    {"run_id": "...", "payload_ref": "0:abc123...", "status": 200, "size": 0, "words": 0,
     "lines": 0, "time_ms": 0, "redirects": 0, "final_url": "...", "classification": "hit"}
  ],
  "findings_summary": {"hit_count": 0, "by_status": {}, "auto_calibrated": false},
  "exit_code": 0
}
```

`outcomes[].payload_ref` is an index into the run's own payload sequence plus a short hash, not
the raw payload string -- the envelope stays chainable without re-embedding wordlist content.
Each outcome's `run_id` is that one exchange's ledger id (`bughunt ledger` can look it up); the
top-level `run.run_id` identifies the whole skiff invocation.

Exit codes: `0` a hit was found, `1` the run completed with no hits (or the wordlist/input file
was missing or empty), `2` the request could not be built or was not authorized (bad arguments,
no `FUZZ` found, out of scope, or no policy grant), `130` interrupted.

## Dependencies

`httpx` (through `bughunt.core.egress`) and `rich` for display. No `requests`, `urllib3`, or
`colorama`.
