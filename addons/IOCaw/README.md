# IOCaw

IOCaw is a read-only command-line client for [TweetFeed.live](https://tweetfeed.live/api/), a public
feed of indicators of compromise (IOCs) that researchers post on X/Twitter: URLs, domains, IP
addresses, MD5 and SHA-256 hashes. The feed is CC0 and needs no API key.

IOCaw looks indicators up; it does not find them. It never extracts IOCs from text, and it never
visits, resolves or verifies an indicator it lists.

Inside Bughunt it is the `ioc` reference tool (alias `iocaw`):

```bash
bughunt ioc --help
bughunt ioc feed week --tag phishing
```

It also runs on its own: `python addons/IOCaw/iocaw.py --help`.

## Requirements

- Python 3.10 or newer
- `httpx==0.28.1` (the version Bughunt's guarded client is built against)
- `rich>=13.7.0`

```bash
pip install -r addons/IOCaw/requirements.txt
```

IOCaw uses `httpx` through Bughunt's shared guarded client. It does not use `requests`.

## Network behaviour and policy gating

Every request is a plain `GET` sent through `bughunt.core.http.api_client`, which sends it through
Bughunt's egress layer under the `passive` operation:

- Only `api.tweetfeed.live` is contacted, plus `raw.githubusercontent.com` for `feed year`, because
  TweetFeed answers `/v1/year` with a redirect to a CSV file on GitHub. Redirects are followed by
  hand, at most five hops, and every hop must stay on one of those two hosts.
- Proxy settings from the environment are ignored, TLS verification stays on, and nothing is sent
  except the `GET` itself (no body, no credentials).
- IOCaw is not scope-gated: the target is the public feed, not an engagement host. It is
  **policy**-gated instead. The workspace needs a verified `policy.json` with an asset for
  `https://api.tweetfeed.live` that permits `passive` `GET` on the paths IOCaw requests (path `/`
  grants the whole host) and, to use `feed year`, a second asset for
  `https://raw.githubusercontent.com`. A missing or stale policy, or a missing asset, is refused
  before anything leaves the machine; the message names the reason (`asset-unknown`,
  `policy-missing-or-invalid`, ...) and the exit code is 2.
- The policy profile decides the `User-Agent` and any required identity headers that go on the wire.
- Each admitted request is recorded by egress in the workspace (`runs/<id>/`), including the full URL.

### Third-party disclosure

What you look up is sent to TweetFeed (which sits behind Cloudflare), and the full URL is kept in
your workspace ledger. `lookup <value>` sends the value, and `feed` / `watch` send the tag, user
and type filters you choose. Looking up an engagement target's hostname tells a third party you
are interested in it. Decide whether that is acceptable before you do it.

## Commands

`--quiet` and `--version` belong to the top-level command and must come **before** the subcommand:
`iocaw --quiet feed week` works, `iocaw feed week --quiet` is rejected. `--quiet` only hides the
banner (the banner is also skipped whenever `--json` is given). Options below are per subcommand;
they are not universal.

| Command | Purpose | Options |
| --- | --- | --- |
| `feed [today\|week\|month\|year]` | Indicators for a time window (default `today`) | `--type`, `--tag`, `--user`, `--json`, `--defang`, `--limit` (40), `--export FILE`, `--contains TEXT`, `--values-only`, `--tweets` |
| `lookup VALUE` | Exact-match one URL, domain, IP or hash across the last 365 days | `--json`, `--defang`, `--tweets` |
| `campaigns` | AI-clustered campaigns; `--id tfc-...` shows one in detail | `--id`, `--json`, `--defang`, `--limit` (40), `--export FILE` |
| `trends` | Week-over-week tag movers, hot TLDs, novelty, daily totals | `--json`, `--limit` (15) |
| `counts [WINDOW]` | Totals by window, type and tag | `--json`, `--limit` (12) |
| `status` | Freshness of TweetFeed's pipeline | `--json` |
| `watch` | Poll for new indicators until Ctrl-C | `--since ISO8601`, `--interval SECONDS` (60), `--type`, `--tag`, `--user`, `--defang` |
| `blocklist KIND` | Ready-made 30-day blocklists | `--limit` (30), `--defang`, `--export FILE` |

`--type` takes `url`, `domain`, `ip`, `sha256` or `md5`. `blocklist` kinds are `domains`, `ips`,
`urls`, `sha256`, `md5`, `hosts`, `adguard`, `rpz`, `dnsmasq` and `nrd-domains`. `--limit 0` means
no limit. `campaigns --export` is accepted but currently does nothing.

### feed

Rolling windows are filtered by the server: IOCaw asks for `/v1/<window>` followed by one path
segment per filter, in the order tag, user, type. A `--user` without a leading `@` gets one added.
Because the segments become URL path components, a filter containing `#`, a space, `%`, `?`, `*` or an
inner `/` is rejected by the policy as `invalid-target` and nothing is sent.

`year` is different: TweetFeed serves the whole year as one unfiltered CSV, so IOCaw downloads it
and applies `--type`, `--tag` and `--user` locally (exact, case-insensitive match; a leading `#` or
`@` is ignored). A one-line notice about this is printed first, even with `--json`. `--contains`
(case-insensitive substring over value, user, type, tweet and tags) is applied to every window.

`--json` prints the first `--limit` rows as a JSON array and nothing else (apart from the year
notice). `--values-only` prints one indicator per line after the header panel. The text view shows
a table of the first `--limit` rows, then a summary of **all** matching rows (counts per type, top
eight tags, top five reporters).

Each row is `{date, user, type, value, tags[], tweet}`.

### lookup, campaigns, trends, counts, status

These print the matching TweetFeed endpoint as panels and tables, or the raw payload with `--json`.
Response fields are all treated as optional. They have only been exercised against mocked
responses, not the live service.

### watch

`watch` polls `/v1/since/<cursor>` every `--interval` seconds, prints rows it has not seen before
(de-duplicated on date, type and value) and advances the cursor to the newest row. A failed poll
prints its error and tries again after the interval, including policy refusals, so a mistyped
`--since` repeats until you press Ctrl-C. Ctrl-C ends the loop with exit code 0.

### Defang and export

`--defang` rewrites `http:`/`https:` to `hxxp:`/`hxxps:` and every `.` to `[.]` in what is
displayed. It never changes JSON output or exported files.

`--export FILE` saves the rows that were shown (so `--limit` applies):

| File ends with | Result |
| --- | --- |
| `.json` | JSON array of the rows |
| `.txt` | one raw indicator value per line |
| anything else | CSV with header `date,user,type,value,tags,tweet` (tags joined by spaces); `.csv` is appended unless already present |

`blocklist --export FILE` instead saves the complete downloaded list, comments included. Nothing is
exported with `--json`, or when no rows matched. Write errors are not handled and surface as a
traceback.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Success, including "no IOCs matched" and "not found" |
| 2 | TweetFeed, network or policy error; bad command-line usage |
| 130 | Interrupted with Ctrl-C (outside `watch`) |

Errors are printed on standard output. On Windows consoles that use a legacy code page, `trends`
and `counts` print characters that the code page cannot encode; set `PYTHONUTF8=1` if you see a
`UnicodeEncodeError`.

## Handling the data

TweetFeed indicators are community-sourced and unverified. Expect false positives. Treat every URL
and domain as hostile, do not open live malicious URLs, and prefer `--defang` when pasting
indicators into tickets or chat. Data text is displayed through `rich`; indicator text that
contains square-bracket markup may be styled or raise an error instead of being shown verbatim.
Use `--json` for the exact bytes the server sent.
