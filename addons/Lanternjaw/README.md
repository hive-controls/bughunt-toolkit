# Lanternjaw

A read-only command-line client for the public [phishunt.io](https://phishunt.io/api/) phishing feed.
It browses and filters the active detections, summarizes them, pivots on shared infrastructure, follows
campaign clusters, checks your own indicator list against the feed, polls for new detections, snapshots and
diffs the feed, and writes a Markdown brief.

Inside Bughunt the addon is the `phish` command (`lanternjaw` is an alias), in the Intel phase:

```
bughunt phish --help
bughunt phish pulse
```

## Install

Lanternjaw is a single file with two third-party dependencies:

```
pip install -r addons/Lanternjaw/requirements.txt    # httpx==0.28.1, rich>=13.7.0
```

Bughunt's own `httpx` pin applies because the egress layer relies on that version. To run the file directly
(`python addons/Lanternjaw/lanternjaw.py ...`) the `bughunt` package must be importable, for example by setting
`PYTHONPATH` to the repository root. Run through the console (`bughunt phish ...`) and no extra setup is needed.

## Policy and scope

All traffic is a plain GET to `phishunt.io`, made through the guarded client in `bughunt.core.http`, so the
engagement policy applies to every request and every redirect hop.

- **Read commands** need a verified policy in the active workspace that lists the asset `https://phishunt.io`
  and permits the `passive` operation for GET on the paths used. Nothing is scope-gated: these commands talk
  to the public feed, not to an engagement target. Without a matching policy a request is refused before it
  is sent (the reason is printed, for example `asset-unknown`).
- **`analyze` and `deep`** hand a URL to phishunt, so they add three gates, checked in this order and all before
  anything is sent: the URL's host must be in the scope file; the policy must grant `active_scan` (GET) on the
  URL's origin; and you must confirm (an interactive y/yes, or `--yes`). Lanternjaw never contacts the submitted
  URL itself. `analyze` asks phishunt to score the string; `deep` makes **phishunt** fetch the URL, so the target
  sees a request from phishunt.
- Redirects are followed by hand, at most 5 hops, and each hop must stay on `phishunt.io`.
- The deep token is sent only to `phishunt.io`.

## Using it

Global flags belong **before** the subcommand: `lanternjaw.py --fresh hunt --company paypal`.

| Flag | Meaning |
| --- | --- |
| `-q`, `--quiet` | do not print the banner |
| `-v`, `--verbose` | print `GET <status> <url>` for every response on stderr |
| `--live` | show raw indicators on screen instead of defanged text (JSON and exports are always raw) |
| `--fresh` | ignore the 10-minute active-feed cache (it is still rewritten) |
| `--timeout N` | HTTP timeout in seconds (default 45; feeds and blocklists always allow 90) |

Many subcommands share these option groups:

- server filters: `--company --since --contains --tier {all,verified} --asn --org --registrar --cert --country --ip`
- client filters: `--verdict {critical,high,medium,low,noise} --min-score N --min-sources N`
- `--json` on everything except `about` and `self-test`: the machine payload on stdout

| Subcommand | What it does | Extra options |
| --- | --- | --- |
| `about` | explains the service and lists the endpoints this tool uses (no network) | |
| `pulse` | dashboard for a slice of the feed | server and client filters, `--json` |
| `hunt` | list detections | filters, `--limit 25 --offset N --all --sort {first_seen,score,sources,brand} --values --export FILE` |
| `search QUERY` | full-text search (3+ characters) | `--limit 50`, client filters, `--sort`, `--export FILE` |
| `analyze URL` | phishunt scores the URL; the target is not fetched | `--yes` |
| `deep URL` | phishunt fetches and analyzes the URL | `--token`, `--yes` |
| `campaigns` | clusters of detections that share infrastructure | `--brand --status {active,all} --min-size N --limit 20 --offset N --all` |
| `campaign KEY` | one cluster | `--export {json,csv,txt} --out FILE` |
| `related UUID` | detections sharing infrastructure with one detection | `--limit 10 --min-score N` |
| `enrich UUID` | registration and geolocation lookups | |
| `brand SLUG` / `cert NAME` | what phishunt knows about a brand or certificate issuer | |
| `feed {json,csv,txt,stix}` | download a feed | `--out FILE --limit 15` |
| `blocklist {domains,hosts,adblock,dnsmasq,unbound,rpz}` | download a ready-made list | `--out FILE --values --limit 20` |
| `pivot {ip,asn,org,cert,country,company,registrar}` | group the slice by one field | filters, `--min-count 2 --limit 25` |
| `triage` | highest scores first, with a detail card for the top row | filters, `--limit 20 --all --export FILE` |
| `inspect UUID` | the detection, its related detections and its enrichment together | `--limit 10 --skip-related --skip-enrich` |
| `match FILE` | check a local indicator list against the feed (`-` reads stdin) | `--show-misses --fail-on-hit --export FILE` |
| `watch` | poll for new detections | `--since --interval 300 --company --country --tier`, client filters, `--limit 50 --once --log FILE` |
| `snapshot` | save the active feed to a file | `--out FILE` |
| `diff SNAPSHOT` | compare a snapshot with the live feed | filters, `--limit 20 --export FILE` |
| `report` | Markdown brief on stdout | filters, `--limit 15 --out FILE` |
| `self-test` | offline sanity checks | |

Notes on the less obvious ones:

- Server filters on `pulse`, `hunt`, `triage`, `pivot` and `report` are sent to phishunt's domains API (paged
  1000 rows at a time, up to its offset ceiling of 10000). With no server filter the whole active feed is used
  and filtered locally. `hunt --offset N` fetches one raw API page, but only together with a server filter;
  without one the offset is ignored and the whole feed is shown.
- `--contains` is cleaned to letters, digits, `.`, `_` and `-` and must then be 3 to 80 characters.
- `match` never uploads your indicators: it downloads the feed and matches locally. It accepts defanged input
  (`hxxps://evil[.]example`), one indicator per line, `#` comments, and takes the first column of a CSV-style line.
  Each indicator is tried as an IP address, an exact URL, an exact domain, a parent of known phish hosts
  (`subdomain-of-indicator`) and finally a host under a known phish host (`under-known-phish-host`), in that
  order; the first rule that finds rows wins.
- `diff` applies the same filters to both sides locally, so a brand-scoped diff does not report other brands as
  gone. `--tier` cannot be applied to a snapshot and is ignored with a warning.
- `watch` never polls more often than every 30 seconds and prints one JSON document per poll that found new rows.
- `report` headings (`# Lanternjaw brief`, `## Snapshot`, `## Verdicts`, `## Targeted brands`, `## Hosting`,
  `## Hottest`, `## Newest`, `## Defanged indicators (hottest)`) are stable if you split on them.

## Output

- Screen output (tables, panels, notices, errors) goes to **stderr** and is defanged (`hxxps://evil[.]example`)
  unless `--live` is set. **stdout** carries only machine output: JSON, `--values` lines, raw feed or blocklist
  text, the Markdown report, help text, and the confirmation prompt when you answer it interactively.
- With `--json` errors are also written to stderr as one JSON line, `{"error": "...", "status": 404}`.
- Exports (`--export`) choose the format from the extension: `.json` (pretty array), `.txt` (one URL or domain per
  line), anything else CSV (`.csv` is appended unless the name already ends in it). CSV columns:
  `uuid, first_seen, date, verdict, score, company, domain, url, ip, country, asn, org, cert,
  malicious_google, malicious_openphish, malicious_phishtank, malicious_tweetfeed, malicious_urlscan`.
  Exports hold live (not defanged) indicators. `--export` is skipped when `--json` is also given.
- The active feed is cached for 10 minutes at `$XDG_CACHE_HOME/lanternjaw/feed.json`, or
  `~/.cache/lanternjaw/feed.json` when that variable is unset.

| Exit code | Meaning |
| --- | --- |
| 0 | success, including empty results |
| 1 | network or API failure, unreadable input, a refused `deep` call, and `match --fail-on-hit` with a hit |
| 2 | bad usage or input, an out-of-scope, unconfirmed or policy-denied URL, HTTP 400 or 404 |
| 130 | stopped with Ctrl-C (the normal way out of `watch`) |

## What leaves your machine

phishunt sees what you ask it. `analyze` and `deep` send the URL (phishunt logs it; prefer a bare domain if a URL
carries tokens). `search` sends the query; filtered `pulse`, `hunt`, `triage`, `pivot`, `report` and `watch` send
the filter values; `campaign`, `brand`, `cert`, `related`, `enrich` and `inspect` send their identifiers. Only
`analyze` and `deep` are confirmed and scope-gated. `match`, unfiltered `pulse`, `hunt`, `triage`, `pivot` and
`report`, `diff`, `snapshot` and the feed part of `inspect` download the whole feed and filter locally, so your
indicators stay with you.

`deep` uses a token and a shared budget of 50 analyses per UTC day. Prefer the `PHISHUNT_DEEP_TOKEN` environment
variable to `--token`, which is visible in process listings and shell history. The egress run ledger
(`runs/<id>/request.http` in the workspace) stores request headers as sent, so the token is in that private
record; protect the workspace accordingly.

## Limits worth knowing

- Names with spaces or apostrophes (`cert "Let's Encrypt"`) are percent-encoded, which the policy path grammar
  rejects, so only single-token issuer names such as `R3` can be queried under an active policy.
- A policy denial is retried like a network error before it is reported (about 7 seconds of backoff).
- Data from the service is rendered for people, not sanitized for terminals; treat strings from the feed as
  untrusted.

## Data and honesty notes

phishunt publishes its detections as CC0 open data. The `sans_score` fields come from SANS ISC DShield data under
CC BY-NC-SA 4.0 and keep that attribution. Scores are heuristics and false positives happen. A source flag that
is false means the source had not flagged the URL when last checked; it does not mean the URL is clean. Campaign
clusters describe shared infrastructure, not attribution to an actor.
