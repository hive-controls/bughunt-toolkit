# Agent operating guide — driving Bughunt

For an AI agent asked to operate the Bughunt tool on a user's behalf. This is
about **running the tool safely**, not editing the repo. Read the
[full manual](manual.md) for exhaustive command detail.

## First principle: authorization is a precondition, not a step

Bughunt probes live network targets. Do **not** run any scan, module, or addon
until the user has confirmed they **own the target or hold written permission**
to test it. If that is unstated, ask — do not infer it from the fact that a
target was named. Unauthorized scanning can be illegal, and the tool's rails
reduce blast radius but do not grant authority.

## The three gates (all must hold before traffic leaves)

1. **Scope.** Targets are checked against `./.bughunt/scope.txt` before any DNS
   or TCP. Establish it first: `python -m bughunt scope init`, then add the
   authorized hosts. Out-of-scope requests are refused, including browser
   subresources and redirect hops.
2. **Mission policy.** Outbound requests also require a *verified* dated profile:
   `bughunt policy example > p.json` → independently verify → set provenance/time
   → mark `verified` → `bughunt policy import --file p.json`. Draft/stale/future
   profiles fail closed. Check a specific action with `bughunt policy check <url>
   --operation <op> --method <M>`.
3. **Network route.** The supported launchers verify a VPN adapter + public route
   before scanning; keep a VPN kill switch covering DNS enabled. Inherited HTTP
   proxy env vars are ignored; a proxy is used only when you pass `--proxy`.

## Invocation

- Canonical: `python -m bughunt <target> [flags]` (equivalently the `bughunt`
  console script, or `bin/http_port_probe.py`).
- Interactive console: `python -m bughunt` with no arguments.
- Modules are grouped into seven phases (engagement, recon, capture, test,
  labs, engines, intel). `bughunt <phase> <module>` runs one grouped, but the
  flat `bughunt <module>` form is fine for agents — prefer it in scripts.
- `bughunt catalog` prints the full phase/module/option-form tree as JSON.
  Enumerate capabilities and build invocations from that, rather than parsing
  help text; a disabled or unavailable module reports `form: null` with a
  reason.
- The scope workspace path is `./.bughunt` or `$BUGHUNT_SCOPE`. Captures can hold
  raw credentials — keep the workspace in the tooling's ignored location and do
  not exfiltrate it.

## Respect the safety rails — do not reflexively override them

Scan defaults are intentionally small. These require an explicit `--authorized`
(alias `--i-own-this`), which you should pass **only on the user's explicit
instruction for a target you have confirmed is authorized**:

- full `1–65535` port sweep (`--all`), or a port list > 4096
- CIDRs larger than `/24` (hard cap 1024 expanded hosts)
- `--skip-tcp` across > 1024 ports
- discover / mutate-paths / params expansions past 400 paths

Automatic redirect following (`scan --follow-redirects`) is disabled by design;
do not seek a way around it.

## Output

Scans write artifacts into the workspace and can emit `--json` / `--csv` / `--md`
reports (redacted via the ledger). Summarize findings for the user; surface the
report paths rather than pasting raw credential-bearing captures.

## When a hunt needs orchestration

The repo ships a `hunt-scan` skill for driving a bounded, authorized web-testing
experiment (evidence selection, permitted tests, sanitized receipts). Prefer it
over ad-hoc flag combinations when the task is a structured hunt.

## Never

- Scan or probe a target whose authorization you have not confirmed.
- Pass `--authorized`/`--all`/large-CIDR flags to "see what's there" without the
  user asking for that specific authorized target.
- Disable or route around the scope, policy, or VPN gates.
- Copy workspace captures (which may contain credentials) outside the engagement.
