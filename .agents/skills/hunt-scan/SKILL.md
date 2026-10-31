---
name: hunt-scan
description: "Drive the bughunt toolkit for an authorized web-testing experiment: recover the mission's execution contract, select one supported bughunt module, preview it, execute the smallest useful test, and return a sanitized receipt. Use when a hunt needs bughunt capture, authorization comparison (replay), one-field IDOR, explicit input discovery, passive ZAP, or bounded engine intake. Not a campaign planner, blanket scanner, or report-submission skill. VERIFIED against bughunt 2.15.0 (catalog schema) 2026-10-26; re-check `bughunt catalog` against the installed version before relying on an exact flag."
---

# Hunt Scan

bughunt is the testing workbench and orchestrator: its modules own policy, owned
actors, scope and evidence. Choose a supported module, never an unrestricted engine
invocation that circumvents bughunt's contracts. The campaign chooses the
hypothesis; this skill drives its smallest useful test.

An invocation, installed engine or bus brief does not authorize target traffic.
Planning-only requests stay offline. Existing explicit mission authorization can
cover execution without a redundant approval; missing authority requires a pause
before the affected action, not an invented grant.

## Recover the execution contract

Read the calling project's instructions and the current mission rules, test ledger
and plan. Recover exact targets/methods, automation restrictions, owned fixtures,
actor roles and outstanding cleanup. State the experiment's invariant, positive and
negative controls, the operation, request/deadline limits, stop condition and
cleanup. Count oracle and control requests, not only the interesting one.

Resolve the bughunt tool for THIS repo — the toolkit checkout or install the
project's own instructions name — and its prepared, mission-private workspace; do
not assume an absolute path or the cwd-default workspace. Then orient from the
tool's own machine-readable surface, not memory:

```text
bughunt version
bughunt doctor          # Python, packages and tools bughunt relies on
bughunt catalog         # full command surface as JSON — the source of truth
bughunt guide           # the next step from the current readiness state
bughunt modules         # every module, grouped by hunt phase
```

`catalog.readiness` reports `scope_ready`, `policy_verified`, `has_identity` and
the next step. `catalog` marks every operation's `side_effect` — **read** (inert),
**write** (local state only), or **network** (sends target traffic) — and whether it
`supports_dry_run`. That side-effect field, not a command's name, is the authority
boundary: every `network` or `write` op previews with `--dry-run` first.

Require independently verified, fresh policy for the exact asset, path, method and
operation. A host scope entry alone is not authority. Do not mark a draft verified,
refresh a timestamp, widen a grant, install a dependency or change a pin just to make
an operation pass. Keep the normal tunnel/route check for external traffic
(`bughunt route check HOST`).

## Select the supported path

Pick by phase (`bughunt modules`); read [operations.md](references/operations.md)
for the one module's real flags before running it.

| Experiment needs | Module and boundary |
| --- | --- |
| Declare/inspect permitted targets | Engagement: `scope` (init/add/allow/list). `write` ops change the workspace. |
| Verified owned actors + one baseline | `identity` (create/set/use), `verify configure` then `verify check` (**network** — a probe request), `repeater` for one authorized baseline send. |
| Compare authorization across actors | Test: `replay REQUEST --owner --lower --anonymous` (**network**); `--dry-run` first. |
| One-field object-reference check | Test: `idor REQUEST --actor --field --compare` (**network**); `--dry-run` first, `--execute`/`--allow-write` are explicit opt-ins. |
| A few explicit hidden inputs | Test: `discover EXCHANGE_ID --query/--header/--cookie --requests --seconds` (**network**); preview first. Not a wordlist miner or crawler. |
| Inspect/import existing traffic | Capture: `exchange import-raw/import-har/import-burp/import-run`, `exchange show/export` — inert; check completeness and provenance before selecting it. |
| Passive ZAP over recorded captures | Engines: `zap export EXCHANGE_IDS --actor ...` then `zap import` — sanitized recorded captures, no new target sends beyond the guarded consumer. |
| Bounded engine intake (e.g. Burp) | Engines: `engine doctor PROFILE`, `engine dry-run PROFILE ...`, `engine start PROFILE ...`; read `engine map`/`engine list` first. |
| Owned active / race / ws / desync | Labs only: their accepted owned-loopback profiles (`zap active --owned-lab`, `race`, `ws`, `desync`). Read the profile's restrictions; never aim them at production. |
| OAST correlation | Engines: `oast register RUN_ID --provider --domain` (already-issued, approved payloads) and `oast import`. Provider registration/polling is a separate, later capability. |

`engine map` is dated acceptance metadata; `engine list` is local component
inspection. Neither proves a running engine, successful login, permission or broad
capability parity. Where `bughunt modules` or `engine map` shows a capability
unavailable or "not on disk", report it unavailable — do not substitute an arbitrary
MCP tool, UI macro, script or direct engine command.

Saved cookies and imported actor labels are not verified authentication. Use
`identity set NAME --prompt` and `verify configure --prompt-principal/--prompt-role`
for hidden input; if no suitable TTY or owned oracle exists, report what is missing.
Never read a credential store into chat or put a secret on a command line.

## Execute and reconcile

Inspect the selected source, the preview and the budgets before any authorized
execution. Do not run every example as a checklist. Changed source/policy/actor
state, an expired grant, rejected bounds or incomplete evidence require
re-investigation, not a wider retry. A GET can still alter server or cache state.

A managed `engine start` / `zap` run is a running CLI, not a fire-and-forget daemon:
keep the receipt (`run_id`, job id, cancel command), keep the process alive, and
inspect status or cancel from a second terminal with the same workspace. A cancel
request alone is not cleanup, and `ledger cleanup ... complete` only labels a record.
Do not broadly kill Burp, Docker or unrelated jobs.

Preserve negative, lead, invalid and inconclusive outcomes separately. Alerts and
callbacks are hypotheses, not confirmed impact; an empty report is not a clean bill
of health. Mark decision-driving observations VERIFIED / ASSUMED / UNVERIFIED /
PROXY, naming what a proxy stands in for. An owned toy lab is not production
applicability. Let the campaign's maturity gates decide a finding's status rather
than upgrading a bughunt result automatically.

Export the run and its linked report/capture through `ledger export`; sanitized
exchange derivatives by default. Hash failures block export. Review sanitized output
for application-specific secrets before sharing. Respect the calling repo's exact
synthetic-fixture cleanup/retention rules; do not destroy retained evidence to turn a
cleanup field green.

## Return to the calling hunt

Return a compact receipt: executed / blocked / not-run; hypothesis and control
result; module, profile and bughunt version; policy and actor provenance;
run/job/exchange and linked report ids; actual traffic count and how it was measured;
classification and evidence limitations; sanitized artifact pointers; cleanup and
residual state; and the next smallest useful test. Reconcile the mission test ledger
when that is in scope, else hand the entry back to its owner. Never submit a report,
or count a confirmed finding, from tool success alone.
