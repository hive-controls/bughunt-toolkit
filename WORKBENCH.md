# Bughunt as the primary workbench

This is the bounded core workflow, not a claim of complete Burp/ZAP replacement.
VERIFIED against Python 3.14.3, HTTPX 0.28.1 and pinned ZAP 2.17.0 owned fixtures
on 2026-10-14. Broader capabilities retain their explicit gaps below.
Use only an owned or explicitly authorized mission. Keep `BUGHUNT_SCOPE` in a
private ignored workspace and use Tooling's normal VPN-gated launcher. This guide
does not authorize live targets or widen the current engine profiles.

## Discover and prepare

```text
bughunt engine map
bughunt engine list
bughunt policy status
bughunt identity list
```

`engine map` is versioned fixture coverage with linked live issues, supported
versions, acceptance commands and remaining gaps. It is inert metadata, not
runtime availability or execution authority. `engine list` checks local launcher
and configured-component state without starting an engine. Configured Burp is
not a connected protocol session. Missing Burp does not block native/ZAP work.

Author and independently verify exact policy/scope before sending anything.
Credentials belong in origin-bound named identities; enter them with
`bughunt identity set owner authorization --prompt`, not command history.
Configure the owned server-side identity oracle with `bughunt verify configure`
and hidden expected-principal/role prompts. Saved cookies or actor labels are
not successful authentication or proof of crawled coverage.

## Collect, select and analyze

For an already authorized raw baseline and independently configured actors:

```text
bughunt identity use owner
bughunt verify check owner
bughunt repeater baseline.http
bughunt ledger list
bughunt exchange import-run CAPTURE_RUN_ID
bughunt exchange show EXCHANGE_ID
bughunt engine dry-run zap-passive EXCHANGE_ID --mission CURRENT_MISSION --actor owner --actor viewer --actor anonymous
bughunt engine start zap-passive EXCHANGE_ID --mission CURRENT_MISSION --actor owner --actor viewer --actor anonymous
bughunt engine status JOB_ID
bughunt engine cancel JOB_ID
```

Substitute IDs returned by the preceding commands; inspect each plan. Passive
ZAP analyzes sanitized recorded traffic in the pinned network-disabled consumer
and automatically imports its report. It sends no new target requests. Named
passive actor labels are not newly verified login sessions. The starting receipt
provides a stable job/run ID and cancel command before execution finishes.

The existing active profile is **owned-lab only**: mission
`whk012-owned-active`, literal `127.0.0.1` HTTP, `/__bughunt_lab__/` paths,
bodyless GET with one non-credential query parameter, Python rule 40012 and a
credential-free default actor. It does not accept production-domain, HTTPS or
authenticated scanning. Select a complete owned HTML capture, switch explicitly
to `default`, then inspect `engine dry-run zap-owned-active ... --owned-lab
--technology Python --requests 8 --seconds 90` before explicitly choosing `start`.
Every physical active send is mediated and accounted for by Bughunt.
Request-count accounting is distinct from write timing. The dispatch gate
uses a workspace-shared lease through the pinned native HTTP request-header write,
then waits the configured interval before the next write. Ledger preparation,
connection setup and final assertions cannot consume that interval early.
Owned HTTP/1.1 sync, async and mixed-client arrival controls pass. This is local
write assurance, not a guarantee of remote arrival or processing timing; opaque
transports and legacy raw operations retain admission-only limits. Read the
[dispatch contract](DISPATCH.md) for exact paths, protocol limits and proof commands.

## Isolated owned browser actors

The `browser-owned` engine profile uses one named actor and a new private
Chromium profile per job. Its current acceptance is **owned literal-loopback
HTTP only**, not production-domain browsing or a general login/crawler.
Read the [engine setup and limits](docs/manual.md#engines--integrated-engines-and-callbacks)
before choosing this profile. It requires the pinned local image/driver and the
actor's independently configured same-origin identity probe; Burp is not used.

```text
bughunt engine dry-run browser-owned PAGE-URL RESOURCE-URL --actor owner --mission whk027-owned-browser --owned-lab --requests 20
bughunt engine start browser-owned PAGE-URL RESOURCE-URL --actor owner --mission whk027-owned-browser --owned-lab --requests 20
bughunt engine status JOB-ID
bughunt engine cancel JOB-ID
```

Select every permitted page/subresource/redirect URL explicitly. Browser traffic
has no direct external network route; Bughunt verifies the actor immediately
before every selected host GET and counts both the probe and that request.
Browser credential headers cannot switch identities. Profiles/cookies/storage
are not shared or imported from personal browsers, and saved selection is not
changed. Rendered observations are hashes with linked private HTTP evidence.
WebSockets/service workers are blocked, not a newly available protocol workflow.
Strict final-write spacing follows the separate [dispatch contract](DISPATCH.md).

## Compare and export

```text
bughunt replay baseline.http --owner owner --lower viewer --anonymous anonymous --dry-run
bughunt replay baseline.http --owner owner --lower viewer --anonymous anonymous
bughunt ledger show RUN_ID
bughunt ledger export RUN_ID
```

Replay makes fresh server-side assertions for each actor. Its negative, lead,
invalid and inconclusive classifications are distinct; matching bodies do not
automatically prove impact or severity. Export both engine and linked report run
IDs for a sanitized evidence packet. Hash/source/job links remain inspectable;
private originals are not a default export. Changed evidence blocks export.
Empty scanner reports are not proof that an application is safe.

## Accepted scope and later work

The opt-in `test_workbench_consumer.py` fixture drives the primary CLI against an
owned two-account/anonymous HTTP server and the actual pinned ZAP consumer. It
checks capture/select, passive zero sends, bounded active wire counts, live
status/cancel, report import, identity/authorization controls and sanitized
exports. The unavailable-Burp-config control does not uninstall or stop the
operator's Burp; no Burp protocol operation is used in this core path.

Acceptance commands in `engine map` name the source-checkout working directory
and its prepared `.venv` interpreter; a global Python with `PYTHONPATH` is not
an equivalent environment for isolated-process controls. From that checkout on
Windows, run the owned fixture with a local Docker daemon and the pinned ZAP
image already present (the fixture does not pull images):

```powershell
$env:BUGHUNT_WORKBENCH_INTEGRATION = '1'
.\.venv\Scripts\python.exe -m pytest -q tests/test_workbench_consumer.py
```

This runs the Burp-independent core and native actor controls. To include the
optional `configured-no-use` comparison, also set `BUGHUNT_BURP_PROFILE` to an
existing inspected absolute local profile. Unset skips only that comparison;
an explicitly supplied missing, redirected or changed profile fails rather
than silently skipping. This is a configuration comparison, not a Burp protocol
test. On fixture failure, cleanup cancels the job before waiting for the CLI;
fallback removal requires its new job ID, exact container name, ownership label
and pinned image, followed by an absence read-back. Offline process-edge tests
are PROXY controls, not substitutes for the real owned consumer run.

Burp intake remains a separate approved read-only `burp-mcp-intake` job; SDK text
is explicitly incomplete, not wire bytes or verified actor identity. Authenticated
exploration, minimization, production-domain browser support, live OAST and
general WebSockets remain linked gaps in `engine map`. Offline selected-exchange
triage and the bounded owned-browser profile are native workbench capabilities.
Specialist control needs
a separately accepted typed adapter and enforced transport, not a GUI macro or
generic MCP/script dispatcher. A Bughunt MCP server is not required by this flow.
