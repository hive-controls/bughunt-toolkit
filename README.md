# Bughunt

**An authorized HTTP attack-surface mapper and toolkit shell.** Bughunt maps
hosts, keeps a per-engagement workspace, and runs its recon/testing modules from
one console — with scope enforcement, a mission-policy gate, and small-by-default
scan limits baked in.

> ⚠️ **Authorized use only.** Run Bughunt against systems you **own** or have
> **written permission** to test. Unauthorized port scanning and web probing can
> be illegal. You are responsible for staying inside your scope and local law.

## Quickstart

Requires Python 3.12 or newer. Python 3.12 is the CI baseline; the
[CI workflow](.github/workflows/ci.yml) lists the tested platforms and versions.
Run these commands from the source checkout.

**Bash (macOS/Linux):**

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-hardened.txt
python -m pip install -e .
bughunt doctor

# Preview the policy decisions for a loopback server you own; sends no requests:
bughunt 127.0.0.1 --ports 8000 --http-only --fast --authorized --dry-run

# Open the interactive console in a terminal:
bughunt
```

**Windows PowerShell:**

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements-hardened.txt
python -m pip install -e .
bughunt doctor
bughunt 127.0.0.1 --ports 8000 --http-only --fast --authorized --dry-run
bughunt
```

`--fast --authorized` records your authorization, adds the targets to scope, and
writes a verified policy for the planned origins. This also writes workspace files
with `--dry-run`; the preview sends no target traffic. To scan an owned server
listening on port 8000, repeat the command without `--dry-run`. Scope alone does
not authorize a scan: without fast mode, import and verify a mission policy first.
Fast mode refuses to overwrite a policy you authored manually.
Its policy expires after 24 hours; added scope entries persist until you remove
them with `bughunt scope remove`. Scope alone grants no network access. The policy
allows GET plus your selected `--method`, including GET used by connection checks.
DNS and CT enrichment require separate explicit policy grants; fast mode warns
when `--dns`, `--ct`, or `--intel` requests that enrichment. Other intel analysis
can still run.

The full distribution is the complete source checkout, including `addons/`,
installed editable (`-e`) inside a virtual environment with the hardened requirements,
matching `bughunt setup` and CI. Keep the checkout in place: addon programs are loaded
from its `addons/` directory. The core wheel contains native modules and integration
helpers; it does not bundle addon source and is not the full toolkit distribution. Activate it in each new shell to use `bughunt`; installation
does not add a global launcher. Activation is optional when calling the interpreter
directly: `.venv/bin/python -m bughunt doctor` on macOS/Linux, or
`.\.venv\Scripts\python.exe -m bughunt doctor` in PowerShell (also works when script
execution policy blocks activation). `python -m bughunt` uses the same environment
and installed dependencies as `bughunt`.

`--screenshots` and Tor routing for `tcurl` need optional extras
(`python -m pip install -e ".[screenshots]"`, `python -m pip install -e ".[tor]"`); see the
[manual's install section](docs/manual.md#install).

`bughunt`, `python -m bughunt`, and
[`bin/http_port_probe.py`](bin/http_port_probe.py) are the same scanner.

## Command surface

Modules are grouped into seven phases that mirror a hunt:
**Engagement → Recon → Capture → Test → Labs → Engines → Intel**. Each phase is
a namespace (`bughunt recon scan app.internal`), and every module also works
flat (`bughunt scan …`), which is the form agents and scripts use. The
interactive console opens on these phases with a one-line purpose each and a
readiness banner that tells you the next step — declare scope, then verify a
mission policy. `bughunt guide` walks you through the hunt step by step from
your current state (the picker's **Guide me** does the same interactively, and
suggests the natural next module after each step). `bughunt catalog` prints the
whole catalog (phases, modules, and each module's option form) as JSON for
scripts and other front-ends.

## Python, JSON and pipelines

The embedding API returns typed, sanitized results without parsing terminal text:

```python
import bughunt

result = bughunt.run_module("scope", operation="list")
print(result.status, result.to_dict()["artifacts"])
```

Prefix a command with `--json` for the same result envelope:

```text
bughunt --json scope list
bughunt --json engagement scope list
bughunt schema result
bughunt pipeline validate owned-chain.json
bughunt pipeline dry-run owned-chain.json
bughunt pipeline run owned-chain.json --execute
```

Catalog v2 lists each operation's parser options, artifact types, side effects,
dry-run support and pipeline restrictions. Pipelines execute sequentially under
shared limits, preserve per-step receipts, and recheck scope, policy and actor
state. Resuming verifies completed evidence and refuses to replay an interrupted
unsafe operation. Running a plan without `--execute` only previews it.
See [the API and pipeline contract](docs/manual.md#python-json-and-pipelines)
for plan examples, explicit typed selections and receipt limitations.

## Running it

Bughunt reads its first argument to decide what to do: a host or scan flag runs the
scanner, a module name runs that module once, and no arguments in a terminal opens
the console. Every path uses the same scope and mission-policy checks. See
[Running Bughunt](docs/manual.md#running-bughunt) in the manual.

Bughunt includes an optional in-process route gate. Configure it with `bughunt route init`; protected console and proxy-scan entry points fail closed when that configuration is invalid or verification fails. With no configuration the route gate is inactive. `BUGHUNT_ALLOW_NO_ROUTE=1` explicitly disables this route check, warns and records an audit event before continuing; audit failure blocks the operation. Scope and mission-policy checks still apply. Bughunt does not create a VPN or provide a continuous kill switch; routing can change after a check.

## Safety model (highlights)

- **Scope-first:** out-of-scope targets are rejected before any DNS or TCP activity; the Snare proxy and `--screenshots` browser automation enforce scope on every hop.
- **Mission policy gate:** outbound requests require a verified `bughunt policy` profile in addition to scope.
- **Small defaults:** common web ports only; a full sweep, large CIDRs, or path explosions require explicit `--authorized`.
- **Proxy discipline:** inherited HTTP proxy env vars are ignored; keep a VPN kill switch covering DNS enabled throughout.

See [the full manual](docs/manual.md#safety-model) for the complete safety model.

## Development checks

Install the pinned development tools in the project virtual environment:

```text
python -m pip install -r requirements-dev.txt
python scripts/check_python_quality.py
python -m pytest
```

The shared quality gate runs Ruff's syntax and undefined-name checks and checks
formatting. Run it before submitting a change; CI checks the working tree. Unchanged legacy formatting is recorded by exact, LF-normalized
content hashes in `scripts/python-quality-baseline.json`. When editing a legacy
Python file, run `python -m ruff format <file>` and remove its baseline entry.
New files must be formatted. Do not regenerate baseline hashes to exempt edits.

## Documentation

- **[Full manual](docs/manual.md)** — install, every command, modules, scanner internals, CLI reference, examples, limitations.
- **[Agent operating guide](docs/agent-operating-guide.md)** — how an AI agent should drive Bughunt safely.
- **[Primary workbench](WORKBENCH.md)** · **[Dispatch](DISPATCH.md)**
- Sample list files live in [`examples/`](examples/).

## Layout

```
bughunt/          the package — core/ console/ integrations/ labs/ modules/
bin/              runnable helpers (http_port_probe.py)
addons/           the programs behind the recon and intel modules
examples/         sample target / header / agent / path lists
tests/            the test suite
docs/             manual, agent guide and product decisions
```

## License / use

Bughunt uses the [Apache-2.0 license](LICENSE). See [NOTICE](NOTICE) and the
[dependency notices](THIRD-PARTY-NOTICES.md) for attribution and dependency scope.

Provided as-is for defensive and authorized testing. Only run it against systems
you own or have written permission to test. You are responsible for staying inside
your scope and local law.
