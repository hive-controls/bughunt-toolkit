# Contributing to Bughunt

Bughunt is for authorized HTTP testing. Report security issues privately as
described in [SECURITY.md](SECURITY.md).

## Development environment

Use a complete source checkout, including `addons/`, and a virtual environment.
Python 3.12 is the baseline. CI also validates Windows on Python 3.14, macOS route
handling on 3.12, and the optional native flow reader on Linux 3.14; see the
[workflow](.github/workflows/ci.yml) for the exact matrix.

Bash:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-hardened.txt -r requirements-dev.txt -e .
python scripts/check_python_quality.py
python -m pytest
```

Windows PowerShell:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-hardened.txt -r requirements-dev.txt -e .
.\.venv\Scripts\python.exe scripts/check_python_quality.py
.\.venv\Scripts\python.exe -m pytest
```

The source installation provides native modules and the shipped addon programs.
The secondary core wheel does not bundle addon source. Optional browser, Tor,
native flow-reader dependencies are described in the
[manual](docs/manual.md#install). Packaging tests install declared dependencies
into fresh virtual environments; they may fetch packages. Other tests use owned
loopback or offline fixtures. Docker, attended Burp and platform-specific
integration checks have explicit prerequisites; a skip is not an execution receipt.

## Workflow

1. Branch from `main` and keep the change focused.
2. For a bug fix, first add a failing regression that reproduces it.
3. Format edited Python files with `python -m ruff format <file>`. Retire their
   entries from `scripts/python-quality-baseline.json`; do not regenerate exemptions.
4. Run the quality checker and affected tests, then the full required validation.
5. Open a pull request with the behavior change and validation results.

The public repository is an exported source snapshot. Maintainers apply reviewed
changes in the source repository before exporting the next snapshot.

## Code and test expectations

Use descriptive names, small functions, explicit exception handling and the
surrounding code's style. Avoid unrelated refactoring. New modules require
relevant behavioral tests and must not create circular imports.

Network traffic must use the guarded clients in `bughunt/core/egress.py` and
honor scope, mission policy, actor verification, physical accounting, cancellation
and deadline checks. Preserve configured route enforcement and audited opt-outs.
Labs stay explicitly owned and loopback-pinned. Do not make authorization flags
implicit or weaken default bounds.

Never commit actual credentials, engagement captures, session data, private
keys, generated binaries or local workspace files. Use clearly synthetic fixtures.
Keep genuine recorded fixture bytes and their provenance checks intact.

Contributions use the project's Apache-2.0 license; see [LICENSE](LICENSE).
