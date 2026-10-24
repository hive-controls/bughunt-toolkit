# Security Policy

Bughunt is an HTTP/HTTPS attack-surface mapper. It is for **authorized use only**:
run it against systems you own or have written permission to test. This document
explains what its safety controls do and do not guarantee, and how to report a
vulnerability in Bughunt itself.

## Authorization and safety model

Bughunt contains real enforcement code. It also relies on the operator being
honest about authorization. Both statements are true, and you should understand
the boundary between them.

### What the code enforces

- **Egress gate.** Outbound HTTP goes through a single transport wrapper
  (`bughunt/core/egress.py`). Each request is checked against the loaded policy
  for its target, operation, and method before dispatch, and is re-checked at
  dispatch time. Redirect hops and proxy endpoints are authorized too, and
  inherited proxy environment variables are ignored (`trust_env=False`).
  A request with no valid policy does not leave the process.
- **Policy state.** `bughunt/core/policy.py` parses a strict JSON profile
  (`policy.json`). Only the `verified` state permits anything; `draft`,
  `stale`, and `unknown` deny, and a `verified` profile goes stale after its
  `stale_after_seconds` window (at most one year). Access is granted per exact
  origin, path, operation, and HTTP method, with exclusions taking precedence.
- **Scope.** Targets must match the workspace `scope.txt` allow-list
  (`bughunt/core/workspace.py`). With no scope file, only loopback is allowed.
- **Loopback-pinned labs.** The higher-risk lab modules (`race`, `desync`,
  `ws`) refuse anything but an explicitly owned, literal-loopback target
  (`bughunt/labs/`).
- **Optional route enforcement.** `bughunt/core/route.py` reads the OS routing
  table without sending packets. A configured route gate can protect console
  entry and proxy-scan startup. Invalid configuration, probe failure or an
  unverified route blocks those protected points. No configuration means inactive.
- **Small defaults.** Large port sweeps, large CIDR ranges, and large path
  sets are refused unless `--authorized` is passed (`bughunt/core/scanner.py`).

### What is self-attested

Bughunt cannot know whether you are actually authorized. These inputs are
**assertions by the operator**, not verified facts:

- `--authorized` (alias `--i-own-this`) is a flag. It lifts the small-default
  limits; it does not check ownership or permission.
- `scope.txt` is a file you write. Bughunt enforces the scope you declare; it
  does not verify that you may test those hosts.
- `policy.json` is a document you write or import. "Verified" means the
  profile is well-formed, marked verified, and within its freshness window. It
  is not proof that a third party granted permission.
- **Loopback is always allowed** at the scope layer and needs no entry.
- `BUGHUNT_ALLOW_NO_ROUTE=1` is an explicit per-run route-gate opt-out. It warns
  and persists an audit event before continuing; audit failure blocks the operation.
  Scope, mission policy and egress checks remain active. Bughunt does not create a
  VPN or a continuous kill switch; a route check cannot prevent later OS route drift.

The controls enforce the boundaries declared by the operator. They do not
establish the operator's permission to test.

## Responsible use

- Test only systems you own or hold written authorization to test, and stay
  inside that authorization's scope, rate limits, and time window.
- Keep `scope.txt` and `policy.json` accurate. Do not widen them to reach
  hosts you are not authorized to test.
- Treat captured traffic, sessions, and run artifacts under `.bughunt/` as
  sensitive; do not commit or share them.
- Obey applicable law. Unauthorized scanning and probing can be illegal.
- Do not use Bughunt to evade, disable, or work around its own scope, policy,
  or egress controls.

## Supported versions

Only the current `main` branch is supported. Fixes land on `main`; there are no
backports or separate supported release branches.

## Reporting a vulnerability

Please report vulnerabilities **privately**. Do not open a public issue or pull
request for a security problem.

Use GitHub's private vulnerability reporting: open this repository's
**Security** tab, choose **Report a vulnerability** (Security Advisories), and
describe the issue. Include affected version, reproduction steps, and impact.

Relevant reports include bypasses of the scope, policy, or egress gates, loopback
lab escapes, credential or secret leakage in output or run artifacts, and unsafe
handling of untrusted input. The following are not vulnerabilities: the
self-attested nature of `--authorized`, `scope.txt`, and `policy.json`
described above, or the absence of a built-in VPN or continuous kill switch.
Bypasses of configured route enforcement or its required opt-out audit are in scope.

We will acknowledge reports as promptly as we can and coordinate a fix and
disclosure with you.
