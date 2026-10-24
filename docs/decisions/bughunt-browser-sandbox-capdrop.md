---
name: bughunt-browser-sandbox-capdrop
title: "Sandboxed Chromium needs namespaced chroot under cap-drop ALL"
purpose: "Preserve the owned browser runtime prerequisite without disabling Chromium sandboxing or adding host capabilities."
subtype: research-finding
signature: "Network-none non-root Chromium; Playwright namespace profile passes unshare but sandbox fails at sys_chroot fdinfo under cap-drop ALL"
metadata:
  type: project
files:
  - bughunt/integrations/browser_actor.py
session: "2026-10-15"
---

Observed with Docker Engine 29.8.2 (8af9fe3): the original Playwright
v1.62.1 seccomp profile permits chroot only when startup OCI bounding capabilities
include CAP_SYS_CHROOT. cap-drop ALL removes that allowance. Later creating a
user namespace cannot restore an omitted inherited seccomp rule.

Read-only discriminating controls: default Docker seccomp rejects unshare -Ur;
the original Playwright profile permits it, but chroot of both / and the existing
/proc/self/fdinfo directory still returns EPERM inside the namespace. A root-cause
review traced the Moby startup capability filter and Chromium's matching fdinfo
filesystem-sandbox operation. Chromium's fatal errno2 was not the authoritative
syscall reading; the reason for that log errno remains UNVERIFIED.

Controlled subsequent proof: retain the exact default-deny upstream profile and
add only an unconditional chroot syscall allowance. With network none, read-only
root, UID/GID1000, cap-drop ALL and no-new-privileges, matching playwright-core
1.62.1 launched Chromium151.0.7922.34 using chromiumSandbox:true and an owned
tmpfs persistent profile with mode0700. No privileged mode, unconfined seccomp,
host capability grant, no-sandbox flag or Docker-daemon change was used.

Pinned image digest dcc5531e97840b9b5e794f2814476b21571c5124a3fca2267d73041f56e7580e.
Driver archive SHA256954be1e183d0ddb9748fe0d2d08b0b66a9210c74dd75c397aeb70303b9f08a00.
Upstream profile SHA256cc3e61cabda6bbc1e53e54d27ba4d55a9d3be829b6dd1a596f4a7b31b1cc7849.
The adapter refuses source drift before generating the one-syscall addition.

Scope: launch feasibility only. Actual browser route containment, verified actor
separation, physical request budgets, cancellation and sanitized evidence still
need the owned browser consumer acceptance. Cross-platform portability and
complete renderer namespace attestation are not established by this launch.

Sources: https://github.com/microsoft/playwright/blob/v1.62.1/utils/docker/seccomp_profile.json
and https://raw.githubusercontent.com/moby/moby/8af9fe3/vendor/github.com/moby/profiles/seccomp/seccomp_linux.go;
Chromium sandbox/linux/services/credentials.cc.
