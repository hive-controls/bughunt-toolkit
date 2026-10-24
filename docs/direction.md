# Bughunt product direction

Bughunt is the primary authorized-testing workbench and orchestrator. Prefer
native functionality where it benefits the mission; use supporting engines for
capabilities whose execution Bughunt can bound, monitor, cancel and ingest.
Burp Community and ZAP are optional supporting engines. Required capabilities
must not depend on Burp Professional or paid Burp features.

Policy enforcement, actor verification, request accounting, redaction and
evidence classification remain under Bughunt control. A file bridge, a vendor
feature listing or a narrow lab fixture does not establish general capability
parity. Keep those limits visible in the [capability map](../WORKBENCH.md).

The [workbench decision](decisions/bughunt-primary-workbench.md) describes how
native and external capabilities are selected. The [specialist contract](decisions/bughunt-typed-specialist-contract.md)
describes the admission boundary for future adapters. Current supported commands
and operational limits live in the [manual](manual.md).
