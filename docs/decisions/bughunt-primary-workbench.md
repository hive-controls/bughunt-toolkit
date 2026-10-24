---
name: bughunt-primary-workbench
title: "Bughunt owns the testing workflow"
purpose: "Define native capability and supporting-engine responsibilities."
subtype: decision
---
# Bughunt owns the testing workflow

Bughunt is the operator's primary authorized-testing workbench. It should replace
external tools where a native implementation serves the mission, and manage
supporting engines where their coverage or protocol machinery is useful.
Required workflows must work without Burp Professional.

## Responsibilities

Bughunt owns authorization, actor verification, scope, request and rate limits,
deadlines, lifecycle, cancellation, redaction, evidence provenance and review of
unconfirmed observations. A supporting engine contributes a selected algorithm
behind an inspected adapter. Configuration generation alone does not prove
execution or containment.

Build a native capability when it closes a measured gap or offers a simpler
maintainable path. Reuse an engine when its coverage or protocol implementation
is valuable. Retire dependencies only after the relevant owned-fixture coverage
passes. Neither a vendor feature list nor a test count establishes general
security-testing parity.

## Current boundaries

- Passive ZAP export creates configuration and sanitized recorded evidence.
  The passive runner analyzes that evidence without new target sends.
- ZAP report imports remain unconfirmed hypotheses linked to private evidence.
- The Burp Community selected-message bridge and approved SDK history intake are
  read-only. They do not grant replay authority or provide a generic extension
  dispatcher.
- The guarded active ZAP profile is a literal-loopback owned laboratory with
  mediated final sends, physical request accounting, cancellation and cleanup.
  It does not establish general authenticated or HTTPS scanning.
- Input discovery accepts explicit candidate names. Callback correlation consumes
  imported evidence; it does not issue payloads or poll a provider.
- Race, HTTP desynchronization and text-WebSocket laboratories stay bounded to
  owned loopback. They do not establish general fuzzing or WSS/proxy parity.
- Browser actors use fresh isolated profiles, selected URLs and verified named
  identities within their documented owned-loopback contract.

The [workbench](../../WORKBENCH.md), [dispatch contract](../../DISPATCH.md) and
`bughunt engine map` provide the operational capability boundaries. Future
specialists require an accepted [typed adapter](bughunt-typed-specialist-contract.md).
A Bughunt MCP server is not required by this workflow.
