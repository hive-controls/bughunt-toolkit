---
name: bughunt-typed-specialist-contract
title: "Specialist control requires an accepted typed adapter"
purpose: "Keep specialist execution inside explicit lifecycle and transport boundaries."
subtype: decision
---
# Specialist control requires an accepted typed adapter

Bughunt's bounded native work and existing engine adapters are usable independently
of future specialist integrations. Approved Burp SDK history intake is read-only
and grants no sends. Active engine work remains restricted to its documented
owned-loopback contract.

A generic MCP connection, CLI startup or GUI action does not establish final-send
accounting, cancellation, actor isolation or containment. An installed extension
is not automatically an accepted execution adapter.

Keep specialist admission on typed, hash-bound requests and receipts using the
existing engine, job, actor and ledger primitives. The initial design is
offline-only, zero sends, one worker, 64 KiB input/output and 30 seconds. These
design limits do not create an enabled API, sandbox or authorization token.

Prefer native offline work where useful. A distinct engine gap may justify a
pinned narrow adapter after actual containment, lifecycle and provenance controls
pass. Do not accept arbitrary function names, scripts or command runners as
specialist operations. Paid Burp remains optional; a Bughunt MCP server is not
required.

This boundary avoids assigning extension traffic and global mutable state
Bughunt's authority. See the [workbench contract](../../WORKBENCH.md) and
[product direction](../direction.md) for current capabilities and design intent.
