# Outbound dispatch contract

Policy rate is a ceiling, not a throughput promise. Bughunt keeps connection/action
admission, concurrency, managed request counts and final write pacing distinct.
The shared state is keyed by workspace inside one Python process. Separate CLI
processes do not share a rate clock or concurrency counter.

| Path | Boundary and evidence |
|---|---|
| Native HTTPX 0.28.1 / httpcore 1.0.9 | Final assertions and one-use proof claim precede the native request-header write. The shared lease remains held until that write completes or fails; the next write waits a full policy interval from completion. Owned HTTP/1.1 sync, async and mixed-client wire controls pass. |
| Managed HTTP jobs / active ZAP host bridge | Trusted preparation wrappers retain their budget/response checks. One budget admission happens before native connection setup, including failed connection attempts; header pacing does not charge it again. Existing six pinned ZAP consumer modes pass. |
| WebSocket and desync laboratories | Each bounded protocol/socket write acquires the shared lease after capture preparation, final checks and timeout preparation. Existing owned wire, cancellation and revocation consumers pass; their original lab limits remain. |
| DNS | Every datagram attempt, including the existing bounded retry, checks the target, resolver and actor/policy binding before taking the write lease. |
| Opaque/custom transports | The final known transport entry receives admission pacing and policy/budget checks. Its internal writes are not inspectable, so no write-spacing assurance is claimed. It retains in-flight concurrency. |
| Other raw function/process guards | Fresh policy/actor checks and bounded admission precede entry. This does not pace every DNS/connect/TLS/protocol operation performed inside an opaque function or process. Browser/engine containment requires its own accepted contract. |

The native seam covers request headers, not every TCP packet, TLS record, HTTP
body chunk or automatic HTTP/2 control frame. A local write timestamp is not a
server arrival timestamp, and neither proves remote processing order. Kernel
buffering and network delay can change arrival spacing. HTTP/2 trace behavior is
source-backed and fault-tested only; the optional HTTP/2 dependency is absent in
the accepted local environment. Actual TLS/proxy/HTTP/2 wire parity is not claimed.

## Policy, accounting and interruption

`bughunt/egress.py` retains the pre-DNS policy gate and shared capacity/admission
state. `PreparedTransport` lets the existing job and capped-response wrappers
finish preparation before the final native seam. Each request keeps its own
ledger run, actor snapshot and source/proof association. Queued checks re-read
policy, actor, scope, deadline and cancellation; one-use proof claiming occurs
once at the final request-header boundary. A waiting task does not hold the
workspace write mutex. A task already writing holds it only through that write,
not through response-header arrival or response-body consumption.

The next gap is calculated from the previous write's completion using the stricter
of its rate and the freshly authorized rate. Tightening policy therefore extends
an outstanding gap; loosening it cannot shorten the previous write's interval.

Exceptions and cancellation release both leases and capacity and retain invalid
or partial evidence. Stop prevents new attempts; it is not in-flight revocation.
Managed timeouts refresh from the remaining job deadline. Connection failures
still consume one request attempt, preventing repeated failed connections from
escaping a cap. Redirects and explicit caller retries enter the gate per hop or
attempt; native hidden transport retries and Unix-socket routes are unavailable.

Native trace/version mismatch is an explicit failure. A preserved operator trace
runs before the pacing point and is restored after the native call. Trace failure
or cancellation cannot retain the write mutex. Native header events must carry
the originating run ID; a repeated or mismatched event cannot reuse a proof.

Manual approved HTTP-proxy CONNECT setup is paced and recorded separately from
origin headers. Managed HTTPS proxy routing is unavailable until its additional
protocol request can meet a separate physical-budget contract. A prepared budget
transport combined with client proxy/mount overrides is rejected because HTTPX
could otherwise route around that wrapper. These are explicit unsupported cases,
not permission to bypass the budget or proxy authority checks.

## Owned acceptance and limits

The same delayed-preparation fixture ran against the previous gate and this gate.
At a configured 200 ms interval, the old server-arrival gaps were 21.5 ms
(sync workers), 0.2 ms (async tasks) and 23.5 ms (mixed clients). The native
header-write lease produced 208.1 ms, 208.0 ms and 201.8 ms respectively.
Each case made exactly two owned loopback requests with hash-checked ledger runs.
These measurements establish that the fixture discriminates this preparation gap,
not a general WAN timing or server-processing guarantee.

An intermediate transport-call-only prototype recorded 211 ms local spacing but
76 ms async server-arrival spacing because native connection setup still ran
after the timestamp. That failed proof is retained; it is not counted as accepted
wire evidence. Deterministic clocks/callbacks and simulated native trace faults
are labeled PROXY controls separately from the real loopback observations.

From the prepared source checkout:

```powershell
.venv/Scripts/python.exe -m pytest -q test_final_dispatch.py test_native_dispatch.py
$env:BUGHUNT_RUN_DISPATCH_CONSUMER = '1'
.venv/Scripts/python.exe -m pytest -q test_dispatch_wire.py
```

The opt-in fixture creates only an owned literal `127.0.0.1` HTTP server and
retains `dispatch-proof.json` with separate dispatch/completion and arrival
timestamps. It does not run a live program target. Existing WebSocket, desync,
race and pinned active-ZAP consumer opt-ins remain documented with their own
fixtures; no Burp installation, paid feature, specialist adapter or live scan
is needed for this contract.
