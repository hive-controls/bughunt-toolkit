"""Built-in Bughunt modules. These ship with the console, not as addon clones."""

from __future__ import annotations

import importlib

_CATALOG: tuple[tuple[str, str], ...] = (
    ("scope", "Maintain target permissions and the workspace URL inventory."),
    ("policy", "Validate exact-asset mission profiles and check permissions offline."),
    ("ledger", "Inspect run provenance and export sanitized evidence."),
    (
        "identity",
        "Manage named, origin-bound owned accounts without displaying secrets.",
    ),
    (
        "verify",
        "Configure and check a selected actor's bounded server-side identity probe.",
    ),
    ("session", "Store request authentication for reuse in this workspace."),
    (
        "roost",
        "Summarize workspace totals and identify URL hosts lacking scope permission.",
    ),
    ("clutch", "Browse captured requests with authentication values concealed."),
    ("blaze", "Attach a workspace label to an existing URL entry."),
    ("quill", "Write dated engagement notes alongside the captured evidence."),
    (
        "snare",
        "Record scoped browser exchanges through a local proxy while using the console.",
    ),
    (
        "robots",
        "Extract crawl hints from robots and sitemap documents into the URL inventory.",
    ),
    ("repeater", "Revise a saved request and dispatch the revised HTTP exchange."),
    (
        "replay",
        "Compare one owned baseline as verified owner, lower privilege, and anonymous.",
    ),
    (
        "exchange",
        "Import/export inert raw HTTP and HAR with traceable provenance "
        "and default redaction.",
    ),
    ("zap", "Export/import passive ZAP evidence or run one guarded owned active lab."),
    ("engine", "List curated engine capabilities and manage bounded job lifecycle."),
    (
        "discover",
        "Probe explicit input candidates with bounded budgets and negative controls.",
    ),
    (
        "idor",
        "Change one JSON field to a second-account owned id and compare owner versus that id.",
    ),
    (
        "oast",
        "Correlate inert approved-domain callbacks with retained initiating runs.",
    ),
    ("race", "Run four bounded requests in an explicitly owned named loopback lab."),
    (
        "desync",
        "Compare HTTP/1.1 parser views in an explicitly owned named loopback lab.",
    ),
    ("ws", "Capture/replay bounded text messages in an explicitly owned named WS lab."),
    ("forms", "Inspect HTML inputs and parameters encoded in page URLs."),
    (
        "silk",
        "Discover site endpoints using bounded crawling and published crawl hints.",
    ),
    (
        "vhost",
        "Compare HTTP status, response length and title across candidate Host headers.",
    ),
    ("cert", "Inspect a server certificate's identity, issuer and validity dates."),
    (
        "redirect",
        "Trace HTTP navigation until it reaches a host or permission boundary.",
    ),
    ("diff", "Contrast response evidence from local files or two permitted URLs."),
    (
        "dns",
        "Query scoped DNS names for address, alias, mail, text and authority records.",
    ),
    ("whois", "Retrieve domain registration details and authoritative nameservers."),
    (
        "jwt",
        "Inspect supplied JWT claims without authenticating the token's signature.",
    ),
    ("mail", "Review domain mail routing and SPF, DKIM and DMARC configuration."),
    (
        "decode",
        "Render textual base64 content embedded in a fetched page, excluding images.",
    ),
    (
        "route",
        "Check that traffic would leave through your tunnel, from the routing table.",
    ),
)

MODULES: dict[str, str] = dict(_CATALOG)


def load_builtin(name: str):
    if name not in MODULES:
        raise KeyError(name)
    return importlib.import_module(f"bughunt.modules.{name}")
