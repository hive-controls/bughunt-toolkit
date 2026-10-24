"""The command vocabulary: which tools exist, how they are grouped into hunt phases, and where the
reference tools live on disk.

Everything else in the console layer (routing, listings, completion, the JSON catalog) reads from
here, so the taxonomy is checked once, at import, against the module registry.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import NamedTuple

from bughunt.modules import MODULES


class ReferenceTool(NamedTuple):
    """A tool that ships as a script under ``addons/<folder>/`` rather than as a built-in module."""

    command: str
    summary: str
    folder: str
    script: str
    aliases: tuple[str, ...] = ()


# Rows are (command, folder, script, aliases, summary). Folder case is significant on disk.
_REFERENCE_ROWS = (
    (
        "pulse",
        "pulse",
        "pulse.py",
        (),
        "Check a list of URLs and report which ones answer, grouped by status.",
    ),
    (
        "ct",
        "crt-scout",
        "crt-scout.py",
        ("crt-scout",),
        "Find subdomains in certificate logs, then test which of them are live.",
    ),
    (
        "carve",
        "flowcarve",
        "flowcarve.py",
        ("flowcarve",),
        "Pull URLs and endpoints out of proxy dumps, HAR files and saved pages.",
    ),
    (
        "phish",
        "Lanternjaw",
        "lanternjaw.py",
        ("lanternjaw",),
        "Read active phishing detections from the public phishunt feed.",
    ),
    (
        "ioc",
        "IOCaw",
        "iocaw.py",
        ("iocaw",),
        "Search the public TweetFeed list of reported indicators of compromise.",
    ),
    (
        "chroma",
        "chromahaus",
        "chromahaus.py",
        ("chromahaus",),
        "Query abuse.ch feeds: URLhaus, MalwareBazaar, ThreatFox and related lists.",
    ),
    (
        "urlscan",
        "urlscan",
        "urlscan.py",
        (),
        "Search, submit and fetch scans on urlscan.io.",
    ),
    (
        "tcurl",
        "tcurl",
        "tcurl.py",
        (),
        "Fetch one URL over Tor through the scope and policy gate and print the exit address.",
    ),
    (
        "skiff",
        "skiff",
        "skiff.py",
        (),
        "Multi-threaded HTTP fuzzer that swaps FUZZ for wordlist entries.",
    ),
)

REFERENCES: tuple[ReferenceTool, ...] = tuple(
    ReferenceTool(command, summary, folder, script, aliases)
    for command, folder, script, aliases, summary in _REFERENCE_ROWS
)

# Held back until their network paths have been scope audited.
DISABLED_REFERENCES = frozenset()

MODULE_GROUPS: tuple[tuple[str, tuple[str, ...]], ...] = (
    (
        "Engagement",
        (
            "scope",
            "policy",
            "identity",
            "session",
            "verify",
            "ledger",
            "roost",
            "route",
        ),
    ),
    (
        "Recon",
        (
            "scan",
            "silk",
            "ct",
            "dns",
            "whois",
            "mail",
            "cert",
            "vhost",
            "redirect",
            "robots",
            "pulse",
        ),
    ),
    ("Capture", ("snare", "clutch", "exchange", "carve", "blaze", "quill")),
    (
        "Test",
        (
            "repeater",
            "replay",
            "discover",
            "idor",
            "forms",
            "diff",
            "jwt",
            "decode",
            "skiff",
        ),
    ),
    ("Labs", ("race", "desync", "ws")),
    ("Engines", ("engine", "zap", "oast")),
    ("Intel", ("phish", "ioc", "chroma", "urlscan", "tcurl")),
)

PHASE_PURPOSE = {
    "Engagement": "Set scope, policy and owned identities before any traffic is sent.",
    "Recon": "Map hosts, ports, endpoints, DNS records and certificates.",
    "Capture": "Record the traffic you observe and keep notes on it.",
    "Test": "Probe and compare requests by hand.",
    "Labs": "Higher-risk techniques, limited to a lab you own on loopback.",
    "Engines": "Integrated engines: ZAP, Burp intake and out-of-band callbacks.",
    "Intel": "Look things up in external threat-intelligence feeds.",
}

MODULE_WHEN = {
    "scope": "You are starting an engagement and need to declare which hosts are in bounds.",
    "policy": "You must import and verify the mission policy before any test traffic.",
    "identity": "A test needs an account you own; register it here, bound to its origin.",
    "session": "You need to keep a Cookie or Authorization header for later requests.",
    "verify": "You want to confirm a saved identity still authenticates, using a bounded check.",
    "ledger": "You want to review what was sent and export sanitized evidence.",
    "roost": "You want a status view: scope, counts, and saved URLs outside scope.",
    "route": "You want proof that traffic leaves through your VPN or tunnel before testing.",
    "scan": "You want to map a host: open ports, live HTTP(S) services, headers and intel.",
    "silk": "You want to crawl one site for endpoints, robots.txt and sitemaps.",
    "ct": "You have a domain and want its subdomains from certificate logs, tested for life.",
    "dns": "You need the DNS records of one in-scope name.",
    "whois": "You want the registrar, dates and nameservers of a domain.",
    "mail": "You want to understand a domain's mail posture: MX, SPF, DKIM and DMARC.",
    "cert": "You want the TLS certificate details of a single host.",
    "vhost": "You suspect other virtual hosts answer on the same address.",
    "redirect": "You want to follow a URL's redirect chain without leaving scope.",
    "robots": "You want robots.txt and sitemap entries turned into a URL list.",
    "pulse": "You have a URL list and want to know which entries are live.",
    "snare": "You want to browse the target through a local proxy and keep in-scope traffic.",
    "clutch": "You want to list or inspect the requests snare saved.",
    "exchange": "You need to import or export raw HTTP or HAR files with provenance.",
    "carve": "You have a proxy dump, HAR or saved page and want the URLs inside it.",
    "blaze": "You want to label a URL that is already in the shared list.",
    "quill": "You want to jot a timestamped note in the engagement workspace.",
    "repeater": "You want to edit a captured request by hand and send it again.",
    "replay": "You want to compare owner, lower-privilege and anonymous answers to one request.",
    "discover": "You want to test a few specific hidden-input candidates, with controls.",
    "idor": "You own two accounts and want to check if one can reach the other's object by id.",
    "forms": "You want the form fields and query parameters on a page.",
    "diff": "You want to compare two saved responses or two in-scope URLs.",
    "jwt": "You hold a token and want to read what is inside it.",
    "decode": "You want a page printed with its base64 blocks shown as text.",
    "skiff": "You want to fuzz a URL, header, cookie or body with a wordlist you supply.",
    "race": "You want to watch concurrent requests interact, in an owned loopback lab.",
    "desync": "You want to see where HTTP/1.1 parsers disagree, in an owned loopback lab.",
    "ws": "You want to capture or replay WebSocket text messages in an owned lab.",
    "engine": "You want to see which engine capabilities exist and manage their jobs.",
    "zap": "You want to move passive ZAP evidence in or out, or run one guarded lab job.",
    "oast": "You want to link approved out-of-band callbacks to the run that caused them.",
    "phish": "You want recent phishing detections from the phishunt feed.",
    "ioc": "You want to look up an indicator in the TweetFeed list.",
    "chroma": "You want abuse.ch lookups: malicious URLs, samples and command servers.",
    "urlscan": "You want to search, submit or fetch scans on urlscan.io.",
    "tcurl": "You want one request fetched through Tor, with scope and policy still enforced.",
}

BUILTIN_SUMMARIES = {
    "scan": "Scan hosts, URLs or CIDR ranges you are authorized to test.",
    "console": "Open the interactive console: choose a module, set its options, run it.",
    "modules": "List every module, grouped by hunt phase (commands is an alias).",
    "catalog": "Print the full command catalog as JSON for other front-ends.",
    "guide": "Walk through the next steps of a hunt from where you are.",
    "doctor": "Check the Python version, packages and tools Bughunt relies on.",
    "setup": "Bootstrap a source checkout: venv, pinned install, workspace, self-check.",
    "examples": "Show copy-paste example command lines.",
    "completion": "Print a bash or zsh completion script.",
    "version": "Print the Bughunt version.",
    "help": "Show help for a command or a module.",
}

_TOOL_INDEX = {tool.command: tool for tool in REFERENCES}
_REFERENCE_SPELLINGS = {
    spelling: tool.command
    for tool in REFERENCES
    for spelling in (tool.command, *tool.aliases)
}
_PHASE_TITLES = {title.lower(): title for title, _members in MODULE_GROUPS}
_PHASE_OF_MEMBER = {name: title for title, members in MODULE_GROUPS for name in members}


def _verify_taxonomy() -> None:
    """Refuse to import when the phases, the guidance copy and the module registry disagree."""
    listed = [name for _title, members in MODULE_GROUPS for name in members]
    expected = {"scan", *MODULES, *_TOOL_INDEX}
    if len(listed) != len(set(listed)) or set(listed) != expected:
        unlisted = sorted(expected - set(listed))
        unknown = sorted(set(listed) - expected)
        raise RuntimeError(
            f"MODULE_GROUPS drifted from the module registry: unlisted={unlisted} unknown={unknown} "
            f"duplicated={sorted({n for n in listed if listed.count(n) > 1})}"
        )
    if set(PHASE_PURPOSE) != {title for title, _members in MODULE_GROUPS}:
        raise RuntimeError("PHASE_PURPOSE does not have exactly one entry per phase")
    unguided = [name for name in listed if not MODULE_WHEN.get(name)]
    if unguided:
        raise RuntimeError(f"MODULE_WHEN has no guidance line for: {unguided}")


_verify_taxonomy()


def group_names() -> list[str]:
    return [title for title, _members in MODULE_GROUPS]


def match_group(token: str) -> str | None:
    """Canonical phase title for a case-insensitive, whitespace-padded token, else None."""
    return _PHASE_TITLES.get(token.strip().lower())


def group_for(name: str) -> str | None:
    """Title of the phase that lists ``name`` exactly as spelled."""
    return _PHASE_OF_MEMBER.get(name)


def phase_purpose(title: str) -> str:
    return PHASE_PURPOSE.get(title, "")


def reference_canonical(token: str) -> str | None:
    """Canonical command for a built-in module, reference tool or reference alias; ``scan`` is not one."""
    if token in MODULES:
        return token
    return _REFERENCE_SPELLINGS.get(token)


def module_when(name: str) -> str:
    return MODULE_WHEN.get(reference_canonical(name) or name, "")


def tool_by_command(name: str) -> ReferenceTool | None:
    return _TOOL_INDEX.get(name)


def addon_roots(tool_file: Path) -> list[Path]:
    """Directories searched for reference tools, most specific first.

    ``tool_file`` is the scanner module, two folders below the project root, so the project root is
    ``parents[2]``. A shorter path keeps only an explicit environment root.
    """
    candidates: list[Path] = []
    override = os.environ.get("BUGHUNT_ADDONS", "").strip()
    if override:
        candidates.append(Path(override).expanduser())
    ancestors = tool_file.resolve().parents
    if len(ancestors) > 2:
        project_root = ancestors[2]
        candidates.append(project_root / "addons")
        candidates.append(project_root.parent / "addons")

    roots: list[Path] = []
    seen: set[Path] = set()
    for candidate in candidates:
        try:
            identity = candidate.resolve()
        except OSError:
            identity = candidate
        if identity not in seen:
            seen.add(identity)
            roots.append(candidate)
    return roots


def locate_script(reference_tool: ReferenceTool, tool_file: Path) -> Path | None:
    """First regular file ``<root>/<folder>/<script>`` over the search roots, or None when none has it."""
    relative_path = Path(reference_tool.folder, reference_tool.script)
    possible = (root / relative_path for root in addon_roots(tool_file))
    return next((path for path in possible if path.is_file()), None)
