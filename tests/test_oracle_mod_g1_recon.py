"""Characterization oracle for the G1 recon group, written BEFORE the clean-room rebuild.

Group: bughunt/modules/{__init__,dns,whois,cert,vhost,mail,scope}.py.

Scope: everything the repo's older tests leave unpinned for these modules - the module registry
(MODULES table + load_builtin), every parser contract the console reads, the pure parsers
(DNS wire format, whois text, X.509 DER, SPF/DMARC/DKIM review rules, Host-header helpers), every
`main()` exit code and stderr/stdout line, and the cross-importer symbols (mail and whois import
from dns; tests and the loader reach into dns/whois/cert).

Network posture: no real network. DNS is answered by a UDP socket bound to 127.0.0.1, whois by a
loopback TCP listener (the IANA hop is rerouted at `socket.create_connection`), vhost by a loopback
`http.server`, and the TLS handshake is replaced at the `socket`/`ssl.SSLContext.wrap_socket` edge.
Every outbound path still runs through the real egress gate and a seeded mission policy.

Wire fixtures (DNS packets, DER certificates) are built by the encoders in THIS file, not by the
modules under test, so a from-scratch rewrite cannot pass by being symmetrically wrong.

Tiers: tests named `test_defect_*` assert the CORRECT behavior and are xfail(strict=True) until the
defect is fixed (M6); a rebuild that accidentally fixes one turns the XPASS into a failure. Every
other test pins current behavior that the rebuild must reproduce.
"""

from __future__ import annotations

import builtins
import dataclasses
import http.server
import importlib
import inspect
import io
import ipaddress
import json
import re
import socket
import ssl
import struct
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from rich.console import Console

from bughunt.console import ui
from bughunt.console.options import load_spec
from bughunt.core import egress
from bughunt.core.workspace import explain_block
from bughunt.modules import MODULES, cert, dns, load_builtin, mail, scope, vhost, whois
from test_gate import seed_policy

NAME = "allowed.example"
ESC = "\x1b"
CYAN, YELLOW, MAGENTA, WHITE, DIM, RESET = (
    "\x1b[1;96m",
    "\x1b[1;93m",
    "\x1b[1;95m",
    "\x1b[1;97m",
    "\x1b[2;96m",
    "\x1b[0m",
)

defect = pytest.mark.xfail(strict=True, raises=AssertionError)


# ======================================================================================
# shared fixtures
# ======================================================================================


@pytest.fixture(autouse=True)
def plain_environment(monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.delenv("BUGHUNT_SESSION", raising=False)


@pytest.fixture
def lab(monkeypatch, tmp_path):
    """A workspace with scope `allowed.example` and a verified policy granting every operation."""
    root = tmp_path / "ws"
    root.mkdir()
    monkeypatch.setenv("BUGHUNT_SCOPE", str(root))
    (root / "scope.txt").write_text(f"{NAME}\n", encoding="utf-8")
    document = seed_policy(root)

    def grant(origin, operations=("manual",), methods=("GET",)):
        document["assets"].append(
            {
                "id": f"extra-{len(document['assets'])}",
                "origin": origin,
                "paths": ["/"],
                "operations": list(operations),
                "methods": list(methods),
            }
        )
        (root / "policy.json").write_text(json.dumps(document), encoding="utf-8")

    def set_scope(*entries):
        (root / "scope.txt").write_text(
            "".join(f"{entry}\n" for entry in entries), encoding="utf-8"
        )

    return SimpleNamespace(
        root=root, document=document, grant=grant, set_scope=set_scope
    )


def run(module, argv, capsys):
    code = module.main(list(argv))
    captured = capsys.readouterr()
    return code, captured.out, captured.err


class TtyBuffer(io.StringIO):
    def isatty(self):
        return True


# ======================================================================================
# independent wire encoders (deliberately not the modules' own)
# ======================================================================================


def wire_name(name):
    parts = [part for part in name.strip(".").split(".") if part]
    return (
        b"".join(bytes([len(part)]) + part.encode("ascii") for part in parts) + b"\x00"
    )


def rr(rtype, rdata, *, ttl=30, owner=b"\xc0\x0c", rclass=1):
    return owner + struct.pack("!HHIH", rtype, rclass, ttl, len(rdata)) + rdata


def a_data(text):
    return socket.inet_aton(text)


def aaaa_data(text):
    return ipaddress.IPv6Address(text).packed


def mx_data(preference, host):
    return struct.pack("!H", preference) + wire_name(host)


def txt_data(*chunks):
    return b"".join(bytes([len(chunk)]) + chunk for chunk in chunks)


def packet(ident, flags, questions=(), answers=(), authorities=(), additionals=()):
    header = struct.pack(
        "!HHHHHH",
        ident,
        flags,
        len(questions),
        len(answers),
        len(authorities),
        len(additionals),
    )
    body = b"".join(
        wire_name(name) + struct.pack("!HH", qtype, 1) for name, qtype in questions
    )
    return (
        header
        + body
        + b"".join(answers)
        + b"".join(authorities)
        + b"".join(additionals)
    )


@dataclass
class Reply:
    answers: list = field(default_factory=list)  # (rtype, rdata)
    authorities: list = field(default_factory=list)
    additionals: list = field(default_factory=list)
    rcode: int = 0
    tc: bool = False
    ident_xor: int = 0
    drop: bool = False
    raw: bytes | None = None
    from_other_socket: bool = False
    forged_answers: list | None = None


class FakeResolver:
    """UDP resolver on loopback, scripted per (qname, qtype); unscripted queries get an empty NOERROR."""

    def __init__(self, host="127.0.0.1"):
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        self.sock = socket.socket(family, socket.SOCK_DGRAM)
        self.sock.bind((host, 0))
        self.sock.settimeout(0.05)
        self.port = self.sock.getsockname()[1]
        self.other = socket.socket(family, socket.SOCK_DGRAM)
        self.other.bind((host, 0))
        self.script = {}
        self.seen = []
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def on(self, name, rtype, *replies):
        self.script[(name, rtype)] = list(replies)
        return self

    def queries_for(self, name, rtype):
        return [row for row in self.seen if row[0] == name and row[1] == rtype]

    def close(self):
        self._stop.set()
        self._thread.join(2)
        self.sock.close()
        self.other.close()

    def _decode(self, data):
        offset, labels = 12, []
        while data[offset]:
            size = data[offset]
            labels.append(data[offset + 1 : offset + 1 + size].decode("ascii"))
            offset += size + 1
        end = offset + 1 + 4
        qtype = struct.unpack("!H", data[offset + 1 : offset + 3])[0]
        return ".".join(labels).lower(), qtype, data[12:end]

    def _reply_for(self, key):
        queue = self.script.get(key)
        if not queue:
            return Reply()
        return queue.pop(0) if len(queue) > 1 else queue[0]

    def _serve(self):
        while not self._stop.is_set():
            try:
                data, address = self.sock.recvfrom(4096)
            except (socket.timeout, OSError):
                continue
            ident, flags = struct.unpack("!HH", data[:4])
            qname, qtype, question = self._decode(data)
            self.seen.append((qname, qtype, ident, flags))
            reply = self._reply_for((qname, qtype))
            if reply.drop:
                continue
            if reply.raw is not None:
                payload = reply.raw
            else:
                out_flags = 0x8180 | (0x0200 if reply.tc else 0) | reply.rcode
                header = struct.pack(
                    "!HHHHHH",
                    ident ^ reply.ident_xor,
                    out_flags,
                    1,
                    len(reply.answers),
                    len(reply.authorities),
                    len(reply.additionals),
                )
                records = b"".join(
                    rr(t, d)
                    for t, d in (*reply.answers, *reply.authorities, *reply.additionals)
                )
                payload = header + question + records
            if reply.forged_answers is not None:
                forged = packet(
                    ident,
                    0x8180,
                    questions=[(qname, qtype)],
                    answers=[rr(rtype, data) for rtype, data in reply.forged_answers],
                )
                self.other.sendto(forged, address)
            sender = self.other if reply.from_other_socket else self.sock
            sender.sendto(payload, address)


@pytest.fixture
def resolver():
    fake = FakeResolver()
    yield fake
    fake.close()


@pytest.fixture
def dns_lab(lab, resolver):
    """Policy for names under allowed.example plus the loopback resolver endpoint."""
    for host in (
        "_dmarc.allowed.example",
        "s1._domainkey.allowed.example",
        "s2._domainkey.allowed.example",
    ):
        lab.grant(f"https://{host}", operations=("dns",))
    lab.grant(f"http://127.0.0.1:{resolver.port}", operations=("dns",))
    lab.resolver = resolver
    return lab


def resolver_args(lab, *extra):
    return [
        "--resolver",
        "127.0.0.1",
        "--port",
        str(lab.resolver.port),
        "--timeout",
        "2",
        *extra,
    ]


@pytest.fixture
def resolv_conf(monkeypatch, tmp_path):
    """Redirect any open() of /etc/resolv.conf to a scratch file the test writes."""
    target = tmp_path / "resolv.conf"
    real_open = io.open

    def redirected(file, *args, **kwargs):
        if str(file).replace("\\", "/").endswith("/etc/resolv.conf"):
            file = target
        return real_open(file, *args, **kwargs)

    monkeypatch.setattr(io, "open", redirected)
    monkeypatch.setattr(builtins, "open", redirected)
    return SimpleNamespace(
        write=lambda text: target.write_text(text, encoding="utf-8"), path=target
    )


@pytest.fixture
def rich_output(monkeypatch):
    stream = io.StringIO()
    monkeypatch.setattr(
        ui, "console", Console(file=stream, theme=ui.THEME, highlight=False, width=400)
    )
    return stream


# ======================================================================================
# 1. module registry (bughunt/modules/__init__.py)
# ======================================================================================

EXPECTED_MODULES = {
    "scope": "Maintain target permissions and the workspace URL inventory.",
    "policy": "Validate exact-asset mission profiles and check permissions offline.",
    "ledger": "Inspect run provenance and export sanitized evidence.",
    "identity": "Manage named, origin-bound owned accounts without displaying secrets.",
    "verify": "Configure and check a selected actor's bounded server-side identity probe.",
    "session": "Store request authentication for reuse in this workspace.",
    "roost": "Summarize workspace totals and identify URL hosts lacking scope permission.",
    "clutch": "Browse captured requests with authentication values concealed.",
    "blaze": "Attach a workspace label to an existing URL entry.",
    "quill": "Write dated engagement notes alongside the captured evidence.",
    "snare": "Record scoped browser exchanges through a local proxy while using the console.",
    "robots": "Extract crawl hints from robots and sitemap documents into the URL inventory.",
    "repeater": "Revise a saved request and dispatch the revised HTTP exchange.",
    "replay": "Compare one owned baseline as verified owner, lower privilege, and anonymous.",
    "exchange": "Import/export inert raw HTTP and HAR with traceable provenance and default redaction.",
    "zap": "Export/import passive ZAP evidence or run one guarded owned active lab.",
    "engine": "List curated engine capabilities and manage bounded job lifecycle.",
    "discover": "Probe explicit input candidates with bounded budgets and negative controls.",
    "idor": "Change one JSON field to a second-account owned id and compare owner versus that id.",
    "oast": "Correlate inert approved-domain callbacks with retained initiating runs.",
    "race": "Run four bounded requests in an explicitly owned named loopback lab.",
    "desync": "Compare HTTP/1.1 parser views in an explicitly owned named loopback lab.",
    "ws": "Capture/replay bounded text messages in an explicitly owned named WS lab.",
    "forms": "Inspect HTML inputs and parameters encoded in page URLs.",
    "silk": "Discover site endpoints using bounded crawling and published crawl hints.",
    "vhost": "Compare HTTP status, response length and title across candidate Host headers.",
    "cert": "Inspect a server certificate's identity, issuer and validity dates.",
    "redirect": "Trace HTTP navigation until it reaches a host or permission boundary.",
    "diff": "Contrast response evidence from local files or two permitted URLs.",
    "dns": "Query scoped DNS names for address, alias, mail, text and authority records.",
    "whois": "Retrieve domain registration details and authoritative nameservers.",
    "jwt": "Inspect supplied JWT claims without authenticating the token's signature.",
    "mail": "Review domain mail routing and SPF, DKIM and DMARC configuration.",
    "decode": "Render textual base64 content embedded in a fetched page, excluding images.",
    "route": "Check that traffic would leave through your tunnel, from the routing table.",
}
GROUP = ("dns", "whois", "cert", "vhost", "mail", "scope")


def test_registry_is_the_exact_ordered_name_to_description_table():
    assert type(MODULES) is dict
    assert len(MODULES) == 35
    assert list(MODULES.items()) == list(EXPECTED_MODULES.items())


def test_registry_and_module_files_name_the_same_set():
    package_dir = Path(importlib.import_module("bughunt.modules").__file__).parent
    files = {item.stem for item in package_dir.glob("*.py") if item.stem != "__init__"}
    assert files == set(MODULES)


@pytest.mark.parametrize("name", list(EXPECTED_MODULES))
def test_load_builtin_returns_the_imported_module(name):
    try:
        loaded = load_builtin(name)
    except ImportError as exc:
        if name in GROUP:
            raise
        pytest.skip(f"optional dependency for {name} is not installed: {exc}")
    assert loaded is importlib.import_module(f"bughunt.modules.{name}")
    assert loaded.__name__ == f"bughunt.modules.{name}"
    assert callable(loaded.main)


@pytest.mark.parametrize(
    "name",
    [
        "nope",
        "",
        "DNS",
        "dns ",
        "os",
        "bughunt.modules.dns",
        "../dns",
        "__init__",
        "policy.py",
    ],
)
def test_load_builtin_rejects_names_outside_the_table_with_key_error(name):
    with pytest.raises(KeyError) as raised:
        load_builtin(name)
    assert raised.value.args == (name,)


def test_load_builtin_checks_the_table_before_importing(monkeypatch):
    def forbidden(name, *args, **kwargs):
        raise AssertionError(f"import attempted for {name}")

    monkeypatch.setattr(importlib, "import_module", forbidden)
    with pytest.raises(KeyError):
        load_builtin("os")


def test_load_builtin_resolves_through_import_module_by_dotted_name(monkeypatch):
    seen = []
    sentinel = object()
    monkeypatch.setattr(
        importlib, "import_module", lambda name: seen.append(name) or sentinel
    )
    assert load_builtin("dns") is sentinel
    assert seen == ["bughunt.modules.dns"]


# ======================================================================================
# 2. parser contracts the console reads (build_parser / Spec rows)
# ======================================================================================

PARSER_FACTS = {
    "dns": (
        "bughunt dns",
        "Query scoped DNS names for address, alias, mail, text and authority records.",
    ),
    "whois": (
        "bughunt whois",
        "Retrieve domain registration details and authoritative nameservers.",
    ),
    "cert": ("bughunt cert", "Read the TLS certificate on one in-scope host."),
    "vhost": (
        "bughunt vhost",
        "Request one in-scope address once per Host name. Prints status, size, and title.",
    ),
    "mail": (
        "bughunt mail",
        "Review domain mail routing and SPF, DKIM and DMARC configuration.",
    ),
    "scope": (
        "bughunt scope",
        "Keep the hosts this engagement may touch, and the URL list other modules share.",
    ),
}

# Option fields: (name, dest, flags, kind, required, help, choices, subcommand, repeatable, store_false, default)
SPEC_ROWS = {
    "dns": [
        (
            "NAME",
            "name",
            (),
            "positional",
            True,
            "Hostname to look up. A URL uses that URL's hostname.",
            (),
            "",
            False,
            False,
            "",
        ),
        (
            "RESOLVER",
            "resolver",
            ("--resolver",),
            "value",
            False,
            "Resolver address. Default: the first system nameserver.",
            (),
            "",
            False,
            False,
            "",
        ),
        (
            "PORT",
            "port",
            ("--port",),
            "value",
            False,
            "Resolver port. Default 53.",
            (),
            "",
            False,
            False,
            "53",
        ),
        (
            "TIMEOUT",
            "timeout",
            ("--timeout",),
            "value",
            False,
            "Seconds to wait for each reply. Default 5.",
            (),
            "",
            False,
            False,
            "5.0",
        ),
    ],
    "whois": [
        (
            "NAME",
            "name",
            (),
            "positional",
            True,
            "Domain to look up. A URL uses that URL's hostname.",
            (),
            "",
            False,
            False,
            "",
        ),
        (
            "SERVER",
            "server",
            ("--server",),
            "value",
            False,
            "Whois server address. Skips the IANA referral.",
            (),
            "",
            False,
            False,
            "",
        ),
        (
            "PORT",
            "port",
            ("--port",),
            "value",
            False,
            "Whois port. Default 43.",
            (),
            "",
            False,
            False,
            "43",
        ),
        (
            "TIMEOUT",
            "timeout",
            ("--timeout",),
            "value",
            False,
            "Seconds to wait. Default 10.",
            (),
            "",
            False,
            False,
            "10.0",
        ),
        (
            "PLAIN",
            "plain",
            ("--plain",),
            "bool",
            False,
            "Skip the banner.",
            (),
            "",
            False,
            False,
            "",
        ),
    ],
    "cert": [
        (
            "HOST",
            "host",
            (),
            "positional",
            True,
            "Hostname, address, or https URL.",
            (),
            "",
            False,
            False,
            "",
        ),
        (
            "PORT",
            "port",
            ("--port",),
            "value",
            False,
            "TLS port. Default 443, or the port in the URL.",
            (),
            "",
            False,
            False,
            "0",
        ),
        (
            "TIMEOUT",
            "timeout",
            ("--timeout",),
            "value",
            False,
            "Seconds to wait for the handshake. Default 10.",
            (),
            "",
            False,
            False,
            "10.0",
        ),
    ],
    "vhost": [
        (
            "URL",
            "url",
            (),
            "positional",
            True,
            "Address to connect to, such as http://127.0.0.1:8080/.",
            (),
            "",
            False,
            False,
            "",
        ),
        (
            "NAMES",
            "names",
            (),
            "positional",
            False,
            "Host names. With none, hostnames from the scope file are used.",
            (),
            "",
            True,
            False,
            "",
        ),
        (
            "NAMES_FILE",
            "names_file",
            ("--names",),
            "value",
            False,
            "File of host names, one per line.",
            (),
            "",
            False,
            False,
            "",
        ),
        (
            "LIMIT",
            "limit",
            ("--limit",),
            "value",
            False,
            "Maximum names to request. Default 50.",
            (),
            "",
            False,
            False,
            "50",
        ),
        (
            "TIMEOUT",
            "timeout",
            ("--timeout",),
            "value",
            False,
            "Seconds for each request. Default 10.",
            (),
            "",
            False,
            False,
            "10.0",
        ),
        (
            "INSECURE",
            "insecure",
            ("--insecure",),
            "bool",
            False,
            "Do not verify TLS certificates.",
            (),
            "",
            False,
            False,
            "",
        ),
        (
            "COOKIE",
            "cookie",
            ("--cookie",),
            "value",
            False,
            "Cookie for this run. Replaces the saved session cookie.",
            (),
            "",
            False,
            False,
            "",
        ),
        (
            "AUTHORIZATION",
            "authorization",
            ("--authorization",),
            "value",
            False,
            "Authorization for this run. Replaces the saved session value.",
            (),
            "",
            False,
            False,
            "",
        ),
    ],
    "mail": [
        (
            "NAME",
            "name",
            (),
            "positional",
            True,
            "Hostname to explain. A URL uses that URL's hostname.",
            (),
            "",
            False,
            False,
            "",
        ),
        (
            "RESOLVER",
            "resolver",
            ("--resolver",),
            "value",
            False,
            "Resolver address. Default: the first system nameserver.",
            (),
            "",
            False,
            False,
            "",
        ),
        (
            "PORT",
            "port",
            ("--port",),
            "value",
            False,
            "Resolver port. Default 53.",
            (),
            "",
            False,
            False,
            "53",
        ),
        (
            "TIMEOUT",
            "timeout",
            ("--timeout",),
            "value",
            False,
            "Seconds to wait for each reply. Default 5.",
            (),
            "",
            False,
            False,
            "5.0",
        ),
        (
            "SELECTOR",
            "selector",
            ("--selector",),
            "value",
            False,
            "DKIM selector, such as s1. Repeat for another. None are guessed.",
            (),
            "",
            True,
            False,
            "",
        ),
        (
            "PLAIN",
            "plain",
            ("--plain",),
            "bool",
            False,
            "Skip the banner.",
            (),
            "",
            False,
            False,
            "",
        ),
    ],
    "scope": [
        (
            "HOSTS",
            "hosts",
            (),
            "positional",
            True,
            "Host, domain, *.domain, CIDR, or URL.",
            (),
            "add",
            True,
            False,
            "",
        ),
        ("HOSTS", "hosts", (), "positional", True, "", (), "remove", True, False, ""),
        (
            "TARGET",
            "target",
            (),
            "positional",
            True,
            "Host or URL.",
            (),
            "allow",
            False,
            False,
            "",
        ),
        (
            "FILE",
            "file",
            (),
            "positional",
            True,
            "One URL per line.",
            (),
            "import-urls",
            False,
            False,
            "",
        ),
        (
            "COMMAND",
            "command",
            (),
            "positional",
            True,
            "Subcommand.",
            ("init", "path", "list", "add", "remove", "allow", "import-urls", "urls"),
            "",
            False,
            False,
            "",
        ),
    ],
}

SCOPE_SUBCOMMANDS = (
    ("init", "Create .bughunt with an empty scope."),
    ("path", "Print the workspace directory."),
    ("list", "Print scope entries."),
    ("add", "Add hosts, domains, *.domains, or CIDRs."),
    ("remove", "Remove scope entries."),
    ("allow", "Exit 0 when the host is in scope."),
    ("import-urls", "Keep in-scope URLs from a file."),
    ("urls", "Print the shared URL list."),
)


@pytest.mark.parametrize("name", GROUP)
def test_parser_program_name_and_description(name):
    parser = load_builtin(name).build_parser()
    assert (parser.prog, parser.description) == PARSER_FACTS[name]


@pytest.mark.parametrize("name", GROUP)
def test_console_form_rows_come_from_the_parser(name):
    spec = load_spec(name, tool_file=Path(__file__), build_parser=None)
    assert [tuple(row) for row in spec.options] == SPEC_ROWS[name]
    assert spec.command_name == ("COMMAND" if name == "scope" else "")
    assert spec.subcommands == (SCOPE_SUBCOMMANDS if name == "scope" else ())


PARSE_CASES = [
    (dns, ["x"], {"name": "x", "resolver": None, "port": 53, "timeout": 5.0}),
    (
        dns,
        ["x", "--resolver", "1.1.1.1", "--port", "5353", "--timeout", "2.5"],
        {"name": "x", "resolver": "1.1.1.1", "port": 5353, "timeout": 2.5},
    ),
    (
        whois,
        ["x"],
        {"name": "x", "server": None, "port": 43, "timeout": 10.0, "plain": False},
    ),
    (
        whois,
        ["x", "--server", "9.9.9.9", "--port", "4343", "--timeout", "3", "--plain"],
        {"name": "x", "server": "9.9.9.9", "port": 4343, "timeout": 3.0, "plain": True},
    ),
    (cert, ["h"], {"host": "h", "port": 0, "timeout": 10.0}),
    (
        cert,
        ["h", "--port", "8443", "--timeout", "1.5"],
        {"host": "h", "port": 8443, "timeout": 1.5},
    ),
    (
        vhost,
        ["http://a/"],
        {
            "url": "http://a/",
            "names": [],
            "names_file": None,
            "limit": 50,
            "timeout": 10.0,
            "insecure": False,
            "cookie": None,
            "authorization": None,
        },
    ),
    (
        vhost,
        [
            "http://a/",
            "n1",
            "n2",
            "--names",
            "f.txt",
            "--limit",
            "3",
            "--timeout",
            "4",
            "--insecure",
            "--cookie",
            "k=v",
            "--authorization",
            "Bearer t",
        ],
        {
            "url": "http://a/",
            "names": ["n1", "n2"],
            "names_file": "f.txt",
            "limit": 3,
            "timeout": 4.0,
            "insecure": True,
            "cookie": "k=v",
            "authorization": "Bearer t",
        },
    ),
    (
        mail,
        ["x"],
        {
            "name": "x",
            "resolver": None,
            "port": 53,
            "timeout": 5.0,
            "selector": None,
            "plain": False,
        },
    ),
    (
        mail,
        ["x", "--selector", "s1", "--selector", "s2", "--plain", "--port", "5300"],
        {
            "name": "x",
            "resolver": None,
            "port": 5300,
            "timeout": 5.0,
            "selector": ["s1", "s2"],
            "plain": True,
        },
    ),
    (scope, ["init"], {"command": "init"}),
    (scope, ["add", "a", "b"], {"command": "add", "hosts": ["a", "b"]}),
    (scope, ["remove", "a"], {"command": "remove", "hosts": ["a"]}),
    (scope, ["allow", "t"], {"command": "allow", "target": "t"}),
    (scope, ["import-urls", "f"], {"command": "import-urls", "file": "f"}),
]


@pytest.mark.parametrize("module,argv,expected", PARSE_CASES)
def test_parser_namespace_shape_types_and_defaults(module, argv, expected):
    assert vars(module.build_parser().parse_args(argv)) == expected


@pytest.mark.parametrize(
    "module,argv",
    [
        (dns, []),
        (whois, []),
        (cert, []),
        (vhost, []),
        (mail, []),
        (scope, []),
        (scope, ["bogus"]),
        (scope, ["add"]),
        (dns, ["x", "--port", "abc"]),
        (cert, ["x", "--timeout", "soon"]),
        (vhost, ["u", "--limit", "1.5"]),
    ],
)
def test_parser_rejects_bad_command_lines_with_exit_two(module, argv, capsys):
    with pytest.raises(SystemExit) as raised:
        module.build_parser().parse_args(argv)
    assert raised.value.code == 2
    capsys.readouterr()


# ======================================================================================
# 3. cross-importer symbols (the names sibling modules, tests and the loader depend on)
# ======================================================================================


def test_dns_symbols_imported_by_mail_and_whois_keep_names_and_signatures():
    assert list(inspect.signature(dns.lookup).parameters) == [
        "name",
        "resolver",
        "port",
        "timeout",
    ]
    assert list(inspect.signature(dns.normalize_name).parameters) == ["value"]
    assert list(inspect.signature(dns.resolver_address).parameters) == ["value"]
    assert list(inspect.signature(dns.system_resolver).parameters) == []
    assert all(
        param.default is inspect.Parameter.empty
        for param in inspect.signature(dns.lookup).parameters.values()
    )


def test_mail_and_whois_use_the_very_same_dns_objects():
    assert mail.lookup is dns.lookup
    assert mail.normalize_name is dns.normalize_name
    assert mail.resolver_address is dns.resolver_address
    assert mail.system_resolver is dns.system_resolver
    assert whois.normalize_name is dns.normalize_name
    assert whois.resolver_address is dns.resolver_address


def test_network_edge_functions_keep_their_parameter_names():
    # The egress gate binds target lists by parameter NAME, so these names are part of the contract.
    assert list(inspect.signature(whois._fetch).parameters) == [
        "host",
        "port",
        "name",
        "timeout",
    ]
    assert list(inspect.signature(cert.fetch_certificate).parameters) == [
        "host",
        "port",
        "timeout",
    ]
    assert list(inspect.signature(whois.fetch_record).parameters) == [
        "name",
        "server",
        "port",
        "timeout",
    ]


def test_module_attributes_other_tests_monkeypatch_exist():
    assert dns.socket is socket
    assert dns.RECORD_TYPES == (
        ("A", 1),
        ("AAAA", 28),
        ("CNAME", 5),
        ("MX", 15),
        ("TXT", 16),
        ("NS", 2),
    )
    assert (
        callable(dns.parse_message)
        and callable(dns.build_query)
        and callable(dns.read_name)
    )
    assert callable(dns.encode_name) and callable(dns.answer_packet)


@pytest.mark.parametrize("name", GROUP)
def test_every_group_module_exposes_main_and_build_parser(name):
    module = load_builtin(name)
    assert list(inspect.signature(module.main).parameters) == ["argv"]
    assert inspect.signature(module.main).parameters["argv"].default is None
    assert callable(module.build_parser)


def test_dataclass_contracts_dns_and_cert():
    def shape(cls):
        return [
            (
                item.name,
                item.default is dataclasses.MISSING
                and item.default_factory is dataclasses.MISSING,
            )
            for item in dataclasses.fields(cls)
        ]

    assert shape(dns.Question) == [("name", True), ("qtype", True), ("qclass", True)]
    assert shape(dns.Record) == [
        ("name", True),
        ("rtype", True),
        ("rclass", True),
        ("ttl", True),
        ("text", True),
    ]
    assert shape(dns.Message) == [
        ("ident", True),
        ("flags", True),
        ("questions", False),
        ("answers", False),
        ("authorities", False),
        ("additionals", False),
    ]
    assert shape(cert.Certificate) == [
        ("subject", True),
        ("issuer", True),
        ("not_before", True),
        ("not_after", True),
        ("names", False),
    ]
    first, second = dns.Message(1, 2), dns.Message(1, 2)
    assert first == second and first.questions is not second.questions
    assert (
        first.questions == first.answers == first.authorities == first.additionals == []
    )
    assert cert.Certificate("s", "i", "b", "a").names == []
    assert (
        cert.Certificate("s", "i", "b", "a").names
        is not cert.Certificate("s", "i", "b", "a").names
    )
    assert dns.Record("n", 1, 1, 60, "t") == dns.Record("n", 1, 1, 60, "t")
    record = dns.Record("n", 1, 1, 60, "t")
    record.text = "changed"
    assert record.text == "changed"
    assert not hasattr(dns.Question("n", 1, 1), "__slots__")


# ======================================================================================
# 4. dns - pure helpers
# ======================================================================================


@pytest.mark.parametrize(
    "value,expected",
    [
        ("Example.COM.", "example.com"),
        ("  app.internal ", "app.internal"),
        ("https://App.Example.com:8443/x?y", "app.example.com"),
        ("ftp://x.example/", "x.example"),
        ("UPPER.Case.", "upper.case"),
        ("a..b", "a..b"),
        ("xn--bcher-kva.example", "xn--bcher-kva.example"),
        ("bücher.example", "bücher.example"),
        ("http://[::1]/", None),
        ("10.0.0.1", None),
        ("::1", None),
        ("host:80", None),
        ("a b", None),
        ("*.x.com", None),
        ("a/b", None),
        ("a\\b", None),
        ("", None),
        ("   ", None),
        ("http://", None),
    ],
)
def test_normalize_name(value, expected):
    assert dns.normalize_name(value) == expected


@pytest.mark.parametrize(
    "value,expected",
    [
        ("127.0.0.1", "127.0.0.1"),
        (" 8.8.8.8 ", "8.8.8.8"),
        ("[::1]", "::1"),
        ("::1", "::1"),
        ("[2001:db8::1]", "2001:db8::1"),
        ("2001:DB8::1", "2001:db8::1"),
        ("0:0:0:0:0:0:0:1", "::1"),
        ("::ffff:1.2.3.4", ("::ffff:1.2.3.4", "::ffff:102:304")),
        ("host", None),
        ("1.2.3", None),
        ("[1.2.3.4", None),
        ("", None),
    ],
)
def test_resolver_address(value, expected):
    result = dns.resolver_address(value)
    if isinstance(expected, tuple):
        # rendering of IPv4-mapped IPv6 differs across CPython patch releases (3.12.10 hextets vs 3.12.15/3.14 dotted)
        assert result in expected
        assert ipaddress.ip_address(result) == ipaddress.ip_address(expected[0])
    else:
        assert result == expected


@pytest.mark.parametrize(
    "value,expected",
    [
        ("a.example", b"\x01a\x07example\x00"),
        ("a.example.", b"\x01a\x07example\x00"),
        (".a.example", b"\x01a\x07example\x00"),
        ("  a.example  ", b"\x01a\x07example\x00"),
        ("A.Example", b"\x01A\x07Example\x00"),
        ("_dmarc.a.example", b"\x06_dmarc\x01a\x07example\x00"),
        ("a b.example", b"\x03a b\x07example\x00"),
        ("bücher.example", b"\rxn--bcher-kva\x07example\x00"),
        ("xéy.example", b"\nxn--xy-bja\x07example\x00"),
        ("a" * 63 + ".example", bytes([63]) + b"a" * 63 + b"\x07example\x00"),
    ],
)
def test_encode_name_values(value, expected):
    assert dns.encode_name(value) == expected


@pytest.mark.parametrize(
    "value,message",
    [
        ("", "empty name"),
        (".", "empty name"),
        ("   ", "empty name"),
        ("a..example", "bad name"),
        ("a" * 64 + ".example", "bad name"),
        ((("a" * 63) + ".") * 4 + "x", "name is too long"),
    ],
)
def test_encode_name_errors(value, message):
    with pytest.raises(ValueError) as raised:
        dns.encode_name(value)
    assert str(raised.value) == message


def test_build_query_layout():
    assert dns.build_query("a.example", 1, 0x1234) == (
        struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
        + wire_name("a.example")
        + struct.pack("!HH", 1, 1)
    )
    assert dns.build_query("a.example", 28, 65535)[:2] == b"\xff\xff"
    assert dns.build_query("a.example", 28, 0)[:2] == b"\x00\x00"
    assert dns.build_query("a.example", 28, 0)[-4:] == struct.pack("!HH", 28, 1)


@pytest.mark.parametrize(
    "ident,message",
    [(-1, "query id is out of range"), (65536, "query id is out of range")],
)
def test_build_query_rejects_bad_ident_before_encoding(ident, message):
    with pytest.raises(ValueError) as raised:
        dns.build_query("", 1, ident)
    assert str(raised.value) == message


def test_build_query_propagates_name_errors():
    with pytest.raises(ValueError, match="empty name"):
        dns.build_query("", 1, 1)


@pytest.mark.parametrize(
    "data,offset,expected",
    [
        (b"\x03www\x07example\x03com\x00rest", 0, ("www.example.com", 17)),
        (b"\x07example\x03com\x00\x03www\xc0\x00", 13, ("www.example.com", 19)),
        (b"\x00", 0, ("", 1)),
        (b"\x03a.b\x00", 0, ("a.b", 5)),
        (b"\x02\xff\xfe\x00", 0, ("��", 4)),
    ],
)
def test_read_name_values(data, offset, expected):
    assert dns.read_name(data, offset) == expected


def _pointer_chain(hops):
    return (
        b"".join(bytes([0xC0, 2 * (index + 1)]) for index in range(hops)) + b"\x01a\x00"
    )


@pytest.mark.parametrize(
    "data,offset,message",
    [
        (b"\x03ww", 0, "dns name was truncated"),
        (b"\xc0", 0, "dns name was truncated"),
        (b"\x00", 5, "dns name was truncated"),
        (b"\xc0\x00", 0, "dns name pointer loop"),
        (b"\x40abc\x00", 0, "dns name is not a hostname"),
        (b"\x80abc\x00", 0, "dns name is not a hostname"),
        (_pointer_chain(18), 0, "dns name pointer loop"),
    ],
)
def test_read_name_errors(data, offset, message):
    with pytest.raises(ValueError) as raised:
        dns.read_name(data, offset)
    assert str(raised.value) == message


def test_read_name_follows_a_pointer_chain_up_to_seventeen_hops():
    assert dns.read_name(_pointer_chain(3), 0) == ("a", 2)
    assert dns.read_name(_pointer_chain(17), 0) == ("a", 2)


def test_read_name_returns_the_end_after_the_first_pointer():
    data = wire_name("example.com") + b"\x03www\xc0\x00" + b"TAIL"
    assert dns.read_name(data, len(wire_name("example.com"))) == (
        "www.example.com",
        len(wire_name("example.com")) + 6,
    )


def _full_message():
    qname = wire_name("a.example")
    return packet(
        0xBEEF,
        0x8580,
        [("a.example", 1)],
        answers=[
            rr(1, a_data("192.0.2.1")),
            rr(28, aaaa_data("2001:db8::1")),
            rr(5, wire_name("target.example")),
            rr(15, mx_data(10, "mail.example")),
            rr(2, wire_name("ns1.example")),
            rr(16, txt_data(b"v=spf1 ", b"-all")),
            rr(16, b""),
            rr(1, b"\x01\x02\x03"),
            rr(99, b"opaque"),
            rr(15, b"\x00\x0a"),
            rr(5, b"\xc0\x0c", ttl=7),
        ],
        authorities=[rr(2, wire_name("ns2.example"), ttl=90)],
        additionals=[
            rr(1, a_data("192.0.2.53"), ttl=3, owner=wire_name("ns2.example"))
        ],
    ), qname


def test_parse_message_header_questions_and_sections():
    data, _ = _full_message()
    message = dns.parse_message(data)
    assert (message.ident, message.flags) == (0xBEEF, 0x8580)
    assert message.questions == [dns.Question("a.example", 1, 1)]
    assert [(r.name, r.rtype, r.rclass, r.ttl, r.text) for r in message.answers] == [
        ("a.example", 1, 1, 30, "192.0.2.1"),
        ("a.example", 28, 1, 30, "2001:db8::1"),
        ("a.example", 5, 1, 30, "target.example"),
        ("a.example", 15, 1, 30, "10 mail.example"),
        ("a.example", 2, 1, 30, "ns1.example"),
        ("a.example", 16, 1, 30, "v=spf1 -all"),
        ("a.example", 16, 1, 30, ""),
        ("a.example", 1, 1, 30, ""),
        ("a.example", 99, 1, 30, ""),
        ("a.example", 15, 1, 30, ""),
        ("a.example", 5, 1, 7, "a.example"),
    ]
    assert message.authorities == [dns.Record("a.example", 2, 1, 90, "ns2.example")]
    assert message.additionals == [dns.Record("ns2.example", 1, 1, 3, "192.0.2.53")]
    assert all(isinstance(record, dns.Record) for record in message.answers)


def test_parse_message_decodes_text_with_replacement_and_tolerates_overlong_chunks():
    data = packet(
        1,
        0,
        [("a.example", 16)],
        answers=[rr(16, txt_data(b"ok", b"\xff\xfe")), rr(16, b"\x09abc")],
    )
    texts = [record.text for record in dns.parse_message(data).answers]
    assert texts == ["ok��", "abc"]


@pytest.mark.parametrize(
    "data,message",
    [
        (b"\x00" * 11, "dns message was truncated"),
        (struct.pack("!HHHHHH", 1, 0, 9, 0, 0, 0), "dns message is too large"),
        (struct.pack("!HHHHHH", 1, 0, 0, 100, 29, 0), "dns message is too large"),
        (struct.pack("!HHHHHH", 1, 0, 0, 0, 0, 129), "dns message is too large"),
        (struct.pack("!HHHHHH", 1, 0, 0, 100, 28, 0), "dns name was truncated"),
        (struct.pack("!HHHHHH", 1, 0, 8, 0, 0, 0), "dns name was truncated"),
        (
            struct.pack("!HHHHHH", 1, 0, 1, 0, 0, 0)
            + wire_name("a.example")
            + b"\x00\x01",
            "dns question was truncated",
        ),
        (
            struct.pack("!HHHHHH", 1, 0, 0, 1, 0, 0)
            + wire_name("a.example")
            + b"\x00\x01\x00\x01\x00",
            "dns record was truncated",
        ),
        (
            struct.pack("!HHHHHH", 1, 0, 0, 1, 0, 0)
            + wire_name("a.example")
            + struct.pack("!HHIH", 1, 1, 1, 9)
            + b"\x01",
            "dns record was truncated",
        ),
    ],
)
def test_parse_message_errors(data, message):
    with pytest.raises(ValueError) as raised:
        dns.parse_message(data)
    assert str(raised.value) == message


def test_parse_message_accepts_the_size_limits_exactly():
    questions = [("a.example", 1)] * 8
    data = packet(1, 0, questions)
    assert len(dns.parse_message(data).questions) == 8
    answers = [rr(1, a_data("192.0.2.1"), owner=wire_name("a.example"))] * 128
    assert len(dns.parse_message(packet(1, 0, [], answers=answers)).answers) == 128


def test_answer_packet_is_a_reply_to_the_query_with_matching_records_only():
    query = dns.build_query("a.example", 1, 7)
    records = [(1, a_data("1.2.3.4")), (28, aaaa_data("::1")), (1, a_data("5.6.7.8"))]
    reply = dns.answer_packet(query, records, tc=True, rcode=3, ident=0x4242)
    expected = (
        struct.pack("!HHHHHH", 0x4242, 0x8383, 1, 2, 0, 0)
        + wire_name("a.example")
        + struct.pack("!HH", 1, 1)
        + rr(1, a_data("1.2.3.4"), ttl=60)
        + rr(1, a_data("5.6.7.8"), ttl=60)
    )
    assert reply == expected
    plain = dns.answer_packet(query, [])
    assert plain == struct.pack("!HHHHHH", 7, 0x8180, 1, 0, 0, 0) + wire_name(
        "a.example"
    ) + struct.pack("!HH", 1, 1)


def test_answer_packet_masks_rcode_and_keeps_query_class():
    query = dns.build_query("a.example", 16, 9)
    assert (
        struct.unpack("!H", dns.answer_packet(query, [], rcode=0x13)[2:4])[0] == 0x8183
    )


def test_answer_packet_requires_a_question():
    with pytest.raises(ValueError, match="^query has no question$"):
        dns.answer_packet(struct.pack("!HHHHHH", 1, 0, 0, 0, 0, 0), [])


def test_answer_packet_round_trips_through_parse_message():
    query = dns.build_query("host.example", 15, 0x0A0B)
    reply = dns.answer_packet(query, [(15, mx_data(5, "mx.host.example"))])
    message = dns.parse_message(reply)
    assert message.ident == 0x0A0B and message.questions == [
        dns.Question("host.example", 15, 1)
    ]
    assert [(r.rtype, r.ttl, r.text) for r in message.answers] == [
        (15, 60, "5 mx.host.example")
    ]


# ---- system_resolver ----------------------------------------------------------------


@pytest.mark.parametrize(
    "content,expected",
    [
        ("nameserver 192.0.2.1\n", "192.0.2.1"),
        (
            "# nameserver 1.1.1.1\nsearch x.example\nnameserver 9.9.9.9 # trailing\n",
            "9.9.9.9",
        ),
        (
            "nameserver notanip\nnameserver\nnameserver 8.8.4.4\nnameserver 8.8.8.8\n",
            "8.8.4.4",
        ),
        ("NameServer 2001:DB8::53\n", "2001:db8::53"),
        ("nameserver 10.1.1.1#note\n", "10.1.1.1"),
        ("search example\noptions edns0\n", None),
        ("", None),
        ("nameserver garbage\n", None),
    ],
)
def test_system_resolver_reads_the_first_valid_nameserver(
    resolv_conf, content, expected
):
    resolv_conf.write(content)
    assert dns.system_resolver() == expected


def test_system_resolver_is_none_when_the_file_is_unreadable(resolv_conf):
    assert not resolv_conf.path.exists()
    assert dns.system_resolver() is None


# ======================================================================================
# 5. dns - lookup() against a loopback resolver
# ======================================================================================


def full_zone(resolver):
    resolver.on(
        NAME,
        1,
        Reply(
            answers=[
                (1, a_data("192.0.2.7")),
                (1, a_data("192.0.2.8")),
                (1, a_data("192.0.2.7")),
            ]
        ),
    )
    resolver.on(NAME, 28, Reply(answers=[(28, aaaa_data("2001:db8::7"))]))
    resolver.on(
        NAME,
        15,
        Reply(
            answers=[
                (15, mx_data(10, "mail.allowed.example")),
                (15, mx_data(20, "mx2.allowed.example")),
            ]
        ),
    )
    resolver.on(
        NAME,
        16,
        Reply(answers=[(16, txt_data(b"v=spf1 ", b"-all")), (16, txt_data(b"hello"))]),
    )
    resolver.on(NAME, 2, Reply(answers=[(2, wire_name("ns1.allowed.example"))]))


def call_lookup(dns_lab, name=NAME, timeout=2):
    return dns.lookup(name, "127.0.0.1", dns_lab.resolver.port, timeout)


def test_lookup_returns_values_notes_and_failed_flag(dns_lab):
    full_zone(dns_lab.resolver)
    found, notes, failed = call_lookup(dns_lab)
    assert list(found) == ["A", "AAAA", "CNAME", "MX", "TXT", "NS"]
    assert found == {
        "A": ["192.0.2.7", "192.0.2.8"],
        "AAAA": ["2001:db8::7"],
        "CNAME": [],
        "MX": ["10 mail.allowed.example", "20 mx2.allowed.example"],
        "TXT": ["v=spf1 -all", "hello"],
        "NS": ["ns1.allowed.example"],
    }
    assert notes == [] and failed is False


def test_lookup_asks_one_question_per_type_in_order_with_recursion_desired(dns_lab):
    full_zone(dns_lab.resolver)
    call_lookup(dns_lab)
    seen = dns_lab.resolver.seen
    assert [(row[0], row[1]) for row in seen] == [
        (NAME, code) for code in (1, 28, 5, 15, 16, 2)
    ]
    assert all(row[3] == 0x0100 for row in seen)


def test_lookup_sorts_records_by_their_own_type_and_merges_every_section(dns_lab):
    dns_lab.resolver.on(
        NAME,
        2,
        Reply(
            answers=[(2, wire_name("ns1.allowed.example"))],
            authorities=[(2, wire_name("ns2.allowed.example"))],
            additionals=[(1, a_data("192.0.2.53")), (28, aaaa_data("2001:db8::53"))],
        ),
    )
    found, _notes, _failed = call_lookup(dns_lab)
    assert found["NS"] == ["ns1.allowed.example", "ns2.allowed.example"]
    assert found["A"] == ["192.0.2.53"] and found["AAAA"] == ["2001:db8::53"]


def test_lookup_ignores_unknown_types_and_empty_text(dns_lab):
    dns_lab.resolver.on(
        NAME, 16, Reply(answers=[(99, b"opaque"), (16, b""), (1, b"\x01\x02")])
    )
    found, notes, failed = call_lookup(dns_lab)
    assert (
        all(values == [] for values in found.values())
        and notes == []
        and failed is False
    )


def test_lookup_nxdomain_is_not_a_failure_but_other_rcodes_are(dns_lab):
    dns_lab.resolver.on(NAME, 1, Reply(rcode=3))
    found, notes, failed = call_lookup(dns_lab)
    assert failed is False and notes == [] and not any(found.values())
    for rcode in (2, 5, 1, 4):
        dns_lab.resolver.on(
            NAME, 28, Reply(rcode=rcode, answers=[(28, aaaa_data("2001:db8::1"))])
        )
        found, _notes, failed = call_lookup(dns_lab)
        assert failed is True, rcode
        assert found["AAAA"] == [], rcode


def test_lookup_failure_of_one_type_keeps_the_other_answers(dns_lab):
    dns_lab.resolver.on(NAME, 1, Reply(answers=[(1, a_data("192.0.2.9"))]))
    dns_lab.resolver.on(NAME, 15, Reply(rcode=2))
    found, _notes, failed = call_lookup(dns_lab)
    assert failed is True and found["A"] == ["192.0.2.9"]


def test_lookup_truncated_flag_adds_one_note_and_still_reads_the_answer(dns_lab):
    dns_lab.resolver.on(NAME, 1, Reply(tc=True, answers=[(1, a_data("192.0.2.9"))]))
    dns_lab.resolver.on(NAME, 16, Reply(tc=True))
    found, notes, failed = call_lookup(dns_lab)
    assert found["A"] == ["192.0.2.9"] and failed is False
    assert notes == ["The answer was truncated."]


def test_lookup_flags_a_cname_without_addresses_after_the_truncation_note(dns_lab):
    dns_lab.resolver.on(
        NAME,
        5,
        Reply(
            tc=True,
            answers=[
                (5, wire_name("elsewhere.example")),
                (5, wire_name("second.example")),
            ],
        ),
    )
    _found, notes, _failed = call_lookup(dns_lab)
    assert notes == [
        "The answer was truncated.",
        "review: CNAME elsewhere.example has no address in this answer",
    ]
    dns_lab.resolver.on(NAME, 1, Reply(answers=[(1, a_data("192.0.2.1"))]))
    _found, notes, _failed = call_lookup(dns_lab)
    assert notes == ["The answer was truncated."]


def test_lookup_reads_replies_up_to_4096_bytes(dns_lab):
    values = [("t%02d-" % index) + "x" * 240 for index in range(14)]
    dns_lab.resolver.on(
        NAME, 16, Reply(answers=[(16, txt_data(value.encode())) for value in values])
    )
    found, _notes, failed = call_lookup(dns_lab)
    assert found["TXT"] == values and failed is False


def test_lookup_rejects_a_reply_with_the_wrong_id(dns_lab):
    dns_lab.resolver.on(NAME, 1, Reply(ident_xor=1, answers=[(1, a_data("192.0.2.9"))]))
    with pytest.raises(ValueError) as raised:
        call_lookup(dns_lab)
    assert str(raised.value) == "response id did not match"
    assert [row[1] for row in dns_lab.resolver.seen] == [1]


def test_lookup_rejects_garbage_replies(dns_lab):
    dns_lab.resolver.on(NAME, 1, Reply(raw=b"\x00\x01"))
    with pytest.raises(ValueError, match="^dns message was truncated$"):
        call_lookup(dns_lab)


def test_lookup_retries_each_query_once_then_raises_a_timeout(dns_lab):
    dns_lab.resolver.on(NAME, 1, Reply(drop=True))
    started = time.monotonic()
    with pytest.raises(TimeoutError):
        call_lookup(dns_lab, timeout=0.2)
    assert time.monotonic() - started < 5
    assert len(dns_lab.resolver.queries_for(NAME, 1)) == 2
    assert dns_lab.resolver.queries_for(NAME, 28) == []
    ident_first, ident_second = (
        row[2] for row in dns_lab.resolver.queries_for(NAME, 1)
    )
    assert ident_first == ident_second


def test_lookup_a_dropped_first_datagram_is_recovered_by_the_retry(dns_lab):
    dns_lab.resolver.on(
        NAME, 1, Reply(drop=True), Reply(answers=[(1, a_data("192.0.2.77"))])
    )
    found, _notes, failed = call_lookup(dns_lab, timeout=0.3)
    assert found["A"] == ["192.0.2.77"] and failed is False
    assert len(dns_lab.resolver.queries_for(NAME, 1)) == 2
    assert len(dns_lab.resolver.queries_for(NAME, 28)) == 1


@pytest.mark.parametrize("host", ["127.0.0.1", "::1"])
def test_lookup_ignores_a_forged_reply_then_accepts_the_resolver_reply(dns_lab, host):
    try:
        resolver = FakeResolver(host)
    except OSError as failure:
        if host == "::1":
            pytest.skip(f"IPv6 loopback unavailable: {failure}")
        raise
    try:
        dns_lab.grant(egress.endpoint(host, resolver.port, "http"), operations=("dns",))
        resolver.on(
            NAME,
            1,
            Reply(
                answers=[(1, a_data("192.0.2.77"))],
                forged_answers=[(1, a_data("192.0.2.66"))],
            ),
        )
        found, _notes, failed = dns.lookup(NAME, host, resolver.port, 0.3)
        assert found["A"] == ["192.0.2.77"] and failed is False
        assert len(resolver.queries_for(NAME, 1)) == 1
    finally:
        resolver.close()


def test_lookup_rejects_a_foreign_address_using_the_resolver_port(dns_lab):
    foreign = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        foreign.bind(("127.0.0.2", dns_lab.resolver.port))
    except OSError as failure:
        foreign.close()
        pytest.skip(f"Second loopback address unavailable: {failure}")
    dns_lab.resolver.other.close()
    dns_lab.resolver.other = foreign
    dns_lab.resolver.on(
        NAME, 1, Reply(from_other_socket=True, answers=[(1, a_data("192.0.2.66"))])
    )
    with pytest.raises(TimeoutError):
        call_lookup(dns_lab, timeout=0.1)
    assert len(dns_lab.resolver.queries_for(NAME, 1)) == 2


def test_lookup_reads_the_module_level_record_type_table_at_call_time(
    dns_lab, monkeypatch
):
    dns_lab.resolver.on(NAME, 1, Reply(answers=[(1, a_data("192.0.2.5"))]))
    monkeypatch.setattr(dns, "RECORD_TYPES", [("A", 1), ("AAAA", 28), ("CNAME", 5)])
    found, _notes, _failed = call_lookup(dns_lab)
    assert list(found) == ["A", "AAAA", "CNAME"] and found["A"] == ["192.0.2.5"]
    assert [row[1] for row in dns_lab.resolver.seen] == [1, 28, 5]


def test_lookup_opens_a_datagram_socket_for_the_resolver_family_and_always_closes_it(
    dns_lab, monkeypatch
):
    events = []

    class Recorder:
        def __init__(self, family, kind, *rest):
            events.append(("open", family, kind))

        def settimeout(self, value):
            events.append(("timeout", value))

        def connect(self, address):
            self.peer = address
            events.append(("connect", address))

        def send(self, data):
            events.append(("send", self.peer))
            raise OSError("stop here")

        def close(self):
            events.append(("close",))

    dns_lab.grant("http://[::1]:5353", operations=("dns",))
    monkeypatch.setattr(socket, "socket", Recorder)
    with pytest.raises(OSError, match="stop here"):
        dns.lookup(NAME, "::1", 5353, 1.25)
    assert events == [
        ("open", socket.AF_INET6, socket.SOCK_DGRAM),
        ("timeout", 1.25),
        ("connect", ("::1", 5353)),
        ("send", ("::1", 5353)),
        ("close",),
    ]
    events.clear()
    dns_lab.grant("http://127.0.0.1:5354", operations=("dns",))
    with pytest.raises(OSError, match="stop here"):
        dns.lookup(NAME, "127.0.0.1", 5354, 2)
    assert events[0] == ("open", socket.AF_INET, socket.SOCK_DGRAM) and events[-1] == (
        "close",
    )


@pytest.mark.parametrize("target", ["lookup", "fetch", "tls"])
def test_network_edges_refuse_to_touch_the_network_without_a_policy(
    lab, monkeypatch, target
):
    (lab.root / "policy.json").unlink()
    touched = []
    monkeypatch.setattr(socket, "socket", lambda *a, **k: touched.append("socket"))
    monkeypatch.setattr(
        socket, "create_connection", lambda *a, **k: touched.append("connect")
    )
    calls = {
        "lookup": lambda: dns.lookup(NAME, "127.0.0.1", 5353, 1),
        "fetch": lambda: whois._fetch("whois.iana.org", 43, NAME, 1),
        "tls": lambda: cert.fetch_certificate(NAME, 443, 1),
    }
    with pytest.raises(egress.PolicyBlocked):
        calls[target]()
    assert touched == []


def test_network_edges_refuse_an_ungranted_secondary_endpoint(lab, monkeypatch):
    touched = []
    monkeypatch.setattr(socket, "socket", lambda *a, **k: touched.append("socket"))
    monkeypatch.setattr(
        socket, "create_connection", lambda *a, **k: touched.append("connect")
    )
    with pytest.raises(egress.PolicyBlocked):
        dns.lookup(NAME, "127.0.0.1", 5353, 1)
    with pytest.raises(egress.PolicyBlocked):
        whois._fetch("whois.iana.org", 43, NAME, 1)
    with pytest.raises(egress.PolicyBlocked):
        dns.lookup("not-granted.example", "127.0.0.1", 5353, 1)
    assert touched == []


# ======================================================================================
# 6. dns - main()
# ======================================================================================


@pytest.mark.parametrize(
    "argv",
    [
        ["x.example", "--timeout", "0"],
        ["x.example", "--timeout", "-1"],
        ["x.example", "--port", "0"],
        ["x.example", "--port", "65536"],
        ["10.0.0.1", "--timeout", "0"],
    ],
)
def test_dns_main_rejects_bad_timeout_or_port_first(lab, capsys, argv):
    code, out, err = run(dns, argv, capsys)
    assert (code, out, err) == (
        2,
        "",
        "Timeout must be greater than 0, and the port must be 1 through 65535.\n",
    )


@pytest.mark.parametrize(
    "value", ["10.0.0.1", "a b", "::1", "", "*.example", "http://[::1]/"]
)
def test_dns_main_rejects_non_hostnames(lab, capsys, value):
    code, out, err = run(dns, [value, "--resolver", "bad"], capsys)
    assert (code, out, err) == (2, "", "Give a hostname, such as app.internal.\n")


def test_dns_main_refuses_out_of_scope_names_before_looking_at_the_resolver(
    lab, capsys
):
    code, out, err = run(dns, ["other.example", "--resolver", "not-an-address"], capsys)
    assert (code, out, err) == (2, "", explain_block("other.example") + "\n")
    (lab.root / "scope.txt").unlink()
    code, out, err = run(dns, ["other.example"], capsys)
    assert (code, out) == (2, "") and err == explain_block("other.example") + "\n"
    assert "no scope file" in err


def test_dns_main_validates_the_resolver_option(lab, capsys):
    code, out, err = run(dns, [NAME, "--resolver", "resolver.example"], capsys)
    assert (code, out, err) == (2, "", "Pass a resolver address, such as 127.0.0.1.\n")


def test_dns_main_without_a_system_resolver_asks_for_one(lab, capsys, resolv_conf):
    resolv_conf.write("# nothing here\n")
    code, out, err = run(dns, [NAME], capsys)
    assert (code, out, err) == (
        1,
        "",
        "No resolver is set. Pass --resolver with an address.\n",
    )


def test_dns_main_without_a_policy_reports_the_block_text(lab, capsys):
    (lab.root / "policy.json").unlink()
    code, out, err = run(dns, [NAME, "--resolver", "127.0.0.1"], capsys)
    assert (code, out, err) == (
        1,
        "",
        "policy-missing-or-invalid; no outbound action ran\n",
    )


def test_dns_main_prints_label_tab_value_in_table_order(dns_lab, capsys):
    full_zone(dns_lab.resolver)
    code, out, err = run(dns, [NAME, *resolver_args(dns_lab)], capsys)
    assert code == 0 and err == ""
    assert out == (
        "A\t192.0.2.7\nA\t192.0.2.8\nAAAA\t2001:db8::7\n"
        "MX\t10 mail.allowed.example\nMX\t20 mx2.allowed.example\n"
        "TXT\tv=spf1 -all\nTXT\thello\nNS\tns1.allowed.example\n"
    )


def test_dns_main_accepts_a_url_and_uppercase_and_a_bracketed_resolver(dns_lab, capsys):
    dns_lab.resolver.on(NAME, 1, Reply(answers=[(1, a_data("192.0.2.3"))]))
    code, out, _err = run(
        dns,
        [
            "https://ALLOWED.example./x",
            "--resolver",
            "127.0.0.1",
            "--port",
            str(dns_lab.resolver.port),
        ],
        capsys,
    )
    assert code == 0 and out == "A\t192.0.2.3\n"
    assert {row[0] for row in dns_lab.resolver.seen} == {NAME}


def test_dns_main_says_no_records_when_everything_is_empty(dns_lab, capsys):
    code, out, err = run(dns, [NAME, *resolver_args(dns_lab)], capsys)
    assert (code, out, err) == (0, "", "no records\n")
    dns_lab.resolver.on(NAME, 1, Reply(rcode=3))
    code, out, err = run(dns, [NAME, *resolver_args(dns_lab)], capsys)
    assert (code, out, err) == (0, "", "no records\n")


def test_dns_main_reports_failure_only_when_nothing_was_printed(dns_lab, capsys):
    for rtype in (1, 28, 5, 15, 16, 2):
        dns_lab.resolver.on(NAME, rtype, Reply(rcode=2))
    code, out, err = run(dns, [NAME, *resolver_args(dns_lab)], capsys)
    assert (code, out, err) == (1, "", f"{NAME} lookup failed.\n")
    dns_lab.resolver.on(NAME, 1, Reply(answers=[(1, a_data("192.0.2.4"))]))
    code, out, err = run(dns, [NAME, *resolver_args(dns_lab)], capsys)
    assert (code, out, err) == (0, "A\t192.0.2.4\n", "")


def test_dns_main_writes_notes_to_stderr_after_the_records(dns_lab, capsys):
    dns_lab.resolver.on(
        NAME, 5, Reply(tc=True, answers=[(5, wire_name("elsewhere.example"))])
    )
    code, out, err = run(dns, [NAME, *resolver_args(dns_lab)], capsys)
    assert code == 0
    assert out == "CNAME\telsewhere.example\n"
    assert (
        err
        == "The answer was truncated.\nreview: CNAME elsewhere.example has no address in this answer\n"
    )


def test_dns_main_value_errors_print_their_text(dns_lab, capsys):
    dns_lab.resolver.on(NAME, 1, Reply(ident_xor=7))
    code, out, err = run(dns, [NAME, *resolver_args(dns_lab)], capsys)
    assert (code, out, err) == (1, "", "response id did not match\n")
    dns_lab.resolver.on(NAME, 1, Reply(raw=b""))
    code, out, err = run(dns, [NAME, *resolver_args(dns_lab)], capsys)
    assert (code, out, err) == (1, "", "dns message was truncated\n")


def test_dns_main_os_errors_print_only_the_class_name(dns_lab, capsys):
    dns_lab.resolver.on(NAME, 1, Reply(drop=True))
    code, out, err = run(
        dns,
        [
            NAME,
            "--resolver",
            "127.0.0.1",
            "--port",
            str(dns_lab.resolver.port),
            "--timeout",
            "0.2",
        ],
        capsys,
    )
    assert (code, out, err) == (1, "", f"Could not look up {NAME}: TimeoutError\n")


# ======================================================================================
# 7. whois - pure helpers
# ======================================================================================

SAMPLE_RECORD = """% comment
% Source: iana
# another
# Hidden: yes
Domain Name:   EXAMPLE.COM
Registrar:  Example   Registrar, Inc.
Creation Date: 1995-08-14T04:00:00Z
Registry Expiry Date: 2099-08-13T04:00:00Z
Name Server: A.IANA-SERVERS.NET
Name Server: B.IANA-SERVERS.NET 1.2.3.4
Name Server: a.iana-servers.net
nserver: c.example.net.
no colon here
Empty:
:novalue
URL: http://x.example/a:b
"""


def test_pairs_lowercases_keys_collapses_space_and_skips_noise():
    assert whois.pairs(SAMPLE_RECORD) == [
        ("domain name", "EXAMPLE.COM"),
        ("registrar", "Example Registrar, Inc."),
        ("creation date", "1995-08-14T04:00:00Z"),
        ("registry expiry date", "2099-08-13T04:00:00Z"),
        ("name server", "A.IANA-SERVERS.NET"),
        ("name server", "B.IANA-SERVERS.NET 1.2.3.4"),
        ("name server", "a.iana-servers.net"),
        ("nserver", "c.example.net."),
        ("url", "http://x.example/a:b"),
    ]
    assert whois.pairs("") == []
    assert whois.pairs("  Key  Two :\t spaced   value  \r\n") == [
        ("key two", "spaced value")
    ]


def test_parse_record_shape_and_value_rules():
    record = whois.parse_record(SAMPLE_RECORD)
    assert list(record) == [
        "registrar",
        "created",
        "created_text",
        "expires",
        "expires_text",
        "nameservers",
    ]
    assert record == {
        "registrar": "Example Registrar, Inc.",
        "created": datetime(1995, 8, 14, 4, 0, tzinfo=timezone.utc),
        "created_text": "1995-08-14T04:00:00Z",
        "expires": datetime(2099, 8, 13, 4, 0, tzinfo=timezone.utc),
        "expires_text": "2099-08-13T04:00:00Z",
        "nameservers": ["a.iana-servers.net", "b.iana-servers.net", "c.example.net"],
    }
    assert whois.parse_record("") == {
        "registrar": "",
        "created": None,
        "created_text": "",
        "expires": None,
        "expires_text": "",
        "nameservers": [],
    }


def test_parse_record_alternate_keys_and_unparseable_dates():
    text = "Sponsoring Registrar: Alt Reg\nCreated: soon\nExpires: 2031-02-03\n"
    record = whois.parse_record(text)
    assert record["registrar"] == "Alt Reg"
    assert (record["created"], record["created_text"]) == (None, "soon")
    assert (
        record["expires"] == datetime(2031, 2, 3, tzinfo=timezone.utc)
        and record["expires_text"] == "2031-02-03"
    )
    assert (
        whois.parse_record("Registrar: First\nSponsoring Registrar: Second\n")[
            "registrar"
        ]
        == "First"
    )
    # Key priority is fixed by the module, not by line order.
    assert (
        whois.parse_record("Expires: 2031-01-01\nExpiration Date: 2032-01-01\n")[
            "expires_text"
        ]
        == "2032-01-01"
    )
    assert (
        whois.parse_record("Expiration Date: 2032-01-01\nExpiry Date: 2033-01-01\n")[
            "expires_text"
        ]
        == "2033-01-01"
    )
    assert (
        whois.parse_record(
            "Expiry Date: 2033-01-01\nRegistry Expiry Date: 2034-01-01\n"
        )["expires_text"]
        == "2034-01-01"
    )
    assert (
        whois.parse_record("Created: 1999-01-01\nCreation Date: 2000-01-01\n")[
            "created_text"
        ]
        == "2000-01-01"
    )
    assert (
        whois.parse_record("Creation Date: 2000-01-01\nCreation Date: 2001-01-01\n")[
            "created_text"
        ]
        == "2000-01-01"
    )


@pytest.mark.parametrize(
    "value,expected",
    [
        ("2030-08-13T04:00:00Z", datetime(2030, 8, 13, 4, 0, tzinfo=timezone.utc)),
        ("2030-08-13 04:00:00", datetime(2030, 8, 13, 4, 0, tzinfo=timezone.utc)),
        ("2030-08-13", datetime(2030, 8, 13, tzinfo=timezone.utc)),
        ("20300813", datetime(2030, 8, 13, tzinfo=timezone.utc)),
        ("2030-08-13T04:00:00.123Z", datetime(2030, 8, 13, 4, 0, tzinfo=timezone.utc)),
        (
            "2030-08-13T04:00:00.1234567Z",
            datetime(2030, 8, 13, 4, 0, tzinfo=timezone.utc),
        ),
        ("2030-08-13 04:00:00 UTC", datetime(2030, 8, 13, 4, 0, tzinfo=timezone.utc)),
        ("2030-08-13T04:00:00 gmt", datetime(2030, 8, 13, 4, 0, tzinfo=timezone.utc)),
        ("  2030-08-13  ", datetime(2030, 8, 13, tzinfo=timezone.utc)),
        ("garbage", None),
        ("", None),
        ("2030-13-45", None),
        ("2030/08/13", None),
        ("2030-08-13T04:00Z", None),
        ("Tue Aug 13 2030", None),
    ],
)
def test_parse_when_accepted_and_rejected_shapes(value, expected):
    assert whois.parse_when(value) == expected


def test_parse_when_returns_utc_aware_datetimes():
    parsed = whois.parse_when("2030-08-13")
    assert parsed.tzinfo is timezone.utc and parsed.utcoffset() == timedelta(0)


@pytest.mark.parametrize(
    "text,expected",
    [
        (
            "refer: whois.verisign-grs.com\nrefer: other.example\n",
            "whois.verisign-grs.com",
        ),
        ("refer: Whois.Example.COM.", "whois.example.com"),
        ("refer: whois.example.com extra words", "whois.example.com"),
        ("REFER: a.example.com", "a.example.com"),
        ("refer: ex.com\n", "ex.com"),
        ("refer: 1.2.3.4", None),
        ("refer: localhost", None),
        ("refer: a_b.example.com", None),
        ("refer: x.y", None),
        ("refer: ex.c0m", None),
        ("refer: a.example.com:43", None),
        ("% refer: a.example.com", None),
        ("refer:  ", None),
        ("nothing at all", None),
        ("", None),
    ],
)
def test_referral_host(text, expected):
    assert whois.referral_host(text) == expected


def test_referral_host_only_considers_the_first_refer_line():
    assert whois.referral_host("refer: 10.0.0.1\nrefer: good.example.com\n") is None


def test_record_rows_order_and_text_fallbacks():
    record = whois.parse_record(SAMPLE_RECORD)
    assert whois.record_rows("example.com", record) == [
        ("domain", "example.com"),
        ("registrar", "Example Registrar, Inc."),
        ("created", "1995-08-14 04:00:00Z"),
        ("expires", "2099-08-13 04:00:00Z"),
        ("nserver", "a.iana-servers.net"),
        ("nserver", "b.iana-servers.net"),
        ("nserver", "c.example.net"),
    ]
    assert whois.record_rows("e.com", whois.parse_record("")) == [("domain", "e.com")]
    raw = {
        "registrar": "",
        "created": None,
        "created_text": "yesterday" * 50,
        "expires": None,
        "expires_text": "",
        "nameservers": ["a", "b"],
    }
    rows = whois.record_rows("e.com", raw)
    assert rows[0] == ("domain", "e.com") and rows[1] == (
        "created",
        ("yesterday" * 50)[:300],
    )
    assert rows[2:] == [("nserver", "a"), ("nserver", "b")]
    assert whois.record_rows("e.com", {}) == [("domain", "e.com")]
    assert whois.record_rows("e.com", {"registrar": 5, "nameservers": "nope"}) == [
        ("domain", "e.com")
    ]


def test_review_notes_expired_soon_and_fine():
    now = datetime.now(timezone.utc)

    def notes_for(delta):
        return whois.review_notes({"expires": now + delta})

    shown = lambda delta: (now + delta).strftime("%Y-%m-%d %H:%M:%SZ")
    assert notes_for(-timedelta(days=1))[0].startswith("review: expired on ")
    assert notes_for(-timedelta(days=1)) == [
        f"review: expired on {shown(-timedelta(days=1))}"
    ]
    assert notes_for(timedelta(days=10)) == [
        f"review: expires within 30 days ({shown(timedelta(days=10))})"
    ]
    assert notes_for(timedelta(days=29, hours=23)) != []
    assert notes_for(timedelta(days=31)) == []
    assert notes_for(timedelta(days=400)) == []
    assert whois.review_notes({"expires": None}) == []
    assert whois.review_notes({"expires": "2020-01-01"}) == []
    assert whois.review_notes({}) == []


WHOIS_BANNER_PLAIN = (
    "     ________________\n   .'_(            )_'.\n   |    registrar    |\n"
    "   |     (whois)     |\n   '-----------------'\nregistrar, dates, and nameservers for one domain"
)
WHOIS_BANNER_COLOR = (
    f"{CYAN}     ________________{RESET}\n"
    f"{CYAN}   .'_{YELLOW}({CYAN}            {YELLOW}){CYAN}_'.{RESET}\n"
    f"{CYAN}   |    registrar    |{RESET}\n"
    f"{CYAN}   |     ({MAGENTA}whois{CYAN})     |{RESET}\n"
    f"{CYAN}   '-----------------'{RESET}\n"
    f"{DIM}registrar, dates, and nameservers for one domain{RESET}"
)
MAIL_BANNER_PLAIN = (
    "    .-----------------.\n    |\\               /|\n    | \\    mail     / |\n"
    "    |  \\   (  )    /  |\n    |   '---------'   |\n    '-----------------'\n"
    "MX, SPF, DKIM, and DMARC for one name"
)
MAIL_BANNER_COLOR = (
    f"{CYAN}    .-----------------.{RESET}\n"
    f"{CYAN}    |\\               /|{RESET}\n"
    f"{CYAN}    | \\    {MAGENTA}mail{CYAN}     / |{RESET}\n"
    f"{CYAN}    |  \\   {YELLOW}({CYAN}  {YELLOW}){CYAN}    /  |{RESET}\n"
    f"{CYAN}    |   '---------'   |{RESET}\n"
    f"{CYAN}    '-----------------'{RESET}\n"
    f"{DIM}MX, SPF, DKIM, and DMARC for one name{RESET}"
)


@pytest.mark.parametrize(
    "module,plain,colored",
    [
        (whois, WHOIS_BANNER_PLAIN, WHOIS_BANNER_COLOR),
        (mail, MAIL_BANNER_PLAIN, MAIL_BANNER_COLOR),
    ],
)
def test_banner_plain_and_colored_forms(module, plain, colored):
    assert module.format_banner(False) == plain
    assert module.format_banner(True) == colored


@pytest.mark.parametrize("module", [whois, mail])
def test_format_field_plain_and_colored(module):
    assert module.format_field("registrar", "X Y", False) == "registrar\tX Y"
    assert (
        module.format_field("registrar", "X Y", True)
        == f"  {CYAN}registrar   {RESET} {WHITE}X Y{RESET}"
    )
    assert (
        module.format_field("a-key-longer-than-12", "v", True)
        == f"  {CYAN}a-key-longer-than-12{RESET} {WHITE}v{RESET}"
    )


# ======================================================================================
# 8. whois - fetch and main()
# ======================================================================================


class FakeWhois:
    """Loopback TCP whois server: one connection at a time; handler(query_text, index) -> bytes."""

    def __init__(self, handler):
        self.handler = handler
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(8)
        self.listener.settimeout(0.05)
        self.port = self.listener.getsockname()[1]
        self.queries = []
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def close(self):
        self._stop.set()
        self._thread.join(2)
        self.listener.close()

    def _serve(self):
        while not self._stop.is_set():
            try:
                connection, _ = self.listener.accept()
            except (socket.timeout, OSError):
                continue
            with connection:
                connection.settimeout(2)
                raw = b""
                try:
                    while not raw.endswith(b"\n"):
                        piece = connection.recv(1024)
                        if not piece:
                            break
                        raw += piece
                except OSError:
                    pass
                self.queries.append(raw)
                try:
                    connection.sendall(
                        self.handler(
                            raw.decode("ascii", "replace"), len(self.queries) - 1
                        )
                    )
                except OSError:
                    pass


@pytest.fixture
def whois_lab(lab):
    servers = []

    def start(handler):
        server = FakeWhois(handler)
        servers.append(server)
        lab.grant(f"http://127.0.0.1:{server.port}", operations=("passive",))
        return server

    lab.start = start
    yield lab
    for server in servers:
        server.close()


def future_record(days=400):
    expires = (datetime.now(timezone.utc) + timedelta(days=days)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    return (
        f"Domain Name: ALLOWED.EXAMPLE\nRegistrar: Reg Co\nCreation Date: 2001-02-03T04:05:06Z\n"
        f"Registry Expiry Date: {expires}\nName Server: NS1.ALLOWED.EXAMPLE\nName Server: ns2.allowed.example\n"
    ), expires


def test_whois_main_with_server_prints_rows_and_asks_the_server_once(whois_lab, capsys):
    text, expires = future_record()
    server = whois_lab.start(lambda query, index: text.encode())
    code, out, err = run(
        whois,
        [NAME, "--server", "127.0.0.1", "--port", str(server.port), "--plain"],
        capsys,
    )
    stamp = datetime.strptime(expires, "%Y-%m-%dT%H:%M:%SZ").strftime(
        "%Y-%m-%d %H:%M:%SZ"
    )
    assert code == 0 and err == ""
    assert out == (
        "domain\tallowed.example\nregistrar\tReg Co\ncreated\t2001-02-03 04:05:06Z\n"
        f"expires\t{stamp}\nnserver\tns1.allowed.example\nnserver\tns2.allowed.example\n"
    )
    assert server.queries == [b"allowed.example\r\n"]


def test_whois_main_sends_the_lowercased_hostname_of_a_url(whois_lab, capsys):
    server = whois_lab.start(lambda query, index: b"")
    run(
        whois,
        [
            "https://ALLOWED.example./x",
            "--server",
            "127.0.0.1",
            "--port",
            str(server.port),
        ],
        capsys,
    )
    assert server.queries == [b"allowed.example\r\n"]


def test_whois_main_without_a_registrar_record(whois_lab, capsys):
    server = whois_lab.start(lambda query, index: b"No match for domain.\n")
    code, out, err = run(
        whois, [NAME, "--server", "127.0.0.1", "--port", str(server.port)], capsys
    )
    assert (code, out, err) == (0, "domain\tallowed.example\n", "no registrar record\n")


def test_whois_main_review_notes_for_expired_and_expiring_domains(whois_lab, capsys):
    soon = datetime.now(timezone.utc) + timedelta(days=10)
    past = datetime.now(timezone.utc) - timedelta(days=3)
    for when, label in ((soon, "expires within 30 days ({})"), (past, "expired on {}")):
        raw = f"Registrar: R\nRegistry Expiry Date: {when.strftime('%Y-%m-%dT%H:%M:%SZ')}\n"
        server = whois_lab.start(lambda query, index, raw=raw: raw.encode())
        code, out, err = run(
            whois, [NAME, "--server", "127.0.0.1", "--port", str(server.port)], capsys
        )
        shown = when.strftime("%Y-%m-%d %H:%M:%SZ")
        assert code == 0
        assert err == "review: " + label.format(shown) + "\n"


def test_whois_main_truncates_at_64k_and_says_so_first(whois_lab, capsys):
    body = ("Registrar: Big Reg\n" + ("X-Pad: " + "p" * 90 + "\n") * 1000).encode()
    assert len(body) > 65536
    server = whois_lab.start(lambda query, index: body)
    code, out, err = run(
        whois, [NAME, "--server", "127.0.0.1", "--port", str(server.port)], capsys
    )
    assert code == 0 and out == "domain\tallowed.example\nregistrar\tBig Reg\n"
    assert err == "The reply was truncated.\n"
    empty = whois_lab.start(lambda query, index: b"X-Pad: " + b"p" * 70000)
    code, out, err = run(
        whois, [NAME, "--server", "127.0.0.1", "--port", str(empty.port)], capsys
    )
    assert (code, out) == (0, "domain\tallowed.example\n")
    assert err == "The reply was truncated.\nno registrar record\n"


def test_whois_main_follows_exactly_one_referral_from_iana(
    whois_lab, capsys, monkeypatch
):
    text, _ = future_record()
    registry_text = text + "refer: second-hop.example.com\n"

    def handler(query, index):
        return (
            b"refer: whois.registry.example\nrefer: ignored.example.com\n"
            if index == 0
            else registry_text.encode()
        )

    server = whois_lab.start(handler)
    whois_lab.grant(f"http://whois.iana.org:{server.port}", operations=("passive",))
    whois_lab.grant(
        f"http://whois.registry.example:{server.port}", operations=("passive",)
    )
    dialled = []
    real = socket.create_connection
    monkeypatch.setattr(
        socket,
        "create_connection",
        lambda address, *args, **kwargs: (
            dialled.append(address) or real(("127.0.0.1", server.port), *args, **kwargs)
        ),
    )
    code, out, err = run(whois, [NAME, "--port", str(server.port), "--plain"], capsys)
    assert code == 0 and err == ""
    assert out.startswith("domain\tallowed.example\nregistrar\tReg Co\n")
    assert dialled == [
        ("whois.iana.org", server.port),
        ("whois.registry.example", server.port),
    ]
    assert server.queries == [b"allowed.example\r\n", b"allowed.example\r\n"]


def test_whois_main_registry_not_named(whois_lab, capsys, monkeypatch):
    server = whois_lab.start(lambda query, index: b"refer: 10.0.0.1\n")
    whois_lab.grant(f"http://whois.iana.org:{server.port}", operations=("passive",))
    real = socket.create_connection
    monkeypatch.setattr(
        socket,
        "create_connection",
        lambda address, *a, **k: real(("127.0.0.1", server.port), *a, **k),
    )
    code, out, err = run(whois, [NAME, "--port", str(server.port)], capsys)
    assert (code, out, err) == (1, "", "The registry was not named.\n")
    assert len(server.queries) == 1


def test_whois_fetch_record_returns_text_and_truncation_notes(whois_lab):
    server = whois_lab.start(lambda query, index: b"Registrar: Plain\n")
    assert whois.fetch_record(NAME, "127.0.0.1", server.port, 2) == (
        "Registrar: Plain\n",
        [],
    )
    big = whois_lab.start(lambda query, index: b"a" * 70000)
    text, notes = whois.fetch_record(NAME, "127.0.0.1", big.port, 2)
    assert len(text) == 65536 and notes == ["The reply was truncated."]


def test_whois_fetch_decodes_with_replacement(whois_lab):
    server = whois_lab.start(lambda query, index: b"Registrar: Caf\xe9\n")
    text, notes = whois.fetch_record(NAME, "127.0.0.1", server.port, 2)
    assert text == "Registrar: Caf�\n" and notes == []


def test_whois_main_validation_messages(lab, capsys):
    both = "Timeout must be greater than 0, and the port must be 1 through 65535.\n"
    for argv in (
        ["x.example", "--timeout", "0"],
        ["x.example", "--port", "0"],
        ["x.example", "--port", "70000"],
    ):
        assert run(whois, argv, capsys) == (2, "", both)
    assert run(whois, ["10.0.0.1"], capsys) == (
        2,
        "",
        "Give a hostname, such as app.internal.\n",
    )
    assert run(whois, ["other.example"], capsys) == (
        2,
        "",
        explain_block("other.example") + "\n",
    )
    assert run(whois, [NAME, "--server", "whois.example"], capsys) == (
        2,
        "",
        "Pass a server address, such as 127.0.0.1.\n",
    )


def test_whois_main_does_not_swallow_policy_blocks(lab, monkeypatch):
    monkeypatch.setattr(
        socket, "create_connection", lambda *a, **k: pytest.fail("dialled")
    )
    with pytest.raises(egress.PolicyBlocked):
        whois.main([NAME, "--plain"])
    with pytest.raises(egress.PolicyBlocked):
        whois.main([NAME, "--server", "127.0.0.1", "--plain"])


def test_whois_main_os_errors_name_the_server_or_iana(whois_lab, capsys, monkeypatch):
    server = whois_lab.start(lambda query, index: b"")

    def refuse(*args, **kwargs):
        raise ConnectionRefusedError("nope")

    monkeypatch.setattr(socket, "create_connection", refuse)
    code, out, err = run(
        whois, [NAME, "--server", "127.0.0.1", "--port", str(server.port)], capsys
    )
    assert (code, out, err) == (
        1,
        "",
        "Could not query 127.0.0.1: ConnectionRefusedError\n",
    )
    whois_lab.grant(f"http://whois.iana.org:{server.port}", operations=("passive",))
    code, out, err = run(whois, [NAME, "--port", str(server.port)], capsys)
    assert (code, out, err) == (
        1,
        "",
        "Could not query whois.iana.org: ConnectionRefusedError\n",
    )


def test_whois_banner_goes_to_stderr_only_on_a_terminal_and_not_with_plain(
    whois_lab, capsys, monkeypatch
):
    server = whois_lab.start(lambda query, index: b"")
    args = [NAME, "--server", "127.0.0.1", "--port", str(server.port)]
    code, out, err = run(whois, args, capsys)
    assert (code, err) == (0, "no registrar record\n")
    tty_err = TtyBuffer()
    monkeypatch.setattr(sys, "stderr", tty_err)
    assert whois.main(args) == 0
    assert tty_err.getvalue().startswith(WHOIS_BANNER_PLAIN + "\n\n")
    assert tty_err.getvalue().endswith("no registrar record\n")
    again = TtyBuffer()
    monkeypatch.setattr(sys, "stderr", again)
    assert whois.main([*args, "--plain"]) == 0
    assert again.getvalue() == "no registrar record\n"


def test_whois_color_requires_a_terminal_term_and_no_no_color(whois_lab, monkeypatch):
    server = whois_lab.start(lambda query, index: b"Registrar: Hue\n")
    args = [NAME, "--server", "127.0.0.1", "--port", str(server.port)]
    monkeypatch.delenv("NO_COLOR")
    monkeypatch.setenv("TERM", "xterm")
    colored_out, colored_err = TtyBuffer(), TtyBuffer()
    monkeypatch.setattr(sys, "stdout", colored_out)
    monkeypatch.setattr(sys, "stderr", colored_err)
    whois.main(args)
    assert colored_out.getvalue() == (
        f"  {CYAN}domain      {RESET} {WHITE}allowed.example{RESET}\n"
        f"  {CYAN}registrar   {RESET} {WHITE}Hue{RESET}\n"
    )
    assert colored_err.getvalue().startswith(WHOIS_BANNER_COLOR + "\n\n")
    for blocked in ({"NO_COLOR": "1", "TERM": "xterm"}, {"TERM": "dumb"}, {"TERM": ""}):
        monkeypatch.delenv("NO_COLOR", raising=False)
        for key, value in blocked.items():
            monkeypatch.setenv(key, value)
        out = TtyBuffer()
        monkeypatch.setattr(sys, "stdout", out)
        whois.main(args)
        assert out.getvalue() == "domain\tallowed.example\nregistrar\tHue\n", blocked
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("TERM", "xterm")
    plain_out = TtyBuffer()
    monkeypatch.setattr(sys, "stdout", plain_out)
    whois.main([*args, "--plain"])
    assert plain_out.getvalue() == "domain\tallowed.example\nregistrar\tHue\n"


def test_whois_review_note_is_yellow_on_a_color_terminal(whois_lab, monkeypatch):
    when = datetime.now(timezone.utc) + timedelta(days=5)
    raw = f"Registrar: R\nExpires: {when.strftime('%Y-%m-%d %H:%M:%S')}\n".encode()
    server = whois_lab.start(lambda query, index: raw)
    monkeypatch.delenv("NO_COLOR")
    monkeypatch.setenv("TERM", "xterm")
    err = TtyBuffer()
    monkeypatch.setattr(sys, "stderr", err)
    whois.main([NAME, "--server", "127.0.0.1", "--port", str(server.port), "--plain"])
    shown = when.strftime("%Y-%m-%d %H:%M:%SZ")
    assert (
        err.getvalue() == f"{YELLOW}review: expires within 30 days ({shown}){RESET}\n"
    )


# ======================================================================================
# 9. cert - DER encoders (independent), parser, endpoint rules
# ======================================================================================


def der(tag, payload):
    size = len(payload)
    if size < 0x80:
        length = bytes([size])
    elif size < 0x100:
        length = b"\x81" + bytes([size])
    else:
        length = b"\x82" + size.to_bytes(2, "big")
    return bytes([tag]) + length + payload


def seq(*items):
    return der(0x30, b"".join(items))


def oid_bytes(dotted):
    arcs = [int(part) for part in dotted.split(".")]
    body = bytearray([arcs[0] * 40 + arcs[1]])
    for arc in arcs[2:]:
        chunk = [arc & 0x7F]
        arc >>= 7
        while arc:
            chunk.append(0x80 | (arc & 0x7F))
            arc >>= 7
        body.extend(reversed(chunk))
    return der(0x06, bytes(body))


def dn(*pairs):
    """pairs: (dotted oid, text, string tag)."""
    rdns = []
    for dotted, text, tag in pairs:
        codec = {0x1E: "utf-16-be", 0x1C: "utf-32-be"}.get(tag, "utf-8")
        rdns.append(der(0x31, seq(oid_bytes(dotted), der(tag, text.encode(codec)))))
    return seq(*rdns)


def san_extension(*general_names):
    return seq(oid_bytes("2.5.29.17"), der(0x04, seq(*general_names)))


def build_certificate(
    *,
    subject,
    issuer,
    not_before=b"261019224112Z",
    not_after=b"361016224112Z",
    extensions=None,
    version=True,
    nb_tag=0x17,
    na_tag=0x17,
):
    signature = seq(oid_bytes("1.2.840.10045.4.3.2"))
    parts = []
    if version:
        parts.append(der(0xA0, der(0x02, b"\x02")))
    parts += [
        der(0x02, b"\x01\x02"),
        signature,
        issuer,
        seq(der(nb_tag, not_before), der(na_tag, not_after)),
        subject,
        seq(seq(oid_bytes("1.2.840.10045.2.1")), der(0x03, b"\x00\x04abc")),
    ]
    if extensions is not None:
        parts.append(der(0xA3, seq(*extensions)))
    return seq(seq(*parts), signature, der(0x03, b"\x00sig"))


CN = "2.5.4.3"
ORG = "2.5.4.10"


def simple_name(common, org="Oracle Org", tag=0x0C):
    return dn((ORG, org, tag), (CN, common, tag))


def test_parse_certificate_subject_issuer_dates_and_names():
    blob = build_certificate(
        subject=dn(
            ("2.5.4.6", "US", 0x13),
            ("2.5.4.8", "Test State", 0x0C),
            ("2.5.4.7", "Test City", 0x0C),
            (ORG, "Oracle Org", 0x0C),
            ("2.5.4.11", "Unit", 0x0C),
            (CN, "host.allowed.example", 0x0C),
        ),
        issuer=simple_name("Oracle CA"),
        extensions=[
            san_extension(
                der(0x82, b"host.allowed.example"),
                der(0x82, b"*.allowed.example"),
                der(0x87, bytes([127, 0, 0, 1])),
                der(0x87, aaaa_data("2001:db8::1")),
            )
        ],
    )
    parsed = cert.parse_certificate(blob)
    assert isinstance(parsed, cert.Certificate)
    assert (
        parsed.subject
        == "C=US, ST=Test State, L=Test City, O=Oracle Org, OU=Unit, CN=host.allowed.example"
    )
    assert parsed.issuer == "O=Oracle Org, CN=Oracle CA"
    assert (parsed.not_before, parsed.not_after) == (
        "2026-10-19 22:41:12Z",
        "2036-10-16 22:41:12Z",
    )
    assert parsed.names == [
        "DNS:host.allowed.example",
        "DNS:*.allowed.example",
        "IP:127.0.0.1",
        "IP:2001:db8::1",
    ]


def test_parse_certificate_ignores_other_general_names_and_bad_ip_lengths():
    blob = build_certificate(
        subject=simple_name("s"),
        issuer=simple_name("i"),
        extensions=[
            san_extension(
                der(0x81, b"a@b.example"),
                der(0x86, b"http://u.example/"),
                der(0x87, b"\x01\x02\x03\x04\x05"),
                der(0x82, b"keep.example"),
                der(0xA4, b"directory"),
            )
        ],
    )
    assert cert.parse_certificate(blob).names == ["DNS:keep.example"]


def test_parse_certificate_without_extensions_or_version():
    blob = build_certificate(
        subject=simple_name("plain"), issuer=simple_name("plain-ca"), version=False
    )
    parsed = cert.parse_certificate(blob)
    assert (parsed.subject, parsed.issuer, parsed.names) == (
        "O=Oracle Org, CN=plain",
        "O=Oracle Org, CN=plain-ca",
        [],
    )


def test_parse_certificate_ignores_extensions_that_are_not_subject_alt_name():
    other = seq(oid_bytes("2.5.29.19"), der(0x04, seq(der(0x01, b"\xff"))))
    blob = build_certificate(
        subject=simple_name("s"),
        issuer=simple_name("i"),
        extensions=[other, san_extension(der(0x82, b"only.example"))],
    )
    assert cert.parse_certificate(blob).names == ["DNS:only.example"]


def test_parse_certificate_string_types_and_unknown_attribute_oids():
    subject = dn(
        ("2.5.4.5", "serial-1", 0x13),
        (CN, "bmp.example", 0x1E),
        (ORG, "uni", 0x1C),
        ("1.2.840.113549.1.9.1", "me@x.example", 0x16),
        ("2.5.4.99", "café", 0x0C),
    )
    parsed = cert.parse_certificate(build_certificate(subject=subject, issuer=dn()))
    assert parsed.subject == (
        "2.5.4.5=serial-1, CN=bmp.example, O=uni, "
        "1.2.840.113549.1.9.1=me@x.example, 2.5.4.99=café"
    )
    assert parsed.issuer == ""


@pytest.mark.parametrize(
    "not_before,nb_tag,expected",
    [
        (b"490101000000Z", 0x17, "2049-01-01 00:00:00Z"),
        (b"500101000000Z", 0x17, "1950-01-01 00:00:00Z"),
        (b"991231235959Z", 0x17, "1999-12-31 23:59:59Z"),
        (b"20491231235959Z", 0x18, "2049-12-31 23:59:59Z"),
        (b"2610192241Z", 0x17, "2610192241Z"),
        (b"odd", 0x17, "odd"),
    ],
)
def test_parse_certificate_time_forms(not_before, nb_tag, expected):
    blob = build_certificate(
        subject=simple_name("s"),
        issuer=simple_name("i"),
        not_before=not_before,
        nb_tag=nb_tag,
    )
    assert cert.parse_certificate(blob).not_before == expected


def test_parse_certificate_unparseable_digits_raise_value_error():
    blob = build_certificate(
        subject=simple_name("s"), issuer=simple_name("i"), not_before=b"xx1019224112Z"
    )
    with pytest.raises(ValueError):
        cert.parse_certificate(blob)


@pytest.mark.parametrize(
    "blob,message",
    [
        (b"", "certificate was truncated"),
        (b"\x30", "certificate was truncated"),
        (b"\x30\x05abc", "certificate was truncated"),
        (b"\x30\x84\x00\x00\x00\x01a", "certificate was truncated"),
        (b"\x30\x84\x00\x00\x00\x00", "certificate was truncated"),
        (b"\x30\x80", "certificate was truncated"),
        (b"\x30\x80abc", "certificate was truncated"),
        (b"\x30\x00", "not a certificate"),
        (seq(der(0x02, b"\x01")), "not a certificate"),
        (
            seq(
                seq(der(0x02, b"\x01"), seq(), seq(), seq(), seq()),
                seq(),
                der(0x03, b"\x00"),
            ),
            "certificate is missing the subject",
        ),
    ],
)
def test_parse_certificate_errors(blob, message):
    with pytest.raises(ValueError) as raised:
        cert.parse_certificate(blob)
    assert str(raised.value) == message


def test_parse_certificate_accepts_long_form_lengths():
    long_cn = "x" * 200
    blob = build_certificate(subject=simple_name(long_cn), issuer=simple_name("i"))
    assert cert.parse_certificate(blob).subject == f"O=Oracle Org, CN={long_cn}"


REAL_CERT_DER_B64 = (
    "MIIC3jCCAoSgAwIBAgIUAXAMWdqxPIh2+bLe8nDG6WckHcswCgYIKoZIzj0EAwIwgYgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApUZXN0IFN0"
    "YXRlMRIwEAYDVQQHDAlUZXN0IENpdHkxHDAaBgNVBAoME0J1Z2h1bnQgT3JhY2xlIExhYnMxETAPBgNVBAsMCEZpeHR1cmVzMR8wHQYDVQQD"
    "DBZvcmFjbGUuYWxsb3dlZC5leGFtcGxlMB4XDTI2MTAxOTIyNDExMloXDTM2MTAxNjIyNDExMlowgYgxCzAJBgNVBAYTAlVTMRMwEQYDVQQI"
    "DApUZXN0IFN0YXRlMRIwEAYDVQQHDAlUZXN0IENpdHkxHDAaBgNVBAoME0J1Z2h1bnQgT3JhY2xlIExhYnMxETAPBgNVBAsMCEZpeHR1cmVz"
    "MR8wHQYDVQQDDBZvcmFjbGUuYWxsb3dlZC5leGFtcGxlMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE20JmMvhRJ/3pts8wxMryje4xZLlX"
    "qSIWF4g++skQ1VAY09UKBOjtzGcmvJ6dzEgJu8jUP0/MrMx09RBlnh6BwqOByTCBxjAdBgNVHQ4EFgQU0kjPGs5FqCwGTsffqemU3TZELXkw"
    "HwYDVR0jBBgwFoAU0kjPGs5FqCwGTsffqemU3TZELXkwDwYDVR0TAQH/BAUwAwEB/zBzBgNVHREEbDBqghZvcmFjbGUuYWxsb3dlZC5leGFt"
    "cGxlghgqLm9yYWNsZS5hbGxvd2VkLmV4YW1wbGWHBH8AAAGHECABDbgAAAAAAAAAAAAAAAGBC2FAYi5leGFtcGxlhhFodHRwOi8vdS5leGFt"
    "cGxlLzAKBggqhkjOPQQDAgNIADBFAiA8yZ0faIQUL9ItY4DUS3aB7As72OSmSo1kOfZPK7fZDgIhAPS26NYogNOIaeh9Uai4CpxS8l/Cnat/"
    "nfrXCmc3ceMU"
)


def real_certificate_der():
    import base64

    return base64.b64decode(REAL_CERT_DER_B64)


def test_parse_certificate_reads_a_real_openssl_certificate():
    parsed = cert.parse_certificate(real_certificate_der())
    dn_text = "C=US, ST=Test State, L=Test City, O=Bughunt Oracle Labs, OU=Fixtures, CN=oracle.allowed.example"
    assert parsed == cert.Certificate(
        subject=dn_text,
        issuer=dn_text,
        not_before="2026-10-19 22:41:12Z",
        not_after="2036-10-16 22:41:12Z",
        names=[
            "DNS:oracle.allowed.example",
            "DNS:*.oracle.allowed.example",
            "IP:127.0.0.1",
            "IP:2001:db8::1",
        ],
    )


@pytest.mark.parametrize(
    "value,port_arg,expected",
    [
        ("example.com", 0, ("example.com", 443)),
        ("Example.COM.", 0, ("example.com", 443)),
        ("  host  ", 0, ("host", 443)),
        ("example.com:8443", 0, ("example.com", 8443)),
        ("example.com:8443", 9999, ("example.com", 9999)),
        ("127.0.0.1:443", 0, ("127.0.0.1", 443)),
        ("https://Example.com", 0, ("example.com", 443)),
        ("https://example.com:8443/x", 0, ("example.com", 8443)),
        ("https://example.com", 9000, ("example.com", 9000)),
        ("https://example.com:8443", 9000, ("example.com", 9000)),
        ("https://example.com:8443", 0, ("example.com", 8443)),
        ("https://HOST./", 0, ("host", 443)),
        ("https://u:p@host/", 0, ("host", 443)),
        ("https://[::1]:9443/", 0, ("::1", 9443)),
        ("https://[::1]/", 0, ("::1", 443)),
        ("http://example.com:8080", 0, ("example.com", 8080)),
        ("http://example.com", 8443, ("example.com", 8443)),
        ("http://example.com", 0, ("", None)),
        ("ftp://x", 0, ("", None)),
        ("https://", 0, ("", None)),
        ("[::1]", 0, ("::1", 443)),
        ("[::1]:8443", 0, ("::1", 8443)),
        ("[::1]:8443", 7, ("::1", 7)),
        ("::1", 0, ("::1", 443)),
        ("", 0, ("", 443)),
    ],
)
def test_cert_endpoint_parsing(value, port_arg, expected):
    assert cert._endpoint(value, port_arg) == expected


@pytest.mark.parametrize(
    "target",
    [
        "[::1]:0",
        "[::1]:abc",
        "[::1]:",
        "[::1]:-1",
        "[::1]junk",
        "https://[::1]:0",
        "https://[::1]:abc",
        "https://[::1]:",
        "allowed.example:0",
        "allowed.example:abc",
        "allowed.example:",
        "allowed.example:-1",
        "[::1",
        "::1]",
        "https://[::1]junk/",
    ],
)
def test_cert_invalid_destination_is_refused_before_read(target, monkeypatch, capsys):
    monkeypatch.setattr(cert, "allowed", lambda host: True)
    monkeypatch.setattr(
        cert, "_read", lambda *args: pytest.fail("invalid destination reached TLS")
    )
    assert cert.main([target]) == 2
    assert capsys.readouterr().err


@pytest.mark.parametrize(
    "target,override,expected",
    [
        ("[::1]:1", 0, 1),
        ("[::1]:65535", 0, 65535),
        ("[::1]:0", 8443, 8443),
        ("https://[::1]:99999", 8443, 8443),
        ("https://[::1]:abc", 8443, 8443),
    ],
)
def test_cert_positive_port_and_explicit_override(
    target, override, expected, monkeypatch
):
    monkeypatch.setattr(cert, "allowed", lambda host: True)
    parsed = cert.build_parser().parse_args([target, "--port", str(override)])
    assert cert._vet(parsed) == ("::1", expected)


# ======================================================================================
# 10. cert - main() with the handshake replaced at the socket/ssl edge
# ======================================================================================


class FakeTls:
    def __init__(self, blob):
        self.blob = blob

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def getpeercert(self, binary_form=False):
        return self.blob if binary_form else {}


class FakeRawSocket:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


@pytest.fixture
def tls_edge(monkeypatch):
    state = SimpleNamespace(
        blob=real_certificate_der(),
        dialled=[],
        wrapped=[],
        connect_error=None,
        wrap_error=None,
    )

    def create_connection(address, *args, **kwargs):
        timeout = kwargs.get("timeout", args[0] if args else None)
        state.dialled.append((address, timeout))
        if state.connect_error is not None:
            raise state.connect_error
        return FakeRawSocket()

    def wrap_socket(self, sock, *args, **kwargs):
        state.wrapped.append(
            SimpleNamespace(
                server_hostname=kwargs.get("server_hostname"),
                verify_mode=self.verify_mode,
                check_hostname=self.check_hostname,
            )
        )
        if state.wrap_error is not None:
            raise state.wrap_error
        return FakeTls(state.blob)

    monkeypatch.setattr(socket, "create_connection", create_connection)
    monkeypatch.setattr(ssl.SSLContext, "wrap_socket", wrap_socket)
    return state


def test_cert_main_prints_the_labelled_lines(lab, capsys, tls_edge):
    code, out, err = run(cert, [NAME], capsys)
    subject = "C=US, ST=Test State, L=Test City, O=Bughunt Oracle Labs, OU=Fixtures, CN=oracle.allowed.example"
    assert code == 0 and err == ""
    assert out == (
        f"subject: {subject}\nissuer: {subject}\nnot before: 2026-10-19 22:41:12Z\n"
        "not after: 2036-10-16 22:41:12Z\nsan: DNS:oracle.allowed.example\n"
        "san: DNS:*.oracle.allowed.example\nsan: IP:127.0.0.1\nsan: IP:2001:db8::1\n"
    )
    assert tls_edge.dialled == [((NAME, 443), 10.0)]


def test_cert_fetch_never_verifies_and_sends_sni_only_for_names(lab, tls_edge):
    cert.fetch_certificate(NAME, 443, 3)
    lab.grant("https://127.0.0.1:8443", operations=("manual",))
    cert.fetch_certificate("127.0.0.1", 8443, 4)
    first, second = tls_edge.wrapped
    assert first.server_hostname == NAME and second.server_hostname is None
    assert all(
        item.verify_mode == ssl.CERT_NONE and item.check_hostname is False
        for item in tls_edge.wrapped
    )
    assert tls_edge.dialled == [((NAME, 443), 3), (("127.0.0.1", 8443), 4)]


def test_cert_fetch_returns_the_peer_der_bytes_untouched(lab, tls_edge):
    assert cert.fetch_certificate(NAME, 443, 1) == real_certificate_der()


def test_cert_main_port_option_url_port_and_timeout_flow_to_the_dial(
    lab, capsys, tls_edge
):
    lab.grant("https://allowed.example:8443", operations=("manual",))
    run(cert, ["https://ALLOWED.example:8443/path", "--timeout", "2.5"], capsys)
    run(cert, [f"{NAME}:8443"], capsys)
    run(cert, [NAME, "--port", "8443"], capsys)
    assert tls_edge.dialled == [
        ((NAME, 8443), 2.5),
        ((NAME, 8443), 10.0),
        ((NAME, 8443), 10.0),
    ]


def test_cert_main_accepts_loopback_ipv6_literal(lab, capsys, tls_edge):
    lab.grant("https://[::1]", operations=("manual",))
    code, out, err = run(cert, ["[::1]"], capsys)
    assert code == 0 and tls_edge.dialled == [(("::1", 443), 10.0)]
    assert tls_edge.wrapped[0].server_hostname is None


def test_cert_main_accepts_the_whole_port_range_zero_through_65535(
    lab, capsys, tls_edge
):
    lab.grant("https://allowed.example:65535", operations=("manual",))
    code, _out, _err = run(cert, [NAME, "--port", "65535"], capsys)
    assert code == 0 and tls_edge.dialled == [((NAME, 65535), 10.0)]
    tls_edge.dialled.clear()
    code, _out, _err = run(cert, [NAME, "--port", "0"], capsys)
    assert code == 0 and tls_edge.dialled == [((NAME, 443), 10.0)]


@pytest.mark.parametrize(
    "argv",
    [
        [NAME, "--timeout", "0"],
        [NAME, "--timeout", "-3"],
        [NAME, "--port", "-1"],
        [NAME, "--port", "65536"],
    ],
)
def test_cert_main_rejects_bad_timeout_or_port(lab, capsys, argv):
    assert run(cert, argv, capsys) == (
        2,
        "",
        "Timeout must be greater than 0, and the port must be 0 through 65535.\n",
    )


@pytest.mark.parametrize(
    "value", ["http://allowed.example", "ftp://allowed.example", "https://", ""]
)
def test_cert_main_rejects_unusable_targets(lab, capsys, value):
    assert run(cert, [value], capsys) == (
        2,
        "",
        "Give a hostname or an https URL, such as 127.0.0.1 or https://127.0.0.1:8443.\n",
    )


def test_cert_main_refuses_out_of_scope_hosts_without_dialling(lab, capsys, tls_edge):
    code, out, err = run(cert, ["https://other.example:9443/x"], capsys)
    assert (code, out) == (2, "") and err == explain_block("other.example") + "\n"
    assert tls_edge.dialled == []


@pytest.mark.parametrize(
    "error,text",
    [
        (TimeoutError("slow"), "Could not connect to {host}:443: timed out."),
        (
            ConnectionRefusedError("no"),
            "Could not connect to {host}:443: ConnectionRefusedError",
        ),
        (socket.gaierror("dns"), "Could not connect to {host}:443: gaierror"),
    ],
)
def test_cert_main_connection_errors(lab, capsys, tls_edge, error, text):
    tls_edge.connect_error = error
    code, out, err = run(cert, [NAME], capsys)
    assert (code, out, err) == (1, "", text.format(host=NAME) + "\n")


def test_cert_main_handshake_errors_use_the_class_name(lab, capsys, tls_edge):
    tls_edge.wrap_error = ssl.SSLError("bad hello")
    assert run(cert, [NAME], capsys) == (
        1,
        "",
        f"Could not connect to {NAME}:443: SSLError\n",
    )


@pytest.mark.parametrize(
    "blob,message",
    [
        (None, "the server presented no certificate"),
        (b"", "the server presented no certificate"),
        (b"\x01\x02", "certificate was truncated"),
        (seq(), "not a certificate"),
    ],
)
def test_cert_main_certificate_problems(lab, capsys, tls_edge, blob, message):
    tls_edge.blob = blob
    assert run(cert, [NAME], capsys) == (
        1,
        "",
        f"Could not read the certificate: {message}\n",
    )


def test_cert_main_policy_block_is_reported_like_a_value_error(lab, capsys, tls_edge):
    (lab.root / "policy.json").unlink()
    assert run(cert, [NAME], capsys) == (
        1,
        "",
        "Could not read the certificate: policy-missing-or-invalid; no outbound action ran\n",
    )
    assert tls_edge.dialled == []


def test_cert_main_prints_only_the_subject_block_when_there_are_no_names(
    lab, capsys, tls_edge
):
    tls_edge.blob = build_certificate(
        subject=simple_name("solo"), issuer=simple_name("ca")
    )
    assert run(cert, [NAME], capsys) == (
        0,
        "subject: O=Oracle Org, CN=solo\nissuer: O=Oracle Org, CN=ca\n"
        "not before: 2026-10-19 22:41:12Z\nnot after: 2036-10-16 22:41:12Z\n",
        "",
    )


# ======================================================================================
# 11. vhost - helpers
# ======================================================================================


@pytest.mark.parametrize(
    "value,expected",
    [
        ("127.0.0.1:8080", "http://127.0.0.1:8080/"),
        ("http://127.0.0.1:8080/", "http://127.0.0.1:8080/"),
        ("HTTPS://Example.COM.:443/a/b?c=d#frag", "https://example.com/a/b?c=d"),
        ("https://example.com:8443", "https://example.com:8443/"),
        ("http://example.com:80/", "http://example.com/"),
        ("https://example.com:80/", "https://example.com:80/"),
        ("http://[::1]:8080/x", "http://[::1]:8080/x"),
        ("https://[2001:DB8::1]/", "https://[2001:db8::1]/"),
        ("example.com", "http://example.com/"),
        ("  example.com/path  ", "http://example.com/path"),
        ("http://u:p@example.com/", "http://example.com/"),
        ("http://example.com?q=1", "http://example.com/?q=1"),
        ("ftp://x.example", None),
        ("http://", None),
        ("", None),
    ],
)
def test_vhost_canonical_target(value, expected):
    assert vhost.canonical_target(value) == expected


@pytest.mark.parametrize(
    "name,port,scheme,expected",
    [
        ("a.example", 8080, "http", "a.example:8080"),
        ("a.example.", 80, "http", "a.example"),
        ("a.example", 443, "https", "a.example"),
        ("a.example", 80, "https", "a.example:80"),
        ("a.example", None, "http", "a.example"),
        ("a.example", 0, "http", "a.example"),
        ("a.example:99", 8080, "http", "a.example:99"),
        (" a.example ", 8080, "http", "a.example:8080"),
    ],
)
def test_vhost_host_header(name, port, scheme, expected):
    assert vhost.host_header(name, port, scheme) == expected


@pytest.mark.parametrize(
    "text,expected",
    [
        ("<title>Hi</title>", "Hi"),
        ("<TITLE lang=x>  A \n\t B  </TITLE>", "A B"),
        ("<title></title>", ""),
        ("no title", ""),
        ("<title>one</title><title>two</title>", "one"),
        ("<title>a\tb</title>", "a b"),
        ("<title>a&amp;b</title>", "a&amp;b"),
        ("<title>" + "x" * 100 + "</title>", "x" * 80),
        ("<title>" + " " * 10 + "y" * 100 + "</title>", "y" * 80),
    ],
)
def test_vhost_page_title(text, expected):
    assert vhost.page_title(text) == expected


def test_vhost_collect_names_dedupes_case_insensitively_keeping_the_first_spelling(lab):
    assert vhost.collect_names(["a.example", "A.EXAMPLE.", "b.example"], None) == [
        "a.example",
        "b.example",
    ]
    assert vhost.collect_names(["B.Example.", " c.example "], None) == [
        "B.Example",
        "c.example",
    ]


def test_vhost_collect_names_reads_a_file_with_comments_and_blank_lines(lab, tmp_path):
    path = tmp_path / "names.txt"
    path.write_text(
        "alpha.example\n# comment\n  beta.example  # trailing\n\nALPHA.example.\ngamma.example\n",
        encoding="utf-8",
    )
    assert vhost.collect_names([], str(path)) == [
        "alpha.example",
        "beta.example",
        "gamma.example",
    ]
    assert vhost.collect_names(["zeta.example", "beta.example"], str(path)) == [
        "zeta.example",
        "beta.example",
        "alpha.example",
        "gamma.example",
    ]


def test_vhost_collect_names_missing_file_raises_os_error(lab, tmp_path):
    with pytest.raises(OSError):
        vhost.collect_names([], str(tmp_path / "missing.txt"))


def test_vhost_collect_names_falls_back_to_plain_scope_hostnames(lab):
    assert vhost.collect_names([], None) == [NAME]
    lab.set_scope(
        "# c",
        "example.com",
        "*.wild.example",
        "10.0.0.0/24",
        "10.0.0.5",
        "host.example",
        "::1",
        "sub.example.org",
    )
    assert vhost.collect_names([], None) == [
        "example.com",
        "host.example",
        "sub.example.org",
    ]
    assert vhost.collect_names(["given.example"], None) == ["given.example"]
    (lab.root / "scope.txt").unlink()
    assert vhost.collect_names([], None) == []


def test_vhost_fetch_one_sends_the_host_header_and_reports_status_size_title():
    seen = []

    def respond(request):
        seen.append((str(request.url), request.headers["host"], request.method))
        return httpx.Response(404, content=b"<html><title> Not   Here </title></html>")

    with httpx.Client(transport=httpx.MockTransport(respond)) as client:
        assert vhost.fetch_one(
            client, "http://127.0.0.1:8080/x?y=1", "named.example:8080"
        ) == (404, len(b"<html><title> Not   Here </title></html>"), "Not Here")
    assert seen == [("http://127.0.0.1:8080/x?y=1", "named.example:8080", "GET")]


def test_vhost_fetch_one_caps_the_body_it_measures_at_one_million_bytes():
    body = b"<title>big</title>" + b"z" * 1_500_000
    with httpx.Client(
        transport=httpx.MockTransport(lambda request: httpx.Response(200, content=body))
    ) as client:
        status, size, title = vhost.fetch_one(client, "http://127.0.0.1/", "h")
    assert (status, size, title) == (200, 1_000_000, "big")


def test_vhost_fetch_one_decodes_the_title_with_replacement():
    body = b"<title>caf\xe9</title>"
    with httpx.Client(
        transport=httpx.MockTransport(lambda request: httpx.Response(200, content=body))
    ) as client:
        assert vhost.fetch_one(client, "http://127.0.0.1/", "h")[2] == "caf�"


def test_vhost_fetch_one_lets_transport_errors_through():
    def explode(request):
        raise httpx.ConnectError("boom")

    with httpx.Client(transport=httpx.MockTransport(explode)) as client:
        with pytest.raises(httpx.ConnectError):
            vhost.fetch_one(client, "http://127.0.0.1/", "h")


# ======================================================================================
# 12. vhost - main() against a loopback http.server
# ======================================================================================


class FakeSite:
    """Loopback HTTP server that answers by Host header and records what it saw."""

    def __init__(self, pages):
        self.pages = pages
        self.seen = []
        site = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                host = self.headers.get("Host", "")
                site.seen.append(
                    {
                        "host": host,
                        "cookie": self.headers.get("Cookie"),
                        "authorization": self.headers.get("Authorization"),
                        "path": self.path,
                    }
                )
                status, body = site.pages.get(host, (404, b"<title>default</title>"))
                self.send_response(status)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        self._thread = threading.Thread(
            target=self.server.serve_forever,
            kwargs={"poll_interval": 0.05},
            daemon=True,
        )
        self._thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self._thread.join(2)


@pytest.fixture
def site_lab(lab):
    sites = []

    def start(pages):
        site = FakeSite(pages)
        sites.append(site)
        lab.grant(f"http://127.0.0.1:{site.port}", operations=("manual",))
        return site

    lab.start = start
    yield lab
    for site in sites:
        site.close()


def test_vhost_main_requests_the_address_once_per_host_name_baseline_first(
    site_lab, capsys
):
    port = None
    site = site_lab.start({})
    port = site.port
    pages = {
        f"127.0.0.1:{port}": (200, b"<title>base</title>"),
        f"alpha.allowed.example:{port}": (200, b"<title>Alpha  Site</title>12345"),
        f"beta.allowed.example:{port}": (403, b""),
    }
    site.pages.update(pages)
    site_lab.grant(f"http://alpha.allowed.example:{port}")
    site_lab.grant(f"http://beta.allowed.example:{port}")
    code, out, err = run(
        vhost,
        [
            f"http://127.0.0.1:{port}/start",
            "alpha.allowed.example",
            "beta.allowed.example",
        ],
        capsys,
    )
    assert code == 0 and err == ""
    assert out == (
        "host\tstatus\tbytes\ttitle\n"
        f"127.0.0.1:{port}\t200\t{len(b'<title>base</title>')}\tbase\n"
        f"alpha.allowed.example:{port}\t200\t{len(b'<title>Alpha  Site</title>12345')}\tAlpha Site\n"
        f"beta.allowed.example:{port}\t403\t0\t\n"
    )
    assert [row["host"] for row in site.seen] == [
        f"127.0.0.1:{port}",
        f"alpha.allowed.example:{port}",
        f"beta.allowed.example:{port}",
    ]
    assert {row["path"] for row in site.seen} == {"/start"}


def test_vhost_main_uses_scope_hostnames_when_no_names_are_given(site_lab, capsys):
    site = site_lab.start({})
    site_lab.set_scope(NAME, "www.allowed.example", "*.skip.example", "10.1.1.1")
    site_lab.grant(f"http://{NAME}:{site.port}")
    site_lab.grant(f"http://www.allowed.example:{site.port}")
    code, out, err = run(vhost, [f"http://127.0.0.1:{site.port}/"], capsys)
    assert code == 0 and err == ""
    assert [row["host"] for row in site.seen] == [
        f"127.0.0.1:{site.port}",
        f"{NAME}:{site.port}",
        f"www.allowed.example:{site.port}",
    ]


def test_vhost_main_names_file_and_dedupe_against_the_baseline(
    site_lab, capsys, tmp_path
):
    site = site_lab.start({})
    names = tmp_path / "n.txt"
    names.write_text("alpha.allowed.example\n127.0.0.1\n# nope\n", encoding="utf-8")
    site_lab.grant(f"http://alpha.allowed.example:{site.port}")
    code, out, err = run(
        vhost, [f"http://127.0.0.1:{site.port}/", "--names", str(names)], capsys
    )
    assert code == 0
    assert [row["host"] for row in site.seen] == [
        f"127.0.0.1:{site.port}",
        f"alpha.allowed.example:{site.port}",
    ]


def test_vhost_main_limit_stops_after_that_many_names(site_lab, capsys):
    site = site_lab.start({})
    for label in ("a1", "a2", "a3"):
        site_lab.grant(f"http://{label}.allowed.example:{site.port}")
    code, out, err = run(
        vhost,
        [
            f"http://127.0.0.1:{site.port}/",
            "a1.allowed.example",
            "a2.allowed.example",
            "a3.allowed.example",
            "--limit",
            "2",
        ],
        capsys,
    )
    assert code == 0 and err == "Stopped after 2 names.\n"
    assert len(site.seen) == 2 and len(out.splitlines()) == 3
    code, out, err = run(
        vhost,
        [f"http://127.0.0.1:{site.port}/", "a1.allowed.example", "--limit", "2"],
        capsys,
    )
    assert err == ""


def test_vhost_main_skips_names_outside_scope_and_says_how_many(site_lab, capsys):
    site = site_lab.start({})
    site_lab.grant(f"http://good.allowed.example:{site.port}")
    code, out, err = run(
        vhost,
        [
            f"http://127.0.0.1:{site.port}/",
            "good.allowed.example",
            "bad.example",
            "worse.example",
        ],
        capsys,
    )
    assert code == 0 and err == "2 name(s) outside scope\n"
    assert [row["host"] for row in site.seen] == [
        f"127.0.0.1:{site.port}",
        f"good.allowed.example:{site.port}",
    ]
    assert "bad.example" not in out


def test_vhost_main_host_without_a_policy_grant_becomes_an_error_row(site_lab, capsys):
    site = site_lab.start({})
    site_lab.grant(f"http://granted.allowed.example:{site.port}")
    code, out, err = run(
        vhost,
        [
            f"http://127.0.0.1:{site.port}/",
            "granted.allowed.example",
            "ungranted.allowed.example",
        ],
        capsys,
    )
    lines = out.splitlines()
    assert code == 0 and err == ""
    assert lines[3] == f"ungranted.allowed.example:{site.port}\terror\t0\tPolicyBlocked"
    assert [row["host"] for row in site.seen] == [
        f"127.0.0.1:{site.port}",
        f"granted.allowed.example:{site.port}",
    ]


def test_vhost_main_every_request_failing_is_exit_one(site_lab, capsys):
    (site_lab.root / "policy.json").unlink()
    code, out, err = run(vhost, ["http://127.0.0.1:9/", "x.allowed.example"], capsys)
    assert code == 1 and err == ""
    assert out == (
        "host\tstatus\tbytes\ttitle\n127.0.0.1:9\terror\t0\tPolicyBlocked\n"
        "x.allowed.example:9\terror\t0\tPolicyBlocked\n"
    )


def test_vhost_main_transport_failure_rows_use_the_exception_class(site_lab, capsys):
    hangup = socket.socket()
    hangup.bind(("127.0.0.1", 0))
    hangup.listen(4)
    hangup.settimeout(0.05)
    stop = threading.Event()

    def answer_with_garbage():
        while not stop.is_set():
            try:
                connection, _ = hangup.accept()
            except (socket.timeout, OSError):
                continue
            with connection:
                connection.settimeout(1)
                try:
                    connection.recv(4096)
                    connection.sendall(b"this is not http\r\n\r\n")
                except OSError:
                    pass

    worker = threading.Thread(target=answer_with_garbage, daemon=True)
    worker.start()
    port = hangup.getsockname()[1]
    try:
        site_lab.grant(f"http://127.0.0.1:{port}")
        site_lab.set_scope("10.0.0.0/8")
        code, out, err = run(
            vhost, [f"http://127.0.0.1:{port}/", "--timeout", "2", "x.invalid"], capsys
        )
    finally:
        stop.set()
        worker.join(2)
        hangup.close()
    assert code == 1
    assert (
        out
        == f"host\tstatus\tbytes\ttitle\n127.0.0.1:{port}\terror\t0\tRemoteProtocolError\n"
    )
    assert err == "1 name(s) outside scope\n"


def test_vhost_main_without_a_scope_file_requests_every_listed_name(site_lab, capsys):
    site = site_lab.start({})
    site_lab.grant(f"http://anything.example:{site.port}")
    (site_lab.root / "scope.txt").unlink()
    code, out, err = run(
        vhost, [f"http://127.0.0.1:{site.port}/", "anything.example"], capsys
    )
    assert code == 0 and err == ""
    assert [row["host"] for row in site.seen] == [
        f"127.0.0.1:{site.port}",
        f"anything.example:{site.port}",
    ]


def test_vhost_main_hands_timeout_tls_and_credentials_to_the_shared_client(
    site_lab, capsys, monkeypatch
):
    built = []
    real = egress.client

    def spy(**kwargs):
        built.append(kwargs)
        return real(
            transport=httpx.MockTransport(
                lambda request: httpx.Response(200, content=b"<title>t</title>")
            ),
            **kwargs,
        )

    monkeypatch.setattr(egress, "client", spy)
    site_lab.grant("http://127.0.0.1:8080")
    site_lab.grant("http://x.allowed.example:8080")
    code, out, err = run(
        vhost,
        [
            "http://127.0.0.1:8080/",
            "x.allowed.example",
            "--timeout",
            "3.5",
            "--insecure",
            "--cookie",
            "k=v",
            "--authorization",
            "Bearer z",
        ],
        capsys,
    )
    assert code == 0 and out.count("\t200\t") == 2
    assert len(built) == 1 and built[0]["operation"] == "manual"
    assert built[0]["timeout"] == 3.5 and built[0]["verify"] is False
    assert built[0]["follow_redirects"] is False and built[0]["trust_env"] is False
    assert (
        built[0]["headers"]["Cookie"] == "k=v"
        and built[0]["headers"]["Authorization"] == "Bearer z"
    )
    run(vhost, ["http://127.0.0.1:8080/", "x.allowed.example"], capsys)
    assert built[1]["verify"] is True and "Cookie" not in built[1]["headers"]


def test_vhost_main_sends_cookie_and_authorization_options(site_lab, capsys):
    site = site_lab.start({})
    run(
        vhost,
        [
            f"http://127.0.0.1:{site.port}/",
            "--cookie",
            "k=v",
            "--authorization",
            "Bearer tok",
        ],
        capsys,
    )
    assert (
        site.seen[0]["cookie"] == "k=v"
        and site.seen[0]["authorization"] == "Bearer tok"
    )


def test_vhost_main_validation_messages(site_lab, capsys, tmp_path):
    assert run(vhost, ["http://127.0.0.1:1/", "--limit", "0"], capsys) == (
        2,
        "",
        "Limit and timeout must be greater than 0.\n",
    )
    assert run(vhost, ["http://127.0.0.1:1/", "--timeout", "0"], capsys) == (
        2,
        "",
        "Limit and timeout must be greater than 0.\n",
    )
    assert run(vhost, ["ftp://127.0.0.1/"], capsys) == (
        2,
        "",
        "Give an http or https URL, such as http://127.0.0.1:8080/.\n",
    )
    assert run(vhost, ["https://elsewhere.example/"], capsys) == (
        2,
        "",
        explain_block("elsewhere.example") + "\n",
    )
    code, out, err = run(
        vhost, ["http://127.0.0.1:1/", "--names", str(tmp_path / "gone.txt")], capsys
    )
    assert code == 1 and out == "" and err.startswith("Could not read names: ")
    site_lab.set_scope("# nothing\n10.0.0.0/8")
    assert run(vhost, ["http://127.0.0.1:1/"], capsys) == (
        2,
        "",
        "Pass host names, or add hostnames with bughunt scope add.\n",
    )


def test_vhost_main_urls_without_a_scheme_default_to_http(site_lab, capsys):
    site = site_lab.start({})
    code, out, err = run(vhost, [f"127.0.0.1:{site.port}"], capsys)
    assert code == 0 and site.seen[0]["host"] == f"127.0.0.1:{site.port}"


# ======================================================================================
# 13. mail - pure rules
# ======================================================================================


@pytest.mark.parametrize(
    "args,expected",
    [
        (
            ([], "", "", [], []),
            [
                "review: no MX",
                "review: no SPF",
                "review: no DMARC",
                "review: no DKIM selector was given",
            ],
        ),
        (
            (
                ["10 mx"],
                "v=spf1 -all",
                "v=DMARC1; p=reject",
                ["s1"],
                [("s1", "key present")],
            ),
            [],
        ),
        (
            (["10 mx"], "v=spf1 ~all", "v=DMARC1; p=none", ["s1"], [("s1", "")]),
            ["review: DMARC policy is none", "review: no DKIM record for s1"],
        ),
        (
            (["10 mx"], "v=spf1 +all", "v=DMARC1; p=quarantine", [], []),
            [
                "review: SPF allows any sender (+all)",
                "review: no DKIM selector was given",
            ],
        ),
        (
            (["10 mx"], "v=spf1 include:a", "v=DMARC1", [], []),
            [
                "review: SPF does not use -all or ~all",
                "review: DMARC policy is none",
                "review: no DKIM selector was given",
            ],
        ),
        (
            (
                ["10 mx"],
                "v=spf1 ?all",
                "v=DMARC1; p=reject",
                ["a", "b"],
                [("a", "x"), ("b", "")],
            ),
            ["review: SPF does not use -all or ~all", "review: no DKIM record for b"],
        ),
        (
            ([], "v=spf1 all", "v=DMARC1; sp=none; p = NONE ", [], []),
            [
                "review: no MX",
                "review: SPF allows any sender (+all)",
                "review: DMARC policy is none",
                "review: no DKIM selector was given",
            ],
        ),
        (
            ([], "v=spf1 -all +all", "p=reject", [], []),
            [
                "review: no MX",
                "review: SPF allows any sender (+all)",
                "review: no DKIM selector was given",
            ],
        ),
        (
            ([], "v=spf1 -ALL;", "v=DMARC1; p=Reject", [], []),
            ["review: no MX", "review: no DKIM selector was given"],
        ),
        (
            (
                [],
                "v=spf1 a:all.example -all",
                "v=DMARC1; p=reject",
                ["x"],
                [("x", "k")],
            ),
            ["review: no MX"],
        ),
        (
            (
                ["10 mx"],
                "v=spf1 allowlist.example",
                "v=DMARC1; p=reject",
                ["x"],
                [("x", "k")],
            ),
            ["review: SPF does not use -all or ~all"],
        ),
    ],
)
def test_mail_review_notes(args, expected):
    assert mail.review_notes(*args) == expected


def test_mail_review_notes_order_mx_spf_dmarc_dkim():
    notes = mail.review_notes(
        [], "v=spf1 +all", "v=DMARC1; p=none", ["s1", "s2"], [("s1", ""), ("s2", "")]
    )
    assert notes == [
        "review: no MX",
        "review: SPF allows any sender (+all)",
        "review: DMARC policy is none",
        "review: no DKIM record for s1",
        "review: no DKIM record for s2",
    ]


# ======================================================================================
# 14. mail - main() against the loopback resolver
# ======================================================================================

DMARC = "_dmarc.allowed.example"
S1 = "s1._domainkey.allowed.example"
S2 = "s2._domainkey.allowed.example"


def txt(*texts):
    def chunks(text):
        raw = text.encode()
        return [raw[start : start + 255] for start in range(0, len(raw), 255)] or [b""]

    return Reply(answers=[(16, txt_data(*chunks(text))) for text in texts])


def good_mail_zone(resolver):
    resolver.on(NAME, 15, Reply(answers=[(15, mx_data(10, "mail.allowed.example"))]))
    resolver.on(
        NAME,
        16,
        txt(
            "unrelated",
            "v=spf2.0/pra mx -all",
            "v=spf1 include:_spf.allowed.example -all",
        ),
    )
    resolver.on(
        DMARC,
        16,
        txt("v=DMARC2; p=none", "v=DMARC1; p=reject; rua=mailto:d@allowed.example"),
    )
    resolver.on(S1, 16, txt("v=DKIM2; p=", "v=DKIM1; k=rsa; p=MIGfMA0GCSq"))


def test_mail_main_prints_mx_spf_dmarc_and_dkim_rows(dns_lab, capsys):
    good_mail_zone(dns_lab.resolver)
    code, out, err = run(
        mail, [NAME, *resolver_args(dns_lab, "--selector", "S1", "--plain")], capsys
    )
    assert code == 0 and err == ""
    assert out == (
        "MX\t10 mail.allowed.example\nSPF\tv=spf1 include:_spf.allowed.example -all\n"
        "DMARC\tv=DMARC1; p=reject; rua=mailto:d@allowed.example\nDKIM\ts1\tkey present\n"
    )
    asked = {(row[0], row[1]) for row in dns_lab.resolver.seen}
    assert (DMARC, 16) in asked and (S1, 16) in asked and (NAME, 1) in asked
    assert all(row[0] in {NAME, DMARC, S1} for row in dns_lab.resolver.seen)


def test_mail_main_with_nothing_published_only_reviews(dns_lab, capsys):
    code, out, err = run(mail, [NAME, *resolver_args(dns_lab)], capsys)
    assert code == 0 and out == ""
    assert (
        err
        == "review: no MX\nreview: no SPF\nreview: no DMARC\nreview: no DKIM selector was given\n"
    )


def test_mail_main_dkim_rows_for_revoked_missing_and_multiple_selectors(
    dns_lab, capsys
):
    good_mail_zone(dns_lab.resolver)
    dns_lab.resolver.on(S1, 16, txt("v=DKIM1; k=rsa; p="))
    code, out, err = run(
        mail,
        [NAME, *resolver_args(dns_lab, "--selector", "s1", "--selector", "s2")],
        capsys,
    )
    assert code == 0
    assert out.splitlines()[-1] == "DKIM\ts1\tv=DKIM1; k=rsa; p="
    assert err == "review: no DKIM record for s2\n"
    assert out.count("DKIM\t") == 1


def test_mail_main_dmarc_policy_none_and_loose_spf_notes(dns_lab, capsys):
    dns_lab.resolver.on(
        NAME, 15, Reply(answers=[(15, mx_data(10, "mail.allowed.example"))])
    )
    dns_lab.resolver.on(NAME, 16, txt("v=spf1 +all"))
    dns_lab.resolver.on(DMARC, 16, txt("V=dmarc1; P=None"))
    code, out, err = run(
        mail, [NAME, *resolver_args(dns_lab, "--selector", "s1")], capsys
    )
    assert code == 0
    assert err == (
        "review: SPF allows any sender (+all)\nreview: DMARC policy is none\n"
        "review: no DKIM record for s1\n"
    )
    assert "DMARC\tV=dmarc1; P=None" in out.splitlines()


def test_mail_main_clips_long_values_at_300_characters_with_an_ellipsis(
    dns_lab, capsys
):
    dns_lab.resolver.on(
        NAME, 16, txt("v=spf1 " + " ".join(["include:x.example"] * 40) + " -all")
    )
    code, out, err = run(mail, [NAME, *resolver_args(dns_lab)], capsys)
    spf_line = [line for line in out.splitlines() if line.startswith("SPF\t")][0]
    value = spf_line.split("\t", 1)[1]
    assert len(value) == 300 and value.endswith("…")


def test_mail_main_collapses_whitespace_runs_in_printed_values(dns_lab, capsys):
    dns_lab.resolver.on(NAME, 16, txt("v=spf1   include:a.example\t -all  "))
    code, out, err = run(mail, [NAME, *resolver_args(dns_lab)], capsys)
    assert "SPF\tv=spf1 include:a.example -all\n" in out


def test_mail_main_keeps_only_truncation_notes_from_the_lookups(dns_lab, capsys):
    dns_lab.resolver.on(
        NAME, 15, Reply(tc=True, answers=[(15, mx_data(10, "m.allowed.example"))])
    )
    dns_lab.resolver.on(NAME, 5, Reply(answers=[(5, wire_name("elsewhere.example"))]))
    dns_lab.resolver.on(NAME, 16, txt("v=spf1 -all"))
    dns_lab.resolver.on(DMARC, 16, txt("v=DMARC1; p=reject"))
    code, out, err = run(
        mail, [NAME, *resolver_args(dns_lab, "--selector", "s1")], capsys
    )
    assert err == "The answer was truncated.\nreview: no DKIM record for s1\n"


def test_mail_main_reports_failed_secondary_lookups_after_the_notes(dns_lab, capsys):
    good_mail_zone(dns_lab.resolver)
    dns_lab.resolver.on(DMARC, 16, Reply(rcode=2))
    dns_lab.resolver.on(S1, 16, Reply(rcode=2))
    code, out, err = run(
        mail,
        [NAME, *resolver_args(dns_lab, "--selector", "s1", "--selector", "s2")],
        capsys,
    )
    assert code == 0
    assert "DMARC\t" not in out and "DKIM\t" not in out
    assert err == (
        "review: no DMARC\nreview: no DKIM record for s2\n"
        "DMARC lookup failed.\nDKIM lookup failed for s1.\n"
    )


def test_mail_main_secondary_timeouts_count_as_failed_lookups(dns_lab, capsys):
    good_mail_zone(dns_lab.resolver)
    dns_lab.resolver.on(DMARC, 16, Reply(drop=True))
    code, out, err = run(
        mail,
        [
            NAME,
            "--resolver",
            "127.0.0.1",
            "--port",
            str(dns_lab.resolver.port),
            "--timeout",
            "0.2",
        ],
        capsys,
    )
    assert code == 0
    assert (
        err
        == "review: no DMARC\nreview: no DKIM selector was given\nDMARC lookup failed.\n"
    )


def test_mail_main_total_lookup_failure_is_exit_one(dns_lab, capsys):
    for rtype in (1, 28, 5, 15, 16, 2):
        dns_lab.resolver.on(NAME, rtype, Reply(rcode=2))
    assert run(mail, [NAME, *resolver_args(dns_lab)], capsys) == (
        1,
        "",
        f"{NAME} lookup failed.\n",
    )
    dns_lab.resolver.on(NAME, 16, txt("v=spf1 -all"))
    code, out, err = run(mail, [NAME, *resolver_args(dns_lab)], capsys)
    assert code == 0 and out.startswith("SPF\tv=spf1 -all\n")


def test_mail_main_primary_errors_print_the_class_name(dns_lab, capsys):
    dns_lab.resolver.on(NAME, 1, Reply(drop=True))
    code, out, err = run(
        mail,
        [
            NAME,
            "--resolver",
            "127.0.0.1",
            "--port",
            str(dns_lab.resolver.port),
            "--timeout",
            "0.2",
        ],
        capsys,
    )
    assert (code, out, err) == (1, "", f"Could not look up {NAME}: TimeoutError\n")
    dns_lab.resolver.on(NAME, 1, Reply(ident_xor=3))
    assert run(mail, [NAME, *resolver_args(dns_lab)], capsys) == (
        1,
        "",
        f"Could not look up {NAME}: ValueError\n",
    )


def test_mail_main_policy_block_is_reported_by_class_name(lab, capsys):
    (lab.root / "policy.json").unlink()
    assert run(mail, [NAME, "--resolver", "127.0.0.1"], capsys) == (
        1,
        "",
        f"Could not look up {NAME}: PolicyBlocked\n",
    )


def test_mail_main_validation_order_and_messages(lab, capsys, resolv_conf):
    bad = "Timeout must be greater than 0, and the port must be 1 through 65535.\n"
    assert run(mail, ["10.0.0.1", "--timeout", "0"], capsys) == (2, "", bad)
    assert run(mail, ["10.0.0.1", "--selector", "a.b"], capsys) == (
        2,
        "",
        "Give a hostname, such as app.internal.\n",
    )
    for selector in ("a.b", "-a", "a-", "", "_x", "a" * 64, "x y"):
        assert run(mail, [NAME, f"--selector={selector}"], capsys) == (
            2,
            "",
            "A selector is one label, such as s1.\n",
        ), selector
    assert run(mail, ["other.example", "--selector", "a.b"], capsys) == (
        2,
        "",
        "A selector is one label, such as s1.\n",
    )
    assert run(mail, ["other.example", "--resolver", "x"], capsys) == (
        2,
        "",
        explain_block("other.example") + "\n",
    )
    assert run(mail, [NAME, "--resolver", "x"], capsys) == (
        2,
        "",
        "Pass a resolver address, such as 127.0.0.1.\n",
    )
    resolv_conf.write("")
    assert run(mail, [NAME], capsys) == (
        1,
        "",
        "No resolver is set. Pass --resolver with an address.\n",
    )


def test_mail_banner_only_on_a_terminal_and_never_with_plain(dns_lab, monkeypatch):
    args = [NAME, *resolver_args(dns_lab)]
    tty_err = TtyBuffer()
    monkeypatch.setattr(sys, "stderr", tty_err)
    mail.main(args)
    assert tty_err.getvalue().startswith(MAIL_BANNER_PLAIN + "\n\n")
    quiet = TtyBuffer()
    monkeypatch.setattr(sys, "stderr", quiet)
    mail.main([*args, "--plain"])
    assert not quiet.getvalue().startswith(MAIL_BANNER_PLAIN)


def test_mail_color_rows_on_a_color_terminal(dns_lab, monkeypatch):
    good_mail_zone(dns_lab.resolver)
    monkeypatch.delenv("NO_COLOR")
    monkeypatch.setenv("TERM", "xterm")
    out = TtyBuffer()
    monkeypatch.setattr(sys, "stdout", out)
    monkeypatch.setattr(sys, "stderr", TtyBuffer())
    mail.main([NAME, *resolver_args(dns_lab)])
    assert (
        out.getvalue().splitlines()[0]
        == f"  {CYAN}MX          {RESET} {WHITE}10 mail.allowed.example{RESET}"
    )
    plain = TtyBuffer()
    monkeypatch.setattr(sys, "stdout", plain)
    mail.main([NAME, *resolver_args(dns_lab, "--plain")])
    assert plain.getvalue().splitlines()[0] == "MX\t10 mail.allowed.example"


# ======================================================================================
# 15. scope - subcommands
# ======================================================================================


@pytest.fixture
def workspace(monkeypatch, tmp_path, rich_output):
    root = tmp_path / "scope-ws"
    monkeypatch.setenv("BUGHUNT_SCOPE", str(root))
    return SimpleNamespace(root=root, rich=rich_output)


def scoped(module, argv, capsys, workspace):
    workspace.rich.seek(0)
    workspace.rich.truncate()
    capsys.readouterr()
    code = module.main(list(argv))
    captured = capsys.readouterr()
    return code, workspace.rich.getvalue(), captured.out


def test_scope_list_before_init_points_at_init(workspace, capsys):
    code, rich, plain = scoped(scope, ["list"], capsys, workspace)
    assert (code, rich, plain) == (2, "No scope file yet.\n  bughunt scope init\n", "")


def test_scope_path_prints_the_workspace_directory(workspace, capsys):
    assert scoped(scope, ["path"], capsys, workspace) == (0, f"{workspace.root}\n", "")


def test_scope_init_creates_scope_urls_and_requests_dir_and_is_idempotent(
    workspace, capsys
):
    code, rich, plain = scoped(scope, ["init"], capsys, workspace)
    assert code == 0 and plain == "" and str(workspace.root) in rich
    assert (workspace.root / "scope.txt").is_file() and (
        workspace.root / "urls.txt"
    ).is_file()
    assert (workspace.root / "requests").is_dir()
    assert (workspace.root / "urls.txt").read_text() == ""
    (workspace.root / "scope.txt").write_text("keep.example\n", encoding="utf-8")
    scoped(scope, ["init"], capsys, workspace)
    assert (workspace.root / "scope.txt").read_text() == "keep.example\n"


def test_scope_list_after_init_says_loopback_is_still_allowed(workspace, capsys):
    scoped(scope, ["init"], capsys, workspace)
    code, rich, plain = scoped(scope, ["list"], capsys, workspace)
    assert (code, plain) == (0, "")
    assert (
        rich
        == f"{workspace.root}\nScope is empty. Loopback is still allowed.\n0 URL(s) in urls.txt\n"
    )


def test_scope_add_normalizes_dedupes_and_persists(workspace, capsys):
    code, rich, _ = scoped(
        scope,
        [
            "add",
            "Example.COM",
            "https://App.Example.org/x",
            "10.0.0.5/24",
            "*.cdn.example.org",
        ],
        capsys,
        workspace,
    )
    assert code == 0
    for entry in ("example.com", "app.example.org", "10.0.0.0/24", "*.cdn.example.org"):
        assert entry in rich
    assert (workspace.root / "scope.txt").read_text().splitlines()[-4:] == [
        "example.com",
        "app.example.org",
        "10.0.0.0/24",
        "*.cdn.example.org",
    ]
    code, rich, _ = scoped(
        scope, ["add", "EXAMPLE.com", "new.example", "new.example"], capsys, workspace
    )
    assert code == 0 and "already in scope" in rich and "new.example" in rich
    assert (workspace.root / "scope.txt").read_text().splitlines().count(
        "new.example"
    ) == 1


def test_scope_add_ordering_added_before_already(workspace, capsys):
    scoped(scope, ["add", "one.example"], capsys, workspace)
    _, rich, _ = scoped(scope, ["add", "one.example", "two.example"], capsys, workspace)
    lines = rich.splitlines()
    assert (
        "two.example" in lines[0]
        and "one.example" in lines[1]
        and "already in scope" in lines[1]
    )


@pytest.mark.parametrize(
    "bad,message",
    [
        ("bad host", "'bad host' is not a host, domain or CIDR range"),
        ("1.2.3.4/99", "'1.2.3.4/99' is not a valid CIDR range"),
        ("[red]x[/red]", "'[red]x[/red]' is not a valid CIDR range"),
        ("http://", "'http://' has no host part"),
    ],
)
def test_scope_add_rejects_bad_entries_with_exit_two_and_stores_nothing(
    workspace, capsys, bad, message
):
    scoped(scope, ["init"], capsys, workspace)
    before = (workspace.root / "scope.txt").read_text()
    code, rich, plain = scoped(scope, ["add", "good.example", bad], capsys, workspace)
    assert code == 2 and plain == "" and rich == message + "\n"
    assert (workspace.root / "scope.txt").read_text() == before


def test_scope_list_shows_entries_and_url_count(workspace, capsys):
    scoped(scope, ["add", "a.example", "b.example"], capsys, workspace)
    (workspace.root / "urls.txt").write_text(
        "http://a.example/1\n# c\nhttp://a.example/2\n", encoding="utf-8"
    )
    code, rich, _ = scoped(scope, ["list"], capsys, workspace)
    assert code == 0
    assert rich == f"{workspace.root}\na.example\nb.example\n2 URL(s) in urls.txt\n"


def test_scope_allow_exit_codes_and_text(workspace, capsys):
    scoped(scope, ["add", "example.com"], capsys, workspace)
    code, rich, _ = scoped(
        scope, ["allow", "http://Sub.Example.com/x"], capsys, workspace
    )
    assert code == 0 and "sub.example.com" in rich and "in scope" in rich
    code, rich, _ = scoped(scope, ["allow", "nope.example"], capsys, workspace)
    assert code == 2 and rich == explain_block("nope.example") + "\n"
    code, rich, _ = scoped(scope, ["allow", "127.0.0.1"], capsys, workspace)
    assert code == 0 and "127.0.0.1" in rich


def test_scope_allow_without_a_scope_file_explains_init(workspace, capsys):
    code, rich, _ = scoped(scope, ["allow", "nope.example"], capsys, workspace)
    assert (
        code == 2
        and rich == explain_block("nope.example") + "\n"
        and "bughunt scope init" in rich
    )


def test_scope_remove_reports_removed_and_missing_and_exit_codes(workspace, capsys):
    scoped(scope, ["add", "example.com", "keep.example"], capsys, workspace)
    code, rich, _ = scoped(
        scope, ["remove", "EXAMPLE.com", "nothere.example"], capsys, workspace
    )
    lines = rich.splitlines()
    assert code == 0 and "removed" in lines[0] and "example.com" in lines[0]
    assert "not in scope" in lines[1] and "nothere.example" in lines[1]
    assert "example.com" not in (workspace.root / "scope.txt").read_text().splitlines()
    assert "keep.example" in (workspace.root / "scope.txt").read_text().splitlines()
    code, rich, _ = scoped(scope, ["remove", "nothere.example"], capsys, workspace)
    assert code == 2 and "not in scope" in rich


def test_scope_remove_without_a_scope_file_reports_everything_missing(
    workspace, capsys
):
    code, rich, _ = scoped(
        scope, ["remove", "x.example", "y.example"], capsys, workspace
    )
    assert (
        code == 2
        and "x.example" in rich
        and "y.example" in rich
        and "not in scope" in rich
    )
    assert not workspace.root.exists()


def test_scope_remove_invalid_entry_exit_two(workspace, capsys):
    scoped(scope, ["init"], capsys, workspace)
    code, rich, _ = scoped(scope, ["remove", "bad host"], capsys, workspace)
    assert (code, rich) == (2, "'bad host' is not a host, domain or CIDR range\n")


def test_scope_urls_prints_the_shared_list_to_stdout(workspace, capsys):
    scoped(scope, ["init"], capsys, workspace)
    (workspace.root / "urls.txt").write_text(
        "# top\nhttp://a.example/1\n\nhttp://a.example/2\n", encoding="utf-8"
    )
    assert scoped(scope, ["urls"], capsys, workspace) == (
        0,
        "",
        "http://a.example/1\nhttp://a.example/2\n",
    )


def test_scope_import_urls_keeps_unique_in_scope_urls(workspace, capsys, tmp_path):
    scoped(scope, ["add", "app.example.org"], capsys, workspace)
    source = tmp_path / "urls.in"
    source.write_text(
        "# c\nhttp://app.example.org/a\nhttp://app.example.org/a\nhttp://evil.example/b\n"
        "noscheme.example\napp.example.org\n\nhttp://127.0.0.1:80/z\nhttp://x.app.example.org/c\n",
        encoding="utf-8",
    )
    code, rich, plain = scoped(scope, ["import-urls", str(source)], capsys, workspace)
    assert code == 0
    assert (
        plain
        == "http://app.example.org/a\nhttp://127.0.0.1:80/z\nhttp://x.app.example.org/c\n"
    )
    assert rich == "3 new  3 in scope  3 skipped\n"
    assert (workspace.root / "urls.txt").read_text() == plain
    code, rich, plain2 = scoped(scope, ["import-urls", str(source)], capsys, workspace)
    assert (code, rich, plain2) == (0, "0 new  3 in scope  3 skipped\n", plain)
    assert (workspace.root / "urls.txt").read_text() == plain


def test_scope_import_urls_missing_file_and_missing_scope(workspace, capsys, tmp_path):
    code, rich, plain = scoped(
        scope, ["import-urls", str(tmp_path / "missing.txt")], capsys, workspace
    )
    assert (
        code == 2
        and plain == ""
        and "No file named" in rich
        and str(tmp_path / "missing.txt") in rich
    )
    source = tmp_path / "u.txt"
    source.write_text("http://a.example/\n", encoding="utf-8")
    code, rich, plain = scoped(scope, ["import-urls", str(source)], capsys, workspace)
    assert (code, plain) == (2, "") and rich == explain_block("(no host)") + "\n"
    assert not (workspace.root / "urls.txt").exists()


def test_scope_commands_bad_or_missing_subcommand_exit_two(workspace, capsys):
    for argv in ([], ["bogus"]):
        with pytest.raises(SystemExit) as raised:
            scope.main(argv)
        assert raised.value.code == 2
    capsys.readouterr()


# ======================================================================================
# 16. known defects (xfail strict): the assertions describe the CORRECT behavior
# ======================================================================================


@pytest.mark.parametrize(
    "argv",
    [["init"], ["add", "a.example"], ["allow", "127.0.0.1"], ["remove", "a.example"]],
)
def test_defect_scope_prints_literal_markup_tags(workspace, capsys, argv):
    """Rich-markup cluster: markup=False was applied to strings that still carry [ok]/[warn] tags."""
    scoped(scope, ["add", "a.example"], capsys, workspace)
    _code, rich, _plain = scoped(scope, argv, capsys, workspace)
    assert re.search(r"\[/?(ok|warn|err|muted|info|brand)\]", rich) is None


def test_defect_scope_missing_import_file_prints_literal_error_tag(
    workspace, capsys, tmp_path
):
    _code, rich, _plain = scoped(
        scope, ["import-urls", str(tmp_path / "gone.txt")], capsys, workspace
    )
    assert re.search(r"\[/?(ok|warn|err|muted|info|brand)\]", rich) is None


def test_dns_main_prints_txt_text_raw_so_a_record_can_forge_lines(dns_lab, capsys):
    """CRLF cluster: a hostile TXT value containing a newline injects extra `LABEL<TAB>value` output lines."""
    dns_lab.resolver.on(
        NAME, 16, Reply(answers=[(16, txt_data(b"harmless\nA\t6.6.6.6"))])
    )
    code, out, _err = run(dns, [NAME, *resolver_args(dns_lab)], capsys)
    assert code == 0
    assert len(out.splitlines()) == 1


def test_dns_main_prints_terminal_escapes_from_records(dns_lab, capsys):
    dns_lab.resolver.on(NAME, 16, Reply(answers=[(16, txt_data(b"\x1b[2Jcleared"))]))
    _code, out, _err = run(dns, [NAME, *resolver_args(dns_lab)], capsys)
    assert ESC not in out


def test_lookup_rejects_a_reply_from_an_unrelated_source(dns_lab):
    """Matching a transaction ID does not authorize a datagram from another resolver port."""
    dns_lab.resolver.on(
        NAME, 1, Reply(from_other_socket=True, answers=[(1, a_data("192.0.2.66"))])
    )
    try:
        found, _notes, _failed = call_lookup(dns_lab, timeout=0.3)
    except OSError:
        return
    assert found["A"] == []


@pytest.mark.parametrize(
    "target",
    [
        "https://allowed.example:99999",
        "https://allowed.example:abc",
        "https://[bad",
        "allowed.example:99999",
        "[::1]:99999",
    ],
)
def test_defect_cert_main_traceback_on_an_out_of_range_url_port(
    lab, capsys, tls_edge, target
):
    try:
        code = cert.main([target])
    except ValueError:
        raise AssertionError("cert.main leaked ValueError from the URL port")
    assert code == 2


def test_cert_prints_certificate_text_raw_so_a_subject_can_forge_lines(
    lab, capsys, tls_edge
):
    tls_edge.blob = build_certificate(
        subject=dn((CN, "evil\nissuer: Trusted Root CA", 0x0C)),
        issuer=simple_name("ca"),
    )
    _code, out, _err = run(cert, [NAME], capsys)
    assert sum(1 for line in out.splitlines() if line.startswith("issuer:")) == 1


def test_defect_vhost_canonical_target_raises_on_an_out_of_range_port():
    try:
        result = vhost.canonical_target("http://example.com:99999/")
    except ValueError:
        raise AssertionError("canonical_target leaked ValueError")
    assert result is None


def test_defect_vhost_main_traceback_on_an_out_of_range_url_port(site_lab, capsys):
    try:
        code = vhost.main(["http://127.0.0.1:99999/"])
    except ValueError:
        raise AssertionError("vhost.main leaked ValueError from the URL port")
    assert code == 2


def test_defect_vhost_host_header_for_ipv6_literal_is_not_bracketed():
    """`::1` with a non-default port is sent as the Host `::1` (no brackets, no port)."""
    assert vhost.host_header("::1", 8080, "http") == "[::1]:8080"


def test_defect_scope_path_is_soft_wrapped_at_the_console_width(
    monkeypatch, tmp_path, capsys
):
    narrow = io.StringIO()
    monkeypatch.setattr(
        ui, "console", Console(file=narrow, theme=ui.THEME, highlight=False, width=30)
    )
    root = tmp_path / ("deep-directory-name-" * 3)
    monkeypatch.setenv("BUGHUNT_SCOPE", str(root))
    assert scope.main(["path"]) == 0
    assert narrow.getvalue() == f"{root}\n"


def test_vhost_prints_page_titles_with_terminal_escapes(site_lab, capsys):
    site = site_lab.start({})
    site.pages[f"127.0.0.1:{site.port}"] = (200, b"<title>\x1b[31mred</title>")
    _code, out, _err = run(vhost, [f"http://127.0.0.1:{site.port}/"], capsys)
    assert ESC not in out


def test_defect_whois_dd_mon_yyyy_dates_never_parse():
    """The offset-stripping regex also eats the year of `13-Aug-2030`, so `%d-%b-%Y` is unreachable."""
    assert whois.parse_when("13-Aug-2030") == datetime(2030, 8, 13, tzinfo=timezone.utc)


@pytest.mark.parametrize("month", ["OCT", "Oct", "oct"])
def test_whois_month_name_case_does_not_change_the_date(month):
    assert whois.parse_when(f"16-{month}-2026") == datetime(
        2026, 10, 16, tzinfo=timezone.utc
    )


def test_defect_whois_ignores_the_utc_offset_of_a_timestamp():
    assert whois.parse_when("2030-08-13T04:00:00+01:00") == datetime(
        2030, 8, 13, 3, 0, tzinfo=timezone.utc
    )


def test_defect_whois_error_names_iana_even_when_the_referred_registry_failed(
    whois_lab, capsys, monkeypatch
):
    server = whois_lab.start(lambda query, index: b"refer: whois.registry.example\n")
    whois_lab.grant(f"http://whois.iana.org:{server.port}", operations=("passive",))
    whois_lab.grant(
        f"http://whois.registry.example:{server.port}", operations=("passive",)
    )
    real = socket.create_connection

    def selective(address, *args, **kwargs):
        if address[0] == "whois.registry.example":
            raise ConnectionRefusedError("registry down")
        return real(("127.0.0.1", server.port), *args, **kwargs)

    monkeypatch.setattr(socket, "create_connection", selective)
    _code, _out, err = run(whois, [NAME, "--port", str(server.port)], capsys)
    assert "whois.registry.example" in err


def test_whois_prints_registry_text_with_terminal_escapes(whois_lab, capsys):
    server = whois_lab.start(lambda query, index: b"Registrar: \x1b]0;pwned\x07Reg\n")
    _code, out, _err = run(
        whois, [NAME, "--server", "127.0.0.1", "--port", str(server.port)], capsys
    )
    assert ESC not in out and "\x07" not in out


def test_mail_prints_dns_text_with_terminal_escapes(dns_lab, capsys):
    dns_lab.resolver.on(
        NAME, 16, Reply(answers=[(16, txt_data(b"v=spf1 \x1b[2J-all"))])
    )
    _code, out, _err = run(mail, [NAME, *resolver_args(dns_lab)], capsys)
    assert ESC not in out
