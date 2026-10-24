"""Route gate commands: write the config, show what it sees, run the gate by hand."""

from __future__ import annotations

import argparse
import json
import os
import socket
import tempfile
from pathlib import Path

from bughunt.console import ui
from bughunt.core import cli, route, route_probe, workspace

_VERBATIM: dict[str, bool] = {"markup": False, "highlight": False}

_NO_CONFIG_LINES = ("No route config found. The route gate is inactive.",
                    "  bughunt route init --interface NAME")


def _resolver(host: str, port: object) -> list:
    return socket.getaddrinfo(host, port)


def _show(text: str) -> None:
    ui.console.print(text, **_VERBATIM)


def _emit_json(payload: dict[str, object]) -> None:
    print(json.dumps(payload, indent=2))


def _load_policy() -> tuple[route.RoutePolicy | None, str]:
    """The active policy, or None with the reason: no config at all, or the config's error text."""
    located = route.locate_config()
    if located is None:
        return None, ""
    try:
        return route.load_config(located), ""
    except route.ConfigError as error:
        return None, str(error)


def _write_atomically(target: Path, text: str, *, force: bool) -> None:
    """Write beside the target then move into place; without force an existing file is never replaced."""
    target.parent.mkdir(parents=True, exist_ok=True)
    handle, staging = tempfile.mkstemp(dir=target.parent, prefix=".route-", suffix=".tmp")
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as staged:
            staged.write(text)
        if force:
            os.replace(staging, target)
        else:
            os.link(staging, target)
    finally:
        if os.path.exists(staging):
            os.unlink(staging)


def _do_init(args: argparse.Namespace) -> int:
    target = Path(args.path).expanduser() if args.path else workspace.workspace_dir() / route.CONFIG_FILENAME
    document = {"schema_version": route.SCHEMA_VERSION, "interfaces": args.interface}
    text = json.dumps(document, indent=2) + "\n"
    try:
        route.parse_config(text, source=str(target))
    except route.ConfigError as error:
        _show(f"Refused: {error}")
        return 2
    try:
        _write_atomically(target, text, force=args.force)
    except FileExistsError:
        _show(f"{target} already exists. Pass --force to replace it.")
        return 2
    except OSError as error:
        _show(f"Could not write {target}: {error}")
        return 2
    _show(f"route {target}")
    return 0


def _interface_rows(policy: route.RoutePolicy, probe: route_probe.RouteProbe) -> list[dict[str, object]]:
    interfaces = probe.interfaces()
    matching = {item.index for item in route._matching_tunnels(policy, interfaces)}
    carrying = probe.egress_indexes(policy.probe_address)
    return [{"name": item.name, "index": item.index, "up": item.up,
             "matches": item.index in matching, "carries_probe": item.index in carrying}
            for item in interfaces]


def _status_report(policy: route.RoutePolicy) -> dict[str, object]:
    report: dict[str, object] = {
        "source": policy.source, "valid": True, "protect": list(policy.protect),
        "interfaces_configured": list(policy.interfaces), "probe_address": policy.probe_address,
        "backend": None, "backend_error": None, "interfaces": []}
    try:
        probe = route_probe.default_probe()
        report["backend"] = type(probe).__name__
        report["interfaces"] = _interface_rows(policy, probe)
    except (route_probe.ProbeError, OSError, ValueError) as error:
        report["backend_error"] = str(error)
    return report


def _print_status(report: dict[str, object]) -> None:
    _show(f"config   {report['source']}")
    _show(f"protects {', '.join(report['protect']) or '(report only)'}")
    _show(f"names    {', '.join(report['interfaces_configured'])}")
    _show(f"probe    {report['probe_address']}")
    if report["backend_error"]:
        _show(f"backend  unavailable: {report['backend_error']}")
        return
    _show(f"backend  {report['backend']}")
    for row in report["interfaces"]:
        flags = ("up" if row["up"] else "down", "match" if row["matches"] else "-",
                 "carries probe" if row["carries_probe"] else "-")
        _show(f"  {row['name']:<20} {'  '.join(flags)}")


def _do_status(args: argparse.Namespace) -> int:
    policy, problem = _load_policy()
    if problem:
        if args.json:
            _emit_json({"valid": False, "error": problem})
        else:
            _show(f"Route config invalid: {problem}")
        return 2
    if policy is None:
        if args.json:
            _emit_json({"valid": True, "source": None})
        else:
            for line in _NO_CONFIG_LINES:
                _show(line)
        return 0
    report = _status_report(policy)
    if args.json:
        _emit_json(report)
    else:
        _print_status(report)
    return 0


def _finish_check(verdict: route.Verdict, as_json: bool) -> int:
    if as_json:
        _emit_json({"ok": verdict.ok, "summary": verdict.summary, "details": list(verdict.details)})
    else:
        _show(f"{'pass' if verdict.ok else 'block'}: {verdict.summary}")
        for line in verdict.details:
            _show(f"  {line}")
    return 0 if verdict.ok else 2


def _do_check(args: argparse.Namespace) -> int:
    policy, problem = _load_policy()
    if problem:
        return _finish_check(route.Verdict(False, f"Route config invalid; blocked: {problem}"), args.json)
    if policy is None:
        return _finish_check(route.Verdict(False, "No route config found; nothing to check."), args.json)
    host = ""
    if args.host:
        host = workspace.hostname_of(args.host) or args.host.strip()
        if not workspace.allowed(host):
            return _finish_check(route.Verdict(False, workspace.explain_block(host)), args.json)
    verdict = route.verify(policy, destination=host or None, kind="target", resolver=_resolver)
    return _finish_check(verdict, args.json)


_JSON_FLAG: cli.Option = (("--json",), {"action": "store_true", "help": "Print machine-readable JSON."})

_COMMANDS = {
    "init": cli.Verb("Write a validated route.json.", _do_init, (
        (("--interface",), {"action": "append", "required": True, "metavar": "NAME",
                            "help": "Tunnel interface name fragment. Repeat for several."}),
        (("--path",), {"default": None, "help": "Write here instead of the workspace route.json."}),
        (("--force",), {"action": "store_true", "help": "Replace an existing file."}),
    )),
    "status": cli.Verb("Show the config source, protected points, backend and interfaces.",
                       _do_status, (_JSON_FLAG,)),
    "check": cli.Verb("Run the route gate by hand. Exit 0 pass, 2 block.", _do_check, (
        (("host",), {"nargs": "?", "default": None, "help": "In-scope host or URL. Omit for a probe check."}),
        _JSON_FLAG,
    )),
}


def build_parser() -> argparse.ArgumentParser:
    parser = cli.build_parser(
        "bughunt route",
        "Check that traffic would leave through your tunnel. Reads the routing table; sends no packets.")
    cli.add_verbs(parser, _COMMANDS, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    parsed = build_parser().parse_args(argv)
    command = _COMMANDS.get(parsed.command)
    if command is None:
        _show("Unknown route command.")
        return 2
    return command.run(parsed)
