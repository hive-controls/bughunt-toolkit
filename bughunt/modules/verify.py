"""Configure and check a selected actor's server-side identity probe."""

from __future__ import annotations

import argparse
import getpass
import json
import sys
from urllib.parse import urlsplit

import httpx

from bughunt.core import egress
from bughunt.core.identity import IdentityError, selected_name
from bughunt.core.verification import VerificationError, configure, read_configuration, verify_selected


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="bughunt verify", description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    editor = commands.add_parser("configure", help="Save one bounded identity probe.")
    editor.add_argument("name", help="Existing named actor, never default.")
    editor.add_argument("--url", required=True, help="Exact owned HTTPS or HTTP probe URL.")
    editor.add_argument("--status", type=int, choices=(200, 401), default=200,
                        help="200 checks a principal and role; 401 checks anonymous denial.")
    editor.add_argument("--principal-path", help="Dotted JSON path, for example user.id.")
    principal = editor.add_mutually_exclusive_group()
    principal.add_argument("--expect-principal", help="Exact principal; may enter shell history.")
    principal.add_argument("--prompt-principal", action="store_true",
                           help="Prompt for principal without terminal echo.")
    editor.add_argument("--role-path", help="Dotted JSON path, for example user.role.")
    editor.add_argument("--role-type", choices=("string", "integer"), default="string",
                        help="Exact JSON role type; integer IDs must be 0..9007199254740991.")
    role = editor.add_mutually_exclusive_group()
    role.add_argument("--expect-role", help="Exact role; may enter shell history.")
    role.add_argument("--prompt-role", action="store_true",
                      help="Prompt for role without terminal echo.")
    editor.add_argument("--role-contains", action="store_true",
                        help="Pass when the expected role is a member of the array at --role-path.")
    editor.add_argument("--max-bytes", type=int, default=65536)
    editor.add_argument("--timeout", type=float, default=5.0, metavar="SECONDS")
    editor.add_argument("--ttl", type=float, default=5.0, metavar="SECONDS")
    viewer = commands.add_parser("show", help="Show probe metadata without expected values.")
    viewer.add_argument("name")
    checker = commands.add_parser("check", help="Check the currently selected named actor once.")
    checker.add_argument("name")
    commands.add_parser("status", help="Report whether the selected actor is probe-ready, value-free.")
    return parser


def _expected_values(args: argparse.Namespace) -> tuple[str | None, str | int | None]:
    if args.status == 401:
        if any((args.principal_path, args.expect_principal, args.prompt_principal,
                args.role_path, args.expect_role, args.prompt_role, args.role_contains)
               ) or args.role_type != "string":
            raise VerificationError("Anonymous denial has no principal or role assertion")
        return None, None
    if (args.prompt_principal or args.prompt_role) and not sys.stdin.isatty():
        raise VerificationError("An interactive terminal is required for hidden input")
    principal = (getpass.getpass("Expected principal: ") if args.prompt_principal
                 else args.expect_principal)
    role = getpass.getpass("Expected role: ") if args.prompt_role else args.expect_role
    if args.role_type == "integer":
        try:
            role = json.loads(role)
        except (ValueError, TypeError) as exc:
            raise VerificationError("Expected role must be a JSON integer") from exc
        if type(role) is not int:
            raise VerificationError("Expected role must be a JSON integer")
    return principal, role


def _public_configuration(name: str, config: dict) -> dict:
    parsed = urlsplit(config["url"])
    return {"name": name, "url": f"{parsed.scheme}://{parsed.netloc}{parsed.path}",
            "status": config["expected_status"],
            "principal_path": config["principal_path"],
            "role_path": config["role_path"],
            "role_type": ("integer" if type(config["expected_role"]) is int else
                          "string" if config["expected_role"] is not None else None),
            "max_bytes": config["max_bytes"],
            "timeout_seconds": config["timeout_seconds"],
            "ttl_seconds": config["ttl_seconds"],
            **({"role_contains": True} if config.get("role_contains") else {})}


def _status_readiness() -> dict:
    name = selected_name()
    try:
        probe = _public_configuration(name, read_configuration(name))
    except (VerificationError, IdentityError):
        probe = None
    return {"selected_actor": name, "configured": probe is not None, "probe": probe}


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "configure":
            principal, role = _expected_values(args)
            configure(args.name, args.url, args.principal_path, principal,
                      args.role_path, role, expected_status=args.status,
                      max_bytes=args.max_bytes, timeout_seconds=args.timeout,
                      ttl_seconds=args.ttl, role_contains=args.role_contains)
            print(f"Verification configured for {args.name}.")
        elif args.command == "show":
            metadata = _public_configuration(args.name, read_configuration(args.name))
            print(json.dumps(metadata, indent=2, sort_keys=True))
        elif args.command == "check":
            if selected_name() != args.name:
                raise VerificationError("Select the named actor before checking it")
            with egress.client(operation="manual", follow_redirects=False) as client:
                run_id = verify_selected(client)
            print(f"Identity verified for {args.name}; run {run_id}.")
        elif args.command == "status":
            print(json.dumps(_status_readiness(), indent=2, sort_keys=True))
        return 0
    except (VerificationError, IdentityError, httpx.HTTPError, OSError, EOFError):
        print("Verification blocked: invalid configuration, actor, or server assertion.")
        return 2
