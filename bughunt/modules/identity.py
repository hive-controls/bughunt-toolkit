"""Manage named, origin-bound identities for an owned workspace."""

from __future__ import annotations

import argparse
import getpass
import json
import sys

from bughunt.core.identity import IdentityError, clear_profile, create_profile, list_profiles, selected_name, set_companion_headers, set_credential, show_profile, use_profile


KINDS = ("owner", "lower_privilege", "anonymous", "browser", "api")
CREDENTIALS = ("cookie", "authorization", "x-api-key", "auth-key")
METADATA = ("name", "kind", "origins", "owned", "credential_headers", "companion_headers", "selected")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bughunt identity",
        description="Manage named, origin-bound identities in the private workspace.",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    creator = commands.add_parser("create", help="Create an owned identity profile.")
    creator.add_argument("name", help="A short unique profile name.")
    creator.add_argument("--kind", required=True, choices=KINDS)
    creator.add_argument("--origin", action="append", required=True,
                         help="Exact HTTP(S) origin; repeat for each owned origin.")
    creator.add_argument("--owned", action="store_true", required=True,
                         help="Confirm that these accounts and origins are yours to test.")
    commands.add_parser("list", help="List profiles without secret values.")
    viewer = commands.add_parser("show", help="Show one profile without secret values.")
    viewer.add_argument("name")
    selector = commands.add_parser("use", help="Select a profile, or default.")
    selector.add_argument("name")
    setter = commands.add_parser("set", help="Save one credential in a named profile.")
    setter.add_argument("name")
    setter.add_argument("header", choices=CREDENTIALS)
    setter.add_argument("value", nargs="*", help="Optional value for scripted use.")
    setter.add_argument("--prompt", action="store_true",
                        help="Enter the value without terminal echo (default if omitted).")
    clearer = commands.add_parser("clear", help="Log out by removing saved credentials.")
    clearer.add_argument("name")
    companion = commands.add_parser(
        "companion", help="Set or show the companion header NAME allowlist (names only).")
    companion.add_argument("name")
    companion.add_argument("header", nargs="*",
                           help="Lowercase header names to allow; omit to show the current names.")
    companion.add_argument("--clear", action="store_true", dest="clear_companions",
                           help="Remove every companion header name.")
    return parser


def _metadata(record: dict) -> dict:
    return {key: record[key] for key in METADATA if key in record}


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "create":
            create_profile(args.name, args.kind, args.origin, owned=args.owned)
            print(f"Identity {args.name} created.")
        elif args.command == "list":
            result = {"selected": selected_name(),
                      "profiles": [_metadata(profile) for profile in list_profiles()]}
            print(json.dumps(result, indent=2, sort_keys=True))
        elif args.command == "show":
            print(json.dumps(_metadata(show_profile(args.name)), indent=2, sort_keys=True))
        elif args.command == "use":
            use_profile(args.name)
            print(f"Identity {args.name} selected.")
        elif args.command == "set":
            if args.prompt and args.value:
                print("Give a value or use --prompt, not both.")
                return 2
            if not args.value and not sys.stdin.isatty():
                print("An interactive terminal is required to prompt for a credential.")
                return 2
            value = (" ".join(args.value) if args.value else
                     getpass.getpass("Credential: ")).strip()
            if not value or "\n" in value or "\r" in value:
                print("Give one nonempty credential value on a single line.")
                return 2
            set_credential(args.name, args.header, value)
            print(f"{args.header} saved for {args.name}.")
        elif args.command == "clear":
            clear_profile(args.name)
            print(f"Credentials cleared for {args.name}.")
        elif args.command == "companion":
            if args.clear_companions and args.header:
                print("Give header names or --clear, not both.")
                return 2
            if args.header or args.clear_companions:
                set_companion_headers(args.name, [] if args.clear_companions else args.header)
                print(f"Companion headers set for {args.name}.")
            else:
                names = show_profile(args.name).get("companion_headers", [])
                print(json.dumps({"name": args.name, "companion_headers": names},
                                 indent=2, sort_keys=True))
        return 0
    except (IdentityError, OSError, EOFError):
        print("Identity rejected: invalid or unreadable profile or credential.")
        return 2
