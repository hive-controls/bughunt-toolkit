"""Serialize the command catalog to JSON: phases, modules, and option forms.

This is the contract a non-terminal front-end (a web UI, another tool) reads
to render Bughunt without parsing help text. Each module's options are the
same argparse-derived `Spec` the console drives, so the form a UI builds and
the form the console builds are the same form. Guidance copy and the readiness
gates travel with it.
"""

from __future__ import annotations

from pathlib import Path

from bughunt import VERSION
from bughunt.console import readiness
from bughunt.console.catalog import (
    DISABLED_REFERENCES,
    MODULE_GROUPS,
    module_when,
    phase_purpose,
)
from bughunt.console.options import Option, Spec, SpecError, load_spec

SCHEMA_VERSION = 2


def _option_dict(opt: Option) -> dict:
    return {
        "name": opt.name,
        "flags": list(opt.flags),
        "kind": opt.kind,
        "required": opt.required,
        "help": opt.help,
        "choices": list(opt.choices),
        "default": opt.default,
        "repeatable": opt.repeatable,
        "subcommand": opt.subcommand,
    }


def _spec_dict(spec: Spec) -> dict:
    return {
        "command_name": spec.command_name,
        "options": [_option_dict(opt) for opt in spec.options],
        "subcommands": [
            {"name": name, "help": help_text} for name, help_text in spec.subcommands
        ],
    }


def _module_dict(name: str, *, tool_file: Path, build_parser) -> dict:
    from bughunt.console.console import _module_facts
    from bughunt.core import adapters

    summary, aliases, reference = _module_facts(name)
    entry: dict = {
        "name": name,
        "id": name,
        "operations": [],
        "summary": summary,
        "when": module_when(name),
        "aliases": list(aliases),
        "reference": reference,
        "disabled": name in DISABLED_REFERENCES,
    }
    try:
        spec = load_spec(name, tool_file=tool_file, build_parser=build_parser)
    except SpecError as exc:
        entry["form"] = None
        entry["unavailable"] = exc.message
    else:
        entry["form"] = _spec_dict(spec)
        entry.update(adapters.describe(name))
    return entry


def export_catalog(*, tool_file: Path, build_parser) -> dict:
    """The whole catalog as a plain, JSON-serializable dict."""
    state = readiness.gather()
    phases = []
    for title, members in MODULE_GROUPS:
        phases.append(
            {
                "name": title.lower(),
                "title": title,
                "purpose": phase_purpose(title),
                "block": state.phase_block(title),
                "modules": [
                    _module_dict(name, tool_file=tool_file, build_parser=build_parser)
                    for name in members
                ],
            }
        )
    return {
        "schema_version": SCHEMA_VERSION,
        "version": VERSION,
        "readiness": {
            "scope_ready": state.scope_ready,
            "policy_verified": state.policy_verified,
            "has_identity": state.has_identity,
            "next_step": {
                "module": state.next_step()[0],
                "message": state.next_step()[1],
            },
        },
        "phases": phases,
    }
