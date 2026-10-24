"""Shared command-line plumbing: the early-exit protocol, parser builders, and common options."""

import argparse

import pytest

from bughunt.core import cli


def test_command_exit_carries_its_code_and_message():
    stop = cli.CommandExit(3, "nope")
    assert (stop.code, stop.message, str(stop)) == (3, "nope", "nope")


def test_run_returns_the_exit_code_the_entry_gives():
    assert cli.run(lambda: 4) == 4


def test_run_counts_a_silent_entry_as_success():
    assert cli.run(lambda: None) == 0


def test_run_passes_the_arguments_through():
    assert cli.run(lambda left, right: left + right, 1, 2) == 3


def test_run_says_the_message_on_stderr_and_returns_the_code(capsys):
    def refuse():
        raise cli.CommandExit(2, "Give a hostname.")

    assert cli.run(refuse) == 2
    captured = capsys.readouterr()
    assert (captured.out, captured.err) == ("", "Give a hostname.\n")


def test_run_lets_other_errors_through():
    def broken():
        raise RuntimeError("boom")

    with pytest.raises(RuntimeError):
        cli.run(broken)


def test_common_options_keep_their_flags_and_help_text():
    assert cli.PLAIN == (("--plain",), {"action": "store_true", "help": "Skip the banner."})
    assert cli.INSECURE == (
        ("--insecure",), {"action": "store_true", "help": "Do not verify TLS certificates."})
    assert cli.COOKIE == (
        ("--cookie",),
        {"default": None, "help": "Cookie for this run. Replaces the saved session cookie."})
    assert cli.AUTHORIZATION == (
        ("--authorization",),
        {"default": None, "help": "Authorization for this run. Replaces the saved session value."})
    assert cli.SESSION_OPTIONS == (cli.COOKIE, cli.AUTHORIZATION)


def options(timeout, port):
    return argparse.Namespace(timeout=timeout, port=port)


@pytest.mark.parametrize(("timeout", "port"), [(0, 53), (-1.5, 53), (5, 0), (5, 65536), (5, -1)])
def test_endpoint_rule_refuses_a_bad_timeout_or_port(timeout, port):
    with pytest.raises(cli.CommandExit) as caught:
        cli.check(options(timeout, port), [cli.ENDPOINT_RULE])
    assert caught.value.code == 2
    assert caught.value.message == "Timeout must be greater than 0, and the port must be 1 through 65535."


@pytest.mark.parametrize(("timeout", "port"), [(0.1, 1), (5, 53), (10, 65535)])
def test_endpoint_rule_passes_a_sane_timeout_and_port(timeout, port):
    cli.check(options(timeout, port), [cli.ENDPOINT_RULE])


def test_check_reports_the_first_rule_that_holds_with_the_given_code():
    rules = [(lambda parsed: False, "never"), (lambda parsed: True, "first"), (lambda parsed: True, "second")]
    with pytest.raises(cli.CommandExit) as caught:
        cli.check(argparse.Namespace(), rules, code=7)
    assert (caught.value.code, caught.value.message) == (7, "first")


def test_build_parser_registers_options_in_order_after_help():
    parser = cli.build_parser(
        "bughunt demo", "Demo command.",
        [(("name",), {"help": "A name."}), cli.PLAIN, (("--count",), {"type": int, "default": 1})])
    assert parser.prog == "bughunt demo"
    assert parser.description == "Demo command."
    assert [action.dest for action in parser._actions] == ["help", "name", "plain", "count"]
    assert vars(parser.parse_args(["x", "--plain"])) == {"name": "x", "plain": True, "count": 1}


def test_build_parser_without_options_has_only_help():
    parser = cli.build_parser("bughunt demo", "Demo command.")
    assert [action.dest for action in parser._actions] == ["help"]


def verb_parser(**keywords):
    parser = cli.build_parser("bughunt demo", "Demo command.", [cli.PLAIN])
    cli.add_verbs(parser, {
        "list": cli.Verb("Print everything.", print),
        "add": cli.Verb("Append one item.", print, (
            (("item",), {"nargs": "+", "help": "What to add."}),
            (("--twice",), {"action": "store_true"}),
        )),
    }, **keywords)
    return parser


def test_add_verbs_lists_the_verbs_in_declaration_order_with_their_summaries():
    branches = verb_parser()._subparsers._group_actions[0]
    assert list(branches.choices) == ["list", "add"]
    assert [(shown.dest, shown.help) for shown in branches._get_subactions()] == [
        ("list", "Print everything."), ("add", "Append one item.")]


def test_add_verbs_gives_each_verb_its_arguments():
    parsed = verb_parser().parse_args(["--plain", "add", "a", "b", "--twice"])
    assert vars(parsed) == {"plain": True, "command": "add", "item": ["a", "b"], "twice": True}
    assert vars(verb_parser().parse_args(["list"])) == {"plain": False, "command": "list"}


def test_add_verbs_leaves_the_verb_optional_by_default():
    assert vars(verb_parser().parse_args([])) == {"plain": False, "command": None}


def test_add_verbs_can_require_a_verb(capsys):
    with pytest.raises(SystemExit) as caught:
        verb_parser(required=True).parse_args([])
    assert caught.value.code == 2
    assert "required" in capsys.readouterr().err


def test_add_verbs_can_name_the_destination():
    parsed = verb_parser(dest="action").parse_args(["list"])
    assert vars(parsed) == {"plain": False, "action": "list"}
