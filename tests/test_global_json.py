import json

import pytest

from bughunt.core import scanner


@pytest.fixture(autouse=True)
def fresh_console_stream(monkeypatch):
    from bughunt.console import ui

    monkeypatch.setattr(ui.console, "_file", None)


@pytest.mark.parametrize("words", [["scope", "list"], ["engagement", "scope", "list"]])
def test_global_json_flat_and_namespaced_are_single_typed_document(
    words, capsys, monkeypatch, tmp_path
):
    monkeypatch.setenv("BUGHUNT_SCOPE", str(tmp_path))
    assert scanner.main(["--json", *words]) == 0
    document = json.loads(capsys.readouterr().out)
    assert document["module_id"] == "scope"
    assert document["artifacts"][0]["kind"] == "inventory"


def test_json_invalid_options_never_leak_argparse_or_start_interactive(capsys):
    assert scanner.main(["--json", "dns", "--made-up"]) == 2
    assert json.loads(capsys.readouterr().out)["status"] == "invalid"
    assert scanner.main(["--json", "console"]) == 2
    assert json.loads(capsys.readouterr().out)["status"] == "unsupported"


def test_json_help_and_catalog_are_inert_structured_values(capsys):
    assert scanner.main(["--json", "help"]) == 0
    assert (
        json.loads(capsys.readouterr().out)["artifacts"][0]["payload"]["resource"]
        == "help"
    )


def test_json_doctor_returns_actual_checks_without_local_paths(
    capsys, monkeypatch, tmp_path
):
    from bughunt.console import doctor
    from pathlib import Path

    monkeypatch.setenv("BUGHUNT_SCOPE", str(tmp_path))
    expected = doctor.collect_checks(Path(scanner.__file__))
    code = scanner.main(["--json", "doctor"])
    text = capsys.readouterr().out
    result = json.loads(text)
    rows = result["artifacts"][0]["payload"]["items"]
    assert {row["name"]: row["ok"] for row in rows} == {
        row.name: row.ok for row in expected
    }
    assert code == int(any(row.required and not row.ok for row in expected))
    assert str(tmp_path) not in text
    assert scanner.__file__ not in text
