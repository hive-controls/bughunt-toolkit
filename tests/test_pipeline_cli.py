import json

import pytest

from bughunt.console import structured
from test_pipeline_plan import document


@pytest.mark.parametrize("command", ["pipeline", "chain"])
def test_cli_validates_one_json_document_without_execution(
    tmp_path, monkeypatch, capsys, command
):
    monkeypatch.setenv("BUGHUNT_SCOPE", str(tmp_path / "absent"))
    path = tmp_path / "plan.json"
    path.write_text(json.dumps(document()))
    assert structured.dispatch([command, "validate", str(path)]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "planned" and result["dry_run"] is True
    assert not (tmp_path / "absent").exists()


def test_cli_run_without_explicit_execution_previews(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("BUGHUNT_SCOPE", str(tmp_path / "absent"))
    path = tmp_path / "plan.json"
    path.write_text(json.dumps(document()))
    assert structured.dispatch(["pipeline", "run", str(path)]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "planned"
    assert not (tmp_path / "absent").exists()


def test_pipeline_schema_has_nested_limits_steps_and_reference_contract(capsys):
    assert structured.dispatch(["schema", "pipeline"]) == 0
    result = json.loads(capsys.readouterr().out)
    schema = result["artifacts"][0]["payload"]["items"][0]
    assert schema["additionalProperties"] is False
    assert schema["properties"]["limits"]["properties"]["concurrency"]["const"] == 1
    reference = schema["properties"]["steps"]["items"]["properties"]["inputs"][
        "additionalProperties"
    ]
    assert set(reference["required"]) == {"step", "artifact"}
    assert reference["oneOf"] == [{"required": ["index"]}, {"required": ["indices"]}]
    assert reference["properties"]["indices"]["maxItems"] == 32
    assert reference["properties"]["indices"]["uniqueItems"] is True
