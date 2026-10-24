"""Pinned API semantics are tested without target or container activity."""

import importlib
import json
from pathlib import Path
import sys

import pytest

from bughunt.integrations import zap_consumer
from bughunt.integrations.zap import SUPPORTED_IMAGE


@pytest.fixture
def helper(monkeypatch):
    monkeypatch.setitem(sys.modules, "zap_consumer", zap_consumer)
    return importlib.import_module("bughunt.integrations.zap_passive_consumer")


def test_history_pages_use_one_based_ordinals_not_zero_offsets_or_ids(
    helper, monkeypatch, tmp_path
):
    url = "https://allowed.example/app/data"
    path = tmp_path / "traffic.har"
    path.write_text(
        json.dumps(
            {
                "log": {
                    "entries": [
                        {
                            "request": {
                                "method": "GET",
                                "url": url,
                                "headers": [],
                                "httpVersion": "HTTP/1.1",
                            },
                            "response": {"status": 200},
                        }
                    ]
                }
            }
        )
    )

    def message(identifier, kind, response, target):
        return {
            "id": str(identifier),
            "type": kind,
            "requestHeader": f"GET {target} HTTP/1.1\r\n\r\n",
            "responseHeader": response,
            "responseBody": "owned" if kind == "15" else "",
        }

    messages = [
        message(1, "15", "HTTP/1.1 200 OK\r\n\r\n", url),
        message(7, "0", "HTTP/1.0 0\r\n\r\n", "https://allowed.example"),
        message(19, "0", "HTTP/1.0 0\r\n\r\n", "https://allowed.example/app"),
    ]
    starts = []

    def api(endpoint, **parameters):
        if endpoint == "core/view/numberOfMessages":
            return {"numberOfMessages": "3"}
        start = int(parameters["start"])
        starts.append(start)
        index = max(start - 1, 0)
        return {"messages": [messages[index]] if index < len(messages) else []}

    monkeypatch.setattr(helper.common, "api", api)
    value = helper.history(path)
    assert starts == [1, 2, 3]
    assert value["imported_messages"] == 1 and value["temporary_ancestor_messages"] == 2
    messages[-1]["requestHeader"] = "GET https://outside.example HTTP/1.1\r\n\r\n"
    with pytest.raises(ValueError) as caught:
        helper.history(path)
    # Fail-closed, but the message now names the offending entry so a field run self-diagnoses.
    assert "id=19" in str(caught.value) and "type=0" in str(caught.value)
    assert "GET https://outside.example HTTP/1.1" in str(caught.value)


def test_import_correspondence_mismatch_is_named_without_leaking_urls(
    helper, monkeypatch, tmp_path
):
    url = "https://allowed.example/app/data"
    path = tmp_path / "traffic.har"
    path.write_text(
        json.dumps(
            {
                "log": {
                    "entries": [
                        {
                            "request": {
                                "method": "GET",
                                "url": url,
                                "headers": [],
                                "httpVersion": "HTTP/1.1",
                            },
                            "response": {"status": 200},
                        }
                    ]
                }
            }
        )
    )
    # A single imported message whose status does not match the recording: observed != expected.
    message = {
        "id": "1",
        "type": "15",
        "requestHeader": f"GET {url} HTTP/1.1\r\n\r\n",
        "responseHeader": "HTTP/1.1 500 Server Error\r\n\r\n",
        "responseBody": "owned",
    }

    def api(endpoint, **parameters):
        if endpoint == "core/view/numberOfMessages":
            return {"numberOfMessages": "1"}
        return {"messages": [message] if int(parameters["start"]) == 1 else []}

    monkeypatch.setattr(helper.common, "api", api)
    with pytest.raises(ValueError) as caught:
        helper.history(path)
    reason = str(caught.value)
    assert "does not match the recording" in reason
    # Counts only — the recorded URL and its query string never appear in the diagnostic.
    assert url not in reason


@pytest.fixture
def captured_history(request, helper, monkeypatch, tmp_path):
    fixture = json.loads(
        (Path(__file__).parent / "fixtures" / "zap_2_17_history.json").read_text()
    )
    assert fixture["provenance"]["version"] == "2.17.0"
    assert fixture["provenance"]["image"] == SUPPORTED_IMAGE
    assert fixture["provenance"]["network"] == "none"
    assert fixture["provenance"]["published_ports"] == []
    case = next(item for item in fixture["cases"] if item["case"] == request.param)
    assert case["addons"]["network"] == "0.30.0"
    assert case["addons"]["exim"] == "0.22.0"
    assert case["addons"]["automation"] == "0.61.0"
    path = tmp_path / "traffic.har"
    path.write_text(json.dumps(case["har"]))
    messages = case["messages"]
    expected_counts = {
        "get_directory": (1, 2),
        "post_query_https": (1, 2),
        "duplicates_trailing_slash": (3, 3),
        "root_slash": (1, 1),
        "repeated_trailing_slash": (1, 3),
    }
    assert (
        tuple(
            sum(message["type"] == kind for message in messages) for kind in ("15", "0")
        )
        == expected_counts[request.param]
    )

    def api(endpoint, **parameters):
        if endpoint == "core/view/numberOfMessages":
            return {"numberOfMessages": str(len(messages))}
        assert endpoint == "core/view/messages" and parameters["count"] == 1
        return {"messages": [messages[parameters["start"] - 1]]}

    monkeypatch.setattr(helper.common, "api", api)
    return path, messages


@pytest.mark.parametrize(
    "captured_history",
    [
        "get_directory",
        "post_query_https",
        "duplicates_trailing_slash",
        "root_slash",
        "repeated_trailing_slash",
    ],
    indirect=True,
)
def test_real_pinned_offline_import_history(helper, captured_history):
    path, messages = captured_history
    result = helper.history(path)
    imported = [message for message in messages if message["type"] == "15"]
    ancestors = [message for message in messages if message["type"] == "0"]
    assert imported and ancestors
    assert result["imported_messages"] == len(imported)
    assert result["temporary_ancestor_messages"] == len(ancestors)
    assert result["unexpected_history"] == 0
    assert result["target_network_enabled"] is False
    assert len(result["history_receipts"]) == len(messages)


@pytest.mark.parametrize("captured_history", ["post_query_https"], indirect=True)
@pytest.mark.parametrize(
    "mutation",
    [
        "method",
        "header",
        "response",
        "body",
        "type",
        "import_status",
        "duplicate_id",
        "different_path",
        "different_scheme",
        "query",
    ],
)
def test_captured_history_mutations_fail_closed(helper, captured_history, mutation):
    path, messages = captured_history
    ancestor = next(message for message in messages if message["type"] == "0")
    imported = next(message for message in messages if message["type"] == "15")
    if mutation == "method":
        ancestor["requestHeader"] = ancestor["requestHeader"].replace(
            "GET ", "POST ", 1
        )
    elif mutation == "header":
        ancestor["requestHeader"] = ancestor["requestHeader"].replace("bh28", "changed")
    elif mutation == "response":
        ancestor["responseHeader"] = "HTTP/1.1 200 OK\r\n\r\n"
    elif mutation == "body":
        ancestor["responseBody"] = "unaccounted"
    elif mutation == "type":
        ancestor["type"] = "1"
    elif mutation == "import_status":
        imported["responseHeader"] = imported["responseHeader"].replace("200", "500", 1)
    elif mutation == "different_path":
        ancestor["requestHeader"] = ancestor["requestHeader"].replace(
            "fixture.example HTTP", "fixture.example/app/data HTTP"
        )
    elif mutation == "different_scheme":
        ancestor["requestHeader"] = ancestor["requestHeader"].replace(
            "https://", "http://"
        )
    elif mutation == "query":
        ancestor["requestHeader"] = ancestor["requestHeader"].replace(
            "fixture.example HTTP", "fixture.example?item=one HTTP"
        )
    else:
        ancestor["id"] = imported["id"]
    with pytest.raises(ValueError, match="Unexpected non-import consumer history"):
        helper.history(path)


@pytest.mark.parametrize(
    "captured_history", ["duplicates_trailing_slash"], indirect=True
)
@pytest.mark.parametrize(
    "mutation", ["missing_no_slash_import", "missing_duplicate", "disguised_import"]
)
def test_ancestor_does_not_replace_an_imported_record(
    helper, captured_history, mutation
):
    path, messages = captured_history
    if mutation == "missing_duplicate":
        messages.pop(0)
    elif mutation == "missing_no_slash_import":
        messages.pop()
    else:
        messages[-1]["type"] = "0"
        messages[-1]["responseHeader"] = "HTTP/1.0 0\r\n\r\n"
        messages[-1]["responseBody"] = ""
    with pytest.raises(ValueError, match="recorded entries not imported"):
        helper.history(path)


@pytest.mark.parametrize(
    "captured_history", ["duplicates_trailing_slash"], indirect=True
)
@pytest.mark.parametrize(
    "replacement", ["/app/data/", "/app//data", "/app/data?item=one", "/app/other"]
)
def test_directory_ancestor_requires_exact_recorded_parent(
    helper, captured_history, replacement
):
    path, messages = captured_history
    ancestor = next(
        message
        for message in messages
        if message["type"] == "0" and "/app/data HTTP" in message["requestHeader"]
    )
    ancestor["requestHeader"] = ancestor["requestHeader"].replace(
        "/app/data HTTP", replacement + " HTTP"
    )
    with pytest.raises(ValueError, match="non-import/non-ancestor"):
        helper.history(path)
