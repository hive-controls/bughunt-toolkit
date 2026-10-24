"""Opt-in ZAP 2.17.0 consumer contract; owned recordings, no container network."""

import json
import os
from pathlib import Path
import subprocess
import time
import uuid

import pytest

from bughunt.core import exchange, ledger
from bughunt.integrations import zap, zap_import
from test_gate import seed_policy
from test_zap import fixture_records

pytestmark = pytest.mark.skipif(os.environ.get("BUGHUNT_ZAP_INTEGRATION") != "1",
                                reason="opt-in pinned Docker/ZAP consumer contract")


def docker(*args, timeout=60) -> str:
    result = subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise AssertionError(f"Docker contract failed: {result.stderr[-3000:]} {result.stdout[-3000:]}")
    return result.stdout.strip()


def api(container: str, endpoint: str, **parameters):
    script = ("import json,urllib.request,urllib.parse; "
              "url='http://127.0.0.1:8080/JSON/'+" + repr(endpoint) + "+'/?'+urllib.parse.urlencode(" +
              repr(parameters) + "); print(urllib.request.urlopen(url,timeout=10).read().decode())")
    return json.loads(docker("exec", container, "python", "-c", script, timeout=20))


@pytest.fixture
def consumer():
    name = "whk008-contract-" + uuid.uuid4().hex[:12]
    docker("run", "-d", "--rm", "--name", name, "--network", "none", "--hostname", "whk008-zap",
           "--add-host", "whk008-zap:127.0.0.1", "--memory", "2g",
           zap.SUPPORTED_IMAGE, "zap.sh", "-Xmx512m", "-daemon", "-host", "127.0.0.1", "-port", "8080",
           "-config", "api.disablekey=true", "-config", "autoupdate.checkOnStart=false",
           "-config", "autoupdate.checkAddonUpdates=false")
    try:
        deadline = time.monotonic() + 100
        while time.monotonic() < deadline:
            try:
                if api(name, "core/view/version")["version"] == zap.SUPPORTED_VERSION:
                    break
            except (AssertionError, KeyError):
                time.sleep(1)
        else:
            raise AssertionError("Pinned consumer did not become ready")
        assert json.loads(docker("inspect", name))[0]["HostConfig"]["NetworkMode"] == "none"
        yield name
    finally:
        docker("stop", name)


def copy_bundle(container, output):
    docker("cp", str(output), f"{container}:/tmp/whk008-bundle")
    docker("exec", "--user", "root", container, "chown", "-R", "zap:zap", "/tmp/whk008-bundle")


def wait_plan(container, plan_id):
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        progress = api(container, "automation/view/planProgress", planId=plan_id)
        if progress.get("finished"):
            return progress
        time.sleep(1)
    raise AssertionError(f"Passive plan exceeded external fixture deadline: {progress}")


def test_supported_context_and_passive_report(consumer, monkeypatch, tmp_path):
    monkeypatch.setenv("BUGHUNT_SCOPE", str(tmp_path))
    seed_policy(tmp_path)
    (tmp_path / "scope.txt").write_text("allowed.example\n")
    records = [owned_html_record(fixture_records(tmp_path)[0])]
    ids = exchange.save(records, source_id="owned-runtime", source_bytes=b"fixture", kind="raw")
    output = tmp_path / "bundle"
    zap.export(ids, ["owner", "guest"], output)
    # Consumer filesystem mapping, not a change to traffic-generation authority.
    plan = json.loads((output / "plan.yaml").read_text())
    plan["env"]["vars"]["BUGHUNT_BUNDLE_DIR"] = "/tmp/whk008-bundle"
    (output / "plan.yaml").write_text(json.dumps(plan))
    copy_bundle(consumer, output)
    check = docker("exec", consumer, "zap.sh", "-Xmx512m", "-cmd", "-host", "127.0.0.1", "-port", "8081", "-dir", "/tmp/whk008-check",
                   "-autocheck", "/tmp/whk008-bundle/plan.yaml", "-config", "autoupdate.checkOnStart=false",
                   "-config", "autoupdate.checkAddonUpdates=false", timeout=60)
    assert "Using JVM args: -Xmx512m" in check, check
    assert api(consumer, "core/action/setMode", mode="protect")["Result"] == "OK"
    assert api(consumer, "core/view/mode")["mode"] == "protect"
    assert "contextId" in api(consumer, "context/action/importContext", contextFile="/tmp/whk008-bundle/context.context")
    check_context(consumer)
    run = api(consumer, "automation/action/runPlan", filePath="/tmp/whk008-bundle/plan.yaml")
    progress = wait_plan(consumer, run["planId"])
    assert not progress.get("error"), progress
    assert not progress.get("errors"), progress
    assert not progress.get("warn"), progress
    check_context(consumer)
    assert api(consumer, "core/view/mode")["mode"] == "protect"
    report = json.loads(docker("exec", consumer, "python", "-c",
                              "print(open('/tmp/whk008-bundle/reports/passive-report.json').read())"))
    assert report["@version"] == zap.SUPPORTED_VERSION
    assert report["site"][0]["@name"] == "https://allowed.example"
    check_report_import(report, records)
    history = api(consumer, "core/view/urls")["urls"]
    # urls is the Sites tree, including ancestor nodes; count actual history messages separately.
    assert set(history) == {"https://allowed.example", "https://allowed.example/app",
                            "https://allowed.example/app/data"}
    messages = api(consumer, "core/view/messages", start=0, count=10)["messages"]
    imported = [message for message in messages if message["type"] == "15"]
    assert len(imported) == 1 and "Owned passive fixture" in imported[0]["responseBody"]
    assert imported[0]["requestHeader"].startswith("GET https://allowed.example/app/data HTTP/1.1")
    assert all(message["type"] == "15" or (message["type"] == "0" and
               message["responseHeader"] == "HTTP/1.0 0\r\n\r\n") for message in messages)
    assert "fixture-private-secret" not in json.dumps(report)


def owned_html_record(original):
    body = b"<html><head><title>Owned passive fixture</title></head><body>owned</body></html>"
    response = (b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: " +
                str(len(body)).encode() + b"\r\n\r\n" + body)
    return exchange.raw_record(exchange.decode(original["request"]["raw_b64"]), response,
                               source_id="whk009-owned-passive")


def check_report_import(report, records):
    run_id = zap_import.import_report(exchange.canonical(report), source_id="whk009-zap-2.17.0", records=records)
    exported = ledger.export_run(run_id)
    observations = exported["artifacts"]["observations.json"]["value"]["observations"]
    assert observations, "Owned HTML must produce real passive report observations"
    assert all(value["hypothesis_level"] == 1 and value["confirmed"] is False for value in observations)
    assert any(records[0]["exchange_id"] in value["source_exchange_candidates"] for value in observations)
    assert all(value["current_scope"]["permitted"] for value in observations)
    assert "fixture-private-secret" not in json.dumps(exported)


def check_context(container):
    context = api(container, "context/view/context", contextName=zap.CONTEXT_NAME)["context"]
    includes = api(container, "context/view/includeRegexs", contextName=zap.CONTEXT_NAME)["includeRegexs"]
    excludes = api(container, "context/view/excludeRegexs", contextName=zap.CONTEXT_NAME)["excludeRegexs"]
    assert isinstance(includes, list) and isinstance(excludes, list), context
    # Evaluate consumer-owned Java regexes, not Python's stand-in alone.
    source = ("import java.util.*; public class ScopeCheck { public static void main(String[] a) { "
              "String[] inc=" + java_array(includes) + "; String[] exc=" + java_array(excludes) + "; "
              'String[] paths={"/app/data","/exact","/exact/more","/app/logout","/app/admin/secret",'
              '"/app//x","/app/../x","/app/%2e/x","/other"}; '
              "for(String p:paths) { String u=\"https://allowed.example\"+p; "
              "System.out.println(p+\":\"+(Arrays.stream(inc).anyMatch(u::matches) && "
              "!Arrays.stream(exc).anyMatch(u::matches))); } } }")
    docker("exec", container, "python", "-c", "open('/tmp/ScopeCheck.java','w').write(" + repr(source) + ")")
    result = docker("exec", container, "java", "/tmp/ScopeCheck.java")
    assert result.splitlines() == ["/app/data:true", "/exact:true", "/exact/more:false", "/app/logout:false",
                                  "/app/admin/secret:false", "/app//x:false", "/app/../x:false",
                                  "/app/%2e/x:false", "/other:false"]
    users = api(container, "users/view/usersList", contextId=context["id"])["usersList"]
    assert {user["name"] for user in users} == {"owner", "guest"}
    assert all(json.loads(user["credentials"]) == {"sessionName": "", "type": "ManualAuthenticationCredentials"}
               for user in users), users
    method = api(container, "authentication/view/getAuthenticationMethod", contextId=context["id"])
    assert "manual" in json.dumps(method).lower()
    assert api(container, "authentication/view/getLoggedInIndicator", contextId=context["id"])["logged_in_regex"] == zap.LOGGED_IN


def java_array(values):
    return "new String[]{" + ",".join(json.dumps(value) for value in values) + "}"
