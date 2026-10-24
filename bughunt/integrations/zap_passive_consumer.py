"""Standalone passive-only helper inside the pinned, network-disabled consumer."""

from __future__ import annotations

import json
import hashlib
from collections import Counter
from pathlib import Path
import subprocess
import sys
import time
from urllib.parse import urlsplit

import zap_consumer as common


def validate_plan(path: Path) -> None:
    plan = json.loads(path.read_bytes())
    if (
        [item["type"] for item in plan["jobs"]]
        != ["passiveScan-config", "import", "passiveScan-wait", "report"]
        or plan["jobs"][1]["parameters"]["sendRequests"] is not False
        or plan["jobs"][1]["parameters"]["type"] != "har"
        or plan["jobs"][1]["parameters"]["fileName"]
        != "${BUGHUNT_BUNDLE_DIR}/traffic.har"
        or plan["env"]["vars"] != {"BUGHUNT_BUNDLE_DIR": "/bughunt/input"}
        or plan["jobs"][-1]["parameters"]["template"] != "traditional-json"
        or plan["jobs"][-1]["parameters"]["reportDir"] != "/reports"
        or plan["jobs"][-1]["parameters"]["displayReport"] is not False
    ):
        raise ValueError("Unsupported passive-only plan")
    for context in plan["env"]["contexts"]:
        if context["authentication"]["method"] != "manual" or any(
            set(user) != {"name"} for user in context["users"]
        ):
            raise ValueError("Passive plan cannot log in or hold credentials")


def approve(seconds: int) -> None:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline and not (common.RPC / "STOP").exists():
        if (common.RPC / "APPROVED").exists():
            return
        time.sleep(0.02)
    raise ValueError("Passive host approval deadline or cancellation")


def _recordings(path: Path) -> tuple[Counter, set[str]]:
    entries = json.loads(path.read_bytes())["log"]["entries"]
    if not isinstance(entries, list) or not 1 <= len(entries) <= 500:
        raise ValueError("Passive recorded-entry cap")
    expected, ancestors = Counter(), set()
    for entry in entries:
        request = entry["request"]
        expected[(request["method"], request["url"], entry["response"]["status"])] += 1
        parsed = urlsplit(request["url"])
        origin = parsed.scheme + "://" + parsed.netloc
        parts = parsed.path.strip("/").split("/") if parsed.path.strip("/") else []
        headers = "".join(
            f"{item['name']}: {item['value']}\r\n"
            for item in request["headers"]
            if item["name"].lower() not in {"content-type", "content-length"}
        )
        ancestor_count = len(parts) + int(parsed.path.endswith("/"))
        for length in range(max(1, ancestor_count)):
            target = origin + ("/" + "/".join(parts[:length]) if length else "")
            raw = f"GET {target} {request['httpVersion']}\r\n" + headers + "\r\n"
            ancestors.add(hashlib.sha256(raw.encode()).hexdigest())
    return expected, ancestors


def _diagnosis(
    anomalies: list, unique_ids: int, count: int, observed: Counter, expected: Counter
) -> str:
    """Name which fail-closed condition tripped, secret-free: entry lines are truncated and
    the recording/import correspondence is reported as counts only, never URLs."""
    reasons = []
    if anomalies:
        reasons.append(
            f"{len(anomalies)} non-import/non-ancestor entries: "
            + "; ".join(anomalies[:10])
        )
    if unique_ids != count:
        reasons.append(f"history id correspondence: {unique_ids} unique of {count}")
    if observed != expected:
        missing = sum((expected - observed).values())
        extra = sum((observed - expected).values())
        reasons.append(
            "imported traffic does not match the recording: "
            f"{missing} recorded entries not imported, {extra} imported not recorded"
        )
    return " | ".join(reasons)


def history(traffic_path: Path) -> dict:
    expected, ancestors = _recordings(traffic_path)
    count = int(common.api("core/view/numberOfMessages")["numberOfMessages"])
    if not 0 <= count <= 550:
        raise ValueError("Passive consumer history cap")
    imported, other, unexpected, receipts, observed, anomalies = (
        0,
        0,
        0,
        [],
        Counter(),
        [],
    )
    for index in range(1, count + 1):
        messages = common.api("core/view/messages", start=index, count=1)["messages"]
        if len(messages) != 1:
            raise ValueError("Passive history correspondence")
        message = messages[0]
        receipts.append(
            {
                "id": message["id"],
                "type": message["type"],
                "request_line": message["requestHeader"].splitlines()[0][:512],
                "request_header_sha256": hashlib.sha256(
                    message["requestHeader"].encode()
                ).hexdigest(),
                "response_line": message["responseHeader"].splitlines()[0],
                "response_body_bytes": len(message["responseBody"].encode()),
                "response_body_sha256": hashlib.sha256(
                    message["responseBody"].encode()
                ).hexdigest(),
            }
        )
        if message["type"] == "15":
            imported += 1
            request_parts = message["requestHeader"].splitlines()[0].split(" ", 2)
            status = int(message["responseHeader"].splitlines()[0].split(" ", 2)[1])
            observed[(request_parts[0], request_parts[1], status)] += 1
        else:
            other += 1
            if (
                message["type"] != "0"
                or message["responseHeader"] != "HTTP/1.0 0\r\n\r\n"
                or message["responseBody"] != ""
                or receipts[-1]["request_header_sha256"] not in ancestors
            ):
                unexpected += 1
                anomalies.append(
                    f"id={message['id']} type={message['type']} {receipts[-1]['request_line']!r}"
                )
    unique_ids = len({item["id"] for item in receipts})
    if unexpected or unique_ids != count or observed != expected:
        raise ValueError(
            "Unexpected non-import consumer history: "
            + _diagnosis(anomalies, unique_ids, count, observed, expected)
        )
    return {
        "imported_messages": imported,
        "temporary_ancestor_messages": other,
        "source_correspondence": "URL/method/status; not wire-byte attestation",
        "unexpected_history": unexpected,
        "target_network_enabled": False,
        "history_receipts": receipts,
    }


def retain_report() -> None:
    source = Path("/reports/passive-report.json")
    maximum = 16 * 1024 * 1024
    if source.is_symlink() or source.stat().st_size > maximum:
        raise ValueError("Passive report byte/path cap")
    target = common.ROOT / "reports" / "passive-report.json"
    remaining = maximum
    with source.open("rb") as incoming, target.open("xb") as outgoing:
        while chunk := incoming.read(65536):
            if len(chunk) > remaining:
                raise ValueError("Passive report grew beyond byte cap")
            outgoing.write(chunk)
            remaining -= len(chunk)
    target.chmod(0o600)


def main() -> None:
    path = Path(sys.argv[1])
    seconds = json.loads(Path(sys.argv[2]).read_bytes())["seconds"]
    if type(seconds) is not int or not 1 <= seconds <= 300:
        raise ValueError("Passive duration cap")
    validate_plan(path)
    process = subprocess.Popen(
        [
            "zap.sh",
            "-Xmx512m",
            "-dir",
            "/tmp/whk018-zap",
            "-daemon",
            "-silent",
            "-host",
            "127.0.0.1",
            "-port",
            "8080",
            "-config",
            "api.disablekey=true",
            "-config",
            "autoupdate.checkOnStart=false",
            "-config",
            "autoupdate.checkAddonUpdates=false",
            "-config",
            "callhome.tel.enabled=false",
        ]
    )
    try:
        common._ready(seconds)
        common._action("core/action/setMode", mode="protect")
        metadata = {
            "inventory": common.inventory(),
            "proxy": common.configure(65535),
            "mode": common.api("core/view/mode")["mode"],
            "profile_id": "zap-passive",
        }
        common._write(common.RPC / "READY", metadata)
        approve(seconds)
        common._plan(str(path), seconds)
        common._write(
            common.ROOT / "consumer-metadata.json", history(path.parent / "traffic.har")
        )
        retain_report()
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


if __name__ == "__main__":
    main()
