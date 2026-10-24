"""Standalone pinned-container helper; only loopback proxy/API sockets exist here."""

from __future__ import annotations

import base64
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request

ROOT = Path("/proof")
RPC = ROOT / "rpc"
LOCK = threading.Lock()
SEQUENCE = 0


def _write(path: Path, value: object) -> None:
    temporary = path.with_suffix(".tmp-json")
    temporary.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")
    temporary.replace(path)


class FileProxy(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def handle_one_request(self):
        self.raw_requestline = b""
        self._request_accounted = False
        try:
            super().handle_one_request()
        finally:
            if self.raw_requestline and not self._request_accounted:
                FileProxy._register(self, None)
                self.close_connection = True

    def _register(self, request: bytes | None) -> tuple[int, str | None]:
        global SEQUENCE
        method = getattr(self, "command", "unparsed")
        method = method[:32] if isinstance(method, str) and method else "unparsed"
        with LOCK:
            SEQUENCE += 1
            sequence = SEQUENCE
            if request is None:
                reason = "proxy-http-rejected"
            elif method != "GET":
                reason = "proxy-method-denied"
            elif ((RPC / "STOP").exists() or len(request) > 65536 or self.headers.get_all("Transfer-Encoding")
                  or self.headers.get_all("Content-Length", []) not in ([], ["0"])):
                reason = "proxy-input-cap-or-stop"
            else:
                reason = None
            if sequence > 500:
                reason = "proxy-request-cap"
            if reason and sequence <= 500:
                _write(RPC / f"{sequence:06d}.denied", {"sequence": sequence, "method": method, "reason": reason})
            elif reason and sequence == 501:
                cap_record = RPC / "000500.denied"
                prior_denial = json.loads(cap_record.read_text(encoding="utf-8")) if cap_record.exists() else None
                _write(cap_record, {"sequence": sequence, "method": method, "reason": reason,
                                    "prior_denial": prior_denial})
            if reason in ("proxy-http-rejected", "proxy-method-denied", "proxy-request-cap") and not (RPC / "STOP").exists():
                (RPC / "STOP").touch(exist_ok=True)
        return sequence, reason

    def do_GET(self):
        self.close_connection = True
        self.connection.settimeout(10)
        request = (f"{self.command} {self.path} {self.request_version}\r\n" +
                   "".join(f"{name}: {value}\r\n" for name, value in self.headers.items()) + "\r\n").encode("latin-1")
        sequence, reason = FileProxy._register(self, request)
        self._request_accounted = True
        if reason:
            self.send_error(503)
            return
        prefix = RPC / f"{sequence:06d}"
        temporary = prefix.with_suffix(".tmp")
        temporary.write_bytes(base64.b64encode(self.path.encode()) + b"\n" + base64.b64encode(request) + b"\n")
        temporary.replace(prefix.with_suffix(".req"))
        deadline = time.monotonic() + 30
        response = prefix.with_suffix(".resp")
        while not response.exists() and time.monotonic() < deadline and not (RPC / "STOP").exists():
            time.sleep(0.01)
        if not response.exists() or response.stat().st_size > 2000000:
            self.send_error(504)
            return
        parts = response.read_bytes().splitlines()
        if len(parts) != 2 or parts[0] == b"ERROR":
            self.send_error(502)
            return
        self.connection.sendall(base64.b64decode(parts[0], validate=True) + base64.b64decode(parts[1], validate=True))

    do_HEAD = do_GET
    do_POST = do_GET
    do_PUT = do_GET
    do_PATCH = do_GET
    do_DELETE = do_GET
    do_OPTIONS = do_GET
    do_TRACE = do_GET
    do_CONNECT = do_GET

    def log_message(self, *_arguments):
        pass


def api(endpoint: str, **parameters):
    url = "http://127.0.0.1:8080/JSON/" + endpoint + "/?" + urllib.parse.urlencode(parameters)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(url, timeout=5) as response:
        raw = response.read(1000001)
    if len(raw) > 1000000:
        raise ValueError("Consumer API response cap")
    return json.loads(raw)


def _action(endpoint: str, **parameters):
    if api(endpoint, **parameters) != {"Result": "OK"}:
        raise ValueError("Consumer control action rejected")


def inventory() -> dict:
    version = api("core/view/version").get("version")
    installed = api("autoupdate/view/installedAddons").get("installedAddons")
    if not isinstance(installed, list) or len(installed) > 500:
        raise ValueError("Invalid pinned add-on inventory")
    versions = {item["id"]: str(item["version"]) for item in installed}
    if version != "2.17.0" or versions.get("network") != "0.30.0" or versions.get("ascanrules") != "84.0.0":
        raise ValueError("Pinned ZAP/core/network/active-rule version drift")
    return {"version": version, "addons": versions}


def configure(port: int) -> dict:
    _action("network/action/setHttpProxy", host="127.0.0.1", port=port)
    exclusions = api("network/view/getHttpProxyExclusions")["getHttpProxyExclusions"]
    if not isinstance(exclusions, list) or len(exclusions) > 500:
        raise ValueError("Invalid proxy exclusions")
    for entry in exclusions:
        _action("network/action/removeHttpProxyExclusion", host=entry["host"])
    for endpoint, parameters in (
            ("setHttpProxyAuthEnabled", {"enabled": "false"}), ("setSocksProxyEnabled", {"enabled": "false"}),
            ("setUseGlobalHttpState", {"use": "false"}), ("setHttpProxyEnabled", {"enabled": "true"})):
        _action("network/action/" + endpoint, **parameters)
    state = {"proxy": api("network/view/getHttpProxy")["getHttpProxy"],
             "enabled": api("network/view/isHttpProxyEnabled")["isHttpProxyEnabled"],
             "excluded": api("network/view/getHttpProxyExclusions")["getHttpProxyExclusions"]}
    if (state["enabled"] not in (True, "true") or state["excluded"] != []
            or state["proxy"]["host"] != "127.0.0.1" or int(state["proxy"]["port"]) != port):
        raise ValueError("Consumer outgoing proxy read-back differs")
    state["disabled"] = {}
    for option in ("isSocksProxyEnabled", "isHttpProxyAuthEnabled", "isUseGlobalHttpState"):
        if api("network/view/" + option)[option] not in (False, "false"):
            raise ValueError("Consumer bypass control read-back differs")
        state["disabled"][option] = True
    state["enabled"] = True
    return state


def _ready(seconds: float):
    deadline = time.monotonic() + min(seconds, 80)
    while time.monotonic() < deadline and not (RPC / "STOP").exists():
        try:
            if api("core/view/version").get("version"):
                return
        except (OSError, ValueError):
            time.sleep(0.2)
    raise ValueError("Consumer readiness deadline or cancellation")


def _plan(path: str, seconds: float):
    plan_id = api("automation/action/runPlan", filePath=path)["planId"]
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline and not (RPC / "STOP").exists():
        progress = api("automation/view/planProgress", planId=plan_id)
        if progress.get("finished"):
            _write(ROOT / "plan-progress.json", progress)
            if progress.get("errors") or progress.get("warnings"):
                raise ValueError("Owned active plan errors or warnings")
            return
        time.sleep(0.2)
    raise ValueError("Consumer plan deadline or cancellation")


def main() -> None:
    configuration = json.loads(Path(sys.argv[2]).read_bytes())
    seconds = configuration["seconds"]
    if type(seconds) not in (int, float) or not 0 < seconds <= 300:
        raise ValueError("Consumer duration cap")
    proxy = ThreadingHTTPServer(("127.0.0.1", 0), FileProxy)
    proxy.daemon_threads = True
    thread = threading.Thread(target=proxy.serve_forever, daemon=True)
    thread.start()
    process = subprocess.Popen(["zap.sh", "-Xmx512m", "-daemon", "-silent", "-host", "127.0.0.1", "-port", "8080",
               "-config", "api.disablekey=true", "-config", "autoupdate.checkOnStart=false",
               "-config", "autoupdate.checkAddonUpdates=false", "-config", "callhome.tel.enabled=false"])
    try:
        _ready(seconds)
        metadata = {"inventory": inventory(), "proxy": configure(proxy.server_port)}
        _write(RPC / "READY", metadata)
        _plan(sys.argv[1], seconds)
    finally:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        proxy.shutdown()
        proxy.server_close()
        thread.join(timeout=5)


if __name__ == "__main__":
    main()
