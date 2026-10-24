"""Inspected Windows Community installation; profile data cannot choose commands."""

from __future__ import annotations

import ctypes
import hashlib
import ipaddress
from pathlib import Path
import re
import socket
import stat
import struct
import sys

from bughunt.core import exchange, ledger
from bughunt.integrations import burp_transport

VERSIONS = {"community": "2026.9.2", "bapp": "1.3.0", "server": "1.1.2"}
TOOLS_SHA256 = "8df4944a5b4adc2d83c87225979c666a7b142da423980cdb3b9ba864c82540b5"
FINGERPRINTS = {
    "burp": "6e9bf05a682c083948f7bc10a455a2e8849c4ad845e16b5d921090919045be7a",
    "java": "a802ecc238d9de7e8d3446bbb159eb149104ec13383a018f3683ccbd45c83741",
    "proxy": "b376b860f114f67e8301e50b06760f1edd23dd99e860c3646cbeac144ce7821a",
    "bapp": "f93e434a9154fbb03bc9b20e46555fc901be57a80ec63d607d9cde192d27691c",
}
NAMES = {"burp": "burpsuite.jar", "java": "java.exe", "proxy": "mcp-proxy-all.jar", "bapp": "burp-mcp-all.jar"}


def local_path(path: Path) -> None:
    if not path.is_absolute() or str(path).replace("\\", "/").startswith("//"):
        raise ValueError("Absolute local inspected path required")
    for part in path.parts[1:]:
        if (part == ".." or ":" in part or part.endswith((".", " "))
                or re.fullmatch(r"CON|PRN|AUX|NUL|CONIN\$|CONOUT\$|COM[1-9¹²³]|LPT[1-9¹²³]",
                                part.split(".")[0].rstrip(" "), re.IGNORECASE)):
            raise ValueError("Unsupported inspected path namespace")
    if sys.platform == "win32":
        if not re.fullmatch(r"[A-Za-z]:", path.drive):
            raise ValueError("Local volume drive required")
        operation = ctypes.WinDLL("kernel32.dll", winmode=0x800).QueryDosDeviceW
        operation.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_ulong]
        operation.restype = ctypes.c_ulong
        buffer = ctypes.create_unicode_buffer(4096)
        length = operation(path.drive, buffer, len(buffer))
        if not 2 <= length <= len(buffer) or not re.fullmatch(r"\\Device\\HarddiskVolume[0-9]+", buffer.value):
            raise ValueError("Inspected path is not on an identified local volume")


def inspect_path(path: Path, *, missing=False):
    local_path(path)
    metadata = None
    for current in (*reversed(path.parents), path):
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            if missing:
                return None
            raise
        if stat.S_ISLNK(metadata.st_mode) or getattr(metadata, "st_file_attributes", 0) & 0x400:
            raise ValueError("Inspected path redirected")
    return metadata


def configured_file(path: Path) -> bool:
    try:
        return stat.S_ISREG(inspect_path(path).st_mode)
    except (OSError, ValueError):
        return False


def private_file(path: Path, maximum: int) -> bytes:
    metadata = inspect_path(path)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > maximum:
        raise ValueError("Inspected file exceeds bound")
    with path.open("rb") as handle:
        raw = handle.read(maximum + 1)
    if len(raw) > maximum:
        raise ValueError("Inspected file grew beyond bound")
    return raw


def fingerprint(path: Path) -> str:
    before = inspect_path(path)
    if not stat.S_ISREG(before.st_mode) or before.st_size > 256 * 1024 * 1024:
        raise ValueError("Invalid component path/size")
    size, digest = 0, hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(65536):
            size += len(chunk)
            if size > 256 * 1024 * 1024:
                raise ValueError("Component grew beyond bound")
            digest.update(chunk)
    after = inspect_path(path)
    if (before.st_size, before.st_mtime_ns, before.st_ino) != (after.st_size, after.st_mtime_ns, after.st_ino):
        raise ValueError("Component changed while fingerprinting")
    return digest.hexdigest()


def load(path: Path) -> dict:
    raw = private_file(path, ledger.CAPTURE_LIMIT)
    value = exchange.load_json(raw)
    if (not isinstance(value, dict) or set(value) != {"schema_version", "endpoint", "versions", "files", "tools_sha256"}
            or value["schema_version"] != 1 or value["versions"] != VERSIONS
            or not isinstance(value["files"], dict) or set(value["files"]) != set(FINGERPRINTS)
            or value["tools_sha256"] != TOOLS_SHA256):
        raise ValueError("Unsupported inspected Community profile")
    burp_transport.endpoint(value["endpoint"])
    for role, name in NAMES.items():
        component = Path(value["files"][role])
        if component.name != name or fingerprint(component) != FINGERPRINTS[role]:
            raise ValueError("Installed Community component differs from inspected profile")
    return value


def stamps(profile: dict, path: Path) -> tuple:
    paths = [path, Path(__file__), Path(burp_transport.__file__), Path(sys.executable)]
    paths.extend(Path(value) for value in profile["files"].values())
    for file in paths:
        local_path(file)
    metadata = [(file, inspect_path(file)) for file in paths]
    if any(not stat.S_ISREG(value.st_mode) for _file, value in metadata):
        raise ValueError("Inspected components must be regular files")
    return tuple((str(file), value.st_size, value.st_mtime_ns, value.st_ino) for file, value in metadata)


def _tcp_table(family: int) -> bytes:
    library = ctypes.WinDLL("iphlpapi.dll", winmode=0x800)
    operation = library.GetExtendedTcpTable
    operation.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong), ctypes.c_bool,
                          ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong]
    operation.restype = ctypes.c_ulong
    size = ctypes.c_ulong(0)
    result = operation(None, ctypes.byref(size), False, family, 3, 0)
    if result not in {0, 122} or not 4 <= size.value <= ledger.CAPTURE_LIMIT:
        raise ValueError("Local listener inspection unavailable")
    buffer = ctypes.create_string_buffer(size.value)
    if operation(buffer, ctypes.byref(size), False, family, 3, 0) != 0:
        raise ValueError("Local listener inspection changed")
    return buffer.raw[:size.value]


def _listeners(raw: bytes, family: int, port: int) -> list[dict]:
    layout = struct.Struct("<6I" if family == 2 else "<16sII16sIIII")
    count = struct.unpack_from("<I", raw)[0]
    if count > 8192 or 4 + count * layout.size > len(raw):
        raise ValueError("Invalid listener table")
    result = []
    for index in range(count):
        row = layout.unpack_from(raw, 4 + index * layout.size)
        if socket.ntohs(row[2] & 65535) == port:
            address = str(ipaddress.ip_address(struct.pack("<I", row[1]) if family == 2 else row[0]))
            result.append({"address": address, "port": port, "pid": row[5] if family == 2 else row[7]})
    return result


def listener(profile: dict) -> dict:
    if sys.platform != "win32":
        raise ValueError("This inspected Community listener profile supports Windows only")
    _host, port = burp_transport.endpoint(profile["endpoint"])
    values = _listeners(_tcp_table(2), 2, port) + _listeners(_tcp_table(23), 23, port)
    if len(values) != 1 or values[0]["address"] != "127.0.0.1" or values[0]["pid"] <= 0:
        raise ValueError("Burp missing, multiply bound or remotely exposed")
    return values[0]


def summary(profile: dict) -> dict:
    return {"profile_id": "burp-mcp-intake", "versions": profile["versions"],
        "fingerprints": dict(FINGERPRINTS), "transport": "Bughunt fixed read-only stdio-to-SSE bridge",
        "endpoint": profile["endpoint"], "tools_sha256": profile["tools_sha256"],
        "tool_allowlist": [burp_transport.HISTORY], "configured": True,
        "connected": False, "loaded": "unverified until protocol handshake",
        "peer_authentication": "none; loopback placement is not cryptographic authentication",
        "request_execution": False, "claim": "Local installed fingerprints, not runtime edition attestation"}
