"""OS routing-table probes for the route gate (stdlib only, no packets sent).

A probe answers two questions: which interfaces exist and are up, and which
interface indexes the OS would use to reach an address. Every failure raises
``ProbeError`` so the caller can fail closed.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import re
import socket
import struct
import subprocess
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Protocol

LOGGER = logging.getLogger(__name__)

_TOOL_TIMEOUT_SECONDS = 10.0
_AF_INET = 2
_AF_INET6_WINDOWS = 23

Runner = Callable[[Sequence[str]], str]


class ProbeError(Exception):
    """The routing table could not be read or interpreted."""


@dataclass(frozen=True)
class Interface:
    index: int
    name: str
    description: str
    up: bool


class RouteProbe(Protocol):
    def interfaces(self) -> list[Interface]: ...

    def egress_indexes(self, address: str) -> set[int]: ...


def run_tool(command: Sequence[str]) -> str:
    """Run a local read-only tool and return stdout; any failure is a ProbeError."""
    try:
        completed = subprocess.run(
            list(command),
            capture_output=True,
            text=True,
            timeout=_TOOL_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise ProbeError(f"cannot run {command[0]}: {error}") from error
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "").strip()
        raise ProbeError(f"{command[0]} exited {completed.returncode}: {detail}")
    return completed.stdout


def _parse_json_list(text: str, tool: str) -> list[dict]:
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as error:
        raise ProbeError(f"{tool} produced invalid JSON: {error}") from error
    if not isinstance(parsed, list) or not all(
        isinstance(item, dict) for item in parsed
    ):
        raise ProbeError(f"{tool} JSON has an unexpected shape")
    return parsed


# ---------------------------------------------------------------- Linux


def parse_linux_links(text: str) -> list[Interface]:
    """Parse ``ip -j -d link show``. Up means ``UP`` in flags, never operstate."""
    interfaces: list[Interface] = []
    for entry in _parse_json_list(text, "ip link"):
        index, name = entry.get("ifindex"), entry.get("ifname")
        if not isinstance(index, int) or not isinstance(name, str):
            raise ProbeError("ip link entry lacks ifindex or ifname")
        flags = entry.get("flags") or []
        linkinfo = entry.get("linkinfo") or {}
        kind = linkinfo.get("info_kind") if isinstance(linkinfo, dict) else None
        interfaces.append(
            Interface(index, name, kind if isinstance(kind, str) else "", "UP" in flags)
        )
    return interfaces


def parse_linux_route_device(text: str) -> str:
    """Parse ``ip -j route get ADDR`` and return the egress device name."""
    entries = _parse_json_list(text, "ip route")
    devices = {entry.get("dev") for entry in entries}
    if len(devices) != 1 or not isinstance(next(iter(devices)), str):
        raise ProbeError("ip route get returned no single egress device")
    return devices.pop()


class LinuxProbe:
    def __init__(self, runner: Runner = run_tool) -> None:
        self._runner = runner

    def interfaces(self) -> list[Interface]:
        return parse_linux_links(self._runner(["ip", "-j", "-d", "link", "show"]))

    def egress_indexes(self, address: str) -> set[int]:
        device = parse_linux_route_device(
            self._runner(["ip", "-j", "route", "get", address])
        )
        matches = {item.index for item in self.interfaces() if item.name == device}
        if not matches:
            raise ProbeError(f"egress device {device} is not in the interface list")
        return matches


# ---------------------------------------------------------------- macOS

_MACOS_INTERFACE_LINE = re.compile(r"^\s*interface:\s*(\S+)\s*$", re.MULTILINE)
_MACOS_FLAGS = re.compile(r"^\S+:\s*flags=[0-9a-fA-F]+<([^>]*)>", re.MULTILINE)


def parse_macos_route_interface(text: str) -> str:
    """Parse ``route -n get ADDR`` and return the ``interface:`` value."""
    match = _MACOS_INTERFACE_LINE.search(text)
    if match is None:
        raise ProbeError("route get output has no interface line (no route?)")
    return match.group(1)


def parse_macos_ifconfig_up(text: str) -> bool:
    """Parse the first ``ifconfig IF`` line; True when the flag list contains UP."""
    match = _MACOS_FLAGS.search(text)
    if match is None:
        raise ProbeError("ifconfig output has no flags line")
    return "UP" in match.group(1).split(",")


class MacOSProbe:
    def __init__(
        self,
        runner: Runner = run_tool,
        name_to_index: Callable[[str], int] = socket.if_nametoindex,
    ) -> None:
        self._runner = runner
        self._name_to_index = name_to_index

    def _index_of(self, name: str) -> int:
        try:
            return self._name_to_index(name)
        except OSError as error:
            raise ProbeError(f"no interface index for {name}: {error}") from error

    def interfaces(self) -> list[Interface]:
        names = self._runner(["ifconfig", "-l"]).split()
        if not names:
            raise ProbeError("ifconfig -l listed no interfaces")
        return [
            Interface(
                self._index_of(name),
                name,
                "",
                parse_macos_ifconfig_up(self._runner(["ifconfig", name])),
            )
            for name in names
        ]

    def egress_indexes(self, address: str) -> set[int]:
        version_flag = ["-inet6"] if ipaddress.ip_address(address).version == 6 else []
        output = self._runner(["route", "-n", "get", *version_flag, address])
        return {self._index_of(parse_macos_route_interface(output))}


# -------------------------------------------------------------- Windows


def build_sockaddr(address: str) -> bytes:
    """Windows SOCKADDR_IN / SOCKADDR_IN6 bytes for an IP literal (pure, any OS)."""
    parsed = ipaddress.ip_address(address.split("%", 1)[0])
    if parsed.version == 4:
        return struct.pack("<HH4s8x", _AF_INET, 0, parsed.packed)
    return struct.pack("<HHI16sI", _AF_INET6_WINDOWS, 0, 0, parsed.packed, 0)


class WindowsProbe:
    """Read Windows adapter state and best-route interfaces through iphlpapi."""

    _OPER_STATUS_UP = 1

    def __init__(self) -> None:
        if sys.platform != "win32":
            raise ProbeError("WindowsProbe requires Windows")
        import ctypes

        self._ctypes = ctypes
        self._iphlpapi = ctypes.WinDLL("iphlpapi.dll", winmode=0x800)

    def _adapter_structure(self):
        ctypes = self._ctypes

        class Adapter(ctypes.Structure):
            pass

        Adapter._fields_ = [
            ("length", ctypes.c_ulong),
            ("if_index", ctypes.c_ulong),
            ("next", ctypes.POINTER(Adapter)),
            ("adapter_name", ctypes.c_char_p),
            ("unicast", ctypes.c_void_p),
            ("anycast", ctypes.c_void_p),
            ("multicast", ctypes.c_void_p),
            ("dns_server", ctypes.c_void_p),
            ("dns_suffix", ctypes.c_wchar_p),
            ("description", ctypes.c_wchar_p),
            ("friendly_name", ctypes.c_wchar_p),
            ("physical", ctypes.c_ubyte * 8),
            ("physical_length", ctypes.c_ulong),
            ("flags", ctypes.c_ulong),
            ("mtu", ctypes.c_ulong),
            ("if_type", ctypes.c_ulong),
            ("oper_status", ctypes.c_ulong),
        ]
        return Adapter

    def interfaces(self) -> list[Interface]:
        ctypes = self._ctypes
        adapter_type = self._adapter_structure()
        size = ctypes.c_ulong(32768)
        for _attempt in range(3):
            buffer = ctypes.create_string_buffer(size.value)
            status = self._iphlpapi.GetAdaptersAddresses(
                0, 0x010F, None, buffer, ctypes.byref(size)
            )
            if status != 111:  # ERROR_BUFFER_OVERFLOW
                break
        if status != 0:
            raise ProbeError(f"GetAdaptersAddresses failed with {status}")
        found: list[Interface] = []
        node = ctypes.cast(buffer, ctypes.POINTER(adapter_type))
        while node:
            adapter = node.contents
            found.append(
                Interface(
                    int(adapter.if_index),
                    adapter.friendly_name or "",
                    adapter.description or "",
                    adapter.oper_status == self._OPER_STATUS_UP,
                )
            )
            node = adapter.next
        return found

    def egress_indexes(self, address: str) -> set[int]:
        ctypes = self._ctypes
        raw = build_sockaddr(address)
        buffer = ctypes.create_string_buffer(raw, len(raw))
        best = ctypes.c_ulong(0)
        status = self._iphlpapi.GetBestInterfaceEx(buffer, ctypes.byref(best))
        if status != 0:
            raise ProbeError(f"GetBestInterfaceEx failed with {status} for {address}")
        return {int(best.value)}


# ------------------------------------------------------------ selection


def default_probe(platform: str | None = None) -> RouteProbe:
    """Backend for this OS; unsupported platforms raise ProbeError (fail closed)."""
    current = platform or sys.platform
    if current.startswith("linux"):
        return LinuxProbe()
    if current == "darwin":
        return MacOSProbe()
    if current == "win32":
        return WindowsProbe()
    raise ProbeError("route verification is not supported on this platform")
