"""Hermetic parser/backend tests for bughunt.core.route_probe."""
import json
import socket
import struct
import sys

import pytest

import route_macos_fixtures as mac
from bughunt.core import route_probe as rp

LINUX_LINKS = json.dumps([
    {"ifindex": 1, "ifname": "lo", "flags": ["LOOPBACK", "UP", "LOWER_UP"], "operstate": "UNKNOWN"},
    {"ifindex": 2, "ifname": "eth0", "flags": ["BROADCAST", "MULTICAST", "UP", "LOWER_UP"], "operstate": "UP"},
    {"ifindex": 5, "ifname": "wg0", "flags": ["POINTOPOINT", "NOARP", "UP", "LOWER_UP"],
     "operstate": "UNKNOWN", "linkinfo": {"info_kind": "wireguard"}},
    {"ifindex": 6, "ifname": "tun1", "flags": ["POINTOPOINT", "NOARP"], "operstate": "DOWN",
     "linkinfo": {"info_kind": "tun"}},
])
LINUX_ROUTE_WG = json.dumps([{"dst": "1.1.1.1", "dev": "wg0", "prefsrc": "10.0.0.2", "flags": [], "uid": 0}])


def fake_runner(table):
    def runner(command):
        key = tuple(command)
        if key not in table:
            raise rp.ProbeError(f"unexpected command {key}")
        return table[key]
    return runner


# ------------------------------------------------------------------ Linux

def test_linux_links_use_flags_not_operstate_and_info_kind_as_description():
    links = {item.name: item for item in rp.parse_linux_links(LINUX_LINKS)}
    assert links["wg0"].up and links["wg0"].description == "wireguard"
    assert links["lo"].up  # operstate UNKNOWN but flag UP
    assert not links["tun1"].up
    assert links["eth0"].index == 2


def test_linux_route_device_and_probe_end_to_end():
    probe = rp.LinuxProbe(fake_runner({
        ("ip", "-j", "-d", "link", "show"): LINUX_LINKS,
        ("ip", "-j", "route", "get", "1.1.1.1"): LINUX_ROUTE_WG,
    }))
    assert probe.egress_indexes("1.1.1.1") == {5}
    assert {item.name for item in probe.interfaces()} == {"lo", "eth0", "wg0", "tun1"}


@pytest.mark.parametrize("text", ["not json", "{}", "[]", json.dumps([{"dev": "a"}, {"dev": "b"}]), json.dumps([{"dst": "x"}])])
def test_linux_route_device_rejects_bad_shapes(text):
    with pytest.raises(rp.ProbeError):
        rp.parse_linux_route_device(text)


def test_linux_links_reject_missing_fields():
    with pytest.raises(rp.ProbeError):
        rp.parse_linux_links(json.dumps([{"ifname": "x"}]))


def test_linux_unknown_device_is_error():
    probe = rp.LinuxProbe(fake_runner({
        ("ip", "-j", "-d", "link", "show"): LINUX_LINKS,
        ("ip", "-j", "route", "get", "9.9.9.9"): json.dumps([{"dev": "ghost0"}]),
    }))
    with pytest.raises(rp.ProbeError):
        probe.egress_indexes("9.9.9.9")


def test_missing_tool_is_probe_error():
    with pytest.raises(rp.ProbeError):
        rp.run_tool(["bughunt-definitely-not-a-real-tool"])


def test_nonzero_exit_is_probe_error():
    with pytest.raises(rp.ProbeError):
        rp.run_tool([sys.executable, "-c", "import sys; sys.exit(3)"])


# ------------------------------------------------------------------ macOS (real captured bytes)

def test_macos_route_interface_parses_real_capture():
    assert rp.parse_macos_route_interface(mac.ROUTE_PUBLIC) == "en0"
    assert rp.parse_macos_route_interface(mac.ROUTE_LOOPBACK) == "lo0"
    assert rp.parse_macos_route_interface(mac.ROUTE_V6_LOOPBACK) == "lo0"


def test_macos_ifconfig_flags_parse_real_capture():
    assert rp.parse_macos_ifconfig_up(mac.IFCONFIG_EN0)
    assert rp.parse_macos_ifconfig_up(mac.IFCONFIG_LO0)
    assert rp.parse_macos_ifconfig_up(mac.IFCONFIG_UTUN4)


def test_macos_ifconfig_down_and_malformed():
    assert not rp.parse_macos_ifconfig_up("utun9: flags=8010<POINTOPOINT,MULTICAST> mtu 1380\n")
    with pytest.raises(rp.ProbeError):
        rp.parse_macos_ifconfig_up("garbage")
    with pytest.raises(rp.ProbeError):
        rp.parse_macos_route_interface("route: writing to routing socket: not in table")


def test_macos_probe_with_captured_outputs():
    indexes = {"lo0": 1, "en0": 11, "utun4": 21}
    commands = {
        ("ifconfig", "-l"): "lo0 en0 utun4\n",
        ("ifconfig", "lo0"): mac.IFCONFIG_LO0,
        ("ifconfig", "en0"): mac.IFCONFIG_EN0,
        ("ifconfig", "utun4"): mac.IFCONFIG_UTUN4,
        ("route", "-n", "get", "1.1.1.1"): mac.ROUTE_PUBLIC,
        ("route", "-n", "get", "-inet6", "::1"): mac.ROUTE_V6_LOOPBACK,
    }
    probe = rp.MacOSProbe(fake_runner(commands), indexes.__getitem__)
    assert [(i.name, i.index, i.up) for i in probe.interfaces()] == [("lo0", 1, True), ("en0", 11, True), ("utun4", 21, True)]
    assert probe.egress_indexes("1.1.1.1") == {11}
    assert probe.egress_indexes("::1") == {1}


def test_macos_route_failure_propagates():
    def runner(command):
        raise rp.ProbeError("route exited 1: not in table")
    with pytest.raises(rp.ProbeError):
        rp.MacOSProbe(runner, lambda name: 1).egress_indexes("2606:4700:4700::1111")


@pytest.mark.skipif(sys.platform != "darwin", reason="live macOS smoke")
def test_macos_live_smoke_loopback_uses_loopback_index():
    probe = rp.MacOSProbe()
    assert probe.egress_indexes("127.0.0.1") == {socket.if_nametoindex("lo0")}
    assert any(item.name == "lo0" and item.up for item in probe.interfaces())


# ------------------------------------------------------------------ Windows helpers

def test_build_sockaddr_ipv4_bytes():
    raw = rp.build_sockaddr("1.1.1.1")
    assert len(raw) == 16 and raw == struct.pack("<H", 2) + b"\x00\x00" + bytes([1, 1, 1, 1]) + b"\x00" * 8


def test_build_sockaddr_ipv6_bytes_and_scope_stripped():
    raw = rp.build_sockaddr("fe80::1%12")
    assert len(raw) == 28 and raw[:2] == struct.pack("<H", 23)
    assert raw[8:24] == socket.inet_pton(socket.AF_INET6, "fe80::1")


def test_build_sockaddr_rejects_non_ip():
    with pytest.raises(ValueError):
        rp.build_sockaddr("example.com")


@pytest.mark.skipif(sys.platform != "win32", reason="Windows ctypes smoke")
def test_windows_live_smoke():
    probe = rp.WindowsProbe()
    assert probe.interfaces()
    assert len(probe.egress_indexes("127.0.0.1")) == 1


# ------------------------------------------------------------------ selection

def test_default_probe_unsupported_platform_fails_closed():
    with pytest.raises(rp.ProbeError, match="not supported"):
        rp.default_probe("plan9")


def test_default_probe_selects_backend():
    assert isinstance(rp.default_probe("linux"), rp.LinuxProbe)
    assert isinstance(rp.default_probe("darwin"), rp.MacOSProbe)
