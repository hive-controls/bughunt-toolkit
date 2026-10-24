"""Scan result records, the "speaking" predicate, and the JSON / CSV / Markdown report writers."""

from __future__ import annotations

import csv
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from bughunt import VERSION
from bughunt.core.ledger import redact_text

CSV_COLUMNS = (
    "target",
    "port",
    "scheme",
    "url",
    "final_url",
    "status",
    "server",
    "title",
    "tags",
    "sha256",
    "bytes",
    "ms",
)
SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")
NOISE_WORDS = (
    "timeout",
    "connect",
    "refused",
    "ssl",
    "eof",
    "wrong version",
    "certificate",
    "handshake",
)
MARKDOWN_LIST_LIMITS = {"dns": 8, "ct": 40, "js": 40}


# Field-meaning names for the record classes below; at runtime each one is just the builtin it aliases.
Url = str
HeaderValue = str
PageText = str
Severity = str
ByteCount = int
Millis = float
Seconds = float
AddressList = list[str]


def _list_field():
    """Default for a list-valued field: a fresh empty list for every instance."""
    return field(default_factory=list)


def _dict_field():
    """Default for a dict-valued field: a fresh empty dict for every instance."""
    return field(default_factory=dict)


@dataclass
class TlsInfo:
    """What the TLS probe learned about one HTTPS endpoint; anything it could not read stays empty."""

    version: str = field(default="")
    cipher: str = field(default="")
    subject: str = field(default="")
    issuer: str = field(default="")
    not_before: str = field(default="")
    not_after: str = field(default="")
    san: list[str] = _list_field()
    expired: bool = field(default=False)
    error: str = field(default="")


@dataclass
class HttpHit:
    """Outcome of one HTTP(S) attempt against a port; with no response, `status` is None and `error` says why."""

    scheme: str
    url: Url
    final_url: Url
    status: Optional[int]
    reason: str
    server: str
    powered_by: HeaderValue
    content_type: HeaderValue
    location: HeaderValue
    title: PageText
    snippet: PageText
    bytes_read: ByteCount
    sha256: str
    elapsed_ms: Millis
    tags: list[str] = _list_field()
    headers: dict[str, str] = _dict_field()
    tls: Optional[TlsInfo] = None
    error: str = field(default="")
    body: bytes = field(repr=False, default=b"")
    body_prefix: bytes = field(repr=False, default=b"")


@dataclass
class PortResult:
    """Scan outcome for one TCP port; callers construct it positionally, so the field order is fixed."""

    port: int
    tcp_open: bool
    hits: list[HttpHit] = _list_field()
    tcp_error: str = field(default="")
    banner: str = field(default="")


@dataclass
class Finding:
    """One observation about a host, graded on the SEVERITY_ORDER scale."""

    severity: Severity
    title: str
    detail: str
    url: str = field(default="")
    evidence: str = field(default="")


@dataclass
class HostReport:
    """Everything gathered for one scan target; callers construct it positionally, so the field order is fixed."""

    target: str
    resolved: AddressList
    results: list[PortResult]
    elapsed: Seconds
    findings: list[Finding] = _list_field()
    dns: dict[str, list[str]] = _dict_field()
    ct_names: list[str] = _list_field()
    banners: list[str] = _list_field()
    js_urls: list[str] = _list_field()
    favicon_hash: str = field(default="")
    favicon_hint: str = field(default="")


def speaking(hit) -> bool:
    """Policy denials are never live; other hits use status or non-connect/TLS errors."""
    if hit is None or "policy-blocked" in hit.tags:
        return False
    if hit.status is not None:
        return True
    if not hit.error:
        return False
    lowered = hit.error.lower()
    return not any(word in lowered for word in NOISE_WORDS)


def _utc_stamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def _hit_records(report: HostReport):
    for port_result in report.results:
        for hit in port_result.hits:
            yield port_result, hit


# --------------------------------------------------------------------------------------
# JSON
# --------------------------------------------------------------------------------------


def _tls_to_dict(tls: TlsInfo | None) -> dict | None:
    if tls is None:
        return None
    return {
        "version": tls.version,
        "cipher": tls.cipher,
        "subject": tls.subject,
        "issuer": tls.issuer,
        "not_before": tls.not_before,
        "not_after": tls.not_after,
        "san": list(tls.san),
        "expired": tls.expired,
        "error": tls.error,
    }


def _hit_to_dict(hit: HttpHit) -> dict:
    return {
        "scheme": hit.scheme,
        "url": hit.url,
        "final_url": hit.final_url,
        "status": hit.status,
        "reason": hit.reason,
        "server": hit.server,
        "powered_by": hit.powered_by,
        "content_type": hit.content_type,
        "location": hit.location,
        "title": hit.title,
        "snippet": hit.snippet,
        "bytes_read": hit.bytes_read,
        "sha256": hit.sha256,
        "elapsed_ms": hit.elapsed_ms,
        "tags": list(hit.tags),
        "headers": dict(hit.headers),
        "tls": _tls_to_dict(hit.tls),
        "error": hit.error,
    }


def _host_to_dict(report: HostReport) -> dict:
    open_ports = [
        {
            "port": entry.port,
            "tcp_open": True,
            "tcp_error": entry.tcp_error,
            "hits": [_hit_to_dict(hit) for hit in entry.hits],
        }
        for entry in report.results
        if entry.tcp_open
    ]
    return {
        "target": report.target,
        "resolved": list(report.resolved),
        "elapsed_seconds": round(float(report.elapsed), 3),
        "dns": {kind: list(values) for kind, values in report.dns.items()},
        "ct_names": list(report.ct_names),
        "favicon_hash": report.favicon_hash,
        "favicon_hint": report.favicon_hint,
        "js_urls": list(report.js_urls),
        "banners": list(report.banners),
        "findings": [
            {
                "severity": item.severity,
                "title": item.title,
                "detail": item.detail,
                "url": item.url,
                "evidence": item.evidence,
            }
            for item in report.findings
        ],
        "ports": open_ports,
    }


def reports_to_json(reports: list[HostReport], elapsed_seconds: float) -> dict:
    return {
        "tool": "Bughunt",
        "version": VERSION,
        "scanned_at": _utc_stamp(),
        "elapsed_seconds": round(float(elapsed_seconds), 3),
        "hosts": [_host_to_dict(report) for report in reports],
    }


# --------------------------------------------------------------------------------------
# CSV
# --------------------------------------------------------------------------------------


def write_csv(path, reports: list[HostReport]) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(CSV_COLUMNS)
        for report in reports:
            for port_result, hit in _hit_records(report):
                if not speaking(hit):
                    continue
                writer.writerow(
                    [
                        redact_text(report.target),
                        port_result.port,
                        hit.scheme,
                        redact_text(hit.url),
                        redact_text(hit.final_url),
                        "" if hit.status is None else hit.status,
                        redact_text(hit.server),
                        redact_text(hit.title),
                        ",".join(hit.tags),
                        hit.sha256,
                        hit.bytes_read,
                        f"{hit.elapsed_ms:.1f}",
                    ]
                )


# --------------------------------------------------------------------------------------
# Markdown
# --------------------------------------------------------------------------------------


def _displayed_port(hit: HttpHit) -> int:
    try:
        explicit = urlparse(hit.url).port
    except ValueError:
        explicit = None
    if explicit:
        return explicit
    return 443 if hit.scheme == "https" else 80


def _backticked(values) -> str:
    return ", ".join(f"`{value}`" for value in values)


def _live_table(report: HostReport) -> list[str]:
    live = [
        hit
        for _, hit in _hit_records(report)
        if speaking(hit) and "filtered" not in hit.tags
    ]
    if not live:
        return []
    lines = [
        "### Live HTTP(S)",
        "| Port | URL | Status | Server | Title | Tags |",
        "| ---: | --- | --- | --- | --- | --- |",
    ]
    for hit in live:
        status = "None" if hit.status is None else hit.status
        title = hit.title.replace("|", "/")
        lines.append(
            f"| {_displayed_port(hit)} | `{hit.url}` | {status} | {hit.server} | {title} | {', '.join(hit.tags)} |"
        )
    return [*lines, ""]


def _finding_line(item: Finding) -> str:
    location = f" — `{item.url}`" if item.url else ""
    extra = f" ({item.evidence})" if item.evidence else ""
    return f"- **{item.severity.upper()}** {item.title}{location}. {item.detail}{extra}"


def _severity_rank(item: Finding) -> int:
    try:
        return SEVERITY_ORDER.index(item.severity)
    except ValueError:
        return len(SEVERITY_ORDER)


def _findings_section(report: HostReport) -> list[str]:
    if not report.findings:
        return ["_No extra findings recorded for this host._", ""]
    ordered = sorted(report.findings, key=_severity_rank)
    return ["### Findings", *[_finding_line(item) for item in ordered], ""]


def _intel_sections(report: HostReport) -> list[str]:
    lines: list[str] = []
    if report.dns:
        lines.append("### DNS")
        for kind, records in report.dns.items():
            lines.append(
                f"- **{kind}**: {_backticked(records[: MARKDOWN_LIST_LIMITS['dns']])}"
            )
        lines.append("")
    if report.ct_names:
        lines += [
            "### Certificate transparency",
            *[f"- `{name}`" for name in report.ct_names[: MARKDOWN_LIST_LIMITS["ct"]]],
            "",
        ]
    return lines


def _host_section(report: HostReport) -> list[str]:
    lines = [f"## {report.target}", ""]
    if report.resolved:
        lines += [f"Resolved: {_backticked(report.resolved)}", ""]
    if report.favicon_hash:
        hint = f" ({report.favicon_hint})" if report.favicon_hint else ""
        lines += [f"Favicon mmh3: `{report.favicon_hash}`{hint}", ""]
    lines += _intel_sections(report)
    lines += _live_table(report)
    if report.banners:
        lines += [
            "### Non-HTTP banners",
            *[f"- `{banner}`" for banner in report.banners],
            "",
        ]
    if report.js_urls:
        lines += [
            "### JavaScript / API URLs",
            *[f"- `{url}`" for url in report.js_urls[: MARKDOWN_LIST_LIMITS["js"]]],
            "",
        ]
    return lines + _findings_section(report)


def write_markdown(path, reports: list[HostReport], elapsed: float) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# Bughunt report",
        "",
        f"Generated `{_utc_stamp()}` by Bughunt {VERSION}.",
        f"Elapsed **{elapsed:.2f}s** across **{len(reports)}** host(s).",
        "",
        "Authorized assessment notes only. Confirm scope before acting on findings.",
        "",
    ]
    for report in reports:
        lines += _host_section(report)
    destination.write_text(redact_text("\n".join(lines)), encoding="utf-8")
