"""Guarded httpx clients shared by the modules and the addons.

Every client here is built through egress, so the engagement policy sees each request
before it reaches the network. None of them follow redirects on their own.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from contextlib import contextmanager
from urllib.parse import urljoin

import httpx

from bughunt import VERSION
from bughunt.core import egress, session

REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})

_CREDENTIAL_HEADER = re.compile(r"cookie|auth|token|api[-_]?key|secret|session|csrf", re.I)

HeaderMap = dict[str, str]
MaybeText = str | None


class HostNotAllowed(httpx.HTTPError):
    """A request aimed at a host outside the fixed list given to api_client."""


def client(timeout: float, *, authorization: MaybeText = None, cookie: MaybeText = None,
           headers: HeaderMap | None = None, insecure: bool = False) -> httpx.Client:
    outgoing = {"User-Agent": f"Bughunt/{VERSION}", "Accept-Encoding": "identity"}
    outgoing.update(headers or {})
    outgoing = session.apply_headers(outgoing, cookie=cookie, authorization=authorization)
    settings = {
        "timeout": timeout,
        "headers": outgoing,
        "verify": not insecure,
        "trust_env": False,
        "follow_redirects": False,
    }
    return egress.client(operation="manual", **settings)


def redirect_target(current: str, response: httpx.Response) -> str:
    if response.status_code not in REDIRECT_STATUSES:
        return ""
    location = response.headers.get("location", "").strip()
    return urljoin(current, location) if location else ""


def host_listed(host: str, hosts: frozenset[str]) -> bool:
    name = host.lower().rstrip(".")
    return any(name == listed or name.endswith(f".{listed}") for listed in hosts)


def api_client(hosts: frozenset[str], *, timeout: float, headers: HeaderMap | None = None,
               transport: httpx.BaseTransport | None = None) -> httpx.Client:
    def refuse_unlisted(request: httpx.Request) -> None:
        destination = request.url.host
        if not host_listed(destination, hosts):
            raise HostNotAllowed(
                f"{destination} is not one of this tool's API hosts; the request was not sent")

    return egress.client(
        operation="passive", timeout=timeout, headers=headers, transport=transport,
        follow_redirects=False, trust_env=False, event_hooks={"request": [refuse_unlisted]})


def is_credential_header(name: str) -> bool:
    return bool(_CREDENTIAL_HEADER.search(name))


def _origin(url: str) -> tuple[str, str, int | None]:
    parsed = httpx.URL(url)
    return parsed.scheme, parsed.host.lower().rstrip("."), parsed.port or {"http": 80, "https": 443}.get(parsed.scheme)


def same_origin(first: str, second: str) -> bool:
    try:
        return _origin(first) == _origin(second)
    except httpx.InvalidURL:
        return False


def hop_request(conn: httpx.Client, method: str, url: str, *, came_from: str | None = None,
                **kwargs) -> httpx.Request:
    """A request for one redirect hop; credential headers are dropped when the origin changed."""
    request = conn.build_request(method, url, **kwargs)
    if came_from and not same_origin(came_from, url):
        for name in {header for header in request.headers if is_credential_header(header)}:
            del request.headers[name]
    return request


@contextmanager
def stream_hop(conn: httpx.Client, method: str, url: str, *, came_from: str | None = None,
               **kwargs) -> Iterator[httpx.Response]:
    response = conn.send(hop_request(conn, method, url, came_from=came_from, **kwargs), stream=True)
    try:
        yield response
    finally:
        response.close()


def get_following(conn: httpx.Client, start_url: str, *, params: dict | None = None,
                  limit: int = 5, **kwargs) -> httpx.Response:
    reply = conn.get(start_url, params=params, **kwargs)
    for _hop in range(limit):
        onward = redirect_target(str(reply.url), reply)
        if not onward:
            break
        reply = conn.get(onward, **kwargs)
    return reply


def read_body(response: httpx.Response, cap: int) -> bytes:
    if cap <= 0:
        return b""
    gathered = bytearray()
    for piece in response.iter_bytes():
        gathered.extend(piece)
        if len(gathered) >= cap:
            break
    return bytes(gathered[:cap])
