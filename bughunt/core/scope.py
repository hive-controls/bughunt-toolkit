"""Scope enforcement for browser-driven (Playwright) scanning.

In-scope http(s) only; redirects are walked one checked hop at a time so the
browser never follows an out-of-scope hop itself.
"""
from __future__ import annotations

from urllib.parse import urljoin, urlparse

import httpx

from bughunt.core import egress, identity
from bughunt.core.workspace import allowed

SCREENSHOT_REDIRECTS = frozenset({301, 302, 303, 307, 308})

SCREENSHOT_MAX_HOPS = 10

def scope_route(route, actor_signature: tuple[str, str, str] | None = None) -> None:
    """Playwright route handler. Only in-scope http(s) requests leave the browser.

    It sees the page and every subresource, so an image, script, or font cannot
    reach an out-of-scope host. Chromium does not route the hops of a redirect it
    follows itself, so the browser never follows one: this handler walks the
    chain one checked hop at a time and hands the browser the final response.
    Any failure aborts the request.
    """
    try:
        response = _fetch_in_scope(route, actor_signature)
    except Exception:
        response = None
    try:
        if response is None:
            route.abort("blockedbyclient")
        else:
            route.fulfill(response=response)
    except Exception:
        pass

def _fetch_in_scope(route, actor_signature: tuple[str, str, str] | None = None):
    """Final response for the routed request, or None when any hop is out of scope."""
    current = route.request.url
    signature = actor_signature or identity.selection_signature()
    method = getattr(route.request, "method", "GET")
    for hop in range(SCREENSHOT_MAX_HOPS + 1):
        if urlparse(current).scheme not in ("http", "https") or not allowed(current):
            return None
        profile = egress.authorize(current, "active_scan", method)
        headers = dict(getattr(route.request, "headers", {}))
        if hop:
            headers = {name: value for name, value in headers.items() if name.lower() != "host"}
        checked = httpx.Request(method, current, headers=headers,
                                extensions={"bughunt_actor_snapshot": signature})
        actor = identity.apply_request(checked)
        for name, value in profile.required_headers:
            checked.headers[name] = value
        checked.headers["User-Agent"] = profile.user_agent
        if actor != "default":
            # Reapply after policy headers so they cannot replace this actor's credentials.
            identity.apply_request(checked)
            # Playwright sends cookies from the browser context, not route headers.
            checked.headers.pop("Cookie", None)
        # route.fetch retains the browser's original body and sets its own framing.
        outbound = {name: value for name, value in checked.headers.items()
                    if name.lower() not in {"content-length", "transfer-encoding"}}
        for name in (*[name for name, _value in profile.required_headers], "User-Agent"):
            value = checked.headers.get(name)
            for existing in list(outbound):
                if existing.lower() == name.lower():
                    outbound.pop(existing)
            if value is not None:
                outbound[name] = value
        with egress.action(current, "active_scan", method):
            identity.snapshot(current, signature)
            response = route.fetch(url=current, max_redirects=0,
                                   headers=outbound)
        location = response.headers.get("location", "")
        if response.status not in SCREENSHOT_REDIRECTS or not location:
            return response
        if method.upper() not in {"GET", "HEAD"}:
            return None
        current = urljoin(current, location)
    return None

def scope_socket(socket, actor_signature: tuple[str, str, str] | None = None) -> None:
    """Playwright WebSocket handler. Out-of-scope sockets never connect.

    A routed socket that does not call connect_to_server() never reaches a
    server. Calling close() here deadlocks the sync API, so it is left alone.
    """
    try:
        signature = actor_signature or identity.selection_signature()
        if signature[1] != "default" or identity.selection_signature() != signature:
            return
        if not allowed(socket.url):
            return
        target = socket.url.replace("wss://", "https://", 1).replace("ws://", "http://", 1)
        # Existing screenshot sockets require a separate CONNECT method grant.
        with egress.action(target, "active_scan", "CONNECT"):
            if identity.selection_signature() != signature:
                return
            socket.connect_to_server()
    except (egress.PolicyBlocked, identity.IdentityError):
        return
