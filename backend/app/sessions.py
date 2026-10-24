from __future__ import annotations

import ipaddress
import time
from typing import Any

from starlette.requests import Request

from app import config
from app.security import generate_id


def _revoke_sid(request: Request) -> None:
    sid = request.session.get("sid")
    if sid:
        request.app.state.runtime.revoke_session(str(sid), config.SESSION_COOKIE_MAX_AGE)


def rotate_session(request: Request, *, auth_at: int | None = None, **values: Any) -> None:
    """Start a fresh session. The previous cookie stops working server-side."""
    _revoke_sid(request)
    request.session.clear()
    now = int(time.time())
    request.session.update(values)
    request.session["sid"] = generate_id()
    request.session["auth_at"] = int(auth_at or now)
    request.session["last_seen"] = now


def end_session(request: Request) -> None:
    _revoke_sid(request)
    request.session.clear()


def session_is_live(request: Request) -> bool:
    sid = request.session.get("sid")
    return bool(sid) and not request.app.state.runtime.session_revoked(str(sid))


def session_auth(request: Request) -> dict[str, Any]:
    amr = request.session.get("amr") or ["pwd"]
    return {
        "auth_version": int(request.session.get("auth_version") or 0),
        "amr": [str(item) for item in amr],
        "auth_at": int(request.session.get("auth_at") or 0),
    }


def _peer(request: Request) -> str | None:
    return request.client.host if request.client else None


def _is_trusted_proxy(host: str | None) -> bool:
    if not host or not config.TRUSTED_PROXIES:
        return False
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return any(address in network for network in config.TRUSTED_PROXIES)


def peer_is_trusted(request: Request) -> bool:
    return _is_trusted_proxy(_peer(request))


def request_is_https(request: Request) -> bool:
    """HTTPS end to end, or X-Forwarded-Proto: https from a trusted proxy.

    The last X-Forwarded-Proto value is the one the trusted proxy wrote; earlier
    ones come from the client when a proxy appends instead of replacing.
    """
    if request.url.scheme == "https":
        return True
    proto = (request.headers.get("x-forwarded-proto") or "").split(",")[-1].strip().lower()
    return proto == "https" and peer_is_trusted(request)


def proxy_diagnostics(request: Request) -> dict[str, Any]:
    """What this request looks like from the backend, to check OIDC_TRUSTED_PROXIES."""
    peer = _peer(request)
    forwarded = any(
        request.headers.get(name) for name in ("x-forwarded-for", "x-forwarded-host", "x-forwarded-proto")
    )
    return {
        "trusted_proxies": [str(network) for network in config.TRUSTED_PROXIES],
        "peer": peer,
        "peer_trusted": _is_trusted_proxy(peer),
        "forwarded_headers": forwarded,
        "client_ip": client_ip(request),
    }


def client_ip(request: Request) -> str | None:
    """Client address. X-Forwarded-For is used only when the peer is a trusted proxy."""
    peer = _peer(request)
    if not _is_trusted_proxy(peer):
        return peer
    forwarded = request.headers.get("x-forwarded-for") or ""
    hops = [item.strip() for item in forwarded.split(",") if item.strip()]
    if peer:
        hops.append(peer)
    if not hops:
        return None
    for hop in reversed(hops):
        if not _is_trusted_proxy(hop):
            return hop
    return hops[0]
