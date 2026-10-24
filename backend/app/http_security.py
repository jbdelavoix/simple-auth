from __future__ import annotations

from collections.abc import Callable
from urllib.parse import urlparse

import time

from starlette.datastructures import Headers
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse, Response
from starlette.types import ASGIApp, Receive, Scope, Send

from app.audit import audit, bind_request, clear_request
from app.config import (
    ALLOWED_HOSTS_RAW,
    APP_ORIGINS,
    FRONTEND_ORIGIN,
    ISSUER,
)
from app.security import generate_id
from app.sessions import client_ip, request_is_https
from app.store.directory import DirectoryStore


def allowed_origins() -> set[str]:
    return console_origins() | {item for item in APP_ORIGINS if item}


def console_origins() -> set[str]:
    """Issuer and console origins, without the Forward app origins."""
    origins = {FRONTEND_ORIGIN.rstrip("/"), ISSUER.rstrip("/")}
    if ISSUER.startswith("http://"):
        origins.update(
            {
                "http://127.0.0.1:5173",
                "http://localhost:5173",
                "http://127.0.0.1:5174",
                "http://localhost:5174",
                "http://127.0.0.1:8000",
                "http://localhost:8000",
            }
        )
    return {item for item in origins if item}


def allowed_hosts() -> list[str]:
    hosts = {"testserver", "localhost", "127.0.0.1"}
    if ALLOWED_HOSTS_RAW:
        hosts.update(item.strip() for item in ALLOWED_HOSTS_RAW.split(",") if item.strip())
    # App hosts are not listed: HostCheckMiddleware allows them on /session/* only.
    for origin in console_origins():
        host = urlparse(origin).hostname
        if host:
            hosts.add(host)
    return sorted(hosts)


class HostCheckMiddleware:
    """Reject unknown Host headers.

    Issuer and console hosts are valid on every route. A Forward client host is
    valid on /session/* only: that is the one path its proxy relays here, and the
    session cookie set there stays bound to that host.
    """

    app_paths = ("/session/",)

    def __init__(self, app: ASGIApp, allowed: list[str], app_hosts: Callable[[], set[str]]):
        self.app = app
        self.allowed = {item.lower() for item in allowed}
        self.app_hosts = app_hosts

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return
        host = Headers(scope=scope).get("host", "").split(":")[0].lower()
        if host in self.allowed or (
            host and scope["path"].startswith(self.app_paths) and host in self.app_hosts()
        ):
            await self.app(scope, receive, send)
            return
        await PlainTextResponse("Invalid host header", status_code=400)(scope, receive, send)


def forward_app_hosts(directory: DirectoryStore) -> Callable[[], set[str]]:
    def hosts() -> set[str]:
        return {
            host.lower()
            for host in (urlparse(origin).hostname for origin in directory.app_origins())
            if host
        }

    return hosts


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        response.headers.setdefault("Cache-Control", "no-store")
        if ISSUER.startswith("https://"):
            response.headers.setdefault(
                "Strict-Transport-Security",
                "max-age=63072000; includeSubDomains",
            )
        # form-action lists issuer/frontend/app origins: Chrome/Safari also apply
        # form-action to redirects after a form POST (e.g. post_logout_redirect_uri).
        form_targets = " ".join(sorted(allowed_origins()))
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; "
            f"base-uri 'self'; form-action 'self' {form_targets}",
        )
        return response


class OriginCheckMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        if request.method in {"POST", "PUT", "PATCH", "DELETE"} and request.url.path.startswith("/api/"):
            origin = request.headers.get("origin")
            if origin and origin.rstrip("/") not in allowed_origins():
                return JSONResponse({"detail": "Invalid origin"}, status_code=403)
        return await call_next(request)


class SecureTransportMiddleware(BaseHTTPMiddleware):
    """Refuse plain HTTP when the issuer is HTTPS, except the health probe.

    Authlib only checks the token endpoint, and exempts any URI whose host is
    localhost, which a remote client controls through the Host header.
    """

    exempt_paths = frozenset({"/api/health"})

    def __init__(self, app, enforce: bool):
        super().__init__(app)
        self.enforce = enforce

    async def dispatch(self, request: Request, call_next) -> Response:
        path = request.url.path
        if self.enforce and path not in self.exempt_paths and not request_is_https(request):
            audit("insecure_transport", path=path, outcome="denied")
            return JSONResponse(
                {"error": "insecure_transport", "error_description": "HTTPS is required."},
                status_code=400,
            )
        return await call_next(request)


class AuditContextMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        request_id = request.headers.get("x-request-id") or generate_id()
        session = getattr(request, "session", {}) or {}
        bind_request(
            ip=client_ip(request),
            request_id=request_id,
            actor_id=session.get("user_id"),
        )
        try:
            response = await call_next(request)
            response.headers.setdefault("X-Request-ID", request_id)
            return response
        finally:
            clear_request()


class SessionGuardMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        session = request.session
        now = int(time.time())
        if session.get("user_id") or session.get("mfa_pending_user_id"):
            issued = int(session.get("auth_at") or now)
            last = int(session.get("last_seen") or issued)
            policy = request.app.state.directory.session_policy()
            if now - last > policy["idle_seconds"] or now - issued > policy["absolute_seconds"]:
                session.clear()
            else:
                session["last_seen"] = now
        return await call_next(request)
