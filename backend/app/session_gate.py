"""Session cookie check for reverse proxies.

GET /session/check — 200 + Remote-* or 401 + Location.
GET /session/start — on the app host: set a state cookie, then go to handoff.
GET /session/handoff — signed in on auth: ticket bound to that state.
GET /session/establish — on the app host: check the state cookie, set the
host-only session cookie, then redirect.

The state cookie ties the ticket to the browser that started the flow, so a
ticket minted for one browser cannot sign another one in.
"""

from __future__ import annotations

import hmac
import re
import secrets
from typing import Annotated
from urllib.parse import quote, urlparse

from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import RedirectResponse

from app.audit import audit
from app.config import APP_ORIGINS, FRONTEND_ORIGIN, ISSUER
from app.deps import APP_SCOPE, get_auth_server, get_directory, get_runtime, get_session_user
from app.oidc.models import OAuth2Client
from app.oidc.server import DirectoryAuthorizationServer
from app.sessions import peer_is_trusted, rotate_session, session_auth
from app.store.directory import DirectoryStore
from app.store.runtime import RuntimeStore

router = APIRouter(tags=["session-gate"])


def allowed_return_origins(extra: list[str] | None = None) -> set[str]:
    listed = extra if extra is not None else APP_ORIGINS
    origins = {ISSUER.rstrip("/"), FRONTEND_ORIGIN.rstrip("/"), *listed}
    return {item.rstrip("/") for item in origins if item}


def safe_return_to(value: str | None, extra: list[str] | None = None) -> str | None:
    text = (value or "").strip()
    if not text or text.startswith("//") or "\\" in text:
        return None
    parsed = urlparse(text)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.username:
        return None
    origin = f"{parsed.scheme}://{parsed.netloc}"
    if origin.rstrip("/") not in allowed_return_origins(extra):
        return None
    return text


def forwarded_return_to(request: Request, extra: list[str] | None = None) -> str | None:
    if not peer_is_trusted(request):
        return None
    proto = (request.headers.get("x-forwarded-proto") or "").split(",")[0].strip()
    host = (request.headers.get("x-forwarded-host") or "").split(",")[0].strip()
    uri = request.headers.get("x-forwarded-uri") or "/"
    if not proto or not host:
        return None
    return safe_return_to(f"{proto}://{host}{uri}", extra)


def login_location(return_to: str | None, path: str = "/login") -> str:
    issuer = ISSUER.rstrip("/")
    if return_to:
        return f"{issuer}{path}?next={quote(return_to, safe='')}"
    return f"{issuer}{path}"


def forbidden_location() -> str:
    return f"{ISSUER.rstrip('/')}/login?error=client_forbidden"


def return_allowed(directory: DirectoryStore, return_to: str | None, group_names: list[str]) -> bool:
    if not return_to or same_site_return(return_to):
        return True
    row = directory.client_for_origin(_origin(return_to))
    if not row:
        return False
    return OAuth2Client(row).allows_user(group_names)


def _origin(url: str) -> str:
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}".rstrip("/")


def same_site_return(return_to: str) -> bool:
    origin = _origin(return_to)
    return origin in {ISSUER.rstrip("/"), FRONTEND_ORIGIN.rstrip("/")}


def header_value(value: str) -> str | None:
    raw = str(value or "")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in raw):
        return None
    text = " ".join(raw.split())
    if not text or any(ch in text for ch in ',;"\\'):
        return None
    return text


def identity_headers(username: str, email: str, name: str, groups: list[str]) -> dict[str, str] | None:
    user = header_value(username)
    if not user:
        return None
    headers = {"Remote-User": user}
    safe_email = header_value(email)
    if safe_email:
        headers["Remote-Email"] = safe_email
    safe_name = header_value(name)
    if safe_name:
        headers["Remote-Name"] = safe_name
    safe_groups = [item for item in (header_value(group) for group in groups) if item]
    if safe_groups:
        headers["Remote-Groups"] = ",".join(safe_groups)
    return headers


_STATE_PATTERN = re.compile(r"[A-Za-z0-9_-]{32,128}")
STATE_MAX_AGE = 600


def state_cookie_name(return_to: str) -> str:
    """``__Host-`` blocks a sibling subdomain from planting the cookie; it needs HTTPS."""
    return "__Host-sa_gate" if urlparse(return_to).scheme == "https" else "sa_gate"


def clean_state(value: str | None) -> str | None:
    text = (value or "").strip()
    return text if _STATE_PATTERN.fullmatch(text) else None


def app_start_url(return_to: str) -> str:
    return f"{_origin(return_to)}/session/start?rd={quote(return_to, safe='')}"


def app_handoff_url(
    return_to: str | None,
    user_id: str,
    runtime: RuntimeStore,
    auth: dict | None = None,
    state: str | None = None,
) -> str | None:
    """Where to send a signed-in browser for ``return_to``.

    Without a state from the app host, go there first to get one.
    """
    if not return_to:
        return None
    if same_site_return(return_to):
        return return_to
    if not state:
        return app_start_url(return_to)
    context = auth or {}
    ticket = runtime.create_session_ticket(
        user_id,
        return_to,
        state=state,
        auth_version=int(context.get("auth_version") or 0),
        amr=list(context.get("amr") or ["pwd"]),
        auth_at=int(context.get("auth_at") or 0) or None,
    )
    return f"{_origin(return_to)}/session/establish?ticket={quote(ticket, safe='')}"


def gate_target(request: Request, directory: DirectoryStore) -> str | None:
    """URL the proxy is asking about.

    Headers from a trusted proxy win. Otherwise only the first ``rd`` counts:
    proxies build it as ``rd=<scheme>://<host><uri>`` without encoding, so a
    later ``rd`` comes from the client's own query string.
    """
    allowed = directory.app_origins()
    forwarded = forwarded_return_to(request, allowed)
    if forwarded and directory.client_for_origin(_origin(forwarded)):
        return forwarded
    values = request.query_params.getlist("rd")
    return safe_return_to(values[0] if values else None, allowed)


@router.get("/session/check")
def check_session(
    request: Request,
    directory: Annotated[DirectoryStore, Depends(get_directory)],
):
    """200 + Remote-* if the cookie is valid for a registered forward app."""
    user = get_session_user(request, allow_app=True)
    return_to = gate_target(request, directory)
    if user and request.session.get("scope") == APP_SCOPE:
        if not return_to or _origin(return_to) != request.session.get("app_origin"):
            user = None
    if user and user.must_change_password:
        return Response(status_code=401, headers={"Location": login_location(return_to, "/change-password")})
    if user:
        row = directory.client_for_origin(_origin(return_to)) if return_to else None
        if not row or not OAuth2Client(row).allows_user(user.group_names):
            audit(
                "client_forbidden",
                user_id=user.id,
                username=user.username,
                client_id=(row or {}).get("client_id"),
            )
            return Response(status_code=403, headers={"Location": forbidden_location()})
        headers = identity_headers(user.username, user.email or "", user.name or user.username, user.group_names)
        if not headers:
            return Response(status_code=403, headers={"Location": forbidden_location()})
        return Response(status_code=200, headers=headers)
    return Response(status_code=401, headers={"Location": login_location(return_to)})


@router.get("/session/start")
def start_session(
    request: Request,
    directory: Annotated[DirectoryStore, Depends(get_directory)],
):
    """On the app host: remember a fresh state in a host-only cookie."""
    return_to = safe_return_to(request.query_params.get("rd"), directory.app_origins())
    if not return_to or same_site_return(return_to) or not directory.client_for_origin(_origin(return_to)):
        return RedirectResponse(login_location(None), status_code=303)
    state = secrets.token_urlsafe(32)
    target = f"{ISSUER.rstrip('/')}/session/handoff?rd={quote(return_to, safe='')}&state={state}"
    response = RedirectResponse(target, status_code=303)
    response.set_cookie(
        state_cookie_name(return_to),
        state,
        max_age=STATE_MAX_AGE,
        path="/",
        secure=urlparse(return_to).scheme == "https",
        httponly=True,
        samesite="lax",
    )
    return response


@router.get("/session/handoff")
def handoff_session(
    request: Request,
    directory: Annotated[DirectoryStore, Depends(get_directory)],
    runtime: Annotated[RuntimeStore, Depends(get_runtime)],
):
    """Issue a one-time ticket for the app host, bound to its state cookie."""
    user = get_session_user(request)
    return_to = safe_return_to(request.query_params.get("rd"), directory.app_origins())
    if not user:
        return RedirectResponse(login_location(return_to), status_code=303)
    if user.must_change_password:
        return RedirectResponse(login_location(return_to, "/change-password"), status_code=303)
    if return_to and not return_allowed(directory, return_to, user.group_names):
        return RedirectResponse(forbidden_location(), status_code=303)
    state = clean_state(request.query_params.get("state"))
    target = app_handoff_url(return_to, user.id, runtime, session_auth(request), state)
    if not target:
        return RedirectResponse(f"{FRONTEND_ORIGIN.rstrip('/')}/admin", status_code=303)
    return RedirectResponse(target, status_code=303)


@router.get("/session/establish")
def establish_session(
    request: Request,
    directory: Annotated[DirectoryStore, Depends(get_directory)],
    runtime: Annotated[RuntimeStore, Depends(get_runtime)],
    auth_server: Annotated[DirectoryAuthorizationServer, Depends(get_auth_server)],
):
    """Set the host cookie, then redirect."""
    ticket = (request.query_params.get("ticket") or "").strip()
    record = runtime.consume_session_ticket(ticket) if ticket else None
    return_to = safe_return_to((record or {}).get("return_to"), directory.app_origins())
    user = auth_server.resolve_user(record["user_id"]) if record else None
    if not record or not return_to or not user or not user.enabled:
        return RedirectResponse(login_location(None), status_code=303)
    cookie_name = state_cookie_name(return_to)
    expected = str(record.get("state") or "")
    presented = request.cookies.get(cookie_name) or ""
    if not expected or not hmac.compare_digest(expected.encode(), presented.encode()):
        audit("session_ticket_unbound", user_id=user.id, username=user.username)
        return RedirectResponse(app_start_url(return_to), status_code=303)
    if int(record.get("auth_version") or 0) != directory.auth_version(user.id):
        return RedirectResponse(login_location(return_to), status_code=303)
    if user.must_change_password:
        return RedirectResponse(login_location(return_to, "/change-password"), status_code=303)
    if not return_allowed(directory, return_to, user.group_names):
        return RedirectResponse(forbidden_location(), status_code=303)
    rotate_session(
        request,
        user_id=user.id,
        scope=APP_SCOPE,
        app_origin=_origin(return_to),
        return_to=return_to,
        auth_version=int(record.get("auth_version") or 0),
        amr=list(record.get("amr") or ["pwd"]),
        auth_at=int(record.get("auth_at") or 0) or None,
    )
    response = RedirectResponse(return_to, status_code=303)
    response.delete_cookie(
        cookie_name,
        path="/",
        secure=urlparse(return_to).scheme == "https",
        httponly=True,
        samesite="lax",
    )
    return response
