from __future__ import annotations

import base64
import binascii
import time
from typing import Annotated
from urllib.parse import unquote, urlencode

from authlib.oauth2.rfc6749.errors import OAuth2Error
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse, RedirectResponse, Response
from joserfc import jwt
from pydantic import BaseModel

from app.audit import audit
from app.config import FRONTEND_ORIGIN, INTERACTION_EXPIRES, ISSUER, REQUIRE_ADMIN_MFA, SCOPES_SUPPORTED
from app.connectors.base import IdentityConnector, ReadOnlyError
from app.deps import get_auth_server, get_directory, get_identity, get_runtime, get_session_user, require_user
from app.revocation import revoke_user_auth
from app.security import validate_password
from app.sessions import client_ip, end_session, rotate_session, session_auth, session_is_live
from app.mfa import (
    new_recovery_codes,
    new_totp_secret,
    provisioning_uri,
    qr_data_uri,
    verify_totp,
)
from app.mfa_trust import (
    MFA_DEVICE_COOKIE,
    clear_mfa_device_cookie,
    device_cookie_owner,
    set_mfa_device_cookie,
)
from app.ratelimit import release, reserve_login, reserve_mfa
from app.oidc.models import UserAccount, build_user_info, describe_release
from app.oidc.request import build_oauth2_request, oauth2_request_from_params
from app.oidc.server import DirectoryAuthorizationServer
from app.session_gate import app_handoff_url, return_allowed, safe_return_to
from app.store.directory import DirectoryStore, as_bool, normalize_login_theme
from app.store.jwks import public_jwks
from app.store.runtime import RuntimeStore

router = APIRouter(tags=["oidc"])


class LoginBody(BaseModel):
    username: str
    password: str
    next: str | None = None


class ConfirmBody(BaseModel):
    approve: bool = True


class ChangePasswordBody(BaseModel):
    current_password: str
    new_password: str
    next: str | None = None


class MfaCodeBody(BaseModel):
    code: str
    trust: bool = False


class ProfileUpdateBody(BaseModel):
    name: str | None = None
    email: str | None = None


def _frontend(directory: DirectoryStore) -> str:
    return directory.get_settings().get("frontend_origin") or FRONTEND_ORIGIN


def _issuer(directory: DirectoryStore) -> str:
    return directory.get_settings().get("issuer") or ISSUER


@router.get("/.well-known/openid-configuration")
def openid_configuration(directory: Annotated[DirectoryStore, Depends(get_directory)]):
    issuer = _issuer(directory)
    return {
        "issuer": issuer,
        "authorization_endpoint": f"{issuer}/oauth/authorize",
        "token_endpoint": f"{issuer}/oauth/token",
        "userinfo_endpoint": f"{issuer}/oauth/userinfo",
        "jwks_uri": f"{issuer}/jwks.json",
        "end_session_endpoint": f"{issuer}/oauth/logout",
        "revocation_endpoint": f"{issuer}/oauth/revoke",
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": SCOPES_SUPPORTED,
        "token_endpoint_auth_methods_supported": [
            "client_secret_basic",
            "client_secret_post",
            "none",
        ],
        "claims_supported": [
            "sub",
            "name",
            "preferred_username",
            "email",
            "email_verified",
            "groups",
        ],
        "code_challenge_methods_supported": ["S256"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
    }


@router.get("/jwks.json")
def jwks():
    return public_jwks()


@router.api_route("/oauth/authorize", methods=["GET", "POST"])
async def authorize(
    request: Request,
    directory: Annotated[DirectoryStore, Depends(get_directory)],
    runtime: Annotated[RuntimeStore, Depends(get_runtime)],
    auth_server: Annotated[DirectoryAuthorizationServer, Depends(get_auth_server)],
):
    params = dict(request.query_params)
    if request.method == "POST":
        form = await request.form()
        params.update({k: v for k, v in form.multi_items()})

    client = _require_registered_redirect(auth_server, params)
    prompts = _prompts(params)
    if "none" in prompts and len(prompts) > 1:
        return _oauth_error_redirect(params, "invalid_request", "prompt none cannot be combined")
    if _max_age_invalid(params):
        return _oauth_error_redirect(params, "invalid_request", "invalid max_age")

    user = get_session_user(request)
    if user and (user.must_change_password or _login_stale(request, params)):
        if "none" in prompts:
            return _oauth_error_redirect(params, "login_required")
        if user.must_change_password:
            interaction = runtime.create_interaction(params, INTERACTION_EXPIRES)
            runtime.update_interaction(interaction["id"], user_id=user.id, status="password")
            frontend = _frontend(directory)
            return RedirectResponse(
                f"{frontend}/change-password?interaction={interaction['id']}",
                status_code=303,
            )
        user = None

    if not user:
        if "none" in prompts:
            return _oauth_error_redirect(params, "login_required")
        interaction = runtime.create_interaction(params, INTERACTION_EXPIRES)
        frontend = _frontend(directory)
        return RedirectResponse(
            f"{frontend}/login?interaction={interaction['id']}",
            status_code=303,
        )

    _require_client_access(client, user)
    if _needs_consent(directory, user.id, params):
        if "none" in prompts:
            return _oauth_error_redirect(params, "consent_required")
        interaction = runtime.create_interaction(params, INTERACTION_EXPIRES)
        runtime.update_interaction(interaction["id"], user_id=user.id, status="consent")
        frontend = _frontend(directory)
        return RedirectResponse(
            f"{frontend}/consent?interaction={interaction['id']}",
            status_code=303,
        )

    _stamp_user_auth(directory, user)
    oauth_req = oauth2_request_from_params(params, f"{_issuer(directory)}/oauth/authorize")
    try:
        grant = auth_server.get_consent_grant(oauth_req, end_user=user)
        return auth_server.create_authorization_response(
            request=oauth_req,
            grant_user=user,
            grant=grant,
        )
    except OAuth2Error as exc:
        status_code, body, headers = exc()
        if isinstance(body, dict):
            return JSONResponse(body, status_code=status_code, headers=dict(headers or []))
        return RedirectResponse(str(body), status_code=302)


def _oauth_error_redirect(params: dict, error: str, description: str = "") -> RedirectResponse:
    redirect_uri = str(params.get("redirect_uri") or "")
    query: dict[str, str] = {"error": error}
    if description:
        query["error_description"] = description
    if params.get("state"):
        query["state"] = str(params["state"])
    sep = "&" if "?" in redirect_uri else "?"
    return RedirectResponse(f"{redirect_uri}{sep}{urlencode(query)}", status_code=303)


def _max_age_invalid(params: dict) -> bool:
    raw = params.get("max_age")
    if raw in (None, ""):
        return False
    try:
        return int(raw) < 0
    except (TypeError, ValueError):
        return True


def _max_age_exceeded(request: Request, params: dict) -> bool:
    raw = params.get("max_age")
    if raw in (None, ""):
        return False
    try:
        max_age = int(raw)
    except (TypeError, ValueError):
        return True
    if max_age < 0:
        return True
    auth_at = int(request.session.get("auth_at") or 0)
    return int(time.time()) - auth_at > max_age


def _login_stale(request: Request, params: dict) -> bool:
    return "login" in _prompts(params) or _max_age_exceeded(request, params)


def _login_next(
    user,
    directory: DirectoryStore,
    interaction_id: str | None = None,
    return_to: str | None = None,
    runtime: RuntimeStore | None = None,
    request: Request | None = None,
    *,
    mfa_done: bool = False,
) -> str:
    if directory.mfa_enabled(user.id) and not mfa_done:
        return f"/mfa?interaction={interaction_id}" if interaction_id else "/mfa"
    if user.must_change_password:
        return f"/change-password?interaction={interaction_id}" if interaction_id else "/change-password"
    if interaction_id:
        return f"/consent?interaction={interaction_id}"
    if return_to:
        if not return_allowed(directory, return_to, user.group_names):
            return "/login?error=client_forbidden"
        if runtime:
            auth = session_auth(request) if request is not None else None
            return app_handoff_url(return_to, user.id, runtime, auth) or return_to
        return return_to
    if "admins" in user.group_names:
        return "/admin"
    return "/profile"


def _drop_other_device(response: Response | None, request: Request, user_id: str) -> None:
    if response is None:
        return
    owner = device_cookie_owner(request.cookies.get(MFA_DEVICE_COOKIE))
    if owner and owner != user_id:
        clear_mfa_device_cookie(response)


def _begin_or_finish_login(
    request: Request,
    user,
    directory: DirectoryStore,
    interaction_id: str | None = None,
    return_to: str | None = None,
    response: Response | None = None,
) -> dict:
    extra = {}
    if return_to:
        extra["return_to"] = return_to
    _drop_other_device(response, request, user.id)
    trusted = directory.mfa_enabled(user.id) and directory.mfa_device_valid(
        user.id, request.cookies.get(MFA_DEVICE_COOKIE)
    )
    if directory.mfa_enabled(user.id) and not trusted:
        pending = {"mfa_pending_user_id": user.id, **extra}
        if interaction_id:
            pending["mfa_pending_interaction"] = interaction_id
        rotate_session(request, **pending)
        return {
            "ok": True,
            "mfa_required": True,
            "must_change_password": user.must_change_password,
            "next": _login_next(
                user, directory, interaction_id, return_to, request.app.state.runtime, request
            ),
        }
    if trusted:
        audit("mfa_trusted", user_id=user.id, username=user.username, ip=client_ip(request))
    rotate_session(
        request,
        user_id=user.id,
        auth_version=directory.auth_version(user.id),
        amr=["pwd", "otp"] if trusted else ["pwd"],
        **extra,
    )
    return {
        "ok": True,
        "mfa_required": False,
        "mfa_trusted": trusted,
        "must_change_password": user.must_change_password,
        "next": _login_next(
            user, directory, interaction_id, return_to, request.app.state.runtime, request, mfa_done=trusted
        ),
    }


def _require_registered_redirect(
    auth_server: DirectoryAuthorizationServer,
    params: dict,
):
    client_id = str(params.get("client_id") or "")
    redirect_uri = str(params.get("redirect_uri") or "")
    client = auth_server.query_client(client_id)
    if not client:
        raise HTTPException(status_code=400, detail="Unknown client")
    if not redirect_uri or not client.check_redirect_uri(redirect_uri):
        raise HTTPException(status_code=400, detail="Invalid redirect_uri")
    challenge = str(params.get("code_challenge") or "").strip()
    method = str(params.get("code_challenge_method") or "").strip()
    if client.token_endpoint_auth_method == "none" and not challenge:
        raise HTTPException(status_code=400, detail="code_challenge is required")
    if challenge or method:
        if not challenge or method != "S256":
            raise HTTPException(status_code=400, detail="code_challenge_method must be S256")
    return client


def _require_client_access(client, user) -> None:
    if client.allows_user(user.group_names):
        return
    audit(
        "client_forbidden",
        user_id=user.id,
        username=user.username,
        client_id=client.client_id,
    )
    raise HTTPException(status_code=403, detail="client_forbidden")


def _prompts(params: dict) -> set[str]:
    return {item for item in str(params.get("prompt") or "").split() if item}


def _needs_consent(directory: DirectoryStore, user_id: str, params: dict) -> bool:
    if "consent" in _prompts(params):
        return True
    return not directory.has_consent(
        user_id,
        str(params.get("client_id") or ""),
        str(params.get("scope") or ""),
        str(params.get("redirect_uri") or ""),
    )


def _stamp_user_auth(directory: DirectoryStore, user) -> None:
    # The account handed to Authlib is a fresh lookup. Its auth_version stays 0
    # unless copied from the directory, so a password change or MFA enrollment
    # makes the token endpoint reject the code ("no user for this code").
    user.auth_version = directory.auth_version(user.id)


def _issue_authorization(directory: DirectoryStore, auth_server, user, params: dict) -> str:
    _stamp_user_auth(directory, user)
    oauth_req = oauth2_request_from_params(params, f"{_issuer(directory)}/oauth/authorize")
    grant = auth_server.get_consent_grant(oauth_req, end_user=user)
    response = auth_server.create_authorization_response(
        request=oauth_req,
        grant_user=user,
        grant=grant,
    )
    location = response.headers.get("location")
    if not location:
        raise HTTPException(status_code=500, detail="Authorization failed")
    return location


def _finish_oidc_interaction(
    directory: DirectoryStore,
    runtime,
    auth_server,
    user,
    interaction_id: str,
) -> dict:
    interaction = runtime.get_interaction(interaction_id)
    if not interaction:
        raise HTTPException(status_code=404, detail="Interaction not found")
    params = interaction["params"]
    client = _require_registered_redirect(auth_server, params)
    _require_client_access(client, user)
    if user.must_change_password:
        runtime.update_interaction(interaction_id, user_id=user.id, status="password")
        return {"next": f"/change-password?interaction={interaction_id}"}
    if _needs_consent(directory, user.id, params):
        runtime.update_interaction(interaction_id, user_id=user.id, status="consent")
        return {"next": f"/consent?interaction={interaction_id}"}
    location = _issue_authorization(directory, auth_server, user, params)
    runtime.delete_interaction(interaction_id)
    return {"next": location, "redirect_to": location}


@router.post("/oauth/token")
async def token(
    request: Request,
    auth_server: Annotated[DirectoryAuthorizationServer, Depends(get_auth_server)],
):
    oauth_req = await build_oauth2_request(request)
    grant_type = ""
    client_id = ""
    try:
        payload = getattr(oauth_req, "payload", None)
        data = getattr(payload, "data", None) or {}
        grant_type = str(data.get("grant_type") or getattr(payload, "grant_type", "") or "")
        client_id = str(data.get("client_id") or getattr(payload, "client_id", "") or "")
    except Exception:
        pass
    response = auth_server.create_token_response(oauth_req)
    status_code = getattr(response, "status_code", 200)
    if status_code >= 400:
        audit("token_failed", client_id=client_id, grant_type=grant_type)
    else:
        audit("token_issued", client_id=client_id, grant_type=grant_type)
    return response


@router.api_route("/oauth/userinfo", methods=["GET", "POST"])
async def userinfo(
    request: Request,
    auth_server: Annotated[DirectoryAuthorizationServer, Depends(get_auth_server)],
):
    token_value = _bearer_token(request)
    if not token_value and request.method == "POST":
        form = await request.form()
        token_value = form.get("access_token")
    if not token_value:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing access token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = auth_server.get_token_by_access(token_value)
    if not token or token.is_expired() or token.is_revoked():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    user = token.get_user()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unknown user")
    client = token.get_client()
    if client and not client.allows_user(user.group_names):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="client_forbidden",
        )
    return build_user_info(user, token.get_scope())


@router.post("/oauth/revoke")
async def revoke(
    request: Request,
    auth_server: Annotated[DirectoryAuthorizationServer, Depends(get_auth_server)],
    runtime: Annotated[RuntimeStore, Depends(get_runtime)],
):
    form = await request.form()
    client = _revoking_client(request, form, auth_server)
    if not client:
        return JSONResponse({"error": "invalid_client"}, status_code=401, headers={"WWW-Authenticate": "Basic"})
    token_value = form.get("token")
    if not token_value:
        raise HTTPException(status_code=400, detail="Missing token")
    runtime.revoke_token(str(token_value), client.client_id)
    audit("token_revoked", client_id=client.client_id)
    return Response(status_code=200)


def _revoking_client(request: Request, form, auth_server: DirectoryAuthorizationServer):
    """RFC 7009 §2.1: confidential clients authenticate; public ones name themselves."""
    client_id = str(form.get("client_id") or "")
    client_secret = str(form.get("client_secret") or "")
    header = request.headers.get("authorization") or ""
    if header.lower().startswith("basic "):
        try:
            raw = base64.b64decode(header.split(" ", 1)[1].strip(), validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError):
            return None
        name, sep, secret = raw.partition(":")
        if not sep:
            return None
        client_id, client_secret = unquote(name), unquote(secret)
    client = auth_server.query_client(client_id) if client_id else None
    if not client:
        return None
    if client.token_endpoint_auth_method == "none":
        return client
    if not client_secret or not client.check_client_secret(client_secret):
        return None
    return client


def _id_token_hint_matches(
    auth_server: DirectoryAuthorizationServer,
    hint: str | None,
    user: UserAccount,
    client_id: str | None,
) -> bool:
    if not hint:
        return False
    try:
        claims = jwt.decode(hint, auth_server.private_key_set).claims
    except Exception:
        return False
    audience = claims.get("aud")
    audiences = audience if isinstance(audience, list) else [audience]
    return (
        claims.get("iss") == auth_server.issuer
        and claims.get("sub") == user.id
        and (not client_id or client_id in audiences)
    )


def _wants_json(request: Request) -> bool:
    return "application/json" in (request.headers.get("accept") or "").lower()


def _logout_navigate(request: Request, url: str) -> Response:
    # Chrome/Safari apply form-action to the redirect after a form POST. The
    # confirmation UI uses fetch + JSON so navigation is not a form redirect.
    if _wants_json(request):
        return JSONResponse({"redirect_to": url})
    return RedirectResponse(url, status_code=303)


@router.api_route("/oauth/logout", methods=["GET", "POST"])
async def logout(
    request: Request,
    directory: Annotated[DirectoryStore, Depends(get_directory)],
    auth_server: Annotated[DirectoryAuthorizationServer, Depends(get_auth_server)],
):
    params = dict(request.query_params)
    if request.method == "POST":
        form = await request.form()
        params.update({k: str(v) for k, v in form.multi_items()})

    # A cross-site GET must not sign the user out. Without a matching
    # id_token_hint, ask for confirmation; the page POSTs back here, and a
    # SameSite=Lax cookie is not sent on a cross-site POST.
    user = get_session_user(request)
    if (
        request.method == "GET"
        and user
        and not _id_token_hint_matches(auth_server, params.get("id_token_hint"), user, params.get("client_id"))
    ):
        query = urlencode({k: v for k, v in params.items() if k != "id_token_hint"})
        frontend = _frontend(directory)
        return RedirectResponse(f"{frontend}/logout{'?' + query if query else ''}", status_code=303)

    end_session(request)
    audit("logout", client_id=params.get("client_id"))
    post_logout = params.get("post_logout_redirect_uri")
    state = params.get("state")
    client_id = params.get("client_id")

    if post_logout:
        allowed = False
        if client_id:
            client = auth_server.query_client(client_id)
            allowed = bool(client and client.check_post_logout_redirect_uri(post_logout))
        else:
            for client_data in directory.list_clients():
                client = auth_server.query_client(client_data["client_id"])
                if client and client.check_post_logout_redirect_uri(post_logout):
                    allowed = True
                    break
        if allowed:
            url = post_logout
            if state:
                sep = "&" if "?" in url else "?"
                url = f"{url}{sep}{urlencode({'state': state})}"
            return _logout_navigate(request, url)

    frontend = _frontend(directory)
    return _logout_navigate(request, f"{frontend}/?logged_out=1")


def _bearer_token(request: Request) -> str | None:
    auth = request.headers.get("authorization") or ""
    if auth.lower().startswith("bearer "):
        return auth.split(" ", 1)[1].strip()
    return None


@router.get("/api/interaction/{interaction_id}")
def get_interaction(
    interaction_id: str,
    request: Request,
    runtime: Annotated[RuntimeStore, Depends(get_runtime)],
    auth_server: Annotated[DirectoryAuthorizationServer, Depends(get_auth_server)],
):
    interaction = runtime.get_interaction(interaction_id)
    if not interaction:
        raise HTTPException(status_code=404, detail="Interaction not found")
    params = interaction["params"]
    client = auth_server.query_client(params.get("client_id", ""))
    claims: list[dict] = []
    user_id = interaction.get("user_id")
    viewer = get_session_user(request) if user_id else None
    if viewer and viewer.id == user_id:
        claims = describe_release(viewer, params.get("scope") or "")
    return {
        "id": interaction["id"],
        "status": interaction["status"],
        "client": {
            "client_id": client.client_id if client else params.get("client_id"),
            "client_name": client.client_name if client else params.get("client_id"),
        },
        "scope": params.get("scope") or "",
        "scopes": (params.get("scope") or "").split(),
        "release": claims,
        "allowed_groups": client.allowed_groups if client else [],
    }


@router.post("/api/interaction/{interaction_id}/login")
def interaction_login(
    interaction_id: str,
    body: LoginBody,
    request: Request,
    response: Response,
    runtime: Annotated[RuntimeStore, Depends(get_runtime)],
    auth_server: Annotated[DirectoryAuthorizationServer, Depends(get_auth_server)],
):
    interaction = runtime.get_interaction(interaction_id)
    if not interaction:
        raise HTTPException(status_code=404, detail="Interaction not found")
    buckets = reserve_login(runtime, request, body.username)
    user = auth_server.authenticate_user(body.username, body.password)
    if not user:
        audit("login_failed", username=body.username, ip=client_ip(request), interaction=interaction_id)
        raise HTTPException(status_code=401, detail="Invalid username or password")
    release(runtime, buckets)
    client = auth_server.query_client(interaction["params"].get("client_id", ""))
    if client:
        _require_client_access(client, user)
    directory = request.app.state.directory
    result = _begin_or_finish_login(request, user, directory, interaction_id, response=response)
    if not result["mfa_required"]:
        result.update(_finish_oidc_interaction(directory, runtime, auth_server, user, interaction_id))
    audit(
        "login",
        user_id=user.id,
        username=user.username,
        ip=client_ip(request),
        mfa="trusted" if result.get("mfa_trusted") else result["mfa_required"],
    )
    result["user"] = {"id": user.id, "username": user.username}
    return result


@router.post("/api/interaction/{interaction_id}/confirm")
def interaction_confirm(
    interaction_id: str,
    body: ConfirmBody,
    request: Request,
    directory: Annotated[DirectoryStore, Depends(get_directory)],
    runtime: Annotated[RuntimeStore, Depends(get_runtime)],
    auth_server: Annotated[DirectoryAuthorizationServer, Depends(get_auth_server)],
):
    interaction = runtime.get_interaction(interaction_id)
    if not interaction:
        raise HTTPException(status_code=404, detail="Interaction not found")
    user = get_session_user(request)
    if not user or user.id != interaction.get("user_id"):
        raise HTTPException(status_code=401, detail="Not authenticated for this interaction")

    params = interaction["params"]
    client = _require_registered_redirect(auth_server, params)
    _require_client_access(client, user)
    if user.must_change_password:
        raise HTTPException(status_code=403, detail="Password change required")
    if _max_age_exceeded(request, params):
        raise HTTPException(status_code=401, detail="login_required")
    if not body.approve:
        runtime.delete_interaction(interaction_id)
        audit(
            "consent_deny",
            user_id=user.id,
            username=user.username,
            client_id=params.get("client_id"),
            scope=params.get("scope"),
        )
        redirect_uri = params.get("redirect_uri")
        query = urlencode(
            {
                "error": "access_denied",
                "error_description": "User denied the request",
                **({"state": params["state"]} if params.get("state") else {}),
            }
        )
        return {"redirect_to": f"{redirect_uri}?{query}"}

    directory.remember_consent(
        user.id,
        str(params.get("client_id") or ""),
        str(params.get("scope") or ""),
        str(params.get("redirect_uri") or ""),
    )
    try:
        location = _issue_authorization(directory, auth_server, user, params)
    except OAuth2Error as exc:
        raise HTTPException(status_code=400, detail=exc.description or exc.error) from exc

    runtime.delete_interaction(interaction_id)
    audit(
        "consent_allow",
        user_id=user.id,
        username=user.username,
        client_id=params.get("client_id"),
        scope=params.get("scope"),
    )
    return {"redirect_to": location}


@router.get("/api/appearance")
def appearance(directory: Annotated[DirectoryStore, Depends(get_directory)]):
    settings = directory.get_settings()
    return {
        "login_theme": normalize_login_theme(settings.get("login_theme")),
        "enable_demo": as_bool(settings.get("enable_demo"), True),
        "enable_help": as_bool(settings.get("enable_help"), True),
        "password_policy": directory.password_policy(),
        "login_branding": directory.login_branding(),
        "session_policy": directory.session_policy(),
        "issuer": str(settings.get("issuer") or ""),
    }


@router.get("/api/session")
def session_info(
    request: Request,
    identity: Annotated[IdentityConnector, Depends(get_identity)],
):
    user = get_session_user(request)
    if not user:
        return {"authenticated": False}
    directory = request.app.state.directory
    is_admin = identity.is_admin(user.data)
    mfa_enabled = directory.mfa_enabled(user.id)
    return {
        "authenticated": True,
        "user": {
            "id": user.id,
            "username": user.username,
            "name": user.name,
            "email": user.email,
            "groups": user.group_names,
            "is_admin": is_admin,
            "must_change_password": user.must_change_password,
            "mfa_enabled": mfa_enabled,
            "mfa_required": bool(REQUIRE_ADMIN_MFA and is_admin and not mfa_enabled),
        },
    }


@router.post("/api/auth/login")
def admin_login(
    body: LoginBody,
    request: Request,
    response: Response,
    runtime: Annotated[RuntimeStore, Depends(get_runtime)],
    identity: Annotated[IdentityConnector, Depends(get_identity)],
    auth_server: Annotated[DirectoryAuthorizationServer, Depends(get_auth_server)],
):
    buckets = reserve_login(runtime, request, body.username)
    user = auth_server.authenticate_user(body.username, body.password)
    if not user:
        audit("login_failed", username=body.username, ip=client_ip(request))
        raise HTTPException(status_code=401, detail="Invalid username or password")
    release(runtime, buckets)
    directory = request.app.state.directory
    result = _begin_or_finish_login(
        request,
        user,
        directory,
        return_to=safe_return_to(body.next, directory.app_origins()),
        response=response,
    )
    audit(
        "login",
        user_id=user.id,
        username=user.username,
        ip=client_ip(request),
        mfa="trusted" if result.get("mfa_trusted") else result["mfa_required"],
    )
    is_admin = identity.is_admin(user.data)
    mfa_enabled = directory.mfa_enabled(user.id)
    result["user"] = {
        "id": user.id,
        "username": user.username,
        "name": user.name,
        "email": user.email,
        "groups": user.group_names,
        "is_admin": is_admin,
        "must_change_password": user.must_change_password,
        "mfa_enabled": mfa_enabled,
        "mfa_required": bool(REQUIRE_ADMIN_MFA and is_admin and not mfa_enabled),
    }
    return result


@router.post("/api/auth/change-password")
def change_password(
    body: ChangePasswordBody,
    request: Request,
    identity: Annotated[IdentityConnector, Depends(get_identity)],
    directory: Annotated[DirectoryStore, Depends(get_directory)],
    runtime: Annotated[RuntimeStore, Depends(get_runtime)],
    auth_server: Annotated[DirectoryAuthorizationServer, Depends(get_auth_server)],
):
    user = get_session_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    new_password = body.new_password.strip()
    error = validate_password(new_password, user.username, directory.password_policy())
    if error:
        raise HTTPException(status_code=400, detail=error)
    if new_password == body.current_password:
        raise HTTPException(status_code=400, detail="New password must be different")
    buckets = reserve_login(runtime, request, user.username)
    checked = auth_server.authenticate_user(user.username, body.current_password)
    if not checked or checked.id != user.id:
        raise HTTPException(status_code=401, detail="Invalid current password")
    release(runtime, buckets)
    kept_return = request.session.get("return_to")
    try:
        identity.update_user(user.id, {"password": new_password, "must_change_password": False})
    except ReadOnlyError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    version = revoke_user_auth(directory, runtime, user.id)
    return_to = safe_return_to(body.next or kept_return, directory.app_origins())
    extra = {"return_to": return_to} if return_to else {}
    rotate_session(request, user_id=user.id, auth_version=version, amr=["pwd"], **extra)
    audit("password_change", user_id=user.id, username=user.username, ip=client_ip(request))
    if return_to and not return_allowed(directory, return_to, user.group_names):
        return {"ok": True, "next": "/login?error=client_forbidden"}
    return {"ok": True, "next": app_handoff_url(return_to, user.id, runtime, session_auth(request)) or return_to or "/profile"}


def _profile_dict(user: UserAccount, identity: IdentityConnector, directory: DirectoryStore) -> dict:
    return {
        "id": user.id,
        "username": user.username,
        "name": user.name,
        "email": user.email,
        "groups": user.group_names,
        "is_admin": identity.is_admin(user.data),
        "must_change_password": user.must_change_password,
        "mfa_enabled": directory.mfa_enabled(user.id),
        "writable": identity.writable,
    }


@router.get("/api/profile")
def get_profile(
    identity: Annotated[IdentityConnector, Depends(get_identity)],
    directory: Annotated[DirectoryStore, Depends(get_directory)],
    user: Annotated[UserAccount, Depends(require_user)],
):
    return _profile_dict(user, identity, directory)


@router.patch("/api/profile")
def update_profile(
    body: ProfileUpdateBody,
    identity: Annotated[IdentityConnector, Depends(get_identity)],
    directory: Annotated[DirectoryStore, Depends(get_directory)],
    auth_server: Annotated[DirectoryAuthorizationServer, Depends(get_auth_server)],
    user: Annotated[UserAccount, Depends(require_user)],
):
    payload: dict[str, str] = {}
    if body.name is not None:
        payload["name"] = body.name.strip()
    if body.email is not None:
        payload["email"] = body.email.strip()
    if not payload:
        return _profile_dict(user, identity, directory)
    try:
        identity.update_user(user.id, payload)
    except ReadOnlyError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    refreshed = auth_server.resolve_user(user.id) or user
    audit("profile_update", user_id=user.id, username=user.username, fields=list(payload))
    return _profile_dict(refreshed, identity, directory)


def _verify_mfa_code(request: Request, directory: DirectoryStore, user_id: str, code: str) -> None:
    if not directory.mfa_enabled(user_id):
        raise HTTPException(status_code=400, detail="MFA is not enabled")
    runtime = request.app.state.runtime
    buckets = reserve_mfa(runtime, request, user_id)
    try:
        method = directory.consume_mfa_code(user_id, code)
    except KeyError as exc:
        raise HTTPException(status_code=400, detail="MFA is not enabled") from exc
    if method is None:
        raise HTTPException(status_code=401, detail="Invalid MFA code")
    release(runtime, buckets)


@router.post("/api/auth/mfa")
def verify_login_mfa(
    body: MfaCodeBody,
    request: Request,
    response: Response,
    directory: Annotated[DirectoryStore, Depends(get_directory)],
    runtime: Annotated[RuntimeStore, Depends(get_runtime)],
    auth_server: Annotated[DirectoryAuthorizationServer, Depends(get_auth_server)],
):
    pending_id = request.session.get("mfa_pending_user_id")
    if not pending_id or not session_is_live(request):
        raise HTTPException(status_code=401, detail="No MFA challenge")
    try:
        _verify_mfa_code(request, directory, pending_id, body.code)
    except HTTPException:
        audit("mfa_failed", user_id=pending_id, ip=client_ip(request))
        raise
    user = auth_server.resolve_user(pending_id)
    if not user:
        raise HTTPException(status_code=401, detail="Unknown user")
    interaction_id = request.session.get("mfa_pending_interaction")
    return_to = safe_return_to(request.session.get("return_to"), directory.app_origins())
    extra = {"return_to": return_to} if return_to else {}
    rotate_session(
        request,
        user_id=user.id,
        auth_version=directory.auth_version(user.id),
        amr=["pwd", "otp"],
        **extra,
    )
    trusted = False
    if body.trust:
        issued = directory.remember_mfa_device(user.id)
        if issued:
            trusted = True
            set_mfa_device_cookie(
                response,
                issued,
                directory.session_policy()["mfa_trust_days"] * 86400,
            )
    audit("mfa_ok", user_id=user.id, username=user.username, ip=client_ip(request), trust=trusted)
    if interaction_id:
        finished = _finish_oidc_interaction(directory, runtime, auth_server, user, interaction_id)
        return {
            "ok": True,
            "must_change_password": user.must_change_password,
            **finished,
        }
    next_path = _login_next(
        user,
        request.app.state.directory,
        return_to=return_to,
        runtime=runtime,
        request=request,
        mfa_done=True,
    )
    return {"ok": True, "next": next_path, "must_change_password": user.must_change_password}


@router.get("/api/mfa")
def mfa_status(
    request: Request,
    directory: Annotated[DirectoryStore, Depends(get_directory)],
    user: Annotated[UserAccount, Depends(require_user)],
):
    return {"enabled": directory.mfa_enabled(user.id)}


@router.post("/api/mfa/setup")
def mfa_setup(
    request: Request,
    directory: Annotated[DirectoryStore, Depends(get_directory)],
    user: Annotated[UserAccount, Depends(require_user)],
):
    if directory.mfa_enabled(user.id):
        raise HTTPException(status_code=409, detail="MFA is already enabled")
    secret = new_totp_secret()
    request.session["mfa_setup_secret"] = directory.seal(secret)
    issuer = _issuer(directory)
    title = directory.login_branding().get("title") or ""
    uri = provisioning_uri(secret, user.username, issuer, title=title)
    return {"secret": secret, "otpauth_url": uri, "qr": qr_data_uri(uri)}


@router.post("/api/mfa/confirm")
def mfa_confirm(
    body: MfaCodeBody,
    request: Request,
    directory: Annotated[DirectoryStore, Depends(get_directory)],
    user: Annotated[UserAccount, Depends(require_user)],
):
    sealed = request.session.get("mfa_setup_secret")
    try:
        secret = directory.unseal(str(sealed)) if sealed else ""
    except ValueError:
        secret = ""
    if not secret:
        raise HTTPException(status_code=400, detail="No MFA setup in progress")
    runtime = request.app.state.runtime
    buckets = reserve_mfa(runtime, request, user.id)
    step = verify_totp(secret, body.code)
    if step is None:
        raise HTTPException(status_code=401, detail="Invalid MFA code")
    release(runtime, buckets)
    codes = new_recovery_codes()
    directory.set_mfa(
        user.id,
        {
            "enabled": True,
            "totp_secret": secret,
            "recovery_hashes": directory.recovery_hashes(codes),
            "last_counter": step,
        },
    )
    request.session.pop("mfa_setup_secret", None)
    version = revoke_user_auth(directory, request.app.state.runtime, user.id)
    request.session["auth_version"] = version
    request.session["amr"] = ["pwd", "otp"]
    audit("mfa_enabled", user_id=user.id, username=user.username, ip=client_ip(request))
    return {"ok": True, "recovery_codes": codes}


@router.post("/api/mfa/disable")
def mfa_disable(
    body: MfaCodeBody,
    request: Request,
    directory: Annotated[DirectoryStore, Depends(get_directory)],
    user: Annotated[UserAccount, Depends(require_user)],
):
    _verify_mfa_code(request, directory, user.id, body.code)
    directory.delete_mfa(user.id)
    version = revoke_user_auth(directory, request.app.state.runtime, user.id)
    request.session["auth_version"] = version
    request.session["amr"] = ["pwd"]
    audit("mfa_disabled", user_id=user.id, username=user.username)
    return {"ok": True}


@router.post("/api/auth/logout")
def admin_logout(request: Request):
    user_id = request.session.get("user_id")
    end_session(request)
    audit("logout", user_id=user_id)
    return {"ok": True}
