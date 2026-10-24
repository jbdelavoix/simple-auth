from __future__ import annotations

import time
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from app.audit import audit, read_events, rotate_logs, rotation_info
from app.config import (
    AUDIT_PATH,
    CLIENTS_PATH,
    DATA_DIR,
    DEFAULT_ADMIN_PASSWORD,
    DEFAULT_ADMIN_USERNAME,
    DEFAULT_DEMO_CLIENT_ID,
    DIRECTORY_PATH,
    FRONTEND_ORIGIN,
    IDENTITIES_PATH,
    JWKS_PATH,
    RUNTIME_PATH,
    SCOPES_SUPPORTED,
)
from app.connectors.base import IdentityConnector, ReadOnlyError
from app.deps import get_directory, get_identity, get_runtime, require_admin
from app.oidc.models import UserAccount
from app.revocation import revoke_user_auth
from app.security import generate_client_secret, normalize_password_policy, validate_password
from app.sessions import proxy_diagnostics
from app.store.directory import (
    LOGIN_THEMES,
    DirectoryStore,
    as_bool,
    normalize_login_branding,
    normalize_login_theme,
    normalize_session_policy,
    seeds_default_admin_password,
    sync_demo_client_redirects,
)
from app.store.jwks import current_kid, rotate_signing_keys
from app.store.runtime import RuntimeStore

router = APIRouter(prefix="/api/admin", tags=["admin"])


class UserCreate(BaseModel):
    username: str
    password: str
    email: str = ""
    name: str = ""
    enabled: bool = True
    email_verified: bool = False
    group_ids: list[str] = Field(default_factory=list)
    attributes: dict[str, Any] = Field(default_factory=dict)


class UserUpdate(BaseModel):
    username: str | None = None
    password: str | None = None
    email: str | None = None
    name: str | None = None
    enabled: bool | None = None
    email_verified: bool | None = None
    group_ids: list[str] | None = None
    attributes: dict[str, Any] | None = None


class GroupCreate(BaseModel):
    name: str
    description: str = ""


class GroupUpdate(BaseModel):
    name: str | None = None
    description: str | None = None


class ClientCreate(BaseModel):
    client_id: str
    client_name: str = ""
    redirect_uris: list[str] = Field(default_factory=list)
    post_logout_redirect_uris: list[str] = Field(default_factory=list)
    grant_types: list[str] = Field(default_factory=lambda: ["authorization_code", "refresh_token"])
    response_types: list[str] = Field(default_factory=lambda: ["code"])
    token_endpoint_auth_method: str = "none"
    scope: str = " ".join(SCOPES_SUPPORTED)
    allowed_groups: list[str] = Field(default_factory=list)
    origins: list[str] = Field(default_factory=list)
    mode: str = "oidc"
    generate_secret: bool = False


class PasswordPolicyUpdate(BaseModel):
    min_length: int | None = None
    require_letter: bool | None = None
    require_digit: bool | None = None
    require_upper: bool | None = None
    require_special: bool | None = None
    forbid_username: bool | None = None


class LoginBrandingUpdate(BaseModel):
    background: str | None = None
    panel: str | None = None
    ink: str | None = None
    accent: str | None = None
    logo: str | None = None
    title: str | None = None
    subtitle: str | None = None


class SessionPolicyUpdate(BaseModel):
    idle_seconds: int | None = None
    absolute_seconds: int | None = None
    mfa_trust_days: int | None = None


class SettingsUpdate(BaseModel):
    login_theme: str | None = None
    enable_demo: bool | None = None
    enable_help: bool | None = None
    password_policy: PasswordPolicyUpdate | None = None
    login_branding: LoginBrandingUpdate | None = None
    session_policy: SessionPolicyUpdate | None = None


class ClientUpdate(BaseModel):
    client_name: str | None = None
    redirect_uris: list[str] | None = None
    post_logout_redirect_uris: list[str] | None = None
    grant_types: list[str] | None = None
    response_types: list[str] | None = None
    token_endpoint_auth_method: str | None = None
    scope: str | None = None
    allowed_groups: list[str] | None = None
    origins: list[str] | None = None
    mode: str | None = None
    rotate_secret: bool | None = None


def _write_or_409(exc: Exception) -> HTTPException:
    if isinstance(exc, ReadOnlyError):
        return HTTPException(status_code=409, detail=str(exc))
    if isinstance(exc, KeyError):
        return HTTPException(status_code=404, detail=str(exc))
    if isinstance(exc, ValueError):
        return HTTPException(status_code=400, detail=str(exc))
    return HTTPException(status_code=500, detail=str(exc))


@router.get("/settings")
def get_settings(
    request: Request,
    _: Annotated[UserAccount, Depends(require_admin)],
    directory: Annotated[DirectoryStore, Depends(get_directory)],
    identity: Annotated[IdentityConnector, Depends(get_identity)],
):
    settings = directory.get_settings()
    seed_user = identity.get_user_by_username(DEFAULT_ADMIN_USERNAME)
    return {
        "issuer": settings.get("issuer"),
        "frontend_origin": settings.get("frontend_origin"),
        "discovery_url": f"{settings.get('issuer')}/.well-known/openid-configuration",
        "scopes_supported": SCOPES_SUPPORTED,
        "login_theme": normalize_login_theme(settings.get("login_theme")),
        "enable_demo": as_bool(settings.get("enable_demo"), True),
        "enable_help": as_bool(settings.get("enable_help"), True),
        "password_policy": directory.password_policy(),
        "login_branding": directory.login_branding(),
        "session_policy": directory.session_policy(),
        "connector": identity.info(),
        "init": {
            "data_dir": str(DATA_DIR),
            "directory": DIRECTORY_PATH.name,
            "identities": IDENTITIES_PATH.name,
            "clients": CLIENTS_PATH.name,
            "runtime": RUNTIME_PATH.name,
            "jwks": JWKS_PATH.name,
            "audit": AUDIT_PATH.name,
            "seed_username": DEFAULT_ADMIN_USERNAME if seed_user else None,
            "seed_password": DEFAULT_ADMIN_PASSWORD if seed_user and seeds_default_admin_password() else None,
            "signing_kid": current_kid(),
        },
        "proxy": proxy_diagnostics(request),
    }


@router.patch("/settings")
def patch_settings(
    request: Request,
    payload: SettingsUpdate,
    admin: Annotated[UserAccount, Depends(require_admin)],
    directory: Annotated[DirectoryStore, Depends(get_directory)],
    identity: Annotated[IdentityConnector, Depends(get_identity)],
):
    updates: dict[str, Any] = {}
    if payload.login_theme is not None:
        theme = str(payload.login_theme).strip().lower()
        if theme not in LOGIN_THEMES:
            raise HTTPException(status_code=400, detail="Unknown login theme")
        updates["login_theme"] = theme
    if payload.enable_demo is not None:
        updates["enable_demo"] = bool(payload.enable_demo)
    if payload.enable_help is not None:
        updates["enable_help"] = bool(payload.enable_help)
    if payload.password_policy is not None:
        current = directory.password_policy()
        current.update({k: v for k, v in payload.password_policy.model_dump().items() if v is not None})
        updates["password_policy"] = normalize_password_policy(current)
    if payload.login_branding is not None:
        current = directory.login_branding()
        current.update({k: v for k, v in payload.login_branding.model_dump().items() if v is not None})
        updates["login_branding"] = normalize_login_branding(current)
    if payload.session_policy is not None:
        current = directory.session_policy()
        current.update({k: v for k, v in payload.session_policy.model_dump().items() if v is not None})
        try:
            updates["session_policy"] = normalize_session_policy(current, strict=True)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not updates:
        raise HTTPException(status_code=400, detail="No settings to update")
    directory.update_settings(**updates)
    if updates.get("enable_demo") and directory.restore_demo_client():
        sync_demo_client_redirects(directory, FRONTEND_ORIGIN)
        audit("client_create", client_id=DEFAULT_DEMO_CLIENT_ID, admin_id=admin.id, actor=admin.username)
    return get_settings(request, admin, directory, identity)


@router.post("/crypto/reset")
def reset_crypto(
    request: Request,
    admin: Annotated[UserAccount, Depends(require_admin)],
    runtime: Annotated[RuntimeStore, Depends(get_runtime)],
):
    public = rotate_signing_keys()
    request.app.state.auth_server.reload_keys()
    revoked = runtime.revoke_all_credentials()
    keys = public.get("keys") or []
    kid = keys[0].get("kid") if keys else None
    audit(
        "crypto_reset",
        admin_id=admin.id,
        actor=admin.username,
        kid=kid,
        tokens=revoked["tokens"],
        authorization_codes=revoked["authorization_codes"],
    )
    return {"ok": True, "kid": kid, "revoked": revoked}


@router.get("/audit")
def list_audit(
    _: Annotated[UserAccount, Depends(require_admin)],
    limit: int = 200,
    action: str | None = None,
    outcome: str | None = None,
    q: str | None = None,
    actor: str | None = None,
    target: str | None = None,
    ip: str | None = None,
    since: int | None = None,
    until: int | None = None,
):
    return {
        "events": read_events(
            limit=limit,
            action=action,
            outcome=outcome,
            q=q,
            actor=actor,
            target=target,
            ip=ip,
            since=since,
            until=until,
        ),
        "rotation": rotation_info(),
    }


@router.post("/audit/rotate")
def rotate_audit(admin: Annotated[UserAccount, Depends(require_admin)]):
    rotated = rotate_logs(force=True)
    if rotated:
        audit("audit_rotate", admin_id=admin.id, actor=admin.username)
    return {"ok": True, "rotated": rotated, "rotation": rotation_info()}


@router.get("/users")
def list_users(
    _: Annotated[UserAccount, Depends(require_admin)],
    identity: Annotated[IdentityConnector, Depends(get_identity)],
    directory: Annotated[DirectoryStore, Depends(get_directory)],
):
    try:
        users = identity.list_users()
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    for user in users:
        user["groups"] = identity.user_group_names(user)
        user["mfa_enabled"] = directory.mfa_enabled(user["id"])
    return users


@router.post("/users", status_code=201)
def create_user(
    body: UserCreate,
    admin: Annotated[UserAccount, Depends(require_admin)],
    identity: Annotated[IdentityConnector, Depends(get_identity)],
    directory: Annotated[DirectoryStore, Depends(get_directory)],
):
    error = validate_password(body.password, body.username, directory.password_policy())
    if error:
        raise HTTPException(status_code=400, detail=error)
    try:
        user = identity.create_user(body.model_dump())
    except (ReadOnlyError, ValueError, KeyError) as exc:
        raise _write_or_409(exc) from exc
    user["groups"] = identity.user_group_names(user)
    audit("user_create", user_id=user["id"], username=user["username"], admin_id=admin.id, actor=admin.username)
    return user


@router.put("/users/{user_id}")
def update_user(
    user_id: str,
    body: UserUpdate,
    request: Request,
    admin: Annotated[UserAccount, Depends(require_admin)],
    identity: Annotated[IdentityConnector, Depends(get_identity)],
    directory: Annotated[DirectoryStore, Depends(get_directory)],
):
    payload = {k: v for k, v in body.model_dump().items() if v is not None}
    if payload.get("password"):
        error = validate_password(
            payload["password"],
            payload.get("username") or "",
            directory.password_policy(),
        )
        if error:
            raise HTTPException(status_code=400, detail=error)
    try:
        user = identity.update_user(user_id, payload)
    except (ReadOnlyError, ValueError, KeyError) as exc:
        raise _write_or_409(exc) from exc
    if payload.get("password") or payload.get("enabled") is False:
        version = revoke_user_auth(directory, request.app.state.runtime, user_id)
        if request.session.get("user_id") == user_id and payload.get("enabled") is not False:
            request.session["auth_version"] = version
            request.session["amr"] = ["pwd"]
            request.session["auth_at"] = int(time.time())
    user["groups"] = identity.user_group_names(user)
    audit(
        "user_update",
        user_id=user_id,
        username=user.get("username"),
        admin_id=admin.id,
        actor=admin.username,
        password_changed=bool(payload.get("password")),
        enabled=payload.get("enabled"),
    )
    return user


@router.post("/users/{user_id}/mfa/reset")
def reset_user_mfa(
    user_id: str,
    request: Request,
    admin: Annotated[UserAccount, Depends(require_admin)],
    directory: Annotated[DirectoryStore, Depends(get_directory)],
    identity: Annotated[IdentityConnector, Depends(get_identity)],
):
    target = identity.get_user(user_id)
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    directory.delete_mfa(user_id)
    revoke_user_auth(directory, request.app.state.runtime, user_id)
    audit("mfa_reset", user_id=user_id, username=target.get("username"), admin_id=admin.id, actor=admin.username)
    return {"ok": True}


@router.delete("/users/{user_id}", status_code=204)
def delete_user(
    user_id: str,
    request: Request,
    admin: Annotated[UserAccount, Depends(require_admin)],
    identity: Annotated[IdentityConnector, Depends(get_identity)],
    directory: Annotated[DirectoryStore, Depends(get_directory)],
):
    try:
        identity.delete_user(user_id)
    except (ReadOnlyError, KeyError) as exc:
        raise _write_or_409(exc) from exc
    revoke_user_auth(directory, request.app.state.runtime, user_id)
    audit("user_delete", user_id=user_id, admin_id=admin.id, actor=admin.username)


@router.get("/groups")
def list_groups(
    _: Annotated[UserAccount, Depends(require_admin)],
    identity: Annotated[IdentityConnector, Depends(get_identity)],
):
    try:
        return identity.list_groups()
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@router.post("/groups", status_code=201)
def create_group(
    body: GroupCreate,
    admin: Annotated[UserAccount, Depends(require_admin)],
    identity: Annotated[IdentityConnector, Depends(get_identity)],
):
    try:
        group = identity.create_group(body.model_dump())
    except (ReadOnlyError, ValueError, KeyError) as exc:
        raise _write_or_409(exc) from exc
    audit("group_create", target_id=group["id"], name=group["name"], admin_id=admin.id, actor=admin.username)
    return group


@router.put("/groups/{group_id}")
def update_group(
    group_id: str,
    body: GroupUpdate,
    admin: Annotated[UserAccount, Depends(require_admin)],
    identity: Annotated[IdentityConnector, Depends(get_identity)],
):
    payload = {k: v for k, v in body.model_dump().items() if v is not None}
    try:
        group = identity.update_group(group_id, payload)
    except (ReadOnlyError, ValueError, KeyError) as exc:
        raise _write_or_409(exc) from exc
    audit("group_update", target_id=group_id, name=group.get("name"), admin_id=admin.id, actor=admin.username)
    return group


@router.delete("/groups/{group_id}", status_code=204)
def delete_group(
    group_id: str,
    admin: Annotated[UserAccount, Depends(require_admin)],
    identity: Annotated[IdentityConnector, Depends(get_identity)],
):
    try:
        identity.delete_group(group_id)
    except (ReadOnlyError, KeyError) as exc:
        raise _write_or_409(exc) from exc
    audit("group_delete", target_id=group_id, admin_id=admin.id, actor=admin.username)


@router.get("/clients")
def list_clients(
    _: Annotated[UserAccount, Depends(require_admin)],
    directory: Annotated[DirectoryStore, Depends(get_directory)],
):
    return directory.list_clients()


@router.post("/clients", status_code=201)
def create_client(
    body: ClientCreate,
    admin: Annotated[UserAccount, Depends(require_admin)],
    directory: Annotated[DirectoryStore, Depends(get_directory)],
):
    secret = generate_client_secret() if body.generate_secret else None
    payload = body.model_dump()
    payload.pop("generate_secret", None)
    if secret:
        payload["token_endpoint_auth_method"] = "client_secret_post"
    try:
        client = directory.create_client(payload, secret)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    audit("client_create", client_id=client["client_id"], admin_id=admin.id, actor=admin.username)
    return client


@router.put("/clients/{client_id}")
def update_client(
    client_id: str,
    body: ClientUpdate,
    admin: Annotated[UserAccount, Depends(require_admin)],
    directory: Annotated[DirectoryStore, Depends(get_directory)],
):
    payload = {k: v for k, v in body.model_dump().items() if v is not None and k != "rotate_secret"}
    new_secret = generate_client_secret() if body.rotate_secret else None
    try:
        client = directory.update_client(client_id, payload, new_secret=new_secret)
    except (KeyError, ValueError) as exc:
        raise _write_or_409(exc) from exc
    audit(
        "client_update",
        client_id=client_id,
        admin_id=admin.id,
        actor=admin.username,
        secret_rotated=bool(new_secret),
    )
    return client


@router.delete("/clients/{client_id}", status_code=204)
def delete_client(
    client_id: str,
    admin: Annotated[UserAccount, Depends(require_admin)],
    directory: Annotated[DirectoryStore, Depends(get_directory)],
):
    try:
        directory.delete_client(client_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Client not found") from exc
    audit("client_delete", client_id=client_id, admin_id=admin.id, actor=admin.username)
