from __future__ import annotations

from typing import Annotated

from fastapi import Depends, HTTPException, Request, status

from app.config import REQUIRE_ADMIN_MFA
from app.connectors.base import IdentityConnector
from app.oidc.models import UserAccount
from app.oidc.server import DirectoryAuthorizationServer
from app.sessions import session_is_live
from app.store.directory import DirectoryStore
from app.store.runtime import RuntimeStore


def get_directory(request: Request) -> DirectoryStore:
    return request.app.state.directory


def get_identity(request: Request) -> IdentityConnector:
    return request.app.state.identity


def get_runtime(request: Request) -> RuntimeStore:
    return request.app.state.runtime


def get_auth_server(request: Request) -> DirectoryAuthorizationServer:
    return request.app.state.auth_server


APP_SCOPE = "app"


def get_session_user(request: Request, *, allow_app: bool = False) -> UserAccount | None:
    """User of the session cookie.

    Cookies set on a gated app host by /session/establish carry scope "app".
    The app's upstream sees that cookie, so it is only good for
    /session/check on its own origin, never for the IdP itself.
    """
    if request.session.get("mfa_pending_user_id"):
        return None
    user_id = request.session.get("user_id")
    if not user_id:
        return None
    if request.session.get("scope") == APP_SCOPE and not allow_app:
        return None
    if not session_is_live(request):
        request.session.clear()
        return None
    user = get_auth_server(request).resolve_user(user_id)
    directory = request.app.state.directory
    if not user or not user.enabled:
        request.session.clear()
        return None
    if int(request.session.get("auth_version") or 0) != directory.auth_version(user.id):
        request.session.clear()
        return None
    user.amr = [str(item) for item in (request.session.get("amr") or ["pwd"])]
    user.auth_time = int(request.session.get("auth_at") or 0) or None
    user.auth_version = int(request.session.get("auth_version") or 0)
    return user


def require_user(request: Request) -> UserAccount:
    user = get_session_user(request)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    if user.must_change_password:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Password change required")
    return user


def require_admin(
    request: Request,
    identity: Annotated[IdentityConnector, Depends(get_identity)],
) -> UserAccount:
    user = require_user(request)
    if not identity.is_admin(user.data):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin required")
    if user.must_change_password:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Password change required")
    if REQUIRE_ADMIN_MFA and not request.app.state.directory.mfa_enabled(user.id):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="MFA enrollment required")
    return user
