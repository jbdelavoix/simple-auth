from __future__ import annotations

import time
from typing import Any

from authlib.oauth2.rfc6749 import ClientMixin, TokenMixin, scope_to_list, list_to_scope
from authlib.oidc.core import AuthorizationCodeMixin as OIDCAuthorizationCodeMixin
from authlib.oidc.core import UserInfo

from app.security import verify_secret


class UserAccount:
    def __init__(self, data: dict[str, Any], group_names: list[str] | None = None):
        self.data = data
        self.id = data["id"]
        self.username = data["username"]
        self.email = data.get("email") or ""
        self.name = data.get("name") or data["username"]
        self.enabled = data.get("enabled", True)
        self.group_names = group_names or []
        self.attributes = data.get("attributes") or {}
        self.must_change_password = bool(data.get("must_change_password"))
        self.amr: list[str] = []
        self.auth_time: int | None = None
        self.auth_version = 0

    def get_user_id(self) -> str:
        return self.id


class OAuth2Client(ClientMixin):
    def __init__(self, data: dict[str, Any]):
        self._data = data
        self.client_id = data["client_id"]
        self.client_name = data.get("client_name") or data["client_id"]
        self.redirect_uris = list(data.get("redirect_uris") or [])
        self.post_logout_redirect_uris = list(data.get("post_logout_redirect_uris") or [])
        self.grant_types = list(data.get("grant_types") or [])
        self.response_types = list(data.get("response_types") or ["code"])
        self.token_endpoint_auth_method = data.get("token_endpoint_auth_method") or "client_secret_basic"
        self.scope = data.get("scope") or ""
        self.allowed_groups = [name for name in (data.get("allowed_groups") or []) if str(name).strip()]
        self.client_secret_hash = data.get("client_secret_hash")
        self.id_token_signed_response_alg = data.get("id_token_signed_response_alg") or "RS256"
        self.client_metadata = {
            "client_id": self.client_id,
            "client_name": self.client_name,
            "redirect_uris": self.redirect_uris,
            "post_logout_redirect_uris": self.post_logout_redirect_uris,
            "grant_types": self.grant_types,
            "response_types": self.response_types,
            "token_endpoint_auth_method": self.token_endpoint_auth_method,
            "scope": self.scope,
            "allowed_groups": self.allowed_groups,
            "id_token_signed_response_alg": self.id_token_signed_response_alg,
        }

    def allows_user(self, group_names: list[str] | None) -> bool:
        if not self.allowed_groups:
            return True
        user_groups = {str(name).lower() for name in (group_names or [])}
        return any(name.lower() in user_groups for name in self.allowed_groups)

    def get_client_id(self) -> str:
        return self.client_id

    def get_default_redirect_uri(self) -> str | None:
        return self.redirect_uris[0] if self.redirect_uris else None

    def get_allowed_scope(self, scope: str | None) -> str:
        if not scope:
            return ""
        allowed = set(scope_to_list(self.scope))
        return list_to_scope([s for s in scope_to_list(scope) if s in allowed])

    def check_redirect_uri(self, redirect_uri: str) -> bool:
        return redirect_uri in self.redirect_uris

    def check_client_secret(self, client_secret: str) -> bool:
        if not self.client_secret_hash:
            return False
        return verify_secret(client_secret, self.client_secret_hash)

    def check_endpoint_auth_method(self, method: str, endpoint: str) -> bool:
        if endpoint == "token":
            return self.token_endpoint_auth_method == method
        return True

    def check_response_type(self, response_type: str) -> bool:
        return response_type in self.response_types

    def check_grant_type(self, grant_type: str) -> bool:
        return grant_type in self.grant_types

    def check_post_logout_redirect_uri(self, uri: str) -> bool:
        return uri in self.post_logout_redirect_uris


class AuthorizationCode(OIDCAuthorizationCodeMixin):
    def __init__(self, data: dict[str, Any]):
        self._data = data
        self.code = data["code"]
        self.client_id = data["client_id"]
        self.redirect_uri = data.get("redirect_uri") or ""
        self.scope = data.get("scope") or ""
        self.user_id = data["user_id"]
        self.nonce = data.get("nonce")
        self.auth_time = data.get("auth_time") or data.get("created_at")
        self.code_challenge = data.get("code_challenge")
        self.code_challenge_method = data.get("code_challenge_method")
        self.expires_at = data.get("expires_at", 0)
        self.amr = list(data.get("amr") or [])
        self.auth_version = int(data.get("auth_version") or 0)
        self.family_gen = data.get("family_gen")

    def get_redirect_uri(self) -> str:
        return self.redirect_uri

    def get_scope(self) -> str:
        return self.scope

    def get_nonce(self) -> str | None:
        return self.nonce

    def get_auth_time(self) -> int | None:
        return self.auth_time

    def get_amr(self) -> list[str] | None:
        return list(self.amr) if self.amr else None

    def is_expired(self) -> bool:
        return int(time.time()) >= int(self.expires_at)


class OAuth2Token(TokenMixin):
    def __init__(self, data: dict[str, Any], client: OAuth2Client | None = None, user: UserAccount | None = None):
        self._data = data
        self.access_token = data.get("access_token")
        self.refresh_token = data.get("refresh_token")
        self.client_id = data["client_id"]
        self.user_id = data.get("user_id")
        self.scope = data.get("scope") or ""
        self.token_type = data.get("token_type") or "Bearer"
        self.expires_at = data.get("expires_at", 0)
        self.refresh_token_expires_at = data.get("refresh_token_expires_at")
        self.revoked = bool(data.get("revoked"))
        self._client = client
        self._user = user

    def check_client(self, client: OAuth2Client) -> bool:
        return self.client_id == client.get_client_id()

    def get_scope(self) -> str:
        return self.scope

    def get_expires_in(self) -> int:
        return max(0, int(self.expires_at) - int(time.time()))

    def is_expired(self) -> bool:
        return int(time.time()) >= int(self.expires_at)

    def is_revoked(self) -> bool:
        return self.revoked

    def get_user(self) -> UserAccount | None:
        return self._user

    def get_client(self) -> OAuth2Client | None:
        return self._client

    def is_refresh_token_active(self) -> bool:
        if self.revoked or not self.refresh_token:
            return False
        if self.refresh_token_expires_at and int(time.time()) >= int(self.refresh_token_expires_at):
            return False
        return True


def build_user_info(user: UserAccount, scope: str) -> UserInfo:
    info = UserInfo(
        sub=user.id,
        name=user.name,
        preferred_username=user.username,
        email=user.email or None,
        email_verified=bool(user.email) and bool(user.data.get("email_verified")),
    )
    filtered = info.filter(scope)
    scopes = scope_to_list(scope)
    if "groups" in scopes:
        filtered["groups"] = list(user.group_names)
    if user.amr:
        filtered["amr"] = list(user.amr)
    # Ensure sub always present for openid
    filtered.setdefault("sub", user.id)
    return filtered


SCOPE_CLAIMS = {
    "openid": ("sub",),
    "profile": ("name", "preferred_username"),
    "email": ("email", "email_verified"),
    "groups": ("groups",),
}


def describe_release(user: UserAccount, scope: str) -> list[dict[str, Any]]:
    info = build_user_info(user, scope)
    items: list[dict[str, Any]] = []
    for name in scope_to_list(scope):
        if name == "offline_access":
            items.append({"scope": name, "claims": []})
            continue
        claims = []
        for key in SCOPE_CLAIMS.get(name, ()):
            if key not in info:
                continue
            value = info[key]
            if isinstance(value, (list, tuple)):
                value = [str(part) for part in value]
            elif value is None:
                value = ""
            elif not isinstance(value, (bool, str, int)):
                value = str(value)
            claims.append({"name": key, "value": value})
        items.append({"scope": name, "claims": claims})
    return items
