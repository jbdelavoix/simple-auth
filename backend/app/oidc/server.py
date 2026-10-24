from __future__ import annotations

import time
from typing import Any

from authlib.common.security import generate_token
from authlib.oauth2.rfc6749 import AuthorizationServer
from authlib.oauth2.rfc6750 import BearerTokenGenerator
from fastapi.responses import JSONResponse, Response
from joserfc.jwk import KeySet

from app.config import (
    ACCESS_TOKEN_EXPIRES,
    DEFAULT_DEMO_CLIENT_ID,
    ISSUER,
    REFRESH_TOKEN_EXPIRES,
    SCOPES_SUPPORTED,
)
from app.connectors.base import IdentityConnector
from app.oidc.grants import (
    AuthorizationCodeGrant,
    DirectoryCodeChallenge,
    OpenIDCode,
    RefreshTokenGrant,
)
from app.oidc.models import OAuth2Client, OAuth2Token, UserAccount
from app.store.directory import DirectoryStore, as_bool, client_mode
from app.store.jwks import load_private_key_set
from app.store.runtime import RuntimeStore


class DirectoryAuthorizationServer(AuthorizationServer):
    def __init__(
        self,
        directory: DirectoryStore,
        runtime: RuntimeStore,
        identity: IdentityConnector,
        issuer: str = ISSUER,
    ):
        super().__init__(scopes_supported=SCOPES_SUPPORTED)
        self.directory = directory
        self.runtime = runtime
        self.identity = identity
        self.issuer = issuer
        self.private_key_set: KeySet = load_private_key_set()
        self.register_token_generator("default", self._bearer_generator())
        openid = OpenIDCode(self, require_nonce=False)
        pkce = DirectoryCodeChallenge(required=True)
        self.register_grant(AuthorizationCodeGrant, [pkce, openid])
        self.register_grant(RefreshTokenGrant)

    def reload_keys(self) -> None:
        self.private_key_set = load_private_key_set()

    def _bearer_generator(self) -> BearerTokenGenerator:
        def access_token_generator(**kwargs):
            return generate_token(42)

        def refresh_token_generator(**kwargs):
            return generate_token(48)

        def expires_generator(client, grant_type):
            return ACCESS_TOKEN_EXPIRES

        return BearerTokenGenerator(
            access_token_generator,
            refresh_token_generator,
            expires_generator,
        )

    def query_client(self, client_id: str):
        data = self.directory.get_client(client_id)
        if not data:
            return None
        if client_id == DEFAULT_DEMO_CLIENT_ID and not as_bool(self.directory.get_settings().get("enable_demo"), True):
            return None
        if client_mode(data) == "forward":
            return None
        return OAuth2Client(data)

    def save_token(self, token: dict[str, Any], request) -> None:
        now = int(time.time())
        expires_in = int(token.get("expires_in") or ACCESS_TOKEN_EXPIRES)
        client_id = request.client.get_client_id()
        user = request.user
        user_id = user.id if user else None
        code = getattr(request, "authorization_code", None)
        refresh = getattr(request, "refresh_token", None)
        family_gen = None
        auth_version = int(getattr(user, "auth_version", 0) or 0) if user else 0
        amr = list(getattr(user, "amr", None) or []) if user else []
        auth_time = getattr(user, "auth_time", None) if user else None
        if code is not None:
            if getattr(code, "family_gen", None) is not None:
                family_gen = int(code.family_gen)
            auth_version = int(getattr(code, "auth_version", auth_version) or 0)
            if code.get_amr():
                amr = list(code.get_amr())
            if code.get_auth_time():
                auth_time = code.get_auth_time()
        if refresh is not None:
            data = getattr(refresh, "_data", {}) or {}
            if data.get("family_gen") is not None:
                family_gen = int(data["family_gen"])
            if data.get("auth_version") is not None:
                auth_version = int(data["auth_version"])
            if data.get("amr"):
                amr = list(data["amr"])
            if data.get("auth_time"):
                auth_time = data["auth_time"]
        item = {
            "access_token": token.get("access_token"),
            "refresh_token": token.get("refresh_token"),
            "token_type": token.get("token_type", "Bearer"),
            "scope": token.get("scope") or "",
            "client_id": client_id,
            "user_id": user_id,
            "family_id": f"{user_id}:{client_id}" if user_id else client_id,
            "family_gen": family_gen,
            "auth_version": auth_version,
            "amr": amr,
            "auth_time": int(auth_time or now),
            "issued_at": now,
            "expires_at": now + expires_in,
            "refresh_token_expires_at": (now + REFRESH_TOKEN_EXPIRES) if token.get("refresh_token") else None,
            "revoked": False,
        }
        self.runtime.save_token(item)

    def resolve_user(self, user_id: str | None) -> UserAccount | None:
        if not user_id:
            return None
        data = self.identity.get_user(user_id)
        if not data:
            return None
        groups = self.identity.user_group_names(data)
        return UserAccount(data, groups)

    def authenticate_user(self, username: str, password: str) -> UserAccount | None:
        public = self.identity.authenticate(username, password)
        if not public:
            return None
        groups = self.identity.user_group_names(public)
        return UserAccount(public, groups)

    def create_oauth2_request(self, request=None):
        from authlib.oauth2.rfc6749 import OAuth2Request

        if isinstance(request, OAuth2Request):
            return request
        raise TypeError("Pass a pre-built OAuth2Request from build_oauth2_request()")

    def create_json_request(self, request=None):
        from authlib.oauth2.rfc6749 import JsonRequest

        if isinstance(request, JsonRequest):
            return request
        raise TypeError("Pass a pre-built JsonRequest from build_json_request()")

    def send_signal(self, name, *args, **kwargs):
        return None

    def handle_response(self, status_code, payload, headers):
        header_list = [(k, v) for k, v in (headers or [])]
        if isinstance(payload, dict):
            return JSONResponse(payload, status_code=status_code, headers=dict(header_list))
        return Response(content=payload or "", status_code=status_code, headers=dict(header_list))

    def get_token_by_access(self, access_token: str) -> OAuth2Token | None:
        from app.revocation import token_is_current

        item = self.runtime.get_token_by_access(access_token)
        if not item:
            return None
        user = self.resolve_user(item.get("user_id")) if item.get("user_id") else None
        if item.get("user_id") and not token_is_current(self.directory, item, user):
            return None
        if user:
            user.amr = list(item.get("amr") or ["pwd"])
            user.auth_time = item.get("auth_time")
            user.auth_version = int(item.get("auth_version") or 0)
        client = self.query_client(item["client_id"])
        return OAuth2Token(item, client=client, user=user)
