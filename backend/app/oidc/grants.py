from __future__ import annotations

import time
from typing import TYPE_CHECKING

from authlib.oauth2.rfc6749 import grants
from authlib.oauth2.rfc7636 import CodeChallenge
from authlib.oidc.core import UserInfo
from authlib.oidc.core.grants import OpenIDCode as _OpenIDCode

from app.config import AUTHORIZATION_CODE_EXPIRES
from app.oidc.models import AuthorizationCode, OAuth2Token, UserAccount, build_user_info

if TYPE_CHECKING:
    from app.oidc.server import DirectoryAuthorizationServer


class AuthorizationCodeGrant(grants.AuthorizationCodeGrant):
    TOKEN_ENDPOINT_AUTH_METHODS = [
        "client_secret_basic",
        "client_secret_post",
        "none",
    ]

    def __init__(self, request, server: DirectoryAuthorizationServer):
        super().__init__(request, server)
        self.server: DirectoryAuthorizationServer = server

    def save_authorization_code(self, code, request):
        payload = request.payload.data
        now = int(time.time())
        item = {
            "code": code,
            "client_id": request.client.get_client_id(),
            "redirect_uri": request.payload.redirect_uri or "",
            "scope": request.payload.scope or "",
            "user_id": request.user.id,
            "nonce": payload.get("nonce"),
            "auth_time": int(getattr(request.user, "auth_time", None) or now),
            "amr": list(getattr(request.user, "amr", None) or ["pwd"]),
            "auth_version": int(getattr(request.user, "auth_version", 0) or 0),
            "code_challenge": payload.get("code_challenge"),
            "code_challenge_method": payload.get("code_challenge_method"),
            "created_at": now,
            "expires_at": now + AUTHORIZATION_CODE_EXPIRES,
        }
        if item["nonce"]:
            self.server.runtime.remember_nonce(
                item["client_id"], item["nonce"], AUTHORIZATION_CODE_EXPIRES
            )
        self.server.runtime.save_authorization_code(item)
        return AuthorizationCode(item)

    def query_authorization_code(self, code, client):
        item, status = self.server.runtime.consume_authorization_code(code, client.get_client_id())
        if status == "replay":
            from app.audit import audit

            audit(
                "code_reuse",
                client_id=client.get_client_id(),
                user_id=(item or {}).get("user_id"),
            )
            return None
        if not item or status != "ok":
            return None
        auth_code = AuthorizationCode(item)
        if auth_code.is_expired():
            return None
        return auth_code

    def delete_authorization_code(self, authorization_code):
        self.server.runtime.delete_authorization_code(authorization_code.code)

    def authenticate_user(self, authorization_code):
        user = self.server.resolve_user(authorization_code.user_id)
        if not user or not user.enabled or user.must_change_password:
            return None
        if int(getattr(authorization_code, "auth_version", 0) or 0) != self.server.directory.auth_version(user.id):
            return None
        client = self.server.query_client(authorization_code.client_id)
        if client and not client.allows_user(user.group_names):
            from app.audit import audit

            audit(
                "client_forbidden",
                user_id=user.id,
                username=user.username,
                client_id=client.client_id,
            )
            return None
        user.amr = list(authorization_code.get_amr() or ["pwd"])
        user.auth_time = authorization_code.get_auth_time()
        user.auth_version = int(getattr(authorization_code, "auth_version", 0) or 0)
        return user


class RefreshTokenGrant(grants.RefreshTokenGrant):
    TOKEN_ENDPOINT_AUTH_METHODS = [
        "client_secret_basic",
        "client_secret_post",
        "none",
    ]
    INCLUDE_NEW_REFRESH_TOKEN = True

    def __init__(self, request, server: DirectoryAuthorizationServer):
        super().__init__(request, server)
        self.server: DirectoryAuthorizationServer = server

    def authenticate_refresh_token(self, refresh_token):
        item, status = self.server.runtime.consume_refresh_token(refresh_token)
        if status == "reuse":
            from app.audit import audit

            audit(
                "refresh_reuse",
                family_id=(item or {}).get("family_id"),
                client_id=(item or {}).get("client_id"),
                user_id=(item or {}).get("user_id"),
            )
            return None
        if not item or status != "ok":
            return None
        client = self.server.query_client(item["client_id"])
        user = self.server.resolve_user(item.get("user_id")) if item.get("user_id") else None
        if not user or not user.enabled or user.must_change_password:
            return None
        if int(item.get("auth_version") or 0) != self.server.directory.auth_version(user.id):
            return None
        if client and not client.allows_user(user.group_names):
            from app.audit import audit

            audit(
                "client_forbidden",
                user_id=user.id,
                username=user.username,
                client_id=client.client_id,
            )
            return None
        user.amr = list(item.get("amr") or ["pwd"])
        user.auth_time = item.get("auth_time")
        user.auth_version = int(item.get("auth_version") or 0)
        token = OAuth2Token(item, client=client, user=user)
        if token.is_refresh_token_active():
            return token
        return None

    def authenticate_user(self, credential):
        user = self.server.resolve_user(credential.user_id)
        if not user or not user.enabled or user.must_change_password:
            return None
        data = getattr(credential, "_data", {}) or {}
        if int(data.get("auth_version") or 0) != self.server.directory.auth_version(user.id):
            return None
        user.amr = list(data.get("amr") or ["pwd"])
        user.auth_time = data.get("auth_time")
        user.auth_version = int(data.get("auth_version") or 0)
        return user

    def revoke_old_credential(self, credential):
        self.server.runtime.mark_refresh_rotated(credential.refresh_token)


class OpenIDCode(_OpenIDCode):
    def __init__(self, server: DirectoryAuthorizationServer, require_nonce: bool = False):
        super().__init__(require_nonce=require_nonce)
        self.server = server

    def exists_nonce(self, nonce, request):
        return self.server.runtime.nonce_exists(request.payload.client_id, nonce)

    def resolve_client_private_key(self, client):
        return self.server.private_key_set

    def get_client_claims(self, client):
        return {
            "iss": self.server.issuer,
            "aud": [client.get_client_id()],
        }

    def get_client_algorithm(self, client):
        return "RS256"

    def get_encode_header(self, client):
        header = {"alg": self.get_client_algorithm(client)}
        keys = self.server.private_key_set.keys
        if keys:
            kid = keys[0].as_dict().get("kid")
            if kid:
                header["kid"] = kid
        return header

    def generate_user_info(self, user, scope):
        if isinstance(user, UserAccount):
            return build_user_info(user, scope)
        return UserInfo(sub=str(user))


class DirectoryCodeChallenge(CodeChallenge):
    DEFAULT_CODE_CHALLENGE_METHOD = "S256"
    SUPPORTED_CODE_CHALLENGE_METHOD = ["S256"]

    def __init__(self, required: bool = True):
        super().__init__(required=required)

    def validate_code_challenge(self, grant, redirect_uri):
        request = grant.request
        challenge = request.payload.data.get("code_challenge")
        method = request.payload.data.get("code_challenge_method")
        # Public clients have no secret, so the code is only bound to the
        # caller by PKCE. A confidential client authenticates at the token
        # endpoint; PKCE stays mandatory when that client actually sends it.
        if not challenge and not method:
            auth_method = getattr(request.client, "token_endpoint_auth_method", None)
            if auth_method == "none":
                from authlib.oauth2.rfc6749 import InvalidRequestError

                raise InvalidRequestError("Missing 'code_challenge'")
            return
        super().validate_code_challenge(grant, redirect_uri)

    def get_authorization_code_challenge(self, authorization_code):
        return authorization_code.code_challenge

    def get_authorization_code_challenge_method(self, authorization_code):
        return authorization_code.code_challenge_method
