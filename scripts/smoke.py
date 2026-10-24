#!/usr/bin/env python3
"""Smoke test: discovery + authorization code + PKCE + userinfo groups."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
import sys
import tempfile
from pathlib import Path
from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
os.environ["OIDC_DATA_DIR"] = tempfile.mkdtemp(prefix="oidc-smoke-")
os.environ["OIDC_APP_ORIGINS"] = "http://app.test"

from fastapi.testclient import TestClient

from app.main import app


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _assert_guards() -> None:
    import ipaddress
    from concurrent.futures import ThreadPoolExecutor

    from app import config
    from app.sessions import client_ip
    from app.session_gate import header_value, identity_headers
    from urllib.parse import unquote

    from app.mfa import provisioning_uri
    from app.store.directory import valid_redirect_uri

    otpauth = provisioning_uri("JBSWY3DPEHPK3PXP", "ada:lovelace", "https://auth.example.com:8443", title="Acme")
    parsed_otp = urlparse(otpauth)
    assert unquote(parsed_otp.path.lstrip("/")) == "Acme:adalovelace"
    assert parse_qs(parsed_otp.query)["issuer"] == ["Acme"]
    assert "https" not in unquote(parsed_otp.path)
    ported = provisioning_uri("JBSWY3DPEHPK3PXP", "ada", "https://auth.example.com:8443")
    parsed_port = urlparse(ported)
    assert unquote(parsed_port.path.lstrip("/")) == "ada"
    assert parse_qs(parsed_port.query)["issuer"] == ["auth.example.com:8443"]

    assert valid_redirect_uri("javascript:alert(1)", https_only=False) is False
    assert valid_redirect_uri("https://app.example/cb#frag", https_only=True) is False
    assert valid_redirect_uri("http://localhost/cb", https_only=True) is False
    assert valid_redirect_uri("https://app.example/cb", https_only=True) is True
    assert valid_redirect_uri("http://localhost:5173/demo/callback", https_only=False) is True
    assert header_value("admins,root") is None
    assert header_value("alice") == "alice"
    assert identity_headers("alice", "a@b.c", "Ada Lovelace", ["users", "bad,admins"]) == {
        "Remote-User": "alice",
        "Remote-Email": "a@b.c",
        "Remote-Name": "Ada Lovelace",
        "Remote-Groups": "users",
    }
    assert identity_headers("a\r\nX: y", "", "", []) is None

    class _Req:
        def __init__(self, host: str, forwarded: str):
            self.client = type("C", (), {"host": host})()
            self.headers = {"x-forwarded-for": forwarded}

    previous = config.TRUSTED_PROXIES
    try:
        config.TRUSTED_PROXIES = (ipaddress.ip_network("127.0.0.1/32"),)
        assert client_ip(_Req("127.0.0.1", "1.2.3.4, 10.1.1.1")) == "10.1.1.1"
        config.TRUSTED_PROXIES = (
            ipaddress.ip_network("127.0.0.1/32"),
            ipaddress.ip_network("10.0.0.0/8"),
        )
        assert client_ip(_Req("127.0.0.1", "1.2.3.4, 10.1.1.1")) == "1.2.3.4"
        assert client_ip(_Req("8.8.8.8", "1.2.3.4")) == "8.8.8.8"
    finally:
        config.TRUSTED_PROXIES = previous

    from authlib.common.security import is_secure_transport
    from starlette.requests import Request

    from app.oidc.request import public_uri

    def _token_call(peer: str, proto: str | None) -> Request:
        headers = [(b"host", b"auth.example.com")]
        if proto:
            headers.append((b"x-forwarded-proto", proto.encode()))
        return Request(
            {
                "type": "http",
                "method": "POST",
                "scheme": "http",
                "path": "/oauth/token",
                "query_string": b"",
                "headers": headers,
                "client": (peer, 40000),
                "server": ("10.0.0.2", 8000),
            }
        )

    previous_insecure = os.environ.pop("AUTHLIB_INSECURE_TRANSPORT", None)
    try:
        config.TRUSTED_PROXIES = (ipaddress.ip_network("10.0.0.1/32"),)
        proxied_uri = public_uri(_token_call("10.0.0.1", "https"))
        assert proxied_uri == "https://auth.example.com/oauth/token", proxied_uri
        assert is_secure_transport(proxied_uri)
        # Plain HTTP straight to uvicorn, a spoofed header from an untrusted peer,
        # or a client value ahead of the one an appending proxy wrote.
        for peer, proto in (
            ("203.0.113.9", None),
            ("203.0.113.9", "https"),
            ("10.0.0.1", None),
            ("10.0.0.1", "https, http"),
        ):
            uri = public_uri(_token_call(peer, proto))
            assert uri.startswith("http://") and not is_secure_transport(uri), (peer, proto, uri)

        from starlette.applications import Starlette
        from starlette.responses import PlainTextResponse
        from starlette.routing import Route

        from app.http_security import SecureTransportMiddleware

        guarded = Starlette(
            routes=[
                Route("/oauth/{name}", lambda _r: PlainTextResponse("ok"), methods=["GET", "POST"]),
                Route("/api/auth/login", lambda _r: PlainTextResponse("ok"), methods=["POST"]),
                Route("/session/check", lambda _r: PlainTextResponse("ok"), methods=["POST"]),
                Route("/api/health", lambda _r: PlainTextResponse("ok")),
            ]
        )
        guarded.add_middleware(SecureTransportMiddleware, enforce=True)
        direct = TestClient(guarded, client=("203.0.113.9", 40000))
        for path in ("/oauth/token", "/oauth/userinfo", "/oauth/revoke", "/api/auth/login", "/session/check"):
            refused = direct.post(path)
            assert refused.status_code == 400, (path, refused.text)
            assert refused.json()["error"] == "insecure_transport"
        assert direct.post("/oauth/token", headers={"Host": "localhost"}).status_code == 400
        assert direct.post("/oauth/token", headers={"X-Forwarded-Proto": "https"}).status_code == 400
        assert direct.get("/api/health").status_code == 200
        via_proxy = TestClient(guarded, client=("10.0.0.1", 40000))
        assert via_proxy.post("/oauth/token", headers={"X-Forwarded-Proto": "https"}).status_code == 200
        assert via_proxy.post("/oauth/token").status_code == 400
        tls = TestClient(guarded, base_url="https://auth.example.com", client=("203.0.113.9", 40000))
        assert tls.post("/oauth/token").status_code == 200
    finally:
        config.TRUSTED_PROXIES = previous
        if previous_insecure is not None:
            os.environ["AUTHLIB_INSECURE_TRANSPORT"] = previous_insecure

    runtime = app.state.runtime
    runtime.save_authorization_code(
        {
            "code": "race-code",
            "client_id": "demo-app",
            "redirect_uri": "http://localhost:5173/demo/callback",
            "scope": "openid",
            "user_id": "race-user",
            "code_challenge": "x",
            "code_challenge_method": "S256",
            "created_at": 1,
            "expires_at": 4_000_000_000,
        }
    )
    winners: list[str] = []

    def once() -> None:
        _item, status = runtime.consume_authorization_code("race-code", "demo-app")
        winners.append(status)

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(lambda _i: once(), range(8)))
    assert winners.count("ok") == 1, winners
    assert winners.count("replay") == 7, winners

    from app.store.runtime import RuntimeStore

    peer = RuntimeStore(runtime.path)
    bucket = "203.0.113.5:ada"
    for _ in range(7):
        assert peer.login_attempt([(bucket, 8)])
    assert runtime.login_attempt([(bucket, 8)]) is True
    assert runtime.login_attempt([(bucket, 8)]) is False
    runtime.login_success(bucket)
    assert peer.login_attempt([(bucket, 8)]) is True
    runtime.login_success(bucket)

    granted: list[bool] = []
    with ThreadPoolExecutor(max_workers=16) as pool:
        granted = list(pool.map(lambda _i: runtime.login_attempt([("race:ada", 5)]), range(16)))
    assert granted.count(True) == 5, granted
    runtime.login_success("race:ada")

    data_dir = Path(os.environ["OIDC_DATA_DIR"])
    directory_doc = json.loads((data_dir / "directory.json").read_text())
    clients_doc = json.loads((data_dir / "clients.json").read_text())
    assert "clients" not in directory_doc
    assert {item["client_id"] for item in clients_doc["clients"]} >= {"demo-app", "session-apps"}


def main() -> None:
    verifier = b64url(secrets.token_bytes(32))
    while len(verifier) < 43:
        verifier += "a"
    challenge = b64url(hashlib.sha256(verifier.encode()).digest())

    _assert_guards()

    client = TestClient(app, follow_redirects=False)

    health = client.get("/api/health")
    assert health.status_code == 200, health.text
    assert health.json() == {"status": "ok"}
    assert "X-Content-Type-Options" in health.headers
    assert health.headers.get("X-Frame-Options") == "DENY"

    discovery = client.get("/.well-known/openid-configuration")
    assert discovery.status_code == 200, discovery.text
    assert discovery.json()["issuer"]

    look = client.get("/api/appearance")
    assert look.status_code == 200, look.text
    assert look.json()["login_theme"] in {"classic", "slate", "light", "contrast"}
    branding = look.json()["login_branding"]
    assert set(branding) >= {"background", "panel", "ink", "accent", "logo", "title", "subtitle"}

    csrf = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "admin"},
        headers={"Origin": "https://evil.example"},
    )
    assert csrf.status_code == 403, csrf.text

    authorize = client.get(
        "/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": "demo-app",
            "redirect_uri": "http://localhost:5173/demo/callback",
            "scope": "openid profile email groups offline_access",
            "state": secrets.token_urlsafe(8),
            "nonce": secrets.token_urlsafe(8),
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        },
    )
    assert authorize.status_code in (302, 303), authorize.text
    match = re.search(r"interaction=([^&]+)", authorize.headers["location"])
    assert match
    interaction_id = match.group(1)

    bad = client.get(
        "/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": "demo-app",
            "redirect_uri": "https://evil.example/callback",
            "scope": "openid",
            "state": "x",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        },
    )
    assert bad.status_code == 400, bad.text

    login = client.post(
        f"/api/interaction/{interaction_id}/login",
        json={"username": "admin", "password": "admin"},
    )
    assert login.status_code == 200, login.text
    assert login.json().get("must_change_password") is True

    forced = client.get(
        "/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": "demo-app",
            "redirect_uri": "http://localhost:5173/demo/callback",
            "scope": "openid",
            "state": "must-change",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        },
    )
    assert forced.status_code in (302, 303), forced.text
    assert "change-password" in forced.headers["location"]
    assert "code=" not in forced.headers["location"]

    changed = client.post(
        "/api/auth/change-password",
        json={"current_password": "admin", "new_password": "SmokeTest.1234"},
    )
    assert changed.status_code == 200, changed.text

    reauth = client.get(
        "/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": "demo-app",
            "redirect_uri": "http://localhost:5173/demo/callback",
            "scope": "openid",
            "state": "prompt-login",
            "prompt": "login",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        },
    )
    assert reauth.status_code in (302, 303), reauth.text
    assert "/login" in reauth.headers["location"]
    assert "code=" not in reauth.headers["location"]

    silent = client.get(
        "/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": "demo-app",
            "redirect_uri": "http://localhost:5173/demo/callback",
            "scope": "openid email",
            "state": "prompt-none",
            "prompt": "none",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        },
    )
    assert silent.status_code in (302, 303), silent.text
    assert "error=consent_required" in silent.headers["location"]

    confirm = client.post(
        f"/api/interaction/{interaction_id}/confirm",
        json={"approve": True},
    )
    assert confirm.status_code == 200, confirm.text
    code = parse_qs(urlparse(confirm.json()["redirect_to"]).query)["code"][0]

    token = client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "http://localhost:5173/demo/callback",
            "client_id": "demo-app",
            "code_verifier": verifier,
        },
    )
    assert token.status_code == 200, token.text
    access_token = token.json()["access_token"]
    refresh_token = token.json()["refresh_token"]
    assert token.json().get("id_token")
    assert token.json().get("expires_in") == 900

    userinfo = client.get(
        "/oauth/userinfo",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert userinfo.status_code == 200, userinfo.text
    assert "admins" in userinfo.json().get("groups", [])
    assert userinfo.json().get("email_verified") is False
    assert userinfo.json().get("amr") == ["pwd"]
    id_payload = token.json()["id_token"].split(".")[1]
    id_payload += "=" * (-len(id_payload) % 4)
    id_claims = json.loads(base64.urlsafe_b64decode(id_payload))
    assert id_claims.get("email_verified") is False
    assert id_claims.get("amr") == ["pwd"]

    rotated = client.post(
        "/oauth/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": "demo-app",
        },
    )
    assert rotated.status_code == 200, rotated.text
    reused = client.post(
        "/oauth/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": "demo-app",
        },
    )
    assert reused.status_code >= 400, reused.text
    family_dead = client.post(
        "/oauth/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": rotated.json()["refresh_token"],
            "client_id": "demo-app",
        },
    )
    assert family_dead.status_code >= 400, family_dead.text

    again = client.get(
        "/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": "demo-app",
            "redirect_uri": "http://localhost:5173/demo/callback",
            "scope": "openid profile email groups offline_access",
            "state": "replay",
            "nonce": secrets.token_urlsafe(8),
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        },
    )
    assert again.status_code in (302, 303), again.text
    code_again = parse_qs(urlparse(again.headers["location"]).query)["code"][0]
    token_again = client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code_again,
            "redirect_uri": "http://localhost:5173/demo/callback",
            "client_id": "demo-app",
            "code_verifier": verifier,
        },
    )
    assert token_again.status_code == 200, token_again.text
    replay = client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code_again,
            "redirect_uri": "http://localhost:5173/demo/callback",
            "client_id": "demo-app",
            "code_verifier": verifier,
        },
    )
    assert replay.status_code >= 400, replay.text
    replay_refresh = client.post(
        "/oauth/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": token_again.json()["refresh_token"],
            "client_id": "demo-app",
        },
    )
    assert replay_refresh.status_code >= 400, replay_refresh.text

    denied = TestClient(app, follow_redirects=False).get(
        "/session/check",
        params={"rd": "http://app.test/secret"},
    )
    assert denied.status_code == 401
    assert "/login" in denied.headers.get("location", "")
    assert "app.test" in denied.headers.get("location", "")

    admin_login = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "SmokeTest.1234", "next": "http://app.test/secret"},
    )
    assert admin_login.status_code == 200, admin_login.text
    assert admin_login.json().get("mfa_required") is not True
    start = urlparse(admin_login.json().get("next") or "")
    assert start.scheme == "http" and start.netloc == "app.test", admin_login.text
    assert start.path == "/session/start"
    assert parse_qs(start.query).get("rd") == ["http://app.test/secret"]

    def forward_ticket(browser: TestClient, idp: TestClient) -> str:
        """App host sets the state cookie, the signed-in IdP binds a ticket to it."""
        started = browser.get(f"{start.path}?{start.query}")
        assert started.status_code == 303, started.text
        assert browser.cookies.get("sa_gate")
        to_handoff = urlparse(started.headers["location"])
        assert to_handoff.path == "/session/handoff"
        handed = idp.get(f"{to_handoff.path}?{to_handoff.query}")
        assert handed.status_code == 303, handed.text
        establish = urlparse(handed.headers["location"])
        assert establish.netloc == "app.test" and establish.path == "/session/establish", handed.headers
        assert parse_qs(establish.query).get("ticket")
        return f"{establish.path}?{establish.query}"

    stranger = TestClient(app, follow_redirects=False)
    assert stranger.get("/session/check").status_code == 401
    ticket_url = forward_ticket(stranger, client)
    established = stranger.get(ticket_url)
    assert established.status_code == 303, established.text
    assert established.headers.get("location") == "http://app.test/secret"
    assert not stranger.cookies.get("sa_gate")
    reused = TestClient(app, follow_redirects=False).get(ticket_url)
    assert reused.status_code == 303
    assert "/login" in reused.headers.get("location", "")
    # A ticket minted for one browser must not sign another one in (login CSRF).
    attacker = TestClient(app, follow_redirects=False)
    planted = forward_ticket(attacker, client)
    victim = TestClient(app, follow_redirects=False)
    landed = victim.get(planted)
    assert landed.status_code == 303
    assert urlparse(landed.headers["location"]).path == "/session/start", landed.headers
    assert victim.get("/session/check", params={"rd": "http://app.test/secret"}).status_code == 401
    unbound = urlparse(client.get("/session/handoff", params={"rd": "http://app.test/secret"}).headers["location"])
    assert unbound.path == "/session/start", unbound
    gate = stranger.get("/session/check", params={"rd": "http://app.test/secret"})
    assert gate.status_code == 200, gate.text
    assert gate.headers.get("remote-user") == "admin"
    assert "admins" in gate.headers.get("remote-groups", "")
    # The app-host cookie reaches the app's upstream: it must not open the IdP.
    assert stranger.get("/api/admin/users").status_code == 401
    assert stranger.get("/api/session").json() == {"authenticated": False}
    assert stranger.get("/session/check").status_code == 401
    assert stranger.get("/session/check", params={"rd": "http://localhost:8000/"}).status_code == 401
    users = client.get("/api/admin/users")
    assert users.status_code == 200
    assert len(users.json()) >= 1
    proxied = client.get("/api/admin/settings", headers={"X-Forwarded-For": "198.51.100.7"})
    assert proxied.status_code == 200, proxied.text
    proxy = proxied.json()["proxy"]
    assert proxy["forwarded_headers"] is True and proxy["peer_trusted"] is False, proxy
    assert proxy["client_ip"] == proxy["peer"], proxy
    assert proxied.json()["init"]["seed_password"] == "admin"
    apps = client.get("/api/admin/clients")
    assert apps.status_code == 200, apps.text
    gated = next(item for item in apps.json() if item["client_id"] == "session-apps")
    assert gated["mode"] == "forward"
    assert "http://app.test" in gated["origins"]
    clash = client.post(
        "/api/admin/clients",
        json={
            "client_id": "dup-app",
            "client_name": "Dup",
            "mode": "forward",
            "origins": ["http://app.test"],
            "allowed_groups": [],
        },
    )
    assert clash.status_code == 400, clash.text
    assert clash.json().get("detail") == "origin_taken"
    other = client.post(
        "/api/admin/clients",
        json={
            "client_id": "other-app",
            "client_name": "Other",
            "mode": "forward",
            "origins": ["https://other-app.test"],
            "allowed_groups": [],
        },
    )
    assert other.status_code == 201, other.text
    # A Forward host added in the console is a valid Host on /session/* only.
    app_host = TestClient(app, follow_redirects=False)
    assert app_host.get("/session/check", headers={"Host": "other-app.test"}).status_code == 401
    assert app_host.get("/session/start", headers={"Host": "other-app.test"}).status_code == 303
    assert app_host.get("/api/health", headers={"Host": "other-app.test"}).status_code == 400
    assert app_host.get("/oauth/authorize", headers={"Host": "other-app.test"}).status_code == 400
    assert app_host.get("/session/check", headers={"Host": "unknown.test"}).status_code == 400
    # Same rule for an app host seeded from OIDC_APP_ORIGINS.
    assert app_host.get("/session/check", headers={"Host": "app.test"}).status_code == 401
    assert app_host.get("/api/health", headers={"Host": "app.test"}).status_code == 400
    assert app_host.get("/api/admin/users", headers={"Host": "app.test"}).status_code == 400
    steal = client.put(
        "/api/admin/clients/other-app",
        json={"mode": "forward", "origins": ["http://app.test"]},
    )
    assert steal.status_code == 400, steal.text
    assert steal.json().get("detail") == "origin_taken"
    demo = next(item for item in apps.json() if item["client_id"] == "demo-app")
    assert demo["mode"] == "oidc"
    public = client.post(
        "/api/admin/clients",
        json={
            "client_id": "spa-app",
            "client_name": "SPA",
            "mode": "oidc",
            "redirect_uris": ["https://spa.test/cb"],
            "token_endpoint_auth_method": "none",
        },
    )
    assert public.status_code == 201, public.text
    assert public.json()["token_endpoint_auth_method"] == "none"
    rotated = client.put("/api/admin/clients/spa-app", json={"rotate_secret": True})
    assert rotated.status_code == 200, rotated.text
    assert rotated.json()["token_endpoint_auth_method"] == "client_secret_post"
    assert rotated.json().get("client_secret")
    back_public = client.put("/api/admin/clients/spa-app", json={"token_endpoint_auth_method": "none"})
    assert back_public.status_code == 200, back_public.text
    assert back_public.json()["token_endpoint_auth_method"] == "none"
    assert back_public.json()["has_secret"] is False
    no_secret = client.put("/api/admin/clients/spa-app", json={"token_endpoint_auth_method": "client_secret_post"})
    assert no_secret.status_code == 400, no_secret.text
    assert no_secret.json().get("detail") == "client_secret_required"
    still_public = next(item for item in client.get("/api/admin/clients").json() if item["client_id"] == "spa-app")
    assert still_public["token_endpoint_auth_method"] == "none"
    confidential = client.put(
        "/api/admin/clients/spa-app",
        json={"token_endpoint_auth_method": "client_secret_post", "rotate_secret": True},
    )
    assert confidential.status_code == 200, confidential.text
    assert confidential.json()["has_secret"] is True
    assert confidential.json().get("client_secret")
    denied_groups = client.put(
        "/api/admin/clients/session-apps",
        json={"mode": "forward", "allowed_groups": ["nobody"], "origins": gated["origins"]},
    )
    assert denied_groups.status_code == 200, denied_groups.text
    blocked = stranger.get("/session/check", params={"rd": "http://app.test/secret"})
    assert blocked.status_code == 403
    assert "client_forbidden" in blocked.headers.get("location", "")
    # Proxies append the request URI without encoding it; a second rd must not
    # swap the checked app for the IdP itself.
    smuggled = client.get("/session/check?rd=http://app.test/secret?x=1&rd=http://localhost:8000/")
    assert smuggled.status_code == 403, smuggled.status_code
    assert client.get("/session/check").status_code == 403
    moved = client.put(
        "/api/admin/clients/session-apps",
        json={"mode": "forward", "allowed_groups": [], "origins": ["https://other.test"]},
    )
    assert moved.status_code == 200, moved.text
    dropped = TestClient(app, follow_redirects=False).get(
        "/session/check",
        params={"rd": "http://app.test/secret"},
    )
    assert dropped.status_code == 401
    assert "app.test" not in dropped.headers.get("location", "")
    me = client.get("/api/profile")
    assert me.status_code == 200, me.text
    assert me.json()["username"] == "admin"
    assert me.json()["writable"] is True
    patched = client.patch("/api/profile", json={"name": "Smoke Admin"})
    assert patched.status_code == 200, patched.text
    assert patched.json()["name"] == "Smoke Admin"
    admin_row = next(item for item in users.json() if item["username"] == "admin")
    edited = client.put(
        f"/api/admin/users/{admin_row['id']}",
        json={"name": "Directory Admin", "email": "admin@example.com", "enabled": True},
    )
    assert edited.status_code == 200, edited.text
    assert edited.json()["name"] == "Directory Admin"

    import pyotp

    setup = client.post("/api/mfa/setup")
    assert setup.status_code == 200, setup.text
    secret = setup.json()["secret"]
    from urllib.parse import unquote

    otpauth = setup.json()["otpauth_url"]
    parsed_otp = urlparse(otpauth)
    label = unquote(parsed_otp.path.lstrip("/"))
    assert label == "admin", label
    assert parse_qs(parsed_otp.query)["issuer"] == ["localhost:8000"]
    confirm_mfa = client.post("/api/mfa/confirm", json={"code": pyotp.TOTP(secret).now()})
    assert confirm_mfa.status_code == 200, confirm_mfa.text
    recovery = confirm_mfa.json()["recovery_codes"]
    assert recovery

    client.post("/api/auth/logout")
    challenge = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "SmokeTest.1234"},
    )
    assert challenge.status_code == 200, challenge.text
    assert challenge.json().get("mfa_required") is True
    blocked = client.get("/api/admin/users")
    assert blocked.status_code == 401
    verified = client.post("/api/auth/mfa", json={"code": recovery[0]})
    assert verified.status_code == 200, verified.text
    assert verified.json().get("next") == "/admin"
    users = client.get("/api/admin/users")
    assert users.status_code == 200
    client.post("/api/auth/logout")
    forward_login = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "SmokeTest.1234", "next": "https://other.test/secret"},
    )
    assert forward_login.status_code == 200, forward_login.text
    assert forward_login.json().get("mfa_required") is True
    assert forward_login.json().get("next") == "/mfa"
    forward_mfa = client.post("/api/auth/mfa", json={"code": recovery[1]})
    assert forward_mfa.status_code == 200, forward_mfa.text
    forward_next = urlparse(forward_mfa.json().get("next") or "")
    assert forward_next.scheme == "https" and forward_next.netloc == "other.test", forward_mfa.text
    assert forward_next.path == "/session/start"
    assert parse_qs(forward_next.query).get("rd") == ["https://other.test/secret"]

    bad_redirect = client.post(
        "/api/admin/clients",
        json={
            "client_id": "js-app",
            "client_name": "JS",
            "redirect_uris": ["javascript:alert(1)"],
            "mode": "oidc",
        },
    )
    assert bad_redirect.status_code == 400, bad_redirect.text
    bad_group = client.post("/api/admin/groups", json={"name": "bad,admins"})
    assert bad_group.status_code == 400, bad_group.text
    long_password = "A1" + ("x" * 80)
    long_user = client.post(
        "/api/admin/users",
        json={"username": "long-pass", "password": long_password, "email": "long@example.com"},
    )
    assert long_user.status_code == 400, long_user.text

    created = client.post(
        "/api/admin/users",
        json={
            "username": "bob",
            "password": "BobTest.12345",
            "email": "bob@example.com",
            "email_verified": True,
            "group_ids": [],
        },
    )
    assert created.status_code == 201, created.text
    bob_id = created.json()["id"]
    bob = TestClient(app, follow_redirects=False)
    bob2 = TestClient(app, follow_redirects=False)
    assert bob.post("/api/auth/login", json={"username": "bob", "password": "BobTest.12345"}).status_code == 200
    assert bob2.post("/api/auth/login", json={"username": "bob", "password": "BobTest.12345"}).status_code == 200
    assert bob.get("/api/profile").status_code == 200
    changed_bob = bob.post(
        "/api/auth/change-password",
        json={"current_password": "BobTest.12345", "new_password": "BobTest.67890"},
    )
    assert changed_bob.status_code == 200, changed_bob.text
    assert bob.get("/api/profile").status_code == 200
    assert bob2.get("/api/profile").status_code == 401
    disabled = client.put(f"/api/admin/users/{bob_id}", json={"enabled": False})
    assert disabled.status_code == 200, disabled.text
    assert bob.get("/api/profile").status_code == 401

    hidden = client.patch("/api/admin/settings", json={"enable_demo": False})
    assert hidden.status_code == 200, hidden.text
    demo_off = client.get(
        "/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": "demo-app",
            "redirect_uri": "http://localhost:5173/demo/callback",
            "scope": "openid",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        },
    )
    assert demo_off.status_code == 400, demo_off.text
    assert client.delete("/api/admin/clients/demo-app").status_code in (200, 204)
    assert client.patch("/api/admin/settings", json={"enable_demo": True}).status_code == 200
    restored = next(item for item in client.get("/api/admin/clients").json() if item["client_id"] == "demo-app")
    assert restored["token_endpoint_auth_method"] == "none", restored
    assert "http://localhost:5173/demo/callback" in restored["redirect_uris"], restored
    assert "http://localhost:8000/demo" in restored["post_logout_redirect_uris"], restored
    demo_back = client.get(
        "/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": "demo-app",
            "redirect_uri": "http://localhost:5173/demo/callback",
            "scope": "openid",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        },
    )
    assert demo_back.status_code in (302, 303), demo_back.text
    assert client.patch("/api/admin/settings", json={"enable_demo": True}).status_code == 200
    assert sum(item["client_id"] == "demo-app" for item in client.get("/api/admin/clients").json()) == 1

    unauth_revoke = client.post("/oauth/revoke", data={"token": "x", "client_id": "spa-app"})
    assert unauth_revoke.status_code == 401, unauth_revoke.text
    public_revoke = client.post("/oauth/revoke", data={"token": "x", "client_id": "demo-app"})
    assert public_revoke.status_code == 200, public_revoke.text

    cross_site = client.get("/oauth/logout", params={"client_id": "demo-app"})
    assert cross_site.status_code == 303
    assert "/logout?" in cross_site.headers["location"]
    assert client.get("/api/profile").status_code == 200

    confirm = client.post(
        "/oauth/logout",
        data={
            "client_id": "demo-app",
            "post_logout_redirect_uri": "http://localhost:8000/demo",
            "state": "bye",
        },
        headers={"Accept": "application/json"},
    )
    assert confirm.status_code == 200, confirm.text
    assert confirm.json()["redirect_to"] == "http://localhost:8000/demo?state=bye"
    assert client.get("/api/profile").status_code == 401
    assert client.post("/api/auth/login", json={"username": "admin", "password": "SmokeTest.1234"}).status_code == 200
    assert client.post("/api/auth/mfa", json={"code": recovery[2]}).status_code == 200

    saved_cookie = client.cookies.get("oidc_session")
    hinted = client.get(
        "/oauth/logout",
        params={"client_id": "demo-app", "id_token_hint": token.json()["id_token"]},
    )
    assert hinted.status_code == 303
    assert "/logout?" not in hinted.headers["location"]
    replayed = TestClient(app).get("/api/profile", cookies={"oidc_session": saved_cookie})
    assert replayed.status_code == 401, replayed.text
    relog = client.post("/api/auth/login", json={"username": "admin", "password": "SmokeTest.1234"})
    assert relog.status_code == 200, relog.text
    assert client.post("/api/auth/mfa", json={"code": recovery[3]}).status_code == 200
    assert client.post("/api/auth/mfa", json={"code": recovery[3]}).status_code == 401

    policy = client.get("/api/admin/settings").json()["session_policy"]
    assert policy["idle_seconds"] == 1800, policy
    assert policy["absolute_seconds"] == 43200, policy
    assert policy["mfa_trust_days"] == 30, policy
    rejected = client.patch(
        "/api/admin/settings",
        json={"session_policy": {"idle_seconds": 7200, "absolute_seconds": 60, "mfa_trust_days": 30}},
    )
    assert rejected.status_code == 400, rejected.text
    hidden = client.patch(
        "/api/admin/settings",
        json={"session_policy": {"idle_seconds": 1800, "absolute_seconds": 43200, "mfa_trust_days": 0}},
    )
    assert hidden.status_code == 200, hidden.text
    assert hidden.json()["session_policy"]["mfa_trust_days"] == 0
    client.post("/api/auth/logout")
    assert client.post("/api/auth/login", json={"username": "admin", "password": "SmokeTest.1234"}).json()["mfa_required"]
    no_cookie = client.post("/api/auth/mfa", json={"code": recovery[4], "trust": True})
    assert no_cookie.status_code == 200, no_cookie.text
    assert client.cookies.get("mfa_device") is None
    restored = client.patch(
        "/api/admin/settings",
        json={"session_policy": {"mfa_trust_days": 14}},
    )
    assert restored.status_code == 200, restored.text
    assert restored.json()["session_policy"]["mfa_trust_days"] == 14
    client.post("/api/auth/logout")
    assert client.post("/api/auth/login", json={"username": "admin", "password": "SmokeTest.1234"}).json()["mfa_required"]
    trusted = client.post("/api/auth/mfa", json={"code": recovery[5], "trust": True})
    assert trusted.status_code == 200, trusted.text
    assert client.cookies.get("mfa_device")
    client.post("/api/auth/logout")
    skipped = client.post("/api/auth/login", json={"username": "admin", "password": "SmokeTest.1234"})
    assert skipped.status_code == 200, skipped.text
    assert skipped.json().get("mfa_required") is False
    assert client.get("/api/profile").status_code == 200
    changed = client.post(
        "/api/auth/change-password",
        json={"current_password": "SmokeTest.1234", "new_password": "SmokeTest.5678"},
    )
    assert changed.status_code == 200, changed.text
    client.post("/api/auth/logout")
    again = client.post("/api/auth/login", json={"username": "admin", "password": "SmokeTest.5678"})
    assert again.status_code == 200, again.text
    assert again.json().get("mfa_required") is True
    assert client.post("/api/auth/mfa", json={"code": recovery[6]}).status_code == 200

    journal = client.get("/api/admin/audit?limit=500")
    assert journal.status_code == 200, journal.text
    actions = {item["action"] for item in journal.json()["events"]}
    assert "login" in actions
    assert "mfa_ok" in actions
    assert "mfa_trusted" in actions
    assert "token_issued" in actions
    assert "refresh_reuse" in actions
    assert "code_reuse" in actions
    assert "consent_allow" in actions
    for item in journal.json()["events"]:
        blob = json.dumps(item)
        assert "SmokeTest.1234" not in blob
        assert "access_token" not in item

    print("smoke ok")


if __name__ == "__main__":
    main()
