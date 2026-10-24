from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from app.admin.routes import router as admin_router
from app.config import (
    COOKIE_HTTPS_ONLY,
    DATA_DIR,
    DEV_MODE,
    FRONTEND_ORIGIN,
    ISSUER,
    SESSION_COOKIE_MAX_AGE,
    STATIC_DIR,
)
from app.connectors import create_identity_connector
from app.deps import get_session_user
from app.http_security import (
    AuditContextMiddleware,
    HostCheckMiddleware,
    OriginCheckMiddleware,
    SecureTransportMiddleware,
    SecurityHeadersMiddleware,
    SessionGuardMiddleware,
    allowed_hosts,
    allowed_origins,
    forward_app_hosts,
)
from app.oidc.routes import router as oidc_router
from app.session_gate import router as session_router
from app.oidc.server import DirectoryAuthorizationServer
from app.store.directory import DirectoryStore, sync_demo_client_redirects
from app.store.jwks import ensure_jwks
from app.store.runtime import RuntimeStore

# Authlib blocks HTTP OAuth unless this is set. HTTP issuers are dev-only.
# An HTTPS issuer never runs with insecure transport, even if the env var says so.
if ISSUER.startswith("http://"):
    os.environ["AUTHLIB_INSECURE_TRANSPORT"] = "1"
else:
    os.environ.pop("AUTHLIB_INSECURE_TRANSPORT", None)


def create_app() -> FastAPI:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(DATA_DIR, 0o700)
    except OSError:
        pass
    directory = DirectoryStore()
    directory.ensure()
    # Env is source of truth for public URLs (important behind Docker / reverse proxy).
    directory.update_settings(issuer=ISSUER, frontend_origin=FRONTEND_ORIGIN)
    sync_demo_client_redirects(directory, FRONTEND_ORIGIN)
    runtime = RuntimeStore()
    runtime.ensure()
    ensure_jwks()
    identity = create_identity_connector(directory)

    settings = directory.get_settings()
    issuer = settings.get("issuer") or ISSUER
    auth_server = DirectoryAuthorizationServer(
        directory,
        runtime,
        identity=identity,
        issuer=issuer,
    )

    app = FastAPI(
        title="simple-auth",
        version="1.0.0",
        docs_url="/docs" if DEV_MODE else None,
        redoc_url="/redoc" if DEV_MODE else None,
        openapi_url="/openapi.json" if DEV_MODE else None,
    )
    app.state.directory = directory
    app.state.runtime = runtime
    app.state.identity = identity
    app.state.auth_server = auth_server

    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(OriginCheckMiddleware)
    app.add_middleware(SecureTransportMiddleware, enforce=ISSUER.startswith("https://"))
    app.add_middleware(SessionGuardMiddleware)
    app.add_middleware(AuditContextMiddleware)
    app.add_middleware(
        SessionMiddleware,
        secret_key=settings["cookie_secret"],
        session_cookie="oidc_session",
        same_site="lax",
        https_only=COOKIE_HTTPS_ONLY,
        max_age=SESSION_COOKIE_MAX_AGE,
    )
    app.add_middleware(HostCheckMiddleware, allowed=allowed_hosts(), app_hosts=forward_app_hosts(directory))
    app.add_middleware(
        CORSMiddleware,
        allow_origins=sorted(allowed_origins()),
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type"],
    )

    app.include_router(oidc_router)
    app.include_router(session_router)
    app.include_router(admin_router)

    @app.get("/api/health")
    def health():
        return {"status": "ok"}

    @app.get("/api/status")
    def status(request: Request):
        user = get_session_user(request)
        if not user or not identity.is_admin(user.data):
            return {"status": "ok"}
        return {
            "status": "ok",
            "issuer": issuer,
            "connector": identity.info(),
        }

    static_root = Path(STATIC_DIR)
    if static_root.is_dir() and (static_root / "index.html").exists():
        assets_dir = static_root / "assets"
        if assets_dir.is_dir():
            app.mount("/assets", StaticFiles(directory=assets_dir), name="assets")

        @app.get("/{full_path:path}")
        def spa(full_path: str):
            root = static_root.resolve()
            if full_path:
                candidate = (root / full_path).resolve()
                try:
                    candidate.relative_to(root)
                except ValueError:
                    return FileResponse(root / "index.html")
                if candidate.is_file():
                    return FileResponse(candidate)
            return FileResponse(root / "index.html")

    return app


app = create_app()
