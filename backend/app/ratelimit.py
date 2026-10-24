from __future__ import annotations

from typing import Any

from fastapi import HTTPException, Request

from app.config import LOGIN_ACCOUNT_LIMIT, LOGIN_SOURCE_LIMIT, MFA_ACCOUNT_LIMIT
from app.sessions import client_ip


def login_key(request: Request, username: str) -> str:
    host = client_ip(request) or "unknown"
    return f"{host}:{username.strip().lower()}"


def _reserve(runtime: Any, limits: list[tuple[str, int]], detail: str) -> list[str]:
    if not runtime.login_attempt(limits):
        raise HTTPException(status_code=429, detail=detail)
    return [bucket for bucket, _limit in limits]


def reserve_login(runtime: Any, request: Request, username: str) -> list[str]:
    """Count a password attempt before checking it. Raises 429 when over budget.

    The per-source bucket stops one client. The per-account bucket caps a
    distributed guess without letting a single source lock the account out.
    """
    account = username.strip().lower()
    return _reserve(
        runtime,
        [(login_key(request, username), LOGIN_SOURCE_LIMIT), (f"account:{account}", LOGIN_ACCOUNT_LIMIT)],
        "Too many login attempts",
    )


def reserve_mfa(runtime: Any, request: Request, user_id: str) -> list[str]:
    return _reserve(
        runtime,
        [(login_key(request, f"mfa:{user_id}"), LOGIN_SOURCE_LIMIT), (f"mfa:{user_id}", MFA_ACCOUNT_LIMIT)],
        "Too many MFA attempts",
    )


def release(runtime: Any, buckets: list[str]) -> None:
    for bucket in buckets:
        runtime.login_success(bucket)
