"""HttpOnly cookie for a browser that already passed MFA.

The cookie is ``user_id.token``. Only the HMAC of the token is stored, bound to
the account's auth version, so a password change or an MFA reset drops it.
"""

from __future__ import annotations

from starlette.responses import Response

from app.config import COOKIE_HTTPS_ONLY

MFA_DEVICE_COOKIE = "mfa_device"


def split_device_cookie(value: str | None) -> tuple[str, str] | None:
    user_id, sep, token = str(value or "").partition(".")
    if not sep or not user_id or not token or "." in user_id or "." in token:
        return None
    if len(user_id) > 80 or len(token) > 128:
        return None
    return user_id, token


def device_cookie_owner(value: str | None) -> str | None:
    parsed = split_device_cookie(value)
    return parsed[0] if parsed else None


def set_mfa_device_cookie(response: Response, value: str, max_age: int) -> None:
    response.set_cookie(
        MFA_DEVICE_COOKIE,
        value,
        max_age=max(1, int(max_age)),
        path="/",
        secure=COOKIE_HTTPS_ONLY,
        httponly=True,
        samesite="lax",
    )


def clear_mfa_device_cookie(response: Response) -> None:
    response.delete_cookie(
        MFA_DEVICE_COOKIE,
        path="/",
        secure=COOKIE_HTTPS_ONLY,
        httponly=True,
        samesite="lax",
    )
