from __future__ import annotations

import base64
import io
import secrets
import time
from urllib.parse import quote, urlencode, urlsplit

import pyotp
import segno

from app.config import ISSUER

_LABEL_LIMIT = 64


def new_totp_secret() -> str:
    return pyotp.random_base32()


def _otp_text(value: str) -> str:
    return " ".join(str(value or "").split())[:_LABEL_LIMIT].strip()


def totp_issuer_name(issuer: str, title: str = "") -> str:
    label = _otp_text(title)
    if label:
        return label
    parsed = urlsplit(str(issuer or "").strip())
    host = parsed.hostname or ""
    if host:
        if ":" in host:
            host = f"[{host}]"
        if parsed.port:
            host = f"{host}:{parsed.port}"
        return host[:_LABEL_LIMIT]
    bare = str(issuer or "").strip()
    lowered = bare.lower()
    for prefix in ("https://", "http://"):
        if lowered.startswith(prefix):
            bare = bare[len(prefix) :]
            break
    return _otp_text(bare.split("/")[0]) or "Auth"


def totp_account_name(username: str) -> str:
    return _otp_text(username).replace(":", "") or "user"


def provisioning_uri(secret: str, username: str, issuer: str = ISSUER, title: str = "") -> str:
    account = totp_account_name(username)
    issuer_name = totp_issuer_name(issuer, title)
    # A port makes the issuer contain a colon. Putting that colon in the path
    # label would be read as the separator, and the account would show the port.
    if ":" in issuer_name:
        label = quote(account, safe="")
    else:
        label = quote(issuer_name, safe="") + ":" + quote(account, safe="")
    query = urlencode({"secret": secret, "issuer": issuer_name})
    return f"otpauth://totp/{label}?{query}"


def qr_data_uri(otpauth_url: str) -> str:
    buffer = io.BytesIO()
    segno.make(otpauth_url, error="m").save(buffer, kind="png", scale=5)
    encoded = base64.b64encode(buffer.getvalue()).decode("ascii")
    return f"data:image/png;base64,{encoded}"


def verify_totp(secret: str, code: str, last_counter: int | None = None) -> int | None:
    cleaned = "".join(ch for ch in (code or "") if ch.isdigit())
    if len(cleaned) != 6:
        return None
    totp = pyotp.TOTP(secret)
    now = int(time.time())
    interval = totp.interval
    for offset in (0, 1, -1):
        moment = now + offset * interval
        step = moment // interval
        if last_counter is not None and step <= last_counter:
            continue
        if totp.at(moment) == cleaned:
            return step
    return None


def new_recovery_codes(count: int = 8) -> list[str]:
    codes = []
    for _ in range(count):
        raw = secrets.token_hex(4)
        codes.append(f"{raw[:4]}-{raw[4:]}")
    return codes


def normalize_recovery_code(code: str) -> str:
    return (code or "").strip().lower().replace(" ", "")
