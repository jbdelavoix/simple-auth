from __future__ import annotations

import hashlib
import re
import secrets
from typing import Any

import bcrypt

from app.config import DEFAULT_ADMIN_PASSWORD, PASSWORD_MIN_LENGTH

_USERNAME = re.compile(r"^[A-Za-z0-9._@+-]{1,64}$")
_GROUP_NAME = re.compile(r"^[A-Za-z0-9._@+\- ]{1,64}$")
BCRYPT_MAX_BYTES = 72

_DUMMY_HASH = bcrypt.hashpw(b"timing-dummy", bcrypt.gensalt()).decode("utf-8")


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
    except ValueError:
        return False


def dummy_password_check(password: str) -> None:
    verify_password(password, _DUMMY_HASH)


def token_digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _flag(value: Any, default: bool) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def normalize_password_policy(value: Any = None) -> dict[str, Any]:
    raw = value if isinstance(value, dict) else {}
    try:
        min_length = int(raw.get("min_length") or PASSWORD_MIN_LENGTH)
    except (TypeError, ValueError):
        min_length = PASSWORD_MIN_LENGTH
    return {
        "min_length": max(PASSWORD_MIN_LENGTH, min(128, min_length)),
        "require_letter": _flag(raw.get("require_letter"), True),
        "require_digit": _flag(raw.get("require_digit"), True),
        "require_upper": _flag(raw.get("require_upper"), False),
        "require_special": _flag(raw.get("require_special"), False),
        "forbid_username": _flag(raw.get("forbid_username"), True),
    }


def validate_username(username: str) -> str | None:
    if not _USERNAME.fullmatch(username or ""):
        return "Username must be 1-64 characters: letters, digits, and . _ @ + -"
    return None


def validate_group_name(name: str) -> str | None:
    text = (name or "").strip()
    if text != (name or "") or not _GROUP_NAME.fullmatch(text):
        return "Group name must be 1-64 characters: letters, digits, spaces, and . _ @ + -"
    return None


def validate_password(password: str, username: str = "", policy: dict[str, Any] | None = None) -> str | None:
    rules = normalize_password_policy(policy)
    if len(password.encode("utf-8")) > BCRYPT_MAX_BYTES:
        return f"Password must be at most {BCRYPT_MAX_BYTES} bytes"
    if len(password) < rules["min_length"]:
        return f"Password must be at least {rules['min_length']} characters"
    if password == DEFAULT_ADMIN_PASSWORD:
        return "Choose a password other than the default"
    if rules["forbid_username"] and username and password.lower() == username.lower():
        return "Password must not match the username"
    if rules["require_letter"] and not any(ch.isalpha() for ch in password):
        return "Password must include a letter"
    if rules["require_digit"] and not any(ch.isdigit() for ch in password):
        return "Password must include a digit"
    if rules["require_upper"] and not any(ch.isupper() for ch in password):
        return "Password must include an uppercase letter"
    if rules["require_special"] and not any(not ch.isalnum() for ch in password):
        return "Password must include a special character"
    return None


def hash_secret(secret: str) -> str:
    return hash_password(secret)


def verify_secret(secret: str, secret_hash: str) -> bool:
    return verify_password(secret, secret_hash)


def generate_client_secret() -> str:
    return secrets.token_urlsafe(32)


def generate_id() -> str:
    return secrets.token_urlsafe(18)
