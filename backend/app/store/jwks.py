from __future__ import annotations

import os

from joserfc.jwk import KeySet, RSAKey

from app.config import JWKS_PATH
from app.store.json_store import read_json, write_json


def _lock_jwks_file() -> None:
    if JWKS_PATH.exists():
        os.chmod(JWKS_PATH, 0o600)


def ensure_jwks() -> dict:
    if JWKS_PATH.exists():
        _lock_jwks_file()
        return read_json(JWKS_PATH, {"keys": []})
    key = RSAKey.generate_key(2048, {"use": "sig", "alg": "RS256"})
    private_set = KeySet([key]).as_dict(private=True)
    write_json(JWKS_PATH, private_set)
    _lock_jwks_file()
    return private_set


def load_private_key_set() -> KeySet:
    data = ensure_jwks()
    return KeySet.import_key_set(data)


def public_jwks() -> dict:
    private = ensure_jwks()
    key_set = KeySet.import_key_set(private)
    return key_set.as_dict(private=False)


def current_kid() -> str | None:
    keys = public_jwks().get("keys") or []
    if not keys:
        return None
    kid = keys[0].get("kid")
    return str(kid) if kid else None


def rotate_signing_keys() -> dict:
    key = RSAKey.generate_key(2048, {"use": "sig", "alg": "RS256"})
    private_set = KeySet([key]).as_dict(private=True)
    write_json(JWKS_PATH, private_set)
    _lock_jwks_file()
    return KeySet.import_key_set(private_set).as_dict(private=False)
