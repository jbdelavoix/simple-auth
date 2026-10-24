from __future__ import annotations

from typing import Any

from app.store.directory import DirectoryStore
from app.store.runtime import RuntimeStore


def revoke_user_auth(directory: DirectoryStore, runtime: RuntimeStore, user_id: str) -> int:
    """Invalidate cookies and bearer tokens issued for this user."""
    version = directory.bump_auth_version(user_id)
    runtime.revoke_user(user_id)
    return version


def token_is_current(directory: DirectoryStore, token: dict[str, Any], user: Any) -> bool:
    if not user or not getattr(user, "enabled", True) or getattr(user, "must_change_password", False):
        return False
    version = int(token.get("auth_version") or 0)
    return directory.auth_version(user.id) == version
