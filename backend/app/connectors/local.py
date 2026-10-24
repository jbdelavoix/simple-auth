from __future__ import annotations

from typing import Any

from app.connectors.base import IdentityConnector
from app.store.directory import DirectoryStore


class LocalIdentityConnector(IdentityConnector):
    """Users/groups persisted in the local JSON directory."""

    def __init__(self, store: DirectoryStore):
        self.store = store

    @property
    def name(self) -> str:
        return "local"

    @property
    def writable(self) -> bool:
        return True

    @property
    def description(self) -> str:
        return "Local JSON directory (data/identities.json)"

    def authenticate(self, username: str, password: str) -> dict[str, Any] | None:
        return self.store.authenticate(username, password)

    def get_user(self, user_id: str) -> dict[str, Any] | None:
        return self.store.get_user(user_id)

    def get_user_by_username(self, username: str) -> dict[str, Any] | None:
        user = self.store.get_user_by_username(username)
        if not user:
            return None
        return self.store._public_user(user)

    def list_users(self) -> list[dict[str, Any]]:
        return self.store.list_users()

    def list_groups(self) -> list[dict[str, Any]]:
        return self.store.list_groups()

    def get_group(self, group_id: str) -> dict[str, Any] | None:
        return self.store.get_group(group_id)

    def user_group_names(self, user: dict[str, Any]) -> list[str]:
        return self.store.user_group_names(user)

    def is_admin(self, user: dict[str, Any]) -> bool:
        return self.store.is_admin(user)

    def create_user(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self.store.create_user(payload)

    def update_user(self, user_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        return self.store.update_user(user_id, payload)

    def delete_user(self, user_id: str) -> None:
        self.store.delete_user(user_id)

    def create_group(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self.store.create_group(payload)

    def update_group(self, group_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        return self.store.update_group(group_id, payload)

    def delete_group(self, group_id: str) -> None:
        self.store.delete_group(group_id)
