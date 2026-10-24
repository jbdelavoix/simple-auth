from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class ReadOnlyError(RuntimeError):
    """Raised when a write is attempted on a read-only identity connector."""


class IdentityConnector(ABC):
    """Source of users/groups for the identity directory."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Connector id: local | ldap."""

    @property
    def writable(self) -> bool:
        return False

    @property
    def description(self) -> str:
        return self.name

    def info(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "writable": self.writable,
            "description": self.description,
        }

    @abstractmethod
    def authenticate(self, username: str, password: str) -> dict[str, Any] | None:
        """Return a public user dict on success."""

    @abstractmethod
    def get_user(self, user_id: str) -> dict[str, Any] | None:
        ...

    @abstractmethod
    def get_user_by_username(self, username: str) -> dict[str, Any] | None:
        ...

    @abstractmethod
    def list_users(self) -> list[dict[str, Any]]:
        ...

    @abstractmethod
    def list_groups(self) -> list[dict[str, Any]]:
        ...

    @abstractmethod
    def get_group(self, group_id: str) -> dict[str, Any] | None:
        ...

    @abstractmethod
    def user_group_names(self, user: dict[str, Any]) -> list[str]:
        ...

    def is_admin(self, user: dict[str, Any]) -> bool:
        return "admins" in self.user_group_names(user)

    # --- optional writes ---
    def create_user(self, payload: dict[str, Any]) -> dict[str, Any]:
        raise ReadOnlyError(f"Connector '{self.name}' is read-only")

    def update_user(self, user_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        raise ReadOnlyError(f"Connector '{self.name}' is read-only")

    def delete_user(self, user_id: str) -> None:
        raise ReadOnlyError(f"Connector '{self.name}' is read-only")

    def create_group(self, payload: dict[str, Any]) -> dict[str, Any]:
        raise ReadOnlyError(f"Connector '{self.name}' is read-only")

    def update_group(self, group_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        raise ReadOnlyError(f"Connector '{self.name}' is read-only")

    def delete_group(self, group_id: str) -> None:
        raise ReadOnlyError(f"Connector '{self.name}' is read-only")
