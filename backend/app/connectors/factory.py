from __future__ import annotations

from app.config import IDENTITY_CONNECTOR
from app.connectors.base import IdentityConnector
from app.connectors.ldap import LdapIdentityConnector
from app.connectors.local import LocalIdentityConnector
from app.store.directory import DirectoryStore


def create_identity_connector(store: DirectoryStore, name: str | None = None) -> IdentityConnector:
    connector = (name or IDENTITY_CONNECTOR).strip().lower()
    if connector == "local":
        return LocalIdentityConnector(store)
    if connector == "ldap":
        return LdapIdentityConnector(store)
    raise ValueError(f"Unknown identity connector: {connector!r} (expected local|ldap)")
