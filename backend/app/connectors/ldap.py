from __future__ import annotations

import hashlib
import ssl
import threading
from typing import Any
from urllib.parse import urlparse

from ldap3 import BASE, NONE, SUBTREE, Connection, Server, Tls
from ldap3.core.exceptions import LDAPException
from ldap3.utils.conv import escape_filter_chars

from app.connectors.base import IdentityConnector
from app.store.directory import DirectoryStore
from app.config import (
    LDAP_ADMIN_GROUP,
    LDAP_ALLOW_INSECURE,
    LDAP_BIND_DN,
    LDAP_BIND_PASSWORD,
    LDAP_CA_FILE,
    LDAP_GROUP_ALLOWLIST,
    LDAP_GROUP_BASE,
    LDAP_GROUP_FILTER,
    LDAP_GROUP_MEMBER_ATTR,
    LDAP_GROUP_NAME_ATTR,
    LDAP_STARTTLS,
    LDAP_URL,
    LDAP_USER_BASE,
    LDAP_USER_ENABLED_FILTER,
    LDAP_USER_FILTER,
    LDAP_USER_ATTR_EMAIL,
    LDAP_USER_ATTR_NAME,
    LDAP_USER_ATTR_USERNAME,
)


class _BadPassword(LDAPException):
    """User bind rejected the password. Distinct from a directory outage."""


def _stable_id(prefix: str, value: str) -> str:
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]
    return f"{prefix}_{digest}"


class LdapIdentityConnector(IdentityConnector):
    """Users/groups backed by an LDAP directory (read + bind auth)."""

    def __init__(
        self,
        directory: DirectoryStore | None = None,
        url: str = LDAP_URL,
        bind_dn: str = LDAP_BIND_DN,
        bind_password: str = LDAP_BIND_PASSWORD,
        user_base: str = LDAP_USER_BASE,
        user_filter: str = LDAP_USER_FILTER,
        group_base: str = LDAP_GROUP_BASE,
        group_filter: str = LDAP_GROUP_FILTER,
        username_attr: str = LDAP_USER_ATTR_USERNAME,
        email_attr: str = LDAP_USER_ATTR_EMAIL,
        name_attr: str = LDAP_USER_ATTR_NAME,
        group_name_attr: str = LDAP_GROUP_NAME_ATTR,
        group_member_attr: str = LDAP_GROUP_MEMBER_ATTR,
        admin_group: str = LDAP_ADMIN_GROUP,
        group_allowlist: list[str] | None = None,
        enabled_filter: str = LDAP_USER_ENABLED_FILTER,
        ca_file: str = LDAP_CA_FILE,
    ):
        if not url:
            raise ValueError("LDAP_URL is required for the ldap connector")
        if not user_base:
            raise ValueError("LDAP_USER_BASE is required for the ldap connector")
        scheme = urlparse(url).scheme.lower()
        self.start_tls = False
        if scheme == "ldaps":
            pass
        elif scheme == "ldap" and LDAP_STARTTLS:
            self.start_tls = True
        elif scheme == "ldap" and LDAP_ALLOW_INSECURE:
            pass
        else:
            raise ValueError(
                "LDAP_URL must use ldaps:// or set LDAP_STARTTLS=1. "
                "LDAP_ALLOW_INSECURE=1 permits cleartext ldap:// for development only."
            )
        self.directory = directory
        self.url = url
        self.bind_dn = bind_dn
        self.bind_password = bind_password
        self.user_base = user_base
        self.user_filter = user_filter
        self.group_base = group_base or user_base
        self.group_filter = group_filter
        self.username_attr = username_attr
        self.email_attr = email_attr
        self.name_attr = name_attr
        self.group_name_attr = group_name_attr
        self.group_member_attr = group_member_attr
        self.admin_group = admin_group
        self.group_allowlist = [item.lower() for item in (group_allowlist if group_allowlist is not None else LDAP_GROUP_ALLOWLIST)]
        self.enabled_filter = enabled_filter
        self.ca_file = ca_file or None
        self.host = urlparse(url).hostname or ""
        self._dn_by_id: dict[str, str] = {}
        self._dn_lock = threading.Lock()

    @property
    def name(self) -> str:
        return "ldap"

    @property
    def writable(self) -> bool:
        return False

    @property
    def description(self) -> str:
        return f"LDAP directory ({self.url})"

    def info(self) -> dict[str, Any]:
        data = super().info()
        data.update(
            {
                "url": self.url,
                "user_base": self.user_base,
                "group_base": self.group_base,
                "group_filter": self.group_filter,
                "admin_group": self.admin_group,
                "group_allowlist": list(self.group_allowlist),
                "groups_source": "auto",
            }
        )
        return data

    def _server(self) -> Server:
        # ldap3 defaults to CERT_NONE; passwords cross this link, so the
        # server certificate and host name must be checked.
        tls = Tls(validate=ssl.CERT_REQUIRED, ca_certs_file=self.ca_file, sni=self.host or None)
        return Server(self.url, get_info=NONE, tls=tls)

    def _user_search_filter(self, username: str) -> str:
        base = self.user_filter.format(username=username)
        if not self.enabled_filter:
            return base
        return f"(&{base}{self.enabled_filter})"

    def _bind(self, user: str | None, password: str | None) -> Connection:
        conn = Connection(
            self._server(),
            user=user or None,
            password=password or None,
            auto_bind=False,
        )
        conn.open()
        if self.start_tls:
            conn.start_tls()
        if not conn.bind():
            result = conn.result or {}
            description = str(result.get("description") or "")
            conn.unbind()
            if description == "invalidCredentials":
                raise _BadPassword("invalid credentials")
            raise LDAPException(str(result))
        return conn

    def _service_connection(self) -> Connection:
        return self._bind(self.bind_dn or None, self.bind_password or None)

    def _attr(self, entry: Any, name: str, default: str = "") -> str:
        if not hasattr(entry, name):
            return default
        values = entry[name].values
        if not values:
            return default
        return str(values[0])

    def _entry_to_user(self, entry: Any, group_names: list[str] | None = None) -> dict[str, Any]:
        dn = str(entry.entry_dn)
        username = self._attr(entry, self.username_attr) or dn
        email = self._attr(entry, self.email_attr)
        name = self._attr(entry, self.name_attr) or username
        groups = group_names if group_names is not None else self._groups_for_dn(dn)
        user_id = _stable_id("ldap", dn)
        with self._dn_lock:
            self._dn_by_id[user_id] = dn
        return {
            "id": user_id,
            "username": username,
            "email": email,
            "name": name,
            "enabled": True,
            "group_ids": [_stable_id("ldapg", g) for g in groups],
            "groups": groups,
            "attributes": {"dn": dn},
            "dn": dn,
        }

    def _groups_for_dn(self, user_dn: str) -> list[str]:
        try:
            with self._service_connection() as conn:
                filt = (
                    f"(&{self.group_filter}"
                    f"({self.group_member_attr}={escape_filter_chars(user_dn)}))"
                )
                conn.search(
                    search_base=self.group_base,
                    search_filter=filt,
                    search_scope=SUBTREE,
                    attributes=[self.group_name_attr],
                )
                names: list[str] = []
                for entry in conn.entries:
                    name = self._attr(entry, self.group_name_attr)
                    if name:
                        names.append(name)
                return self._filter_groups(names)
        except LDAPException:
            return []

    def _find_user_entry(self, conn: Connection, username: str) -> Any | None:
        filt = self._user_search_filter(escape_filter_chars(username))
        conn.search(
            search_base=self.user_base,
            search_filter=filt,
            search_scope=SUBTREE,
            attributes=[self.username_attr, self.email_attr, self.name_attr],
        )
        if not conn.entries:
            return None
        return conn.entries[0]

    def authenticate(self, username: str, password: str) -> dict[str, Any] | None:
        from app.security import dummy_password_check

        if not username or not password:
            dummy_password_check(password or "missing")
            return None
        try:
            with self._service_connection() as conn:
                entry = self._find_user_entry(conn, username)
                if entry is None:
                    dummy_password_check(password)
                    return None
                user_dn = str(entry.entry_dn)
            # Bind as the end-user to verify credentials.
            user_conn = self._bind(user_dn, password)
            user_conn.unbind()
        except LDAPException:
            dummy_password_check(password)
            return None
        return self._entry_to_user(entry)

    def get_user(self, user_id: str) -> dict[str, Any] | None:
        with self._dn_lock:
            dn = self._dn_by_id.get(user_id)
        if dn:
            return self._user_at_dn(dn)
        for user in self.list_users():
            if user["id"] == user_id:
                return user
        return None

    def _user_at_dn(self, dn: str) -> dict[str, Any] | None:
        """Re-read one account, so a deleted or disabled entry stops resolving."""
        try:
            with self._service_connection() as conn:
                conn.search(
                    search_base=dn,
                    search_filter=self.enabled_filter or "(objectClass=*)",
                    search_scope=BASE,
                    attributes=[self.username_attr, self.email_attr, self.name_attr],
                )
                if not conn.entries:
                    return None
                return self._entry_to_user(conn.entries[0])
        except LDAPException:
            return None

    def get_user_by_username(self, username: str) -> dict[str, Any] | None:
        try:
            with self._service_connection() as conn:
                entry = self._find_user_entry(conn, username)
                if entry is None:
                    return None
                return self._entry_to_user(entry)
        except LDAPException:
            return None

    def list_users(self) -> list[dict[str, Any]]:
        try:
            with self._service_connection() as conn:
                # Replace {username} placeholder with wildcard for listing.
                filt = self._user_search_filter("*")
                conn.search(
                    search_base=self.user_base,
                    search_filter=filt,
                    search_scope=SUBTREE,
                    attributes=[self.username_attr, self.email_attr, self.name_attr],
                )
                users = []
                for entry in conn.entries:
                    users.append(self._entry_to_user(entry))
                return users
        except LDAPException as exc:
            raise RuntimeError(f"LDAP list_users failed: {exc}") from exc

    def list_groups(self) -> list[dict[str, Any]]:
        try:
            with self._service_connection() as conn:
                conn.search(
                    search_base=self.group_base,
                    search_filter=self.group_filter,
                    search_scope=SUBTREE,
                    attributes=[self.group_name_attr, "description"],
                )
                groups = []
                for entry in conn.entries:
                    name = self._attr(entry, self.group_name_attr)
                    if not name:
                        continue
                    if not self._group_allowed(name):
                        continue
                    groups.append(
                        {
                            "id": _stable_id("ldapg", name),
                            "name": name,
                            "description": self._attr(entry, "description"),
                        }
                    )
                return groups
        except LDAPException as exc:
            raise RuntimeError(f"LDAP list_groups failed: {exc}") from exc

    def get_group(self, group_id: str) -> dict[str, Any] | None:
        for group in self.list_groups():
            if group["id"] == group_id:
                return group
        return None

    def user_group_names(self, user: dict[str, Any]) -> list[str]:
        if "groups" in user and isinstance(user["groups"], list):
            return list(user["groups"])
        dn = (user.get("attributes") or {}).get("dn") or user.get("dn")
        if dn:
            return self._groups_for_dn(str(dn))
        return []

    def is_admin(self, user: dict[str, Any]) -> bool:
        return self.admin_group in self.user_group_names(user)

    def _group_allowed(self, name: str) -> bool:
        if not self.group_allowlist:
            return True
        return name.lower() in self.group_allowlist

    def _filter_groups(self, names: list[str]) -> list[str]:
        return [name for name in names if self._group_allowed(name)]
