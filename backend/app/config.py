from __future__ import annotations

import ipaddress
import os
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[2]
DATA_DIR = Path(os.environ.get("OIDC_DATA_DIR", ROOT_DIR / "data"))
STATIC_DIR = Path(os.environ.get("OIDC_STATIC_DIR", ROOT_DIR / "frontend" / "dist"))

ISSUER = os.environ.get("OIDC_ISSUER", "http://localhost:8000")
FRONTEND_ORIGIN = os.environ.get("OIDC_FRONTEND_ORIGIN", "http://localhost:5173")
HOST = os.environ.get("OIDC_HOST", "127.0.0.1")
PORT = int(os.environ.get("OIDC_PORT", "8000"))
_ISSUER_HTTPS = ISSUER.startswith("https://")
COOKIE_HTTPS_ONLY = os.environ.get(
    "OIDC_COOKIE_HTTPS_ONLY",
    "1" if _ISSUER_HTTPS else "0",
) in {"1", "true", "True"}

DIRECTORY_PATH = DATA_DIR / "directory.json"
IDENTITIES_PATH = DATA_DIR / "identities.json"
CLIENTS_PATH = DATA_DIR / "clients.json"
RUNTIME_PATH = DATA_DIR / "runtime.sqlite"
JWKS_PATH = DATA_DIR / "jwks.json"
AUDIT_PATH = DATA_DIR / "audit.jsonl"
AUDIT_MAX_BYTES = int(os.environ.get("OIDC_AUDIT_MAX_BYTES", str(10 * 1024 * 1024)))
AUDIT_KEEP = max(1, int(os.environ.get("OIDC_AUDIT_KEEP", "10")))

DEV_MODE = os.environ.get("OIDC_DEV", "1" if not _ISSUER_HTTPS else "0") in {"1", "true", "True"}
REQUIRE_ADMIN_MFA = os.environ.get(
    "OIDC_REQUIRE_ADMIN_MFA",
    "1" if _ISSUER_HTTPS else "0",
) in {"1", "true", "True"}

PASSWORD_MIN_LENGTH = 12
# Failed sign-ins allowed per (client IP, account) and per account in the window.
LOGIN_SOURCE_LIMIT = 8
LOGIN_ACCOUNT_LIMIT = int(os.environ.get("OIDC_LOGIN_ACCOUNT_LIMIT", "50"))
LOGIN_WINDOW_SECONDS = 600
MFA_ACCOUNT_LIMIT = 5
# Optional key for secrets at rest (TOTP seeds, recovery-code pepper). Keep it
# outside the data directory; without it the cookie secret in directory.json is used.
SECRET_KEY = os.environ.get("OIDC_SECRET_KEY", "")
# Initial admin password. An HTTPS issuer never seeds the well-known default.
INITIAL_ADMIN_PASSWORD = os.environ.get("OIDC_ADMIN_PASSWORD", "")
SESSION_IDLE_SECONDS = int(os.environ.get("OIDC_SESSION_IDLE", "1800"))
SESSION_ABSOLUTE_SECONDS = int(os.environ.get("OIDC_SESSION_ABSOLUTE", "43200"))
# Bounds for the admin setting. The cookie itself lives up to the maximum so a
# longer limit does not need a restart; idle and absolute are enforced per request.
SESSION_MIN_SECONDS = 60
SESSION_MAX_SECONDS = 30 * 24 * 3600
SESSION_COOKIE_MAX_AGE = SESSION_MAX_SECONDS
MFA_TRUST_DAYS = int(os.environ.get("OIDC_MFA_TRUST_DAYS", "30"))
MFA_TRUST_MAX_DAYS = 365
ALLOWED_HOSTS_RAW = os.environ.get("OIDC_ALLOWED_HOSTS", "")


def _parse_trusted_proxies(raw: str) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for item in raw.split(","):
        text = item.strip()
        if not text:
            continue
        if "/" not in text:
            address = ipaddress.ip_address(text)
            text = f"{text}/32" if address.version == 4 else f"{text}/128"
        networks.append(ipaddress.ip_network(text, strict=False))
    return tuple(networks)


TRUSTED_PROXIES = _parse_trusted_proxies(os.environ.get("OIDC_TRUSTED_PROXIES", ""))
APP_ORIGINS = [
    item.strip().rstrip("/")
    for item in os.environ.get("OIDC_APP_ORIGINS", "").split(",")
    if item.strip()
]

# Identity connector: local (JSON) | ldap
IDENTITY_CONNECTOR = os.environ.get("OIDC_CONNECTOR", "local").strip().lower()

# LDAP connector settings (used when OIDC_CONNECTOR=ldap)
LDAP_URL = os.environ.get("LDAP_URL", "")
LDAP_BIND_DN = os.environ.get("LDAP_BIND_DN", "")
LDAP_BIND_PASSWORD = os.environ.get("LDAP_BIND_PASSWORD", "")
LDAP_USER_BASE = os.environ.get("LDAP_USER_BASE", "")
LDAP_USER_FILTER = os.environ.get("LDAP_USER_FILTER", "(uid={username})")
LDAP_GROUP_BASE = os.environ.get("LDAP_GROUP_BASE", "")
LDAP_GROUP_FILTER = os.environ.get("LDAP_GROUP_FILTER", "(objectClass=groupOfNames)")
LDAP_USER_ATTR_USERNAME = os.environ.get("LDAP_USER_ATTR_USERNAME", "uid")
LDAP_USER_ATTR_EMAIL = os.environ.get("LDAP_USER_ATTR_EMAIL", "mail")
LDAP_USER_ATTR_NAME = os.environ.get("LDAP_USER_ATTR_NAME", "cn")
LDAP_GROUP_NAME_ATTR = os.environ.get("LDAP_GROUP_NAME_ATTR", "cn")
LDAP_GROUP_MEMBER_ATTR = os.environ.get("LDAP_GROUP_MEMBER_ATTR", "member")
LDAP_ADMIN_GROUP = os.environ.get("LDAP_ADMIN_GROUP", "admins")
LDAP_GROUP_ALLOWLIST = [
    item.strip()
    for item in os.environ.get("LDAP_GROUP_ALLOWLIST", "").split(",")
    if item.strip()
]
LDAP_STARTTLS = os.environ.get("LDAP_STARTTLS", "0") in {"1", "true", "True"}
LDAP_ALLOW_INSECURE = os.environ.get("LDAP_ALLOW_INSECURE", "0") in {"1", "true", "True"}
LDAP_CA_FILE = os.environ.get("LDAP_CA_FILE", "")
# Extra filter an account must match to count as enabled, e.g. for Active Directory:
# (!(userAccountControl:1.2.840.113556.1.4.803:=2))
LDAP_USER_ENABLED_FILTER = os.environ.get("LDAP_USER_ENABLED_FILTER", "").strip()

DEFAULT_ADMIN_USERNAME = "admin"
DEFAULT_ADMIN_PASSWORD = "admin"
DEFAULT_DEMO_CLIENT_ID = "demo-app"

ACCESS_TOKEN_EXPIRES = 900
REFRESH_TOKEN_EXPIRES = 14 * 24 * 3600
AUTHORIZATION_CODE_EXPIRES = 120
INTERACTION_EXPIRES = 300

SCOPES_SUPPORTED = [
    "openid",
    "profile",
    "email",
    "groups",
    "offline_access",
]
