from __future__ import annotations

import copy
import re
import secrets
import sys
import time
from typing import Any
from urllib.parse import urlparse

from app.config import (
    APP_ORIGINS,
    CLIENTS_PATH,
    DATA_DIR,
    DEFAULT_ADMIN_PASSWORD,
    DEFAULT_ADMIN_USERNAME,
    DEFAULT_DEMO_CLIENT_ID,
    DIRECTORY_PATH,
    FRONTEND_ORIGIN,
    IDENTITIES_PATH,
    INITIAL_ADMIN_PASSWORD,
    ISSUER,
    MFA_TRUST_DAYS,
    MFA_TRUST_MAX_DAYS,
    SCOPES_SUPPORTED,
    SECRET_KEY,
    SESSION_ABSOLUTE_SECONDS,
    SESSION_IDLE_SECONDS,
    SESSION_MAX_SECONDS,
    SESSION_MIN_SECONDS,
)
from app.store.lock import StoreLock
from app.crypto import SecretBox
from app.mfa import normalize_recovery_code, verify_totp
from app.security import (
    dummy_password_check,
    generate_id,
    hash_password,
    normalize_password_policy,
    validate_group_name,
    validate_password,
    validate_username,
    verify_password,
)
from app.store.json_store import read_json, write_json


def _now() -> int:
    return int(time.time())


def _normalize_names(values: Any) -> list[str]:
    names: list[str] = []
    for item in values or []:
        name = str(item).strip()
        if name and name not in names:
            names.append(name)
    return names


LOGIN_THEMES = ("classic", "slate", "light", "contrast")


def _scope_set(scope: str) -> set[str]:
    return {part for part in str(scope or "").split() if part}


def _purge_client_consents(data: dict[str, Any], client_id: str) -> None:
    store = data.setdefault("consents", {})
    for user_id, grants in list(store.items()):
        kept = [item for item in grants if item.get("client_id") != client_id]
        if kept:
            store[user_id] = kept
        else:
            store.pop(user_id, None)


CLIENT_MODES = ("oidc", "forward")


def normalize_client_mode(
    value: Any = None,
    *,
    origins: Any = None,
    redirect_uris: Any = None,
) -> str:
    mode = str(value or "").strip().lower()
    if mode in CLIENT_MODES:
        return mode
    if normalize_app_origins(origins) and not [item for item in (redirect_uris or []) if str(item).strip()]:
        return "forward"
    return "oidc"


def client_mode(client: dict[str, Any] | None) -> str:
    row = client or {}
    return normalize_client_mode(
        row.get("mode"),
        origins=row.get("origins"),
        redirect_uris=row.get("redirect_uris"),
    )


def issuer_requires_https() -> bool:
    return ISSUER.startswith("https://")


def valid_redirect_uri(uri: str, *, https_only: bool) -> bool:
    text = str(uri or "").strip()
    if not text or text.startswith("//") or "\\" in text or any(ch.isspace() for ch in text):
        return False
    parsed = urlparse(text)
    if parsed.scheme not in {"http", "https"}:
        return False
    if https_only and parsed.scheme != "https":
        return False
    if parsed.fragment or parsed.username or parsed.password:
        return False
    host = parsed.hostname
    if not host or "*" in host:
        return False
    return True


def filter_redirect_uris(values: Any, *, https_only: bool) -> list[str]:
    clean: list[str] = []
    for item in values or []:
        text = str(item or "").strip()
        if text and valid_redirect_uri(text, https_only=https_only) and text not in clean:
            clean.append(text)
    return clean


def parse_redirect_uris(values: Any, *, https_only: bool) -> list[str]:
    clean: list[str] = []
    for item in values or []:
        text = str(item or "").strip()
        if not text:
            continue
        if not valid_redirect_uri(text, https_only=https_only):
            raise ValueError("Invalid redirect URI")
        if text not in clean:
            clean.append(text)
    return clean


_GRANT_TYPES = {"authorization_code", "refresh_token"}
_AUTH_METHODS = {"none", "client_secret_basic", "client_secret_post"}


def normalize_app_origins(value: Any = None) -> list[str]:
    raw = value if isinstance(value, list) else []
    origins: list[str] = []
    for item in raw:
        text = str(item or "").strip()
        if not text or text.startswith("//") or "\\" in text:
            continue
        parsed = urlparse(text if "://" in text else f"https://{text}")
        if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.username:
            continue
        origin = f"{parsed.scheme}://{parsed.netloc}".rstrip("/")
        if origin not in origins:
            origins.append(origin)
    return origins


def normalize_login_theme(value: Any) -> str:
    theme = str(value or "").strip().lower()
    return theme if theme in LOGIN_THEMES else "classic"


_HEX_COLOR = re.compile(r"^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6})$")
_LOGO_PREFIXES = (
    "data:image/png;base64,",
    "data:image/jpeg;base64,",
    "data:image/jpg;base64,",
    "data:image/webp;base64,",
    "data:image/gif;base64,",
)
_LOGO_MAX_CHARS = 220_000


def as_bool(value: Any, default: bool = True) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _hex_color(value: Any, default: str = "") -> str:
    text = str(value or "").strip()
    return text.lower() if _HEX_COLOR.match(text) else default


def _logo_data(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    if len(text) > _LOGO_MAX_CHARS:
        return ""
    lowered = text[:40].lower()
    if not any(lowered.startswith(prefix) for prefix in _LOGO_PREFIXES):
        return ""
    return text


def _plain_label(value: Any, limit: int = 80) -> str:
    text = " ".join(str(value or "").split())
    return text[:limit]


def _bounded_int(value: Any, default: int, low: int, high: int) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        number = default
    return min(high, max(low, number))


def default_session_policy() -> dict[str, int]:
    idle = _bounded_int(SESSION_IDLE_SECONDS, 1800, SESSION_MIN_SECONDS, SESSION_MAX_SECONDS)
    absolute = _bounded_int(SESSION_ABSOLUTE_SECONDS, 43200, SESSION_MIN_SECONDS, SESSION_MAX_SECONDS)
    if absolute < idle:
        absolute = idle
    trust = _bounded_int(MFA_TRUST_DAYS, 30, 0, MFA_TRUST_MAX_DAYS)
    return {"idle_seconds": idle, "absolute_seconds": absolute, "mfa_trust_days": trust}


def normalize_session_policy(value: Any = None, *, strict: bool = False) -> dict[str, int]:
    """Idle and absolute session limits, plus how long a trusted MFA device lasts.

    Missing or broken stored values fall back to the environment defaults.
    ``strict`` is for an admin save: out of range is an error, not a silent clamp.
    """
    defaults = default_session_policy()
    raw = value if isinstance(value, dict) else {}
    if strict:
        try:
            idle = int(raw["idle_seconds"])
            absolute = int(raw["absolute_seconds"])
            trust = int(raw["mfa_trust_days"])
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("Session settings must be whole numbers") from exc
        if not SESSION_MIN_SECONDS <= idle <= SESSION_MAX_SECONDS:
            raise ValueError("Idle timeout must be between 1 minute and 30 days")
        if not idle <= absolute <= SESSION_MAX_SECONDS:
            raise ValueError("Absolute timeout must be between the idle timeout and 30 days")
        if not 0 <= trust <= MFA_TRUST_MAX_DAYS:
            raise ValueError("MFA trust must be between 0 and 365 days")
        return {"idle_seconds": idle, "absolute_seconds": absolute, "mfa_trust_days": trust}
    idle = _bounded_int(raw.get("idle_seconds"), defaults["idle_seconds"], SESSION_MIN_SECONDS, SESSION_MAX_SECONDS)
    absolute = _bounded_int(
        raw.get("absolute_seconds"),
        defaults["absolute_seconds"],
        SESSION_MIN_SECONDS,
        SESSION_MAX_SECONDS,
    )
    if absolute < idle:
        absolute = idle
    trust = _bounded_int(raw.get("mfa_trust_days"), defaults["mfa_trust_days"], 0, MFA_TRUST_MAX_DAYS)
    return {"idle_seconds": idle, "absolute_seconds": absolute, "mfa_trust_days": trust}


def normalize_login_branding(value: Any = None) -> dict[str, str]:
    raw = value if isinstance(value, dict) else {}
    return {
        "background": _hex_color(raw.get("background")),
        "panel": _hex_color(raw.get("panel")),
        "ink": _hex_color(raw.get("ink")),
        "accent": _hex_color(raw.get("accent")),
        "logo": _logo_data(raw.get("logo")),
        "title": _plain_label(raw.get("title")),
        "subtitle": _plain_label(raw.get("subtitle")),
    }


def _seed_directory() -> dict[str, Any]:
    return {
        "settings": {
            "issuer": ISSUER,
            "cookie_secret": secrets.token_urlsafe(32),
            "frontend_origin": FRONTEND_ORIGIN,
            "login_theme": "classic",
            "enable_demo": not issuer_requires_https(),
            "enable_help": True,
            "password_policy": normalize_password_policy(),
            "login_branding": normalize_login_branding(),
            "session_policy": default_session_policy(),
        },
        "mfa": {},
        "mfa_devices": {},
        "consents": {},
        "auth_state": {},
    }


def seeds_default_admin_password() -> bool:
    return not INITIAL_ADMIN_PASSWORD and not issuer_requires_https()


def _initial_admin_password() -> str:
    if INITIAL_ADMIN_PASSWORD:
        return INITIAL_ADMIN_PASSWORD
    if seeds_default_admin_password():
        return DEFAULT_ADMIN_PASSWORD
    generated = secrets.token_urlsafe(18)
    print(
        f"simple-auth: initial password for '{DEFAULT_ADMIN_USERNAME}': {generated} "
        "(it must be changed at first sign-in)",
        file=sys.stderr,
        flush=True,
    )
    return generated


def _demo_client() -> dict[str, Any]:
    now = _now()
    return {
        "client_id": DEFAULT_DEMO_CLIENT_ID,
        "client_name": "Demo App",
        "client_secret_hash": None,
        "redirect_uris": [
            f"{FRONTEND_ORIGIN}/demo/callback",
            "http://127.0.0.1:5173/demo/callback",
        ],
        "post_logout_redirect_uris": [
            f"{FRONTEND_ORIGIN}/",
            f"{FRONTEND_ORIGIN}/demo",
            "http://127.0.0.1:5173/",
            "http://127.0.0.1:5173/demo",
        ],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
        "scope": " ".join(SCOPES_SUPPORTED),
        "allowed_groups": ["admins", "users"],
        "origins": [],
        "mode": "oidc",
        "created_at": now,
        "updated_at": now,
    }


def _seed_clients() -> dict[str, Any]:
    return {"clients": [_demo_client()]}


def sync_demo_client_redirects(directory: DirectoryStore, frontend_origin: str) -> None:
    client = directory.get_client(DEFAULT_DEMO_CLIENT_ID)
    if not client:
        return
    # Loopback HTTP redirects exist only for an HTTP issuer. An HTTPS issuer
    # keeps HTTPS callbacks and does not re-add localhost.
    if issuer_requires_https():
        redirects = [uri for uri in (client.get("redirect_uris") or []) if str(uri).startswith("https://")]
        post_logout = [
            uri for uri in (client.get("post_logout_redirect_uris") or []) if str(uri).startswith("https://")
        ]
        if frontend_origin.startswith("https://"):
            redirects.append(f"{frontend_origin}/demo/callback")
            post_logout.extend([f"{frontend_origin}/", f"{frontend_origin}/demo"])
    else:
        redirects = [
            f"{frontend_origin}/demo/callback",
            "http://localhost:5173/demo/callback",
            "http://127.0.0.1:5173/demo/callback",
            "http://localhost:8000/demo/callback",
            "http://127.0.0.1:8000/demo/callback",
        ]
        post_logout = [
            f"{frontend_origin}/",
            f"{frontend_origin}/demo",
            "http://localhost:5173/",
            "http://localhost:5173/demo",
            "http://127.0.0.1:5173/",
            "http://127.0.0.1:5173/demo",
            "http://localhost:8000/",
            "http://localhost:8000/demo",
            "http://127.0.0.1:8000/",
            "http://127.0.0.1:8000/demo",
        ]
        redirects = [*(client.get("redirect_uris") or []), *redirects]
        post_logout = [*(client.get("post_logout_redirect_uris") or []), *post_logout]
    redirects = list(dict.fromkeys(redirects))
    post_logout = list(dict.fromkeys(post_logout))
    if not redirects:
        return
    directory.update_client(
        DEFAULT_DEMO_CLIENT_ID,
        {
            "redirect_uris": redirects,
            "post_logout_redirect_uris": post_logout,
        },
    )


def _seed_identities() -> dict[str, Any]:
    admin_group_id = generate_id()
    users_group_id = generate_id()
    return {
        "groups": [
            {
                "id": admin_group_id,
                "name": "admins",
                "description": "Directory administrators",
            },
            {
                "id": users_group_id,
                "name": "users",
                "description": "Standard users",
            },
        ],
        "users": [
            {
                "id": generate_id(),
                "username": DEFAULT_ADMIN_USERNAME,
                "password_hash": hash_password(_initial_admin_password()),
                "email": "admin@example.com",
                "name": "Administrator",
                "enabled": True,
                "group_ids": [admin_group_id, users_group_id],
                "attributes": {},
                "must_change_password": True,
                "created_at": _now(),
                "updated_at": _now(),
            }
        ],
    }


def _shape_client_payload(payload: dict[str, Any], client_secret: str | None = None) -> dict[str, Any]:
    https_only = issuer_requires_https()
    origins = normalize_app_origins(payload.get("origins"))
    redirects = parse_redirect_uris(payload.get("redirect_uris"), https_only=https_only)
    post_logout = parse_redirect_uris(payload.get("post_logout_redirect_uris"), https_only=https_only)
    mode = normalize_client_mode(payload.get("mode"), origins=origins, redirect_uris=redirects)
    if mode == "forward":
        if not origins:
            raise ValueError("Forward client needs at least one origin")
        return {
            "mode": "forward",
            "origins": origins,
            "redirect_uris": [],
            "post_logout_redirect_uris": [],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",
            "scope": payload.get("scope") or " ".join(SCOPES_SUPPORTED),
            "allowed_groups": _normalize_names(payload.get("allowed_groups")),
            "id_token_signed_response_alg": "RS256",
        }
    if not redirects:
        raise ValueError("OIDC client needs at least one redirect URI")
    auth_method = payload.get("token_endpoint_auth_method") or (
        "none" if not client_secret and not payload.get("client_secret_hash") else "client_secret_post"
    )
    # A stored secret has to be checked. "none" would ignore it.
    if client_secret and auth_method == "none":
        auth_method = "client_secret_post"
    if auth_method not in _AUTH_METHODS:
        raise ValueError("Invalid token endpoint auth method")
    grant_types = [item for item in (payload.get("grant_types") or []) if item in _GRANT_TYPES]
    if not grant_types:
        grant_types = ["authorization_code", "refresh_token"]
    return {
        "mode": "oidc",
        "origins": [],
        "redirect_uris": redirects,
        "post_logout_redirect_uris": post_logout,
        "grant_types": grant_types,
        "response_types": ["code"],
        "token_endpoint_auth_method": auth_method,
        "scope": payload.get("scope") or " ".join(SCOPES_SUPPORTED),
        "allowed_groups": _normalize_names(payload.get("allowed_groups")),
        "id_token_signed_response_alg": "RS256",
    }


class DirectoryStore:
    def __init__(self, path=DIRECTORY_PATH, identities_path=IDENTITIES_PATH, clients_path=CLIENTS_PATH):
        self.path = path
        self.identities_path = identities_path
        self.clients_path = clients_path
        self._booted = False
        self._data: dict[str, Any] | None = None
        self._identities: dict[str, Any] | None = None
        self._clients: dict[str, Any] | None = None
        self._lock = StoreLock(DATA_DIR / ".directory.lock", self._reload_for_lock)

    def _reload_for_lock(self) -> None:
        if not self._booted:
            self._ensure_unlocked()
            self._booted = True
            return
        if self.path.exists():
            self._data = read_json(self.path, None) or _seed_directory()
        if self.identities_path.exists():
            self._identities = read_json(self.identities_path, None) or {"users": [], "groups": []}
        if self.clients_path.exists():
            self._clients = read_json(self.clients_path, None) or {"clients": []}
        if self._data is None or self._identities is None or self._clients is None:
            self._ensure_unlocked()
            self._booted = True

    def ensure(self) -> dict[str, Any]:
        with self._lock:
            return self._data or {}

    def _ensure_unlocked(self) -> None:
        if self.path.exists():
            self._data = read_json(self.path, None) or _seed_directory()
            self._data.setdefault("settings", {})
            self._data.setdefault("mfa", {})
            self._data.setdefault("consents", {})
            self._data.setdefault("auth_state", {})
        else:
            self._data = _seed_directory()
            write_json(self.path, self._data)

        clients_dirty = False
        if self.clients_path.exists():
            self._clients = read_json(self.clients_path, None) or {"clients": []}
            self._clients.setdefault("clients", [])
        else:
            self._clients = _seed_clients()
            clients_dirty = True
        if self._normalize_clients_unlocked():
            clients_dirty = True

        directory_dirty = False
        settings = self._data.setdefault("settings", {})
        theme = normalize_login_theme(settings.get("login_theme"))
        if settings.get("login_theme") != theme:
            settings["login_theme"] = theme
            directory_dirty = True
        for key in ("enable_demo", "enable_help"):
            flag = as_bool(settings.get(key), True)
            if settings.get(key) is not flag:
                settings[key] = flag
                directory_dirty = True
        policy = normalize_password_policy(settings.get("password_policy"))
        if settings.get("password_policy") != policy:
            settings["password_policy"] = policy
            directory_dirty = True
        branding = normalize_login_branding(settings.get("login_branding"))
        if settings.get("login_branding") != branding:
            settings["login_branding"] = branding
            directory_dirty = True
        policy_session = normalize_session_policy(settings.get("session_policy"))
        if settings.get("session_policy") != policy_session:
            settings["session_policy"] = policy_session
            directory_dirty = True
        if "mfa_devices" not in self._data:
            self._data["mfa_devices"] = {}
            directory_dirty = True
        if self._attach_session_origins():
            clients_dirty = True

        if self.identities_path.exists():
            self._identities = read_json(self.identities_path, None) or {"users": [], "groups": []}
            self._identities.setdefault("users", [])
            self._identities.setdefault("groups", [])
        else:
            self._identities = _seed_identities()
            write_json(self.identities_path, self._identities)

        if clients_dirty:
            self._save_clients()
        if directory_dirty:
            write_json(self.path, self._data)

    def _normalize_clients_unlocked(self) -> bool:
        dirty = False
        https_only = issuer_requires_https()
        for client in (self._clients or {}).get("clients") or []:
            client.setdefault("allowed_groups", [])
            client.setdefault("origins", [])
            mode = client_mode(client)
            redirects = filter_redirect_uris(client.get("redirect_uris"), https_only=https_only)
            post_logout = filter_redirect_uris(client.get("post_logout_redirect_uris"), https_only=https_only)
            if (
                client.get("mode") != mode
                or client.get("redirect_uris") != redirects
                or client.get("post_logout_redirect_uris") != post_logout
                or client.get("id_token_signed_response_alg") != "RS256"
            ):
                client["mode"] = mode
                client["redirect_uris"] = redirects
                client["post_logout_redirect_uris"] = post_logout
                client["id_token_signed_response_alg"] = "RS256"
                dirty = True
        return dirty

    def _client_origins_unlocked(self) -> list[str]:
        origins: list[str] = []
        for client in (self._clients or {}).get("clients") or []:
            if client_mode(client) != "forward":
                continue
            for origin in normalize_app_origins(client.get("origins")):
                if origin not in origins:
                    origins.append(origin)
        return origins

    def _attach_session_origins(self) -> bool:
        dirty = False
        for client in (self._clients or {}).setdefault("clients", []):
            client.setdefault("origins", [])
            origins = normalize_app_origins(client.get("origins"))
            mode = client_mode(client)
            if client.get("origins") != origins or client.get("mode") != mode:
                client["origins"] = origins
                client["mode"] = mode
                dirty = True
        incoming = normalize_app_origins(APP_ORIGINS)
        owned = set(self._client_origins_unlocked())
        unowned = [origin for origin in incoming if origin not in owned]
        if not unowned:
            return dirty
        clients = (self._clients or {}).setdefault("clients", [])
        target = next((item for item in clients if item.get("client_id") == "session-apps"), None)
        if target is None:
            now = _now()
            target = {
                "client_id": "session-apps",
                "client_name": "Session apps",
                "client_secret_hash": None,
                "redirect_uris": [],
                "post_logout_redirect_uris": [],
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
                "token_endpoint_auth_method": "none",
                "scope": " ".join(SCOPES_SUPPORTED),
                "allowed_groups": [],
                "origins": [],
                "mode": "forward",
                "created_at": now,
                "updated_at": now,
            }
            clients.append(target)
        target["mode"] = "forward"
        target["origins"] = normalize_app_origins([*(target.get("origins") or []), *unowned])
        return True

    def _ready(self) -> None:
        if self._data is None or self._identities is None or self._clients is None:
            self._ensure_unlocked()
            self._booted = True

    def _load(self) -> dict[str, Any]:
        self._ready()
        assert self._data is not None
        return self._data

    def _idents(self) -> dict[str, Any]:
        self._ready()
        assert self._identities is not None
        return self._identities

    def _client_rows(self) -> list[dict[str, Any]]:
        self._ready()
        assert self._clients is not None
        return self._clients.setdefault("clients", [])

    def _save(self) -> None:
        assert self._data is not None
        write_json(self.path, self._data)

    def _save_identities(self) -> None:
        assert self._identities is not None
        write_json(self.identities_path, self._identities)

    def _save_clients(self) -> None:
        assert self._clients is not None
        write_json(self.clients_path, self._clients)

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "directory": copy.deepcopy(self._load()),
                "identities": copy.deepcopy(self._idents()),
                "clients": copy.deepcopy(self._client_rows()),
            }

    def reload(self) -> dict[str, Any]:
        with self._lock:
            self._booted = False
            self._data = None
            self._identities = None
            self._clients = None
            self._ensure_unlocked()
            self._booted = True
            return copy.deepcopy(self._load())

    def auth_version(self, user_id: str) -> int:
        with self._lock:
            state = self._load().setdefault("auth_state", {}).get(user_id) or {}
            return int(state.get("version") or 0)

    def bump_auth_version(self, user_id: str) -> int:
        with self._lock:
            state = self._load().setdefault("auth_state", {}).setdefault(str(user_id), {})
            version = int(state.get("version") or 0) + 1
            state["version"] = version
            self._save()
            return version

    # --- settings ---
    def get_settings(self) -> dict[str, Any]:
        with self._lock:
            return copy.deepcopy(self._load()["settings"])

    def session_policy(self) -> dict[str, int]:
        with self._lock:
            return self._session_policy_unlocked()

    def _session_policy_unlocked(self) -> dict[str, int]:
        return normalize_session_policy(self._load()["settings"].get("session_policy"))

    def _auth_version_unlocked(self, user_id: str) -> int:
        state = self._load().setdefault("auth_state", {}).get(user_id) or {}
        return int(state.get("version") or 0)

    _MFA_DEVICE_LIMIT = 8

    def remember_mfa_device(self, user_id: str) -> str | None:
        """Store a new trusted browser and return the cookie value. None if trust is off."""
        token = secrets.token_urlsafe(32)
        with self._lock:
            days = self._session_policy_unlocked()["mfa_trust_days"]
            if days <= 0:
                return None
            now = _now()
            devices = self._live_mfa_devices(user_id, now)
            devices.append(
                {
                    "token_hash": self._box().hmac_hex(token),
                    "expires_at": now + days * 86400,
                    "created_at": now,
                    "auth_version": self._auth_version_unlocked(user_id),
                }
            )
            if len(devices) > self._MFA_DEVICE_LIMIT:
                devices = devices[-self._MFA_DEVICE_LIMIT :]
            self._load().setdefault("mfa_devices", {})[user_id] = devices
            self._save()
        return f"{user_id}.{token}"

    def mfa_device_valid(self, user_id: str, cookie: str | None) -> bool:
        from app.mfa_trust import split_device_cookie

        parsed = split_device_cookie(cookie)
        if not parsed or parsed[0] != user_id:
            return False
        token = parsed[1]
        with self._lock:
            if self._session_policy_unlocked()["mfa_trust_days"] <= 0:
                return False
            now = _now()
            version = self._auth_version_unlocked(user_id)
            previous = list(self._load().setdefault("mfa_devices", {}).get(user_id) or [])
            devices = self._live_mfa_devices(user_id, now, version)
            if devices != previous:
                self._load().setdefault("mfa_devices", {})[user_id] = devices
                self._save()
            candidates = set(self._box().hmac_candidates(token))
            return any(item.get("token_hash") in candidates for item in devices)

    def _live_mfa_devices(self, user_id: str, now: int, version: int | None = None) -> list[dict[str, Any]]:
        if version is None:
            version = self._auth_version_unlocked(user_id)
        devices = self._load().setdefault("mfa_devices", {}).get(user_id) or []
        return [
            item
            for item in devices
            if int(item.get("expires_at") or 0) > now and int(item.get("auth_version") or 0) == version
        ]

    def password_policy(self) -> dict[str, Any]:
        with self._lock:
            return self._password_policy_unlocked()

    def _password_policy_unlocked(self) -> dict[str, Any]:
        return normalize_password_policy(self._load()["settings"].get("password_policy"))

    def login_branding(self) -> dict[str, str]:
        with self._lock:
            return normalize_login_branding(self._load()["settings"].get("login_branding"))

    def app_origins(self) -> list[str]:
        with self._lock:
            return self._client_origins_unlocked()

    def client_for_origin(self, origin: str) -> dict[str, Any] | None:
        needle = str(origin or "").rstrip("/")
        with self._lock:
            for client in self._client_rows():
                if client_mode(client) != "forward":
                    continue
                if needle in normalize_app_origins(client.get("origins")):
                    return copy.deepcopy(client)
        return None

    def update_settings(self, **kwargs: Any) -> dict[str, Any]:
        with self._lock:
            data = self._load()
            data["settings"].update(kwargs)
            self._save()
            return copy.deepcopy(data["settings"])

    # --- users ---
    def list_users(self) -> list[dict[str, Any]]:
        with self._lock:
            return [self._public_user(u) for u in self._idents()["users"]]

    def get_user(self, user_id: str) -> dict[str, Any] | None:
        with self._lock:
            user = self._find_user(user_id)
            return self._public_user(user) if user else None

    def get_user_by_username(self, username: str) -> dict[str, Any] | None:
        with self._lock:
            for user in self._idents()["users"]:
                if user["username"].lower() == username.lower():
                    return copy.deepcopy(user)
            return None

    def _box(self) -> SecretBox:
        cookie_secret = str(self._load()["settings"]["cookie_secret"])
        return SecretBox(SECRET_KEY or cookie_secret, cookie_secret)

    def seal(self, plaintext: str) -> str:
        with self._lock:
            return self._box().encrypt(plaintext)

    def unseal(self, value: str) -> str:
        with self._lock:
            return self._box().decrypt(value)

    def create_user(self, payload: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            data = self._idents()
            username_error = validate_username(str(payload.get("username") or ""))
            if username_error:
                raise ValueError(username_error)
            if any(u["username"].lower() == payload["username"].lower() for u in data["users"]):
                raise ValueError("username already exists")
            error = validate_password(payload["password"], payload["username"], self._password_policy_unlocked())
            if error:
                raise ValueError(error)
            now = _now()
            user = {
                "id": generate_id(),
                "username": payload["username"],
                "password_hash": hash_password(payload["password"]),
                "email": payload.get("email") or "",
                "name": payload.get("name") or payload["username"],
                "enabled": payload.get("enabled", True),
                "group_ids": list(payload.get("group_ids") or []),
                "attributes": dict(payload.get("attributes") or {}),
                "email_verified": bool(payload.get("email_verified")),
                "created_at": now,
                "updated_at": now,
            }
            data["users"].append(user)
            self._save_identities()
            return self._public_user(user)

    def update_user(self, user_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            data = self._idents()
            user = self._find_user(user_id)
            if not user:
                raise KeyError("user not found")
            if "username" in payload and payload["username"] != user["username"]:
                username_error = validate_username(str(payload["username"]))
                if username_error:
                    raise ValueError(username_error)
                if any(
                    u["username"].lower() == payload["username"].lower()
                    for u in data["users"]
                    if u["id"] != user_id
                ):
                    raise ValueError("username already exists")
                user["username"] = payload["username"]
            for key in ("email", "name", "enabled", "group_ids", "attributes"):
                if key in payload:
                    user[key] = payload[key]
            if "email_verified" in payload:
                user["email_verified"] = bool(payload["email_verified"])
            if payload.get("password"):
                error = validate_password(
                    payload["password"],
                    payload.get("username") or user["username"],
                    self._password_policy_unlocked(),
                )
                if error:
                    raise ValueError(error)
                user["password_hash"] = hash_password(payload["password"])
                user["must_change_password"] = False
                user.pop("failed_logins", None)
                user.pop("locked_until", None)
            if "must_change_password" in payload:
                user["must_change_password"] = bool(payload["must_change_password"])
            user["updated_at"] = _now()
            self._save_identities()
            return self._public_user(user)

    def delete_user(self, user_id: str) -> None:
        with self._lock:
            idents = self._idents()
            before = len(idents["users"])
            idents["users"] = [u for u in idents["users"] if u["id"] != user_id]
            if len(idents["users"]) == before:
                raise KeyError("user not found")
            self._load().setdefault("mfa", {}).pop(user_id, None)
            self._load().setdefault("consents", {}).pop(user_id, None)
            self._save_identities()
            self._save()

    def authenticate(self, username: str, password: str) -> dict[str, Any] | None:
        # bcrypt runs outside the store lock: holding it would serialize every
        # request on the server behind each sign-in attempt. Throttling is done
        # by the caller (app.ratelimit).
        with self._lock:
            user = next(
                (copy.deepcopy(u) for u in self._idents()["users"] if u["username"].lower() == username.lower()),
                None,
            )
        if not user or not user.get("enabled", True):
            dummy_password_check(password)
            return None
        if not verify_password(password, user["password_hash"]):
            return None
        with self._lock:
            current = self._find_user(user["id"])
            if (
                not current
                or not current.get("enabled", True)
                or current.get("password_hash") != user["password_hash"]
            ):
                return None
            now = _now()
            current.pop("failed_logins", None)
            current.pop("locked_until", None)
            current["last_login_at"] = now
            if password == DEFAULT_ADMIN_PASSWORD:
                current["must_change_password"] = True
            current["updated_at"] = now
            self._save_identities()
            return self._public_user(current)

    def user_group_names(self, user: dict[str, Any]) -> list[str]:
        with self._lock:
            groups = {g["id"]: g["name"] for g in self._idents()["groups"]}
            return [groups[gid] for gid in user.get("group_ids", []) if gid in groups]

    def is_admin(self, user: dict[str, Any]) -> bool:
        return "admins" in self.user_group_names(user)

    # --- groups ---
    def list_groups(self) -> list[dict[str, Any]]:
        with self._lock:
            return copy.deepcopy(self._idents()["groups"])

    def get_group(self, group_id: str) -> dict[str, Any] | None:
        with self._lock:
            for group in self._idents()["groups"]:
                if group["id"] == group_id:
                    return copy.deepcopy(group)
            return None

    def create_group(self, payload: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            data = self._idents()
            name_error = validate_group_name(str(payload.get("name") or ""))
            if name_error:
                raise ValueError(name_error)
            if any(g["name"].lower() == payload["name"].lower() for g in data["groups"]):
                raise ValueError("group name already exists")
            group = {
                "id": generate_id(),
                "name": payload["name"],
                "description": payload.get("description") or "",
            }
            data["groups"].append(group)
            self._save_identities()
            return copy.deepcopy(group)

    def update_group(self, group_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            data = self._idents()
            group = next((g for g in data["groups"] if g["id"] == group_id), None)
            if not group:
                raise KeyError("group not found")
            if "name" in payload and payload["name"] != group["name"]:
                name_error = validate_group_name(str(payload["name"]))
                if name_error:
                    raise ValueError(name_error)
                if any(
                    g["name"].lower() == payload["name"].lower()
                    for g in data["groups"]
                    if g["id"] != group_id
                ):
                    raise ValueError("group name already exists")
                group["name"] = payload["name"]
            if "description" in payload:
                group["description"] = payload["description"]
            self._save_identities()
            return copy.deepcopy(group)

    def delete_group(self, group_id: str) -> None:
        with self._lock:
            data = self._idents()
            before = len(data["groups"])
            data["groups"] = [g for g in data["groups"] if g["id"] != group_id]
            if len(data["groups"]) == before:
                raise KeyError("group not found")
            for user in data["users"]:
                user["group_ids"] = [gid for gid in user.get("group_ids", []) if gid != group_id]
            self._save_identities()

    # --- clients ---
    def list_clients(self) -> list[dict[str, Any]]:
        with self._lock:
            return [self._public_client(c) for c in self._client_rows()]

    def get_client(self, client_id: str) -> dict[str, Any] | None:
        with self._lock:
            client = self._find_client(client_id)
            return copy.deepcopy(client) if client else None

    def get_client_public(self, client_id: str) -> dict[str, Any] | None:
        client = self.get_client(client_id)
        return self._public_client(client) if client else None

    def _claim_forward_origins(self, origins: list[str], owner: str) -> None:
        for client in self._client_rows():
            if client.get("client_id") == owner:
                continue
            if client_mode(client) != "forward":
                continue
            taken = set(normalize_app_origins(client.get("origins")))
            if any(origin in taken for origin in origins):
                raise ValueError("origin_taken")

    def create_client(self, payload: dict[str, Any], client_secret: str | None) -> dict[str, Any]:
        with self._lock:
            rows = self._client_rows()
            if any(c["client_id"] == payload["client_id"] for c in rows):
                raise ValueError("client_id already exists")
            now = _now()
            shaped = _shape_client_payload(payload, client_secret=client_secret)
            if shaped["mode"] == "forward":
                self._claim_forward_origins(shaped["origins"], payload["client_id"])
            client = {
                "client_id": payload["client_id"],
                "client_name": payload.get("client_name") or payload["client_id"],
                **shaped,
                "client_secret_hash": None if shaped["mode"] == "forward" else (
                    hash_password(client_secret) if client_secret else None
                ),
                "created_at": now,
                "updated_at": now,
            }
            rows.append(client)
            self._save_clients()
            public = self._public_client(client)
            if client_secret:
                public["client_secret"] = client_secret
            return public

    def update_client(self, client_id: str, payload: dict[str, Any], new_secret: str | None = None) -> dict[str, Any]:
        with self._lock:
            client = self._find_client(client_id)
            if not client:
                raise KeyError("client not found")
            merged = {**client, **payload}
            shaped = _shape_client_payload(merged, client_secret=new_secret)
            if shaped["token_endpoint_auth_method"] != "none" and not new_secret and not client.get("client_secret_hash"):
                raise ValueError("client_secret_required")
            if shaped["mode"] == "forward":
                self._claim_forward_origins(shaped["origins"], client_id)
            client.update(shaped)
            if "client_name" in payload:
                client["client_name"] = payload["client_name"]
            if new_secret is not None:
                if new_secret == "":
                    client["client_secret_hash"] = None
                    client["token_endpoint_auth_method"] = "none"
                else:
                    client["client_secret_hash"] = hash_password(new_secret)
            if client["token_endpoint_auth_method"] == "none":
                client["client_secret_hash"] = None
            client["updated_at"] = _now()
            self._save_clients()
            public = self._public_client(client)
            if new_secret:
                public["client_secret"] = new_secret
            return public

    def restore_demo_client(self) -> bool:
        """Re-create the demo client if it was deleted. True when it was missing."""
        with self._lock:
            if self._find_client(DEFAULT_DEMO_CLIENT_ID):
                return False
            self._client_rows().append(_demo_client())
            self._normalize_clients_unlocked()
            self._save_clients()
            return True

    def delete_client(self, client_id: str) -> None:
        with self._lock:
            rows = self._client_rows()
            before = len(rows)
            kept = [c for c in rows if c["client_id"] != client_id]
            if len(kept) == before:
                raise KeyError("client not found")
            assert self._clients is not None
            self._clients["clients"] = kept
            _purge_client_consents(self._load(), client_id)
            self._save_clients()
            self._save()

    def get_mfa(self, user_id: str) -> dict[str, Any] | None:
        with self._lock:
            record = self._load().setdefault("mfa", {}).get(user_id)
            if not record:
                return None
            data = copy.deepcopy(record)
            secret = data.get("totp_secret")
            if secret:
                data["totp_secret"] = self._box().decrypt(secret)
            return data

    def recovery_hashes(self, codes: list[str]) -> list[str]:
        with self._lock:
            box = self._box()
            return [box.hmac_hex(normalize_recovery_code(code)) for code in codes]

    def consume_mfa_code(self, user_id: str, code: str) -> str | None:
        """Check a TOTP or recovery code and burn it in one locked step.

        Returns "totp", "recovery", or None. Raises KeyError if MFA is off.
        """
        with self._lock:
            record = self._load().setdefault("mfa", {}).get(user_id)
            if not record or not record.get("enabled") or not record.get("totp_secret"):
                raise KeyError("MFA is not enabled")
            box = self._box()
            step = verify_totp(box.decrypt(record["totp_secret"]), code, record.get("last_counter"))
            if step is not None:
                record["last_counter"] = step
                self._save()
                return "totp"
            hashes = list(record.get("recovery_hashes") or [])
            candidates = set(box.hmac_candidates(normalize_recovery_code(code)))
            remaining = [item for item in hashes if item not in candidates]
            if len(remaining) == len(hashes):
                return None
            record["recovery_hashes"] = remaining
            self._save()
            return "recovery"

    def mfa_enabled(self, user_id: str) -> bool:
        record = self.get_mfa(user_id)
        return bool(record and record.get("enabled") and record.get("totp_secret"))

    def set_mfa(self, user_id: str, record: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            stored = copy.deepcopy(record)
            if stored.get("totp_secret"):
                stored["totp_secret"] = self._box().encrypt(stored["totp_secret"])
            data = self._load()
            data.setdefault("mfa", {})[user_id] = stored
            self._save()
            return copy.deepcopy(record)

    def delete_mfa(self, user_id: str) -> None:
        with self._lock:
            data = self._load()
            data.setdefault("mfa", {}).pop(user_id, None)
            data.setdefault("mfa_devices", {}).pop(user_id, None)
            self._save()

    def has_consent(self, user_id: str, client_id: str, scope: str, redirect_uri: str = "") -> bool:
        requested = _scope_set(scope)
        if not user_id or not client_id or not requested:
            return False
        with self._lock:
            grants = self._load().setdefault("consents", {}).get(user_id) or []
            for grant in grants:
                if grant.get("client_id") != client_id:
                    continue
                if redirect_uri and grant.get("redirect_uri") and grant["redirect_uri"] != redirect_uri:
                    continue
                if requested <= _scope_set(str(grant.get("scope") or "")):
                    return True
        return False

    def remember_consent(self, user_id: str, client_id: str, scope: str, redirect_uri: str = "") -> None:
        if not user_id or not client_id:
            return
        with self._lock:
            data = self._load()
            grants = data.setdefault("consents", {}).setdefault(user_id, [])
            for grant in grants:
                if grant.get("client_id") == client_id and grant.get("redirect_uri") == redirect_uri:
                    grant["scope"] = " ".join(sorted(_scope_set(str(grant.get("scope") or "")) | _scope_set(scope)))
                    grant["updated_at"] = _now()
                    self._save()
                    return
            grants.append(
                {
                    "client_id": client_id,
                    "scope": " ".join(sorted(_scope_set(scope))),
                    "redirect_uri": redirect_uri,
                    "updated_at": _now(),
                }
            )
            self._save()

    def _find_user(self, user_id: str) -> dict[str, Any] | None:
        for user in self._idents()["users"]:
            if user["id"] == user_id:
                return user
        return None

    def _find_client(self, client_id: str) -> dict[str, Any] | None:
        for client in self._client_rows():
            if client["client_id"] == client_id:
                return client
        return None

    @staticmethod
    def _public_user(user: dict[str, Any]) -> dict[str, Any]:
        data = copy.deepcopy(user)
        data.pop("password_hash", None)
        data.pop("totp_secret", None)
        data.pop("recovery_hashes", None)
        data.pop("failed_logins", None)
        data.pop("locked_until", None)
        return data

    @staticmethod
    def _public_client(client: dict[str, Any]) -> dict[str, Any]:
        data = copy.deepcopy(client)
        data.pop("client_secret_hash", None)
        data["has_secret"] = bool(client.get("client_secret_hash"))
        return data
