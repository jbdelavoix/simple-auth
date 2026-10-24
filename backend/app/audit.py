from __future__ import annotations

import json
import os
import time
import unicodedata
from contextvars import ContextVar
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import Any

from app.config import AUDIT_KEEP, AUDIT_MAX_BYTES, AUDIT_PATH
from app.security import generate_id

_lock = Lock()
_ip: ContextVar[str | None] = ContextVar("audit_ip", default=None)
_request_id: ContextVar[str | None] = ContextVar("audit_request_id", default=None)
_actor_id: ContextVar[str | None] = ContextVar("audit_actor_id", default=None)
_actor_name: ContextVar[str | None] = ContextVar("audit_actor_name", default=None)

_SECRET_KEYS = {
    "password",
    "current_password",
    "new_password",
    "secret",
    "client_secret",
    "cookie_secret",
    "token",
    "access_token",
    "refresh_token",
    "id_token",
    "code",
    "code_verifier",
    "totp_secret",
    "recovery",
    "recovery_codes",
    "recovery_hashes",
}

_FAILURE_ACTIONS = {
    "login_failed",
    "mfa_failed",
    "token_failed",
    "refresh_reuse",
    "code_reuse",
}
_DENIED_ACTIONS = {"consent_deny", "client_forbidden"}

_ACTION_ALIASES = {
    "login": "connexion sign-in anmeldung acceso accesso",
    "login_failed": "échec de connexion failed sign-in anmeldung fehlgeschlagen",
    "mfa_ok": "mfa validé verified bestätigt",
    "mfa_trusted": "mfa appareil de confiance trusted device vertrautes gerät",
    "mfa_failed": "mfa refusé rejected abgelehnt",
    "mfa_enabled": "mfa activé enabled aktiviert",
    "mfa_disabled": "mfa désactivé disabled deaktiviert",
    "mfa_reset": "mfa réinitialisé reset zurückgesetzt",
    "password_change": "mot de passe changé password changed passwort",
    "profile_update": "profil modifié profile updated",
    "logout": "déconnexion sign-out abmeldung",
    "consent_allow": "accès autorisé access granted",
    "consent_deny": "accès refusé access denied",
    "token_issued": "jeton émis token issued",
    "token_failed": "échec d’émission token failed",
    "token_revoked": "jeton révoqué token revoked",
    "refresh_reuse": "refresh token réutilisé reused",
    "user_create": "utilisateur créé user created benutzer",
    "user_update": "utilisateur modifié user updated",
    "user_delete": "utilisateur supprimé user deleted",
    "group_create": "groupe créé group created",
    "group_update": "groupe modifié group updated",
    "group_delete": "groupe supprimé group deleted",
    "client_create": "client créé created",
    "client_update": "client modifié updated",
    "client_delete": "client supprimé deleted",
    "crypto_reset": "clés de signature régénérées signing keys rotated",
    "audit_rotate": "journal d’audit archivé audit log rotated",
    "client_forbidden": "accès client refusé client access denied",
}

_OUTCOME_ALIASES = {
    "success": "succès success erfolg êxito",
    "failure": "échec failure fail fehler falha",
    "denied": "refusé denied abgelehnt denegado recusado",
}


def bind_request(ip: str | None, request_id: str, actor_id: str | None = None, actor_name: str | None = None) -> None:
    _ip.set(ip)
    _request_id.set(request_id)
    _actor_id.set(actor_id)
    _actor_name.set(actor_name)


def clear_request() -> None:
    _ip.set(None)
    _request_id.set(None)
    _actor_id.set(None)
    _actor_name.set(None)


def _redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: ("***" if key.lower() in _SECRET_KEYS else _redact(item)) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact(item) for item in value]
    return value


def _outcome_for(action: str, explicit: str | None) -> str:
    if explicit:
        return explicit
    if action in _FAILURE_ACTIONS:
        return "failure"
    if action in _DENIED_ACTIONS:
        return "denied"
    return "success"


def audit(action: str, **fields: Any) -> dict[str, Any]:
    now = int(time.time())
    outcome = _outcome_for(action, fields.pop("outcome", None))
    actor_id = fields.pop("actor_id", None) or fields.pop("admin_id", None) or _actor_id.get()
    actor = fields.pop("actor", None) or fields.pop("admin", None) or fields.get("username") or _actor_name.get()
    user_id = fields.pop("user_id", None)
    target_id = fields.pop("target_id", None) or user_id
    target = fields.pop("target", None) or fields.get("username") or fields.get("client_id") or fields.get("name")
    target_type = fields.pop("target_type", None)
    if not target_type:
        if fields.get("client_id") and action.startswith("client"):
            target_type = "client"
        elif action.startswith("group"):
            target_type = "group"
        elif user_id or action.startswith(("login", "mfa", "password", "user")):
            target_type = "user"
    ip = fields.pop("ip", None) or _ip.get()
    request_id = fields.pop("request_id", None) or _request_id.get()
    record = {
        "id": generate_id(),
        "ts": now,
        "at": datetime.fromtimestamp(now, tz=timezone.utc).isoformat(),
        "action": action,
        "outcome": outcome,
        "actor_id": actor_id,
        "actor": actor,
        "ip": ip,
        "request_id": request_id,
        "target_type": target_type,
        "target_id": target_id,
        "target": target,
        **{key: value for key, value in _redact(fields).items() if value is not None},
    }
    path = Path(AUDIT_PATH)
    path.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(record, ensure_ascii=False, separators=(",", ":"), default=str)
    with _lock:
        with path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        _rotate_unlocked(force=False)
    return record


def _rotated_path(index: int) -> Path:
    return Path(f"{AUDIT_PATH}.{index}")


def _audit_files() -> list[Path]:
    files: list[Path] = []
    current = Path(AUDIT_PATH)
    if current.exists():
        files.append(current)
    index = 1
    while True:
        archive = _rotated_path(index)
        if not archive.exists():
            break
        files.append(archive)
        index += 1
    return files


def _lock_file(path: Path) -> None:
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def _rotate_unlocked(force: bool = False) -> bool:
    path = Path(AUDIT_PATH)
    if not path.exists():
        return False
    size = path.stat().st_size
    if size <= 0:
        return False
    if not force and size < AUDIT_MAX_BYTES:
        return False
    last = _rotated_path(AUDIT_KEEP)
    if last.exists():
        last.unlink()
    for index in range(AUDIT_KEEP - 1, 0, -1):
        source = _rotated_path(index)
        if source.exists():
            dest = _rotated_path(index + 1)
            if dest.exists():
                dest.unlink()
            source.rename(dest)
            _lock_file(dest)
    path.rename(_rotated_path(1))
    _lock_file(_rotated_path(1))
    return True


def rotate_logs(force: bool = True) -> bool:
    with _lock:
        return _rotate_unlocked(force=force)


def rotation_info() -> dict[str, Any]:
    current = Path(AUDIT_PATH)
    archives: list[dict[str, Any]] = []
    for index in range(1, AUDIT_KEEP + 1):
        path = _rotated_path(index)
        if not path.exists():
            continue
        stat = path.stat()
        archives.append(
            {
                "name": path.name,
                "bytes": stat.st_size,
                "mtime": int(stat.st_mtime),
            }
        )
    return {
        "current_bytes": current.stat().st_size if current.exists() else 0,
        "max_bytes": AUDIT_MAX_BYTES,
        "keep": AUDIT_KEEP,
        "archives": archives,
    }


def _fold(value: Any) -> str:
    text = unicodedata.normalize("NFKD", str(value or ""))
    return "".join(char for char in text if not unicodedata.combining(char)).casefold()


def _haystack(item: dict[str, Any]) -> str:
    action = str(item.get("action") or "")
    outcome = str(item.get("outcome") or "")
    parts = [
        action,
        action.replace("_", " "),
        _ACTION_ALIASES.get(action, ""),
        outcome,
        _OUTCOME_ALIASES.get(outcome, ""),
        item.get("actor"),
        item.get("target"),
        item.get("ip"),
        item.get("client_id"),
        item.get("request_id"),
        item.get("target_id"),
        item.get("actor_id"),
    ]
    return _fold(" ".join(str(part) for part in parts if part))


def _matches(
    item: dict[str, Any],
    action: str | None,
    outcome: str | None,
    q: str | None,
    actor: str | None,
    target: str | None,
    ip: str | None,
    since: int | None,
    until: int | None,
) -> bool:
    if action and item.get("action") != action:
        return False
    if outcome and item.get("outcome") != outcome:
        return False
    if actor and _fold(actor) not in _fold(item.get("actor")):
        return False
    target_value = item.get("target") or item.get("client_id") or ""
    if target and _fold(target) not in _fold(target_value):
        return False
    if ip and ip not in str(item.get("ip") or ""):
        return False
    if q and _fold(q) not in _haystack(item):
        return False
    ts = int(item.get("ts") or 0)
    if since and ts < since:
        return False
    if until and ts > until:
        return False
    return True


def read_events(
    limit: int = 200,
    action: str | None = None,
    outcome: str | None = None,
    q: str | None = None,
    actor: str | None = None,
    target: str | None = None,
    ip: str | None = None,
    since: int | None = None,
    until: int | None = None,
) -> list[dict[str, Any]]:
    limit = max(1, min(int(limit), 500))
    events: list[dict[str, Any]] = []
    for path in _audit_files():
        try:
            raw = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for line in reversed(raw.splitlines()):
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not _matches(item, action, outcome, q, actor, target, ip, since, until):
                continue
            events.append(item)
            if len(events) >= limit:
                return events
    return events
