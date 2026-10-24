from __future__ import annotations

import json
import os
import sqlite3
import time
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from app.config import LOGIN_WINDOW_SECONDS, RUNTIME_PATH
from app.security import generate_id, token_digest

_USED_CODE_TTL = 600
_LOGIN_WINDOW = LOGIN_WINDOW_SECONDS


def _now() -> int:
    return int(time.time())


def _dumps(item: dict[str, Any]) -> str:
    return json.dumps(item, separators=(",", ":"), ensure_ascii=False)


def _loads(raw: str) -> dict[str, Any]:
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise TypeError("runtime row is not an object")
    return data


class RuntimeStore:
    """Short-lived OIDC state in SQLite (WAL).

    Codes, tokens, interactions, nonces and tickets are disposable. Several
    processes on one host share the file; a write is one row, not a rewrite of
    the whole store.
    """

    def __init__(self, path=RUNTIME_PATH):
        self.path = path

    def ensure(self) -> dict[str, Any]:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.path.parent, 0o700)
        except OSError:
            pass
        with self._tx():
            pass
        self._chmod()
        return {}

    def _chmod(self) -> None:
        for name in (self.path.name, self.path.name + "-wal", self.path.name + "-shm"):
            candidate = self.path.parent / name
            if not candidate.exists():
                continue
            try:
                os.chmod(candidate, 0o600)
            except OSError:
                pass

    def _connect(self) -> sqlite3.Connection:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.path, timeout=5.0, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA busy_timeout=5000")
        conn.execute("PRAGMA temp_store=MEMORY")
        conn.execute("PRAGMA foreign_keys=ON")
        self._schema(conn)
        return conn

    def _schema(self, conn: sqlite3.Connection) -> None:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS authorization_codes (
                code_hash TEXT PRIMARY KEY,
                client_id TEXT NOT NULL,
                user_id TEXT,
                nonce TEXT,
                expires_at INTEGER NOT NULL,
                payload TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_codes_nonce
                ON authorization_codes(client_id, nonce);
            CREATE TABLE IF NOT EXISTS used_codes (
                code_hash TEXT NOT NULL,
                client_id TEXT NOT NULL,
                user_id TEXT,
                family_id TEXT,
                expires_at INTEGER NOT NULL,
                PRIMARY KEY (client_id, code_hash)
            );
            CREATE TABLE IF NOT EXISTS tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                access_hash TEXT,
                refresh_hash TEXT,
                user_id TEXT,
                client_id TEXT NOT NULL,
                family_id TEXT,
                family_gen INTEGER NOT NULL DEFAULT 0,
                revoked INTEGER NOT NULL DEFAULT 0,
                expires_at INTEGER NOT NULL,
                refresh_expires_at INTEGER,
                payload TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_tokens_access ON tokens(access_hash);
            CREATE INDEX IF NOT EXISTS idx_tokens_refresh ON tokens(refresh_hash);
            CREATE INDEX IF NOT EXISTS idx_tokens_user ON tokens(user_id);
            CREATE INDEX IF NOT EXISTS idx_tokens_family ON tokens(family_id);
            CREATE TABLE IF NOT EXISTS interactions (
                id TEXT PRIMARY KEY,
                expires_at INTEGER NOT NULL,
                payload TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS nonces (
                client_id TEXT NOT NULL,
                nonce TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                PRIMARY KEY (client_id, nonce)
            );
            CREATE TABLE IF NOT EXISTS session_tickets (
                ticket_hash TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                payload TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_tickets_user ON session_tickets(user_id);
            CREATE TABLE IF NOT EXISTS family_epochs (
                family_id TEXT PRIMARY KEY,
                epoch INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS login_hits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                bucket TEXT NOT NULL,
                at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_login_hits ON login_hits(bucket, at);
            CREATE TABLE IF NOT EXISTS revoked_sessions (
                sid TEXT PRIMARY KEY,
                expires_at INTEGER NOT NULL
            );
            """
        )

    @contextmanager
    def _tx(self) -> Iterator[sqlite3.Connection]:
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            self._purge(conn, _now())
            yield conn
            conn.execute("COMMIT")
        except BaseException:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            conn.close()
            self._chmod()

    def _purge(self, conn: sqlite3.Connection, now: int) -> None:
        conn.execute("DELETE FROM authorization_codes WHERE expires_at <= ?", (now,))
        conn.execute(
            """
            DELETE FROM tokens
            WHERE COALESCE(NULLIF(refresh_expires_at, 0), expires_at) <= ?
            """,
            (now,),
        )
        conn.execute("DELETE FROM interactions WHERE expires_at <= ?", (now,))
        conn.execute("DELETE FROM nonces WHERE expires_at <= ?", (now,))
        conn.execute("DELETE FROM session_tickets WHERE expires_at <= ?", (now,))
        conn.execute("DELETE FROM used_codes WHERE expires_at <= ?", (now,))
        conn.execute("DELETE FROM login_hits WHERE at <= ?", (now - _LOGIN_WINDOW,))
        conn.execute("DELETE FROM revoked_sessions WHERE expires_at <= ?", (now,))

    def _epoch(self, conn: sqlite3.Connection, family_id: str) -> int:
        if not family_id:
            return 0
        row = conn.execute(
            "SELECT epoch FROM family_epochs WHERE family_id = ?",
            (family_id,),
        ).fetchone()
        return int(row["epoch"]) if row else 0

    def _kill_family(self, conn: sqlite3.Connection, family_id: str) -> None:
        if not family_id:
            return
        conn.execute(
            """
            INSERT INTO family_epochs (family_id, epoch) VALUES (?, 1)
            ON CONFLICT(family_id) DO UPDATE SET epoch = epoch + 1
            """,
            (family_id,),
        )
        conn.execute("UPDATE tokens SET revoked = 1 WHERE family_id = ?", (family_id,))

    def _token_from_row(self, row: sqlite3.Row) -> dict[str, Any]:
        item = _loads(row["payload"])
        item["revoked"] = bool(row["revoked"])
        item["family_gen"] = int(row["family_gen"])
        item["family_id"] = row["family_id"]
        item["access_token_hash"] = row["access_hash"]
        item["refresh_token_hash"] = row["refresh_hash"]
        item["user_id"] = row["user_id"]
        item["client_id"] = row["client_id"]
        item["expires_at"] = int(row["expires_at"])
        item["refresh_token_expires_at"] = row["refresh_expires_at"]
        return item

    # --- interactions ---
    def create_interaction(self, params: dict[str, Any], expires_in: int) -> dict[str, Any]:
        item = {
            "id": generate_id(),
            "params": params,
            "user_id": None,
            "status": "login",
            "created_at": _now(),
            "expires_at": _now() + expires_in,
        }
        with self._tx() as conn:
            conn.execute(
                "INSERT INTO interactions (id, expires_at, payload) VALUES (?, ?, ?)",
                (item["id"], item["expires_at"], _dumps(item)),
            )
        return item

    def get_interaction(self, interaction_id: str) -> dict[str, Any] | None:
        with self._tx() as conn:
            row = conn.execute(
                "SELECT payload FROM interactions WHERE id = ?",
                (interaction_id,),
            ).fetchone()
        if not row:
            return None
        return _loads(row["payload"])

    def update_interaction(self, interaction_id: str, **kwargs: Any) -> dict[str, Any]:
        with self._tx() as conn:
            row = conn.execute(
                "SELECT payload, expires_at FROM interactions WHERE id = ?",
                (interaction_id,),
            ).fetchone()
            if not row:
                raise KeyError("interaction not found")
            item = _loads(row["payload"])
            item.update(kwargs)
            expires_at = int(item.get("expires_at") or row["expires_at"])
            conn.execute(
                "UPDATE interactions SET expires_at = ?, payload = ? WHERE id = ?",
                (expires_at, _dumps(item), interaction_id),
            )
        return item

    def delete_interaction(self, interaction_id: str) -> None:
        with self._tx() as conn:
            conn.execute("DELETE FROM interactions WHERE id = ?", (interaction_id,))

    # --- authorization codes ---
    def save_authorization_code(self, code_data: dict[str, Any]) -> dict[str, Any]:
        item = dict(code_data)
        raw = item.pop("code", None)
        if raw:
            item["code_hash"] = token_digest(str(raw))
        code_hash = str(item.get("code_hash") or "")
        if not code_hash:
            raise ValueError("authorization code is missing")
        client_id = str(item.get("client_id") or "")
        nonce = item.get("nonce") or None
        expires_at = int(item.get("expires_at") or 0)
        with self._tx() as conn:
            conn.execute(
                """
                INSERT INTO authorization_codes
                    (code_hash, client_id, user_id, nonce, expires_at, payload)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(code_hash) DO UPDATE SET
                    client_id = excluded.client_id,
                    user_id = excluded.user_id,
                    nonce = excluded.nonce,
                    expires_at = excluded.expires_at,
                    payload = excluded.payload
                """,
                (
                    code_hash,
                    client_id,
                    item.get("user_id"),
                    nonce,
                    expires_at,
                    _dumps(item),
                ),
            )
        if raw:
            item["code"] = raw
        return item

    def consume_authorization_code(self, code: str, client_id: str) -> tuple[dict[str, Any] | None, str]:
        """Take a code once. A second presentation revokes the token family."""
        digest = token_digest(code)
        with self._tx() as conn:
            row = conn.execute(
                """
                SELECT payload, expires_at FROM authorization_codes
                WHERE code_hash = ? AND client_id = ?
                """,
                (digest, client_id),
            ).fetchone()
            if row is None:
                used = conn.execute(
                    """
                    SELECT user_id, family_id, expires_at FROM used_codes
                    WHERE client_id = ? AND code_hash = ?
                    """,
                    (client_id, digest),
                ).fetchone()
                if used is None:
                    return None, "missing"
                self._kill_family(conn, str(used["family_id"] or ""))
                return {
                    "code_hash": digest,
                    "client_id": client_id,
                    "user_id": used["user_id"],
                    "family_id": used["family_id"],
                    "expires_at": int(used["expires_at"]),
                }, "replay"
            conn.execute(
                "DELETE FROM authorization_codes WHERE code_hash = ? AND client_id = ?",
                (digest, client_id),
            )
            if int(row["expires_at"]) <= _now():
                return None, "expired"
            found = _loads(row["payload"])
            family_id = f"{found.get('user_id')}:{found.get('client_id')}"
            epoch = self._epoch(conn, family_id)
            conn.execute(
                """
                INSERT INTO used_codes (code_hash, client_id, user_id, family_id, expires_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(client_id, code_hash) DO UPDATE SET
                    user_id = excluded.user_id,
                    family_id = excluded.family_id,
                    expires_at = excluded.expires_at
                """,
                (digest, client_id, found.get("user_id"), family_id, _now() + _USED_CODE_TTL),
            )
            found["code"] = code
            found["family_id"] = family_id
            found["family_gen"] = epoch
            return found, "ok"

    def get_authorization_code(self, code: str, client_id: str) -> dict[str, Any] | None:
        item, status = self.consume_authorization_code(code, client_id)
        if status != "ok":
            return None
        return item

    def delete_authorization_code(self, code: str) -> None:
        digest = token_digest(code)
        with self._tx() as conn:
            conn.execute("DELETE FROM authorization_codes WHERE code_hash = ?", (digest,))

    def nonce_exists(self, client_id: str, nonce: str) -> bool:
        with self._tx() as conn:
            row = conn.execute(
                """
                SELECT 1 FROM nonces WHERE client_id = ? AND nonce = ?
                UNION ALL
                SELECT 1 FROM authorization_codes WHERE client_id = ? AND nonce = ?
                LIMIT 1
                """,
                (client_id, nonce, client_id, nonce),
            ).fetchone()
        return row is not None

    def remember_nonce(self, client_id: str, nonce: str, expires_in: int) -> None:
        with self._tx() as conn:
            conn.execute(
                """
                INSERT INTO nonces (client_id, nonce, expires_at) VALUES (?, ?, ?)
                ON CONFLICT(client_id, nonce) DO UPDATE SET expires_at = excluded.expires_at
                """,
                (client_id, nonce, _now() + expires_in),
            )

    # --- tokens ---
    def save_token(self, token_data: dict[str, Any]) -> dict[str, Any]:
        item = dict(token_data)
        access = item.pop("access_token", None)
        refresh = item.pop("refresh_token", None)
        if access:
            item["access_token_hash"] = token_digest(str(access))
        if refresh:
            item["refresh_token_hash"] = token_digest(str(refresh))
        family_id = str(item.get("family_id") or "")
        with self._tx() as conn:
            epoch = self._epoch(conn, family_id)
            if item.get("family_gen") is None:
                item["family_gen"] = epoch
            else:
                item["family_gen"] = int(item["family_gen"])
            if item["family_gen"] != epoch:
                item["revoked"] = True
            conn.execute(
                """
                INSERT INTO tokens (
                    access_hash, refresh_hash, user_id, client_id, family_id,
                    family_gen, revoked, expires_at, refresh_expires_at, payload
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    item.get("access_token_hash"),
                    item.get("refresh_token_hash"),
                    item.get("user_id"),
                    str(item.get("client_id") or ""),
                    family_id or None,
                    int(item["family_gen"]),
                    1 if item.get("revoked") else 0,
                    int(item.get("expires_at") or 0),
                    item.get("refresh_token_expires_at"),
                    _dumps(item),
                ),
            )
        if access:
            item["access_token"] = access
        if refresh:
            item["refresh_token"] = refresh
        return item

    def get_token_by_access(self, access_token: str) -> dict[str, Any] | None:
        digest = token_digest(access_token)
        with self._tx() as conn:
            row = conn.execute(
                """
                SELECT * FROM tokens
                WHERE revoked = 0 AND access_hash = ?
                ORDER BY id
                LIMIT 1
                """,
                (digest,),
            ).fetchone()
        if not row:
            return None
        found = self._token_from_row(row)
        found["access_token"] = access_token
        return found

    def consume_refresh_token(self, refresh_token: str) -> tuple[dict[str, Any] | None, str]:
        """Rotate a refresh token. Reuse revokes the whole family."""
        digest = token_digest(refresh_token)
        with self._tx() as conn:
            row = conn.execute(
                """
                SELECT * FROM tokens
                WHERE refresh_hash = ?
                ORDER BY id
                LIMIT 1
                """,
                (digest,),
            ).fetchone()
            if not row:
                return None, "missing"
            family_id = str(row["family_id"] or "")
            epoch = self._epoch(conn, family_id)
            token_gen = int(row["family_gen"] or 0)
            expires = row["refresh_expires_at"]
            if expires and int(expires) <= _now():
                return None, "expired"
            if row["revoked"] or token_gen != epoch:
                self._kill_family(conn, family_id)
                found = self._token_from_row(row)
                found["revoked"] = True
                return found, "reuse"
            conn.execute("UPDATE tokens SET revoked = 1 WHERE id = ?", (row["id"],))
            result = self._token_from_row(row)
            result["revoked"] = False
            result["refresh_token"] = refresh_token
            result["family_gen"] = epoch
            return result, "ok"

    def get_token_by_refresh(self, refresh_token: str, include_revoked: bool = False) -> dict[str, Any] | None:
        digest = token_digest(refresh_token)
        revoked_sql = "" if include_revoked else "AND revoked = 0"
        with self._tx() as conn:
            row = conn.execute(
                f"""
                SELECT * FROM tokens
                WHERE refresh_hash = ? {revoked_sql}
                ORDER BY id
                LIMIT 1
                """,
                (digest,),
            ).fetchone()
        if not row:
            return None
        found = self._token_from_row(row)
        found["refresh_token"] = refresh_token
        return found

    def revoke_token(self, access_or_refresh: str, client_id: str) -> bool:
        digest = token_digest(access_or_refresh)
        with self._tx() as conn:
            cur = conn.execute(
                """
                UPDATE tokens SET revoked = 1
                WHERE (access_hash = ? OR refresh_hash = ?) AND client_id = ?
                """,
                (digest, digest, client_id),
            )
        return cur.rowcount > 0

    def mark_refresh_rotated(self, refresh_token: str) -> None:
        digest = token_digest(refresh_token)
        with self._tx() as conn:
            conn.execute(
                "UPDATE tokens SET revoked = 1 WHERE refresh_hash = ?",
                (digest,),
            )

    def revoke_user(self, user_id: str) -> None:
        with self._tx() as conn:
            families = [
                str(row["family_id"])
                for row in conn.execute(
                    """
                    SELECT DISTINCT family_id FROM tokens
                    WHERE user_id = ? AND family_id IS NOT NULL AND family_id != ''
                    """,
                    (user_id,),
                )
            ]
            conn.execute("UPDATE tokens SET revoked = 1 WHERE user_id = ?", (user_id,))
            for family_id in families:
                self._kill_family(conn, family_id)
            conn.execute("DELETE FROM authorization_codes WHERE user_id = ?", (user_id,))
            conn.execute("DELETE FROM session_tickets WHERE user_id = ?", (user_id,))

    def revoke_all_credentials(self) -> dict[str, int]:
        with self._tx() as conn:
            counts = {
                "tokens": self._count(conn, "tokens"),
                "authorization_codes": self._count(conn, "authorization_codes"),
                "interactions": self._count(conn, "interactions"),
                "nonces": self._count(conn, "nonces"),
            }
            for table in (
                "authorization_codes",
                "tokens",
                "interactions",
                "nonces",
                "session_tickets",
                "used_codes",
                "family_epochs",
            ):
                conn.execute(f"DELETE FROM {table}")
        return counts

    def _count(self, conn: sqlite3.Connection, table: str) -> int:
        row = conn.execute(f"SELECT COUNT(*) AS n FROM {table}").fetchone()
        return int(row["n"])

    def create_session_ticket(
        self,
        user_id: str,
        return_to: str,
        *,
        state: str,
        auth_version: int = 0,
        amr: list[str] | None = None,
        auth_at: int | None = None,
        expires_in: int = 120,
    ) -> str:
        raw = generate_id() + generate_id()
        item = {
            "ticket_hash": token_digest(raw),
            "user_id": user_id,
            "return_to": return_to,
            "state": state,
            "auth_version": int(auth_version),
            "amr": list(amr or ["pwd"]),
            "auth_at": int(auth_at or _now()),
            "expires_at": _now() + expires_in,
        }
        with self._tx() as conn:
            conn.execute(
                """
                INSERT INTO session_tickets (ticket_hash, user_id, expires_at, payload)
                VALUES (?, ?, ?, ?)
                """,
                (item["ticket_hash"], user_id, item["expires_at"], _dumps(item)),
            )
        return raw

    def consume_session_ticket(self, ticket: str) -> dict[str, Any] | None:
        digest = token_digest(ticket)
        with self._tx() as conn:
            row = conn.execute(
                "SELECT payload, expires_at FROM session_tickets WHERE ticket_hash = ?",
                (digest,),
            ).fetchone()
            if not row:
                return None
            conn.execute("DELETE FROM session_tickets WHERE ticket_hash = ?", (digest,))
            if int(row["expires_at"]) <= _now():
                return None
            return _loads(row["payload"])

    def login_attempt(self, limits: list[tuple[str, int]]) -> bool:
        """Reserve one attempt in every bucket, or none if any bucket is full.

        Check and record happen in one transaction, so parallel requests
        cannot all slip under the limit.
        """
        cutoff = _now() - _LOGIN_WINDOW
        with self._tx() as conn:
            for bucket, limit in limits:
                row = conn.execute(
                    "SELECT COUNT(*) AS n FROM login_hits WHERE bucket = ? AND at > ?",
                    (bucket, cutoff),
                ).fetchone()
                if int(row["n"]) >= limit:
                    return False
            conn.executemany(
                "INSERT INTO login_hits (bucket, at) VALUES (?, ?)",
                [(bucket, _now()) for bucket, _limit in limits],
            )
        return True

    def revoke_session(self, sid: str, expires_in: int) -> None:
        if not sid:
            return
        with self._tx() as conn:
            conn.execute(
                """
                INSERT INTO revoked_sessions (sid, expires_at) VALUES (?, ?)
                ON CONFLICT(sid) DO UPDATE SET expires_at = excluded.expires_at
                """,
                (sid, _now() + expires_in),
            )

    def session_revoked(self, sid: str) -> bool:
        with self._tx() as conn:
            row = conn.execute("SELECT 1 FROM revoked_sessions WHERE sid = ?", (sid,)).fetchone()
        return row is not None

    def login_success(self, bucket: str) -> None:
        with self._tx() as conn:
            conn.execute("DELETE FROM login_hits WHERE bucket = ?", (bucket,))

    def revoke_family(self, family_id: str) -> int:
        if not family_id:
            return 0
        with self._tx() as conn:
            before = self._epoch(conn, family_id)
            self._kill_family(conn, family_id)
            row = conn.execute(
                "SELECT COUNT(*) AS n FROM tokens WHERE family_id = ? AND revoked = 1",
                (family_id,),
            ).fetchone()
            after = self._epoch(conn, family_id)
        return int(row["n"]) if after != before else 0
