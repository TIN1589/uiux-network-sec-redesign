"""Persistent user and session storage for the SOC dashboard.

The store deliberately keeps authentication primitives independent from FastAPI
so account recovery and operational tooling can use the same code without
importing the web application.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
import sqlite3
import threading
import time
from collections.abc import Callable, Iterable, Mapping
from pathlib import Path

ROLES = ("tier1", "tier2", "admin")
PASSWORD_SCHEME = "pbkdf2_sha256"
DEFAULT_PASSWORD_ITERATIONS = 600_000
_USERNAME_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{2,63}$")
def normalize_username(username: str) -> str:
    """Normalize and validate an operational account name."""
    normalized = username.strip().lower()
    if not _USERNAME_PATTERN.fullmatch(normalized):
        raise ValueError(
            "Username must be 3-64 characters using letters, numbers, '.', '_', or '-'."
        )
    return normalized


def validate_role(role: str) -> str:
    """Return a valid SOC role or raise a configuration error."""
    normalized = role.strip().lower()
    if normalized not in ROLES:
        raise ValueError(f"Role must be one of: {', '.join(ROLES)}")
    return normalized


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def hash_password(
    password: str,
    *,
    iterations: int = DEFAULT_PASSWORD_ITERATIONS,
    salt: bytes | None = None,
) -> str:
    """Hash a password with a unique salt using PBKDF2-HMAC-SHA256."""
    if len(password) < 12:
        raise ValueError("Password must contain at least 12 characters.")
    if iterations < 100_000:
        raise ValueError("PBKDF2 iterations must be at least 100000.")
    password_salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        password_salt,
        iterations,
    )
    return f"{PASSWORD_SCHEME}${iterations}${_b64encode(password_salt)}${_b64encode(digest)}"


def verify_password(password: str, encoded: str) -> bool:
    """Verify a password without exposing parsing failures or timing comparisons."""
    try:
        scheme, raw_iterations, raw_salt, raw_digest = encoded.split("$", 3)
        if scheme != PASSWORD_SCHEME:
            return False
        iterations = int(raw_iterations)
        if iterations < 100_000:
            return False
        expected = _b64decode(raw_digest)
        actual = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            _b64decode(raw_salt),
            iterations,
        )
        return hmac.compare_digest(actual, expected)
    except (TypeError, ValueError):
        return False


class AuthStore:
    """SQLite-backed users and revocable server-side sessions."""

    def __init__(
        self,
        database_path: str | Path,
        *,
        idle_timeout_seconds: int = 30 * 60,
        absolute_timeout_seconds: int = 8 * 60 * 60,
        touch_interval_seconds: int = 60,
        password_iterations: int = DEFAULT_PASSWORD_ITERATIONS,
        now: Callable[[], float] = time.time,
    ) -> None:
        if idle_timeout_seconds <= 0:
            raise ValueError("Session idle timeout must be positive.")
        if absolute_timeout_seconds < idle_timeout_seconds:
            raise ValueError("Absolute session timeout must not be shorter than idle timeout.")
        if touch_interval_seconds < 0:
            raise ValueError("Session touch interval must not be negative.")
        if password_iterations < 100_000:
            raise ValueError("PBKDF2 iterations must be at least 100000.")

        self.database_path = str(database_path).strip()
        if not self.database_path:
            raise ValueError("Authentication database path must not be empty.")
        self.idle_timeout_seconds = idle_timeout_seconds
        self.absolute_timeout_seconds = absolute_timeout_seconds
        self.touch_interval_seconds = touch_interval_seconds
        self.password_iterations = password_iterations
        self._now = now
        self._lock = threading.RLock()
        self._dummy_password_hash = hash_password(
            "invalid-account-password",
            iterations=password_iterations,
            salt=b"auth-dummy-salt!",
        )

        if self.database_path != ":memory:":
            Path(self.database_path).expanduser().resolve().parent.mkdir(
                parents=True,
                exist_ok=True,
            )

        self._connection = sqlite3.connect(
            self.database_path,
            check_same_thread=False,
        )
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._connection.execute("PRAGMA busy_timeout = 5000")
        if self.database_path != ":memory:":
            self._connection.execute("PRAGMA journal_mode = WAL")
        self._migrate()

    def close(self) -> None:
        """Close the SQLite connection."""
        with self._lock:
            self._connection.close()

    def _migrate(self) -> None:
        """Apply idempotent schema migrations inside one transaction."""
        with self._lock, self._connection:
            self._connection.execute(
                """
                CREATE TABLE IF NOT EXISTS auth_schema_migrations (
                    version INTEGER PRIMARY KEY,
                    applied_at INTEGER NOT NULL
                )
                """
            )
            applied = {
                row["version"]
                for row in self._connection.execute(
                    "SELECT version FROM auth_schema_migrations"
                )
            }
            if 1 not in applied:
                self._connection.executescript(
                    """
                    CREATE TABLE users (
                        username TEXT PRIMARY KEY COLLATE NOCASE,
                        role TEXT NOT NULL CHECK (role IN ('tier1', 'tier2', 'admin')),
                        password_hash TEXT NOT NULL,
                        credential_version INTEGER NOT NULL DEFAULT 1,
                        is_active INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
                        is_demo INTEGER NOT NULL DEFAULT 0 CHECK (is_demo IN (0, 1)),
                        created_at INTEGER NOT NULL,
                        updated_at INTEGER NOT NULL,
                        password_changed_at INTEGER NOT NULL
                    );

                    CREATE TABLE sessions (
                        session_hash TEXT PRIMARY KEY,
                        username TEXT NOT NULL,
                        credential_version INTEGER NOT NULL,
                        created_at INTEGER NOT NULL,
                        last_seen_at INTEGER NOT NULL,
                        expires_at INTEGER NOT NULL,
                        revoked_at INTEGER,
                        remember INTEGER NOT NULL DEFAULT 0 CHECK (remember IN (0, 1)),
                        FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
                    );

                    CREATE INDEX sessions_username_idx ON sessions(username);
                    CREATE INDEX sessions_expiry_idx ON sessions(expires_at, revoked_at);
                    """
                )
                self._connection.execute(
                    "INSERT INTO auth_schema_migrations(version, applied_at) VALUES (?, ?)",
                    (1, self._timestamp()),
                )

    def _timestamp(self) -> int:
        return int(self._now())

    @staticmethod
    def _session_hash(session_id: str) -> str:
        return hashlib.sha256(session_id.encode("utf-8")).hexdigest()

    def create_user(
        self,
        username: str,
        password: str,
        role: str,
        *,
        is_demo: bool = False,
    ) -> dict:
        """Create a user; existing usernames are rejected."""
        normalized = normalize_username(username)
        normalized_role = validate_role(role)
        password_hash = hash_password(
            password,
            iterations=self.password_iterations,
        )
        now = self._timestamp()
        try:
            with self._lock, self._connection:
                self._connection.execute(
                    """
                    INSERT INTO users(
                        username, role, password_hash, credential_version,
                        is_active, is_demo, created_at, updated_at, password_changed_at
                    ) VALUES (?, ?, ?, 1, 1, ?, ?, ?, ?)
                    """,
                    (normalized, normalized_role, password_hash, int(is_demo), now, now, now),
                )
        except sqlite3.IntegrityError as exc:
            raise ValueError(f"User '{normalized}' already exists.") from exc
        return self.get_user(normalized) or {}

    def ensure_demo_users(self, accounts: Mapping[str, Mapping[str, str]]) -> None:
        """Create or reset explicitly configured demo-only accounts."""
        for username, account in accounts.items():
            normalized = normalize_username(username)
            role = validate_role(account["role"])
            password_hash = hash_password(
                account["password"],
                iterations=self.password_iterations,
            )
            now = self._timestamp()
            with self._lock, self._connection:
                existing = self._connection.execute(
                    "SELECT password_hash, role, is_active, is_demo FROM users WHERE username = ?",
                    (normalized,),
                ).fetchone()
                if existing is None:
                    self._connection.execute(
                        """
                        INSERT INTO users(
                            username, role, password_hash, credential_version,
                            is_active, is_demo, created_at, updated_at, password_changed_at
                        ) VALUES (?, ?, ?, 1, 1, 1, ?, ?, ?)
                        """,
                        (normalized, role, password_hash, now, now, now),
                    )
                    continue
                changed = (
                    existing["role"] != role
                    or not existing["is_active"]
                    or not existing["is_demo"]
                    or not verify_password(account["password"], existing["password_hash"])
                )
                if changed:
                    self._connection.execute(
                        """
                        UPDATE users
                        SET role = ?, password_hash = ?, credential_version = credential_version + 1,
                            is_active = 1, is_demo = 1, updated_at = ?, password_changed_at = ?
                        WHERE username = ?
                        """,
                        (role, password_hash, now, now, normalized),
                    )
                    self._revoke_user_sessions_locked(normalized, now)

    def get_user(self, username: str) -> dict | None:
        """Return non-secret account metadata."""
        try:
            normalized = normalize_username(username)
        except ValueError:
            return None
        with self._lock:
            row = self._connection.execute(
                """
                SELECT username, role, credential_version, is_active, is_demo,
                       created_at, updated_at, password_changed_at
                FROM users WHERE username = ?
                """,
                (normalized,),
            ).fetchone()
        return dict(row) if row else None

    def list_users(self) -> list[dict]:
        """List accounts without returning password hashes."""
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT username, role, credential_version, is_active, is_demo,
                       created_at, updated_at, password_changed_at
                FROM users ORDER BY username
                """
            ).fetchall()
        return [dict(row) for row in rows]

    def authenticate_user(
        self,
        username: str,
        password: str,
        *,
        allow_demo: bool = False,
    ) -> dict | None:
        """Authenticate an active user, optionally allowing demo-only accounts."""
        try:
            normalized = normalize_username(username)
        except ValueError:
            normalized = ""
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM users WHERE username = ?",
                (normalized,),
            ).fetchone()

        encoded = row["password_hash"] if row else self._dummy_password_hash
        password_matches = verify_password(password, encoded)
        if (
            row is None
            or not password_matches
            or not row["is_active"]
            or (row["is_demo"] and not allow_demo)
        ):
            return None
        return {
            "username": row["username"],
            "role": row["role"],
            "is_demo": bool(row["is_demo"]),
        }

    def set_password(self, username: str, password: str) -> None:
        """Rotate a password and revoke every existing session for that user."""
        normalized = normalize_username(username)
        password_hash = hash_password(password, iterations=self.password_iterations)
        now = self._timestamp()
        with self._lock, self._connection:
            cursor = self._connection.execute(
                """
                UPDATE users
                SET password_hash = ?, credential_version = credential_version + 1,
                    updated_at = ?, password_changed_at = ?
                WHERE username = ?
                """,
                (password_hash, now, now, normalized),
            )
            if cursor.rowcount != 1:
                raise ValueError(f"User '{normalized}' does not exist.")
            self._revoke_user_sessions_locked(normalized, now)

    def set_role(self, username: str, role: str) -> None:
        """Change a user's role and revoke sessions carrying the old authorization."""
        normalized = normalize_username(username)
        normalized_role = validate_role(role)
        now = self._timestamp()
        with self._lock, self._connection:
            cursor = self._connection.execute(
                """
                UPDATE users
                SET role = ?, credential_version = credential_version + 1, updated_at = ?
                WHERE username = ?
                """,
                (normalized_role, now, normalized),
            )
            if cursor.rowcount != 1:
                raise ValueError(f"User '{normalized}' does not exist.")
            self._revoke_user_sessions_locked(normalized, now)

    def set_active(self, username: str, active: bool) -> None:
        """Enable or disable an account; disabling immediately revokes sessions."""
        normalized = normalize_username(username)
        now = self._timestamp()
        with self._lock, self._connection:
            cursor = self._connection.execute(
                """
                UPDATE users
                SET is_active = ?, credential_version = credential_version + 1, updated_at = ?
                WHERE username = ?
                """,
                (int(active), now, normalized),
            )
            if cursor.rowcount != 1:
                raise ValueError(f"User '{normalized}' does not exist.")
            self._revoke_user_sessions_locked(normalized, now)

    def create_session(self, username: str, *, remember: bool = False) -> str:
        """Create a random session and persist only its SHA-256 digest."""
        normalized = normalize_username(username)
        now = self._timestamp()
        session_id = secrets.token_urlsafe(32)
        with self._lock, self._connection:
            user = self._connection.execute(
                """
                SELECT credential_version FROM users
                WHERE username = ? AND is_active = 1
                """,
                (normalized,),
            ).fetchone()
            if user is None:
                raise ValueError(f"Active user '{normalized}' does not exist.")
            self._connection.execute(
                """
                INSERT INTO sessions(
                    session_hash, username, credential_version, created_at,
                    last_seen_at, expires_at, revoked_at, remember
                ) VALUES (?, ?, ?, ?, ?, ?, NULL, ?)
                """,
                (
                    self._session_hash(session_id),
                    normalized,
                    user["credential_version"],
                    now,
                    now,
                    now + self.absolute_timeout_seconds,
                    int(remember),
                ),
            )
        return session_id

    def get_session(self, session_id: str | None) -> dict | None:
        """Return a live session and enforce idle, absolute, and credential expiry."""
        if not session_id:
            return None
        now = self._timestamp()
        session_hash = self._session_hash(session_id)
        with self._lock, self._connection:
            row = self._connection.execute(
                """
                SELECT s.username, s.credential_version, s.created_at, s.last_seen_at,
                       s.expires_at, s.revoked_at, s.remember,
                       u.role, u.credential_version AS user_credential_version,
                       u.is_active
                FROM sessions AS s
                JOIN users AS u ON u.username = s.username
                WHERE s.session_hash = ?
                """,
                (session_hash,),
            ).fetchone()
            if row is None:
                return None

            expired = (
                row["revoked_at"] is not None
                or not row["is_active"]
                or row["credential_version"] != row["user_credential_version"]
                or now >= row["expires_at"]
                or now - row["last_seen_at"] >= self.idle_timeout_seconds
            )
            if expired:
                if row["revoked_at"] is None:
                    self._connection.execute(
                        "UPDATE sessions SET revoked_at = ? WHERE session_hash = ?",
                        (now, session_hash),
                    )
                return None

            if now - row["last_seen_at"] >= self.touch_interval_seconds:
                self._connection.execute(
                    "UPDATE sessions SET last_seen_at = ? WHERE session_hash = ?",
                    (now, session_hash),
                )
            return {
                "username": row["username"],
                "role": row["role"],
                "created_at": row["created_at"],
                "expires_at": row["expires_at"],
                "remember": bool(row["remember"]),
            }

    def revoke_session(self, session_id: str | None) -> bool:
        """Revoke one server-side session."""
        if not session_id:
            return False
        now = self._timestamp()
        with self._lock, self._connection:
            cursor = self._connection.execute(
                """
                UPDATE sessions SET revoked_at = ?
                WHERE session_hash = ? AND revoked_at IS NULL
                """,
                (now, self._session_hash(session_id)),
            )
        return cursor.rowcount == 1

    def _revoke_user_sessions_locked(self, username: str, now: int) -> int:
        cursor = self._connection.execute(
            """
            UPDATE sessions SET revoked_at = ?
            WHERE username = ? AND revoked_at IS NULL
            """,
            (now, username),
        )
        return cursor.rowcount

    def revoke_user_sessions(self, username: str) -> int:
        """Revoke every current session for an account."""
        normalized = normalize_username(username)
        with self._lock, self._connection:
            return self._revoke_user_sessions_locked(normalized, self._timestamp())

    def cleanup_sessions(self) -> int:
        """Delete expired or revoked session records."""
        now = self._timestamp()
        with self._lock, self._connection:
            cursor = self._connection.execute(
                """
                DELETE FROM sessions
                WHERE revoked_at IS NOT NULL OR expires_at <= ?
                   OR last_seen_at <= ?
                """,
                (now, now - self.idle_timeout_seconds),
            )
        return cursor.rowcount

    def seed_users(self, users: Iterable[tuple[str, str, str]]) -> None:
        """Create a set of non-demo users; intended for controlled provisioning."""
        for username, password, role in users:
            self.create_user(username, password, role)
