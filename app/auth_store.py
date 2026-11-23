"""Persistent user and session storage for the SOC dashboard.

The store deliberately keeps authentication primitives independent from FastAPI
so account recovery and operational tooling can use the same code without
importing the web application.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
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
WEBAUTHN_CHALLENGE_TTL_SECONDS = 5 * 60
WEBAUTHN_PURPOSES = ("registration", "authentication")
_MAX_WEBAUTHN_SIGN_COUNT = (1 << 32) - 1
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


def _validate_webauthn_purpose(purpose: str) -> str:
    normalized = purpose.strip().lower()
    if normalized not in WEBAUTHN_PURPOSES:
        raise ValueError(
            f"WebAuthn purpose must be one of: {', '.join(WEBAUTHN_PURPOSES)}"
        )
    return normalized


def _validate_sign_count(sign_count: int) -> int:
    if not isinstance(sign_count, int) or isinstance(sign_count, bool):
        raise TypeError("WebAuthn sign count must be an integer.")
    if not 0 <= sign_count <= _MAX_WEBAUTHN_SIGN_COUNT:
        raise ValueError("WebAuthn sign count must be an unsigned 32-bit integer.")
    return sign_count


def _normalize_credential_id(credential_id: str) -> str:
    normalized = credential_id.strip()
    if not normalized or len(normalized) > 2048:
        raise ValueError("WebAuthn credential ID must contain 1-2048 characters.")
    return normalized


def _serialize_transports(transports: Iterable[str] | None) -> str:
    normalized: set[str] = set()
    for transport in transports or ():
        value = transport.strip().lower()
        if not value or len(value) > 32:
            raise ValueError("WebAuthn transports must contain 1-32 characters.")
        normalized.add(value)
    return json.dumps(sorted(normalized), separators=(",", ":"))


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
            raise ValueError(
                "Absolute session timeout must not be shorter than idle timeout."
            )
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
            if 2 not in applied:
                self._connection.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS webauthn_user_handles (
                        username TEXT PRIMARY KEY COLLATE NOCASE,
                        user_handle BLOB NOT NULL UNIQUE,
                        created_at INTEGER NOT NULL,
                        FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
                    );

                    CREATE TABLE IF NOT EXISTS webauthn_credentials (
                        credential_id TEXT PRIMARY KEY,
                        username TEXT NOT NULL COLLATE NOCASE,
                        public_key BLOB NOT NULL,
                        sign_count INTEGER NOT NULL DEFAULT 0
                            CHECK (sign_count BETWEEN 0 AND 4294967295),
                        transports TEXT NOT NULL DEFAULT '[]',
                        backup_state INTEGER NOT NULL DEFAULT 0
                            CHECK (backup_state IN (0, 1)),
                        backup_eligible INTEGER NOT NULL DEFAULT 0
                            CHECK (backup_eligible IN (0, 1)),
                        device_label TEXT,
                        created_at INTEGER NOT NULL,
                        last_used_at INTEGER,
                        revoked_at INTEGER,
                        CHECK (backup_eligible = 1 OR backup_state = 0),
                        FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
                    );

                    CREATE INDEX IF NOT EXISTS webauthn_credentials_username_idx
                        ON webauthn_credentials(username);
                    CREATE INDEX IF NOT EXISTS webauthn_credentials_revoked_idx
                        ON webauthn_credentials(revoked_at);

                    CREATE TABLE IF NOT EXISTS webauthn_challenges (
                        challenge_hash TEXT PRIMARY KEY,
                        username TEXT COLLATE NOCASE,
                        session_hash TEXT,
                        purpose TEXT NOT NULL
                            CHECK (purpose IN ('registration', 'authentication')),
                        created_at INTEGER NOT NULL,
                        expires_at INTEGER NOT NULL,
                        consumed_at INTEGER,
                        CHECK (length(challenge_hash) = 64),
                        CHECK (expires_at > created_at),
                        CHECK (
                            (purpose = 'registration' AND username IS NOT NULL
                                AND session_hash IS NOT NULL)
                            OR
                            (purpose = 'authentication' AND session_hash IS NULL)
                        ),
                        FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
                    );

                    CREATE INDEX IF NOT EXISTS webauthn_challenges_lookup_idx
                        ON webauthn_challenges(purpose, expires_at, consumed_at);
                    CREATE INDEX IF NOT EXISTS webauthn_challenges_user_idx
                        ON webauthn_challenges(username);
                    """
                )
                self._connection.execute(
                    "INSERT INTO auth_schema_migrations(version, applied_at) VALUES (?, ?)",
                    (2, self._timestamp()),
                )

    def _timestamp(self) -> int:
        return int(self._now())

    @staticmethod
    def _session_hash(session_id: str) -> str:
        return hashlib.sha256(session_id.encode("utf-8")).hexdigest()

    @staticmethod
    def _challenge_hash(challenge_token: str) -> str:
        return hashlib.sha256(challenge_token.encode("ascii")).hexdigest()

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
                    (
                        normalized,
                        normalized_role,
                        password_hash,
                        int(is_demo),
                        now,
                        now,
                        now,
                    ),
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
                    or not verify_password(
                        account["password"], existing["password_hash"]
                    )
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
                    self._revoke_user_webauthn_locked(normalized, now)

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
        """Reset a password and revoke the user's sessions and WebAuthn state."""
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
            self._revoke_user_webauthn_locked(normalized, now)

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
        """Enable or disable an account; disabling revokes all authenticators."""
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
            if not active:
                self._revoke_user_webauthn_locked(normalized, now)

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

    def get_or_create_webauthn_user_handle(self, username: str) -> bytes:
        """Return a stable opaque WebAuthn user handle for an active account."""
        normalized = normalize_username(username)
        with self._lock, self._connection:
            user = self._connection.execute(
                "SELECT is_active FROM users WHERE username = ?",
                (normalized,),
            ).fetchone()
            if user is None or not user["is_active"]:
                raise ValueError(f"Active user '{normalized}' does not exist.")

            existing = self._connection.execute(
                "SELECT user_handle FROM webauthn_user_handles WHERE username = ?",
                (normalized,),
            ).fetchone()
            if existing is not None:
                return bytes(existing["user_handle"])

            for _ in range(3):
                user_handle = secrets.token_bytes(32)
                try:
                    self._connection.execute(
                        """
                        INSERT INTO webauthn_user_handles(username, user_handle, created_at)
                        VALUES (?, ?, ?)
                        """,
                        (normalized, sqlite3.Binary(user_handle), self._timestamp()),
                    )
                    return user_handle
                except sqlite3.IntegrityError:
                    existing = self._connection.execute(
                        "SELECT user_handle FROM webauthn_user_handles WHERE username = ?",
                        (normalized,),
                    ).fetchone()
                    if existing is not None:
                        return bytes(existing["user_handle"])
            raise RuntimeError("Unable to allocate a unique WebAuthn user handle.")

    def get_username_by_webauthn_user_handle(self, user_handle: bytes) -> str | None:
        """Resolve an opaque WebAuthn user handle without exposing account secrets."""
        if not user_handle:
            return None
        with self._lock:
            row = self._connection.execute(
                """
                SELECT h.username
                FROM webauthn_user_handles AS h
                JOIN users AS u ON u.username = h.username
                WHERE h.user_handle = ? AND u.is_active = 1
                """,
                (sqlite3.Binary(bytes(user_handle)),),
            ).fetchone()
        return row["username"] if row else None

    def create_webauthn_challenge(
        self,
        purpose: str,
        *,
        username: str | None = None,
        session_id: str | None = None,
        ttl_seconds: int = WEBAUTHN_CHALLENGE_TTL_SECONDS,
    ) -> str:
        """Create a one-use challenge and persist only its SHA-256 digest."""
        normalized_purpose = _validate_webauthn_purpose(purpose)
        if not isinstance(ttl_seconds, int) or isinstance(ttl_seconds, bool):
            raise TypeError("WebAuthn challenge TTL must be an integer.")
        if not 1 <= ttl_seconds <= 60 * 60:
            raise ValueError(
                "WebAuthn challenge TTL must be between 1 and 3600 seconds."
            )

        normalized_username = normalize_username(username) if username else None
        session_hash = None
        if normalized_purpose == "registration":
            if normalized_username is None or not session_id:
                raise ValueError(
                    "Registration challenges require both a username and active session."
                )
            session = self.get_session(session_id)
            if session is None or session["username"] != normalized_username:
                raise ValueError(
                    "Registration challenge session does not match the user."
                )
            session_hash = self._session_hash(session_id)
        elif session_id is not None:
            raise ValueError("Authentication challenges must not be session-bound.")

        now = self._timestamp()
        with self._lock, self._connection:
            if normalized_username is not None:
                user = self._connection.execute(
                    "SELECT is_active FROM users WHERE username = ?",
                    (normalized_username,),
                ).fetchone()
                if user is None or not user["is_active"]:
                    raise ValueError(
                        f"Active user '{normalized_username}' does not exist."
                    )

            for _ in range(3):
                challenge_token = _b64encode(secrets.token_bytes(32))
                try:
                    self._connection.execute(
                        """
                        INSERT INTO webauthn_challenges(
                            challenge_hash, username, session_hash, purpose,
                            created_at, expires_at, consumed_at
                        ) VALUES (?, ?, ?, ?, ?, ?, NULL)
                        """,
                        (
                            self._challenge_hash(challenge_token),
                            normalized_username,
                            session_hash,
                            normalized_purpose,
                            now,
                            now + ttl_seconds,
                        ),
                    )
                    return challenge_token
                except sqlite3.IntegrityError:
                    continue
        raise RuntimeError("Unable to allocate a unique WebAuthn challenge.")

    def consume_challenge(
        self,
        challenge_token: str,
        purpose: str,
        *,
        username: str | None = None,
        session_id: str | None = None,
    ) -> dict | None:
        """Atomically consume a live challenge, rejecting replay and mismatched binding."""
        normalized_purpose = _validate_webauthn_purpose(purpose)
        normalized_username = normalize_username(username) if username else None
        session_hash = None
        if normalized_purpose == "registration":
            if normalized_username is None or not session_id:
                raise ValueError(
                    "Registration challenge consumption requires username and session."
                )
            session = self.get_session(session_id)
            if session is None or session["username"] != normalized_username:
                return None
            session_hash = self._session_hash(session_id)
        elif session_id is not None:
            raise ValueError("Authentication challenges must not be session-bound.")

        try:
            challenge_hash = self._challenge_hash(challenge_token)
        except (AttributeError, UnicodeEncodeError):
            return None

        now = self._timestamp()
        conditions = [
            "challenge_hash = ?",
            "purpose = ?",
            "consumed_at IS NULL",
            "expires_at > ?",
        ]
        parameters: list[object] = [challenge_hash, normalized_purpose, now]
        if normalized_username is not None:
            conditions.append("username = ?")
            parameters.append(normalized_username)
        if normalized_purpose == "registration":
            conditions.append("session_hash = ?")
            parameters.append(session_hash)

        with self._lock, self._connection:
            cursor = self._connection.execute(
                f"UPDATE webauthn_challenges SET consumed_at = ? "
                f"WHERE {' AND '.join(conditions)}",
                (now, *parameters),
            )
            if cursor.rowcount != 1:
                return None
            row = self._connection.execute(
                """
                SELECT username, purpose, created_at, expires_at, consumed_at
                FROM webauthn_challenges WHERE challenge_hash = ?
                """,
                (challenge_hash,),
            ).fetchone()
        return dict(row) if row else None

    def get_challenge(
        self,
        challenge_token: str,
        purpose: str,
        *,
        username: str | None = None,
        session_id: str | None = None,
    ) -> dict | None:
        """Return a live challenge without consuming it after checking its binding."""
        normalized_purpose = _validate_webauthn_purpose(purpose)
        normalized_username = normalize_username(username) if username else None
        session_hash = None
        if normalized_purpose == "registration":
            if normalized_username is None or not session_id:
                raise ValueError(
                    "Registration challenge lookup requires username and session."
                )
            session = self.get_session(session_id)
            if session is None or session["username"] != normalized_username:
                return None
            session_hash = self._session_hash(session_id)
        elif session_id is not None:
            raise ValueError("Authentication challenges must not be session-bound.")

        try:
            challenge_hash = self._challenge_hash(challenge_token)
        except (AttributeError, UnicodeEncodeError):
            return None

        conditions = [
            "challenge_hash = ?",
            "purpose = ?",
            "consumed_at IS NULL",
            "expires_at > ?",
        ]
        parameters: list[object] = [
            challenge_hash,
            normalized_purpose,
            self._timestamp(),
        ]
        if normalized_username is not None:
            conditions.append("username = ?")
            parameters.append(normalized_username)
        if normalized_purpose == "registration":
            conditions.append("session_hash = ?")
            parameters.append(session_hash)

        with self._lock:
            row = self._connection.execute(
                "SELECT username, purpose, created_at, expires_at, consumed_at "
                f"FROM webauthn_challenges WHERE {' AND '.join(conditions)}",
                parameters,
            ).fetchone()
        return dict(row) if row else None

    def cleanup_webauthn_challenges(self) -> int:
        """Delete expired or consumed challenge records."""
        now = self._timestamp()
        with self._lock, self._connection:
            cursor = self._connection.execute(
                """
                DELETE FROM webauthn_challenges
                WHERE consumed_at IS NOT NULL OR expires_at <= ?
                """,
                (now,),
            )
        return cursor.rowcount

    @staticmethod
    def _credential_from_row(row: sqlite3.Row) -> dict:
        credential = dict(row)
        credential["public_key"] = bytes(credential["public_key"])
        credential["transports"] = json.loads(credential["transports"])
        credential["backup_state"] = bool(credential["backup_state"])
        credential["backup_eligible"] = bool(credential["backup_eligible"])
        return credential

    def store_credential(
        self,
        credential_id: str,
        username: str,
        public_key: bytes,
        *,
        sign_count: int = 0,
        transports: Iterable[str] | None = None,
        backup_state: bool = False,
        backup_eligible: bool = False,
        device_label: str | None = None,
    ) -> dict:
        """Persist a verified WebAuthn credential for an active account."""
        normalized_id = _normalize_credential_id(credential_id)
        normalized_username = normalize_username(username)
        normalized_count = _validate_sign_count(sign_count)
        public_key_bytes = bytes(public_key)
        if not public_key_bytes:
            raise ValueError("WebAuthn public key must not be empty.")
        if backup_state and not backup_eligible:
            raise ValueError("A backed-up credential must be backup eligible.")
        normalized_label = device_label.strip() if device_label else None
        if normalized_label and len(normalized_label) > 128:
            raise ValueError("WebAuthn device label must not exceed 128 characters.")

        self.get_or_create_webauthn_user_handle(normalized_username)
        now = self._timestamp()
        try:
            with self._lock, self._connection:
                self._connection.execute(
                    """
                    INSERT INTO webauthn_credentials(
                        credential_id, username, public_key, sign_count, transports,
                        backup_state, backup_eligible, device_label, created_at,
                        last_used_at, revoked_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL)
                    """,
                    (
                        normalized_id,
                        normalized_username,
                        sqlite3.Binary(public_key_bytes),
                        normalized_count,
                        _serialize_transports(transports),
                        int(backup_state),
                        int(backup_eligible),
                        normalized_label,
                        now,
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise ValueError("WebAuthn credential ID is already registered.") from exc
        return self.get_credential(normalized_id) or {}

    def get_credential(
        self,
        credential_id: str,
        *,
        include_revoked: bool = False,
    ) -> dict | None:
        """Return a WebAuthn credential by ID, excluding revoked rows by default."""
        normalized_id = _normalize_credential_id(credential_id)
        query = "SELECT * FROM webauthn_credentials WHERE credential_id = ?"
        if not include_revoked:
            query += " AND revoked_at IS NULL"
        with self._lock:
            row = self._connection.execute(query, (normalized_id,)).fetchone()
        return self._credential_from_row(row) if row else None

    def list_credentials(
        self,
        username: str,
        *,
        include_revoked: bool = False,
    ) -> list[dict]:
        """List credentials for one account, excluding revoked rows by default."""
        normalized = normalize_username(username)
        query = "SELECT * FROM webauthn_credentials WHERE username = ?"
        if not include_revoked:
            query += " AND revoked_at IS NULL"
        query += " ORDER BY created_at, credential_id"
        with self._lock:
            rows = self._connection.execute(query, (normalized,)).fetchall()
        return [self._credential_from_row(row) for row in rows]

    def update_sign_counter(
        self,
        credential_id: str,
        sign_count: int,
        *,
        backup_state: bool | None = None,
    ) -> dict:
        """Advance a credential counter while allowing the unsupported 0-to-0 case."""
        normalized_id = _normalize_credential_id(credential_id)
        normalized_count = _validate_sign_count(sign_count)
        now = self._timestamp()
        with self._lock, self._connection:
            current = self._connection.execute(
                """
                SELECT sign_count, backup_eligible
                FROM webauthn_credentials
                WHERE credential_id = ? AND revoked_at IS NULL
                """,
                (normalized_id,),
            ).fetchone()
            if current is None:
                raise ValueError("Active WebAuthn credential does not exist.")
            if (
                not (current["sign_count"] == 0 and normalized_count == 0)
                and normalized_count <= current["sign_count"]
            ):
                raise ValueError(
                    "WebAuthn sign count did not increase; possible cloned credential."
                )
            if backup_state and not current["backup_eligible"]:
                raise ValueError(
                    "A non-backup-eligible credential cannot be backed up."
                )

            new_backup_state = int(backup_state) if backup_state is not None else None
            cursor = self._connection.execute(
                """
                UPDATE webauthn_credentials
                SET sign_count = ?,
                    backup_state = COALESCE(?, backup_state),
                    last_used_at = ?
                WHERE credential_id = ? AND revoked_at IS NULL AND sign_count = ?
                """,
                (
                    normalized_count,
                    new_backup_state,
                    now,
                    normalized_id,
                    current["sign_count"],
                ),
            )
            if cursor.rowcount != 1:
                raise RuntimeError(
                    "WebAuthn credential changed concurrently; retry verification."
                )
        return self.get_credential(normalized_id) or {}

    def finalize_webauthn_authentication(
        self,
        challenge_token: str,
        credential_id: str,
        sign_count: int,
        *,
        backup_state: bool,
        remember: bool = False,
    ) -> str | None:
        """Atomically consume an assertion, update its credential, and start a session."""
        normalized_id = _normalize_credential_id(credential_id)
        normalized_count = _validate_sign_count(sign_count)
        try:
            challenge_hash = self._challenge_hash(challenge_token)
        except (AttributeError, UnicodeEncodeError):
            return None

        now = self._timestamp()
        session_id = secrets.token_urlsafe(32)
        failure: str | None = None
        with self._lock, self._connection:
            challenge_cursor = self._connection.execute(
                """
                UPDATE webauthn_challenges SET consumed_at = ?
                WHERE challenge_hash = ? AND purpose = 'authentication'
                  AND consumed_at IS NULL AND expires_at > ?
                """,
                (now, challenge_hash, now),
            )
            if challenge_cursor.rowcount != 1:
                return None

            current = self._connection.execute(
                """
                SELECT c.username, c.sign_count, c.backup_eligible,
                       u.credential_version
                FROM webauthn_credentials AS c
                JOIN users AS u ON u.username = c.username
                WHERE c.credential_id = ? AND c.revoked_at IS NULL
                  AND u.is_active = 1
                """,
                (normalized_id,),
            ).fetchone()
            if current is None:
                failure = "Active WebAuthn credential does not exist."
            elif (
                not (current["sign_count"] == 0 and normalized_count == 0)
                and normalized_count <= current["sign_count"]
            ):
                failure = (
                    "WebAuthn sign count did not increase; possible cloned credential."
                )
            elif backup_state and not current["backup_eligible"]:
                failure = "A non-backup-eligible credential cannot be backed up."
            else:
                credential_cursor = self._connection.execute(
                    """
                    UPDATE webauthn_credentials
                    SET sign_count = ?, backup_state = ?, last_used_at = ?
                    WHERE credential_id = ? AND revoked_at IS NULL
                      AND sign_count = ?
                    """,
                    (
                        normalized_count,
                        int(backup_state),
                        now,
                        normalized_id,
                        current["sign_count"],
                    ),
                )
                if credential_cursor.rowcount != 1:
                    failure = "WebAuthn credential changed concurrently."
                else:
                    self._connection.execute(
                        """
                        INSERT INTO sessions(
                            session_hash, username, credential_version, created_at,
                            last_seen_at, expires_at, revoked_at, remember
                        ) VALUES (?, ?, ?, ?, ?, ?, NULL, ?)
                        """,
                        (
                            self._session_hash(session_id),
                            current["username"],
                            current["credential_version"],
                            now,
                            now,
                            now + self.absolute_timeout_seconds,
                            int(remember),
                        ),
                    )
        if failure is not None:
            raise ValueError(failure)
        return session_id

    def revoke_credential(self, credential_id: str) -> bool:
        """Revoke one active WebAuthn credential."""
        normalized_id = _normalize_credential_id(credential_id)
        with self._lock, self._connection:
            cursor = self._connection.execute(
                """
                UPDATE webauthn_credentials SET revoked_at = ?
                WHERE credential_id = ? AND revoked_at IS NULL
                """,
                (self._timestamp(), normalized_id),
            )
        return cursor.rowcount == 1

    def _revoke_user_webauthn_locked(self, username: str, now: int) -> int:
        cursor = self._connection.execute(
            """
            UPDATE webauthn_credentials SET revoked_at = ?
            WHERE username = ? AND revoked_at IS NULL
            """,
            (now, username),
        )
        self._connection.execute(
            """
            UPDATE webauthn_challenges SET consumed_at = ?
            WHERE username = ? AND consumed_at IS NULL
            """,
            (now, username),
        )
        return cursor.rowcount

    def revoke_all_user_credentials(self, username: str) -> int:
        """Revoke every active credential and outstanding challenge for an account."""
        normalized = normalize_username(username)
        with self._lock, self._connection:
            return self._revoke_user_webauthn_locked(
                normalized,
                self._timestamp(),
            )

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
