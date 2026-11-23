"""Storage-level tests for WebAuthn credentials and one-use challenges."""

from __future__ import annotations

import sqlite3

import pytest

from app.auth_store import AuthStore


class MutableClock:
    def __init__(self, value: float = 1_700_000_000) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: int) -> None:
        self.value += seconds


def _store(database_path, clock: MutableClock | None = None) -> AuthStore:
    return AuthStore(
        database_path,
        idle_timeout_seconds=600,
        absolute_timeout_seconds=3600,
        touch_interval_seconds=0,
        password_iterations=100_000,
        now=clock or MutableClock(),
    )


def _create_v1_database(database_path) -> None:
    with sqlite3.connect(database_path) as connection:
        connection.executescript(
            """
            PRAGMA foreign_keys = ON;
            CREATE TABLE auth_schema_migrations (
                version INTEGER PRIMARY KEY,
                applied_at INTEGER NOT NULL
            );
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
            INSERT INTO auth_schema_migrations(version, applied_at)
            VALUES (1, 1700000000);
            INSERT INTO users(
                username, role, password_hash, credential_version, is_active,
                is_demo, created_at, updated_at, password_changed_at
            ) VALUES (
                'existing.user', 'tier1', 'legacy-hash', 1, 1,
                0, 1700000000, 1700000000, 1700000000
            );
            INSERT INTO sessions(
                session_hash, username, credential_version, created_at,
                last_seen_at, expires_at, revoked_at, remember
            ) VALUES (
                'existing-session-hash', 'existing.user', 1, 1700000000,
                1700000000, 1700003600, NULL, 0
            );
            """
        )


def test_migration_v2_applies_without_losing_v1_users_or_sessions(tmp_path):
    database = tmp_path / "migration.sqlite3"
    _create_v1_database(database)

    store = _store(database)
    assert store.get_user("existing.user")["role"] == "tier1"
    store.close()

    with sqlite3.connect(database) as connection:
        versions = connection.execute(
            "SELECT version FROM auth_schema_migrations ORDER BY version"
        ).fetchall()
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        assert versions == [(1,), (2,)]
        assert connection.execute("SELECT COUNT(*) FROM users").fetchone() == (1,)
        assert connection.execute("SELECT COUNT(*) FROM sessions").fetchone() == (1,)
        assert {
            "webauthn_user_handles",
            "webauthn_credentials",
            "webauthn_challenges",
        } <= tables


def test_registration_challenge_is_session_bound_single_use_and_hashed(tmp_path):
    database = tmp_path / "challenge.sqlite3"
    store = _store(database)
    store.create_user("soc.admin", "persistent-password", "admin")
    session_id = store.create_session("soc.admin")

    challenge = store.create_webauthn_challenge(
        "registration",
        username="soc.admin",
        session_id=session_id,
    )
    with sqlite3.connect(database) as connection:
        stored = connection.execute(
            "SELECT challenge_hash, session_hash FROM webauthn_challenges"
        ).fetchone()
    assert stored is not None
    assert challenge not in stored
    assert session_id not in stored
    assert (
        store.get_challenge(
            challenge,
            "registration",
            username="soc.admin",
            session_id=session_id,
        )["username"]
        == "soc.admin"
    )

    consumed = store.consume_challenge(
        challenge,
        "registration",
        username="soc.admin",
        session_id=session_id,
    )
    assert consumed["username"] == "soc.admin"
    assert (
        store.get_challenge(
            challenge,
            "registration",
            username="soc.admin",
            session_id=session_id,
        )
        is None
    )
    assert (
        store.consume_challenge(
            challenge,
            "registration",
            username="soc.admin",
            session_id=session_id,
        )
        is None
    )
    store.close()


def test_challenge_expiry_is_strict_and_discoverable_login_can_omit_username(
    tmp_path,
):
    clock = MutableClock()
    store = _store(tmp_path / "expiry.sqlite3", clock)
    challenge = store.create_webauthn_challenge(
        "authentication",
        ttl_seconds=5,
    )

    clock.advance(5)
    assert store.consume_challenge(challenge, "authentication") is None

    fresh = store.create_webauthn_challenge("authentication")
    assert store.consume_challenge(fresh, "authentication")["username"] is None
    store.close()


def test_registration_challenge_rejects_a_different_or_revoked_session(tmp_path):
    store = _store(tmp_path / "binding.sqlite3")
    store.create_user("soc.admin", "persistent-password", "admin")
    store.create_user("soc.other", "persistent-password", "tier1")
    admin_session = store.create_session("soc.admin")
    other_session = store.create_session("soc.other")

    with pytest.raises(ValueError, match="does not match"):
        store.create_webauthn_challenge(
            "registration",
            username="soc.admin",
            session_id=other_session,
        )

    challenge = store.create_webauthn_challenge(
        "registration",
        username="soc.admin",
        session_id=admin_session,
    )
    store.revoke_session(admin_session)
    assert (
        store.consume_challenge(
            challenge,
            "registration",
            username="soc.admin",
            session_id=admin_session,
        )
        is None
    )
    store.close()


def test_credential_persists_metadata_and_counter_never_regresses(tmp_path):
    database = tmp_path / "credential.sqlite3"
    store = _store(database)
    store.create_user("soc.admin", "persistent-password", "admin")
    user_handle = store.get_or_create_webauthn_user_handle("soc.admin")
    assert len(user_handle) == 32
    assert store.get_or_create_webauthn_user_handle("soc.admin") == user_handle
    assert store.get_username_by_webauthn_user_handle(user_handle) == "soc.admin"

    created = store.store_credential(
        "credential-a",
        "soc.admin",
        b"cose-public-key",
        transports=["usb", "internal", "usb"],
        backup_eligible=True,
        device_label="Primary key",
    )
    assert created["transports"] == ["internal", "usb"]
    assert created["public_key"] == b"cose-public-key"

    zero_counter = store.update_sign_counter(
        "credential-a",
        0,
        backup_state=True,
    )
    assert zero_counter["backup_state"] is True
    assert store.update_sign_counter("credential-a", 7)["sign_count"] == 7
    with pytest.raises(ValueError, match="did not increase"):
        store.update_sign_counter("credential-a", 6)
    store.close()

    reopened = _store(database)
    assert reopened.get_credential("credential-a")["sign_count"] == 7
    reopened.close()


def test_credential_revocation_and_account_cascade(tmp_path):
    store = _store(tmp_path / "revocation.sqlite3")
    store.create_user("soc.admin", "persistent-password", "admin")
    session_id = store.create_session("soc.admin")
    challenge = store.create_webauthn_challenge(
        "registration",
        username="soc.admin",
        session_id=session_id,
    )
    store.store_credential("credential-a", "soc.admin", b"public-key-a")
    store.store_credential("credential-b", "soc.admin", b"public-key-b")

    assert store.revoke_credential("credential-a") is True
    assert store.get_credential("credential-a") is None
    assert len(store.list_credentials("soc.admin", include_revoked=True)) == 2

    store.set_password("soc.admin", "replacement-password")
    assert store.get_session(session_id) is None
    assert store.list_credentials("soc.admin") == []
    assert (
        store.consume_challenge(
            challenge,
            "registration",
            username="soc.admin",
            session_id=session_id,
        )
        is None
    )
    store.close()


def test_disabling_account_revokes_credentials(tmp_path):
    store = _store(tmp_path / "disabled.sqlite3")
    store.create_user("soc.admin", "persistent-password", "admin")
    user_handle = store.get_or_create_webauthn_user_handle("soc.admin")
    store.store_credential("credential-a", "soc.admin", b"public-key-a")

    store.set_active("soc.admin", False)
    assert store.get_credential("credential-a") is None
    assert store.get_username_by_webauthn_user_handle(user_handle) is None
    store.close()


def test_authentication_finalization_is_atomic_and_rejects_revoked_credential(
    tmp_path,
):
    store = _store(tmp_path / "finalize.sqlite3")
    store.create_user("soc.admin", "persistent-password", "admin")
    store.store_credential(
        "credential-a",
        "soc.admin",
        b"public-key-a",
    )
    challenge = store.create_webauthn_challenge("authentication")

    session_id = store.finalize_webauthn_authentication(
        challenge,
        "credential-a",
        1,
        backup_state=False,
        remember=True,
    )

    assert store.get_session(session_id)["username"] == "soc.admin"
    assert store.get_credential("credential-a")["sign_count"] == 1
    assert (
        store.finalize_webauthn_authentication(
            challenge,
            "credential-a",
            2,
            backup_state=False,
        )
        is None
    )

    rejected_challenge = store.create_webauthn_challenge("authentication")
    store.revoke_credential("credential-a")
    with pytest.raises(ValueError, match="does not exist"):
        store.finalize_webauthn_authentication(
            rejected_challenge,
            "credential-a",
            2,
            backup_state=False,
        )
    assert store.get_challenge(rejected_challenge, "authentication") is None
    store.close()
