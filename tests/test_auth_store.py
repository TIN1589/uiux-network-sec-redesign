"""Persistence, timeout, and credential lifecycle tests for server-side auth."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

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
        idle_timeout_seconds=10,
        absolute_timeout_seconds=100,
        touch_interval_seconds=0,
        password_iterations=100_000,
        now=clock or MutableClock(),
    )


def test_users_and_sessions_survive_store_restart_without_plaintext_secrets(tmp_path):
    database = tmp_path / "auth.sqlite3"
    password = "persistent-password-2026"
    first = _store(database)
    first.create_user("soc.admin", password, "admin")
    session_id = first.create_session("soc.admin", remember=True)
    first.close()

    database_bytes = database.read_bytes()
    assert password.encode() not in database_bytes
    assert session_id.encode() not in database_bytes

    second = _store(database)
    assert second.authenticate_user("soc.admin", password) == {
        "username": "soc.admin",
        "role": "admin",
        "is_demo": False,
    }
    assert second.get_session(session_id)["username"] == "soc.admin"
    second.close()


def test_session_idle_timeout_is_enforced_server_side(tmp_path):
    clock = MutableClock()
    store = _store(tmp_path / "idle.sqlite3", clock)
    store.create_user("tier.one", "tier-one-password", "tier1")
    session_id = store.create_session("tier.one")

    clock.advance(9)
    assert store.get_session(session_id) is not None
    clock.advance(10)
    assert store.get_session(session_id) is None
    store.close()


def test_absolute_timeout_cannot_be_extended_by_activity(tmp_path):
    clock = MutableClock()
    store = _store(tmp_path / "absolute.sqlite3", clock)
    store.create_user("tier.two", "tier-two-password", "tier2")
    session_id = store.create_session("tier.two")

    for _ in range(11):
        clock.advance(9)
        assert store.get_session(session_id) is not None
    clock.advance(1)
    assert store.get_session(session_id) is None
    store.close()


def test_password_reset_revokes_sessions_and_rotates_credentials(tmp_path):
    store = _store(tmp_path / "reset.sqlite3")
    old_password = "old-password-2026"
    new_password = "new-password-2026"
    store.create_user("recover.me", old_password, "admin")
    session_id = store.create_session("recover.me")

    store.set_password("recover.me", new_password)

    assert store.get_session(session_id) is None
    assert store.authenticate_user("recover.me", old_password) is None
    assert store.authenticate_user("recover.me", new_password) is not None
    store.close()


def test_role_change_and_account_disable_revoke_authorization(tmp_path):
    store = _store(tmp_path / "lifecycle.sqlite3")
    store.create_user("analyst.one", "analyst-password", "tier1")
    first_session = store.create_session("analyst.one")

    store.set_role("analyst.one", "tier2")
    assert store.get_session(first_session) is None
    second_session = store.create_session("analyst.one")
    assert store.get_session(second_session)["role"] == "tier2"

    store.set_active("analyst.one", False)
    assert store.get_session(second_session) is None
    assert store.authenticate_user("analyst.one", "analyst-password") is None
    store.close()


def test_demo_accounts_require_explicit_demo_authorization(tmp_path):
    store = _store(tmp_path / "demo.sqlite3")
    store.ensure_demo_users(
        {
            "admin": {
                "role": "admin",
                "password": "vnpt-soc-2026",
                "label": "SecOps Admin",
            }
        }
    )

    assert store.authenticate_user("admin", "vnpt-soc-2026", allow_demo=False) is None
    assert store.authenticate_user("admin", "vnpt-soc-2026", allow_demo=True) == {
        "username": "admin",
        "role": "admin",
        "is_demo": True,
    }
    store.close()


def test_account_cli_does_not_boot_web_app_or_require_web_secret(tmp_path):
    """Recovery tooling remains usable when the web process cannot start."""
    env = os.environ.copy()
    env["ENV"] = "production"
    env["DEMO_MODE"] = "false"
    env.pop("AUTH_SECRET_KEY", None)
    result = subprocess.run(
        [
            sys.executable,
            "scripts/manage_auth.py",
            "--db",
            str(tmp_path / "cli.sqlite3"),
            "list",
        ],
        cwd=Path(__file__).resolve().parents[1],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert "USERNAME\tROLE\tACTIVE" in result.stdout
    assert "AUTH_SECRET_KEY" not in result.stderr
