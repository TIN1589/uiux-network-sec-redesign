"""Operator CLI for provisioning and recovering SOC dashboard accounts."""

from __future__ import annotations

import argparse
import getpass
import os
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from app.auth_store import DEFAULT_PASSWORD_ITERATIONS, ROLES, AuthStore


def _positive_env_int(name: str, default: int, minimum: int) -> int:
    raw_value = os.getenv(name, str(default))
    try:
        value = int(raw_value)
    except ValueError as exc:
        raise SystemExit(f"{name} must be an integer.") from exc
    if value < minimum:
        raise SystemExit(f"{name} must be at least {minimum}.")
    return value


def _database_path(cli_value: str | None) -> str:
    return cli_value or os.getenv(
        "AUTH_DB_PATH",
        str(ROOT_DIR / "data" / "auth.sqlite3"),
    )


def _read_new_password() -> str:
    password = getpass.getpass("New password: ")
    confirmation = getpass.getpass("Confirm password: ")
    if password != confirmation:
        raise SystemExit("Passwords do not match.")
    return password


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Manage persistent users and sessions without exposing passwords in argv.",
    )
    parser.add_argument(
        "--db",
        help="SQLite path (defaults to AUTH_DB_PATH or data/auth.sqlite3).",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    create = commands.add_parser("create", help="Create a non-demo account.")
    create.add_argument("username")
    create.add_argument("--role", choices=ROLES, required=True)

    reset = commands.add_parser(
        "reset-password",
        help="Set a new password and revoke sessions and passkeys for the account.",
    )
    reset.add_argument("username")

    set_role = commands.add_parser(
        "set-role",
        help="Change role and revoke every session for the account.",
    )
    set_role.add_argument("username")
    set_role.add_argument("role", choices=ROLES)

    for command, help_text in (
        ("enable", "Enable an account and invalidate old sessions."),
        ("disable", "Disable an account and revoke its sessions and passkeys."),
        ("revoke-sessions", "Revoke every session for an account."),
    ):
        item = commands.add_parser(command, help=help_text)
        item.add_argument("username")

    commands.add_parser("list", help="List non-secret account metadata.")
    commands.add_parser("cleanup-sessions", help="Delete expired and revoked sessions.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    store = AuthStore(
        _database_path(args.db),
        idle_timeout_seconds=_positive_env_int(
            "AUTH_SESSION_IDLE_SECONDS",
            30 * 60,
            1,
        ),
        absolute_timeout_seconds=_positive_env_int(
            "AUTH_SESSION_ABSOLUTE_SECONDS",
            8 * 60 * 60,
            1,
        ),
        touch_interval_seconds=_positive_env_int(
            "AUTH_SESSION_TOUCH_SECONDS",
            60,
            0,
        ),
        password_iterations=_positive_env_int(
            "AUTH_PBKDF2_ITERATIONS",
            DEFAULT_PASSWORD_ITERATIONS,
            100_000,
        ),
    )
    try:
        if args.command == "create":
            user = store.create_user(
                args.username,
                _read_new_password(),
                args.role,
            )
            print(f"Created {user['username']} ({user['role']}).")
        elif args.command == "reset-password":
            store.set_password(args.username, _read_new_password())
            print(
                f"Password reset for {args.username}; "
                "all sessions and passkeys revoked."
            )
        elif args.command == "set-role":
            store.set_role(args.username, args.role)
            print(f"Role updated for {args.username}; all sessions revoked.")
        elif args.command == "enable":
            store.set_active(args.username, True)
            print(f"Enabled {args.username}; old sessions remain invalid.")
        elif args.command == "disable":
            store.set_active(args.username, False)
            print(f"Disabled {args.username}; all sessions and passkeys revoked.")
        elif args.command == "revoke-sessions":
            count = store.revoke_user_sessions(args.username)
            print(f"Revoked {count} session(s) for {args.username}.")
        elif args.command == "cleanup-sessions":
            count = store.cleanup_sessions()
            print(f"Deleted {count} expired/revoked session record(s).")
        elif args.command == "list":
            print("USERNAME\tROLE\tACTIVE\tDEMO\tCREDENTIAL_VERSION")
            for user in store.list_users():
                print(
                    f"{user['username']}\t{user['role']}\t"
                    f"{bool(user['is_active'])}\t{bool(user['is_demo'])}\t"
                    f"{user['credential_version']}"
                )
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    finally:
        store.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
