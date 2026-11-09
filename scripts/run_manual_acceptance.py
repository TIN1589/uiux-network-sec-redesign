"""Run the manual-acceptance checklist against an isolated local server.

The runner intentionally starts a fresh application process so alert and
scenario mutations never affect a developer's already-running server.
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _git(*args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    return result.stdout.strip()


def _available_port(preferred: int) -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        try:
            probe.bind(("127.0.0.1", preferred))
        except OSError:
            probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _wait_until_ready(base_url: str, process: subprocess.Popen[str]) -> None:
    deadline = time.monotonic() + 30
    login_url = f"{base_url}/login"
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("The isolated acceptance server exited before it became ready.")
        try:
            with urllib.request.urlopen(login_url, timeout=1) as response:
                if response.status == 200:
                    return
        except (OSError, urllib.error.URLError):
            time.sleep(0.2)
    raise TimeoutError(f"Timed out waiting for {login_url}")


def _stop_process(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=8)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Automate the Sprint 3 manual browser-acceptance checklist.",
    )
    parser.add_argument(
        "--base-url",
        help="Use an existing server instead of starting an isolated one.",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8765,
        help="Preferred port for the isolated server (default: 8765).",
    )
    parser.add_argument(
        "--headed",
        action="store_true",
        help="Show Chromium while the acceptance suite runs.",
    )
    parser.add_argument(
        "--require-clean",
        action="store_true",
        help="Fail the release gate when the Git worktree is not clean.",
    )
    parser.add_argument(
        "pytest_args",
        nargs=argparse.REMAINDER,
        help="Extra pytest arguments after '--', for example: -- -k auth.",
    )
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    started_at = datetime.now(UTC)
    stamp = started_at.strftime("%Y%m%dT%H%M%SZ")
    head_sha = _git("rev-parse", "HEAD") or "unknown-head"
    evidence_dir = ROOT / "evidence" / "manual_acceptance_auto" / f"{stamp}_{head_sha[:8]}"
    evidence_dir.mkdir(parents=True, exist_ok=False)

    server_process: subprocess.Popen[str] | None = None
    server_log_handle = None
    base_url = args.base_url.rstrip("/") if args.base_url else ""

    try:
        if not base_url:
            port = _available_port(args.port)
            base_url = f"http://127.0.0.1:{port}"
            server_log_handle = (evidence_dir / "server.log").open(
                "w",
                encoding="utf-8",
            )
            creation_flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
            server_process = subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "uvicorn",
                    "app.main:app",
                    "--host",
                    "127.0.0.1",
                    "--port",
                    str(port),
                    "--log-level",
                    "warning",
                ],
                cwd=ROOT,
                stdout=server_log_handle,
                stderr=subprocess.STDOUT,
                text=True,
                creationflags=creation_flags,
            )
            _wait_until_ready(base_url, server_process)

        env = os.environ.copy()
        env["MANUAL_ACCEPTANCE_BASE_URL"] = base_url
        env["MANUAL_ACCEPTANCE_EVIDENCE_DIR"] = str(evidence_dir)
        env["MANUAL_ACCEPTANCE_HEADED"] = "1" if args.headed else "0"

        pytest_args = list(args.pytest_args)
        if pytest_args[:1] == ["--"]:
            pytest_args = pytest_args[1:]
        junit_path = evidence_dir / "junit.xml"
        command = [
            sys.executable,
            "-m",
            "pytest",
            "-q",
            "tests/manual_acceptance.py",
            f"--junitxml={junit_path}",
            *pytest_args,
        ]
        print(f"Acceptance server: {base_url}")
        print(f"Evidence: {evidence_dir}")
        completed = subprocess.run(command, cwd=ROOT, env=env, check=False)

        git_status = _git("status", "--short")
        metadata = {
            "started_at_utc": started_at.isoformat(),
            "finished_at_utc": datetime.now(UTC).isoformat(),
            "head_sha": head_sha,
            "base_url": base_url,
            "isolated_server": server_process is not None,
            "pytest_exit_code": completed.returncode,
            "git_clean": not bool(git_status),
            "git_status": git_status.splitlines(),
            "require_clean": args.require_clean,
            "command": command,
        }
        (evidence_dir / "metadata.json").write_text(
            json.dumps(metadata, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )

        if completed.returncode:
            return completed.returncode
        if args.require_clean and git_status:
            print("Release gate failed: the Git worktree is not clean.", file=sys.stderr)
            return 2
        if git_status:
            print("Note: browser acceptance passed, but the worktree is not clean.")
        return 0
    finally:
        if server_process is not None:
            _stop_process(server_process)
        if server_log_handle is not None:
            server_log_handle.close()


if __name__ == "__main__":
    raise SystemExit(main())
