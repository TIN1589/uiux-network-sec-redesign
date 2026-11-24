"""Rendered UI and client-asset contracts for Passkey workflows."""

import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app import app


@pytest.fixture
def client() -> TestClient:
    with TestClient(app) as test_client:
        yield test_client


def _login(client: TestClient) -> None:
    csrf = client.get("/api/auth/csrf-token").json()["csrf_token"]
    response = client.post(
        "/api/auth/login",
        data={
            "username": "admin",
            "password": "vnpt-soc-2026",
            "csrf_token": csrf,
        },
    )
    assert response.status_code == 200


def test_signin_page_exposes_username_less_passkey_action(client: TestClient):
    response = client.get("/login")

    assert response.status_code == 200
    assert 'id="passkey-signin-btn"' in response.text
    assert "Sign in with a passkey" in response.text
    button_markup = re.search(
        r'<button[^>]+id="passkey-signin-btn"[^>]*>(.*?)</button>',
        response.text,
        re.DOTALL,
    )
    assert button_markup
    assert "Waiting for your passkey" not in button_markup.group(1)
    assert 'aria-describedby="passkey-status"' in response.text
    assert re.search(
        r'<div[^>]+id="passkey-status"[^>]+hidden>', response.text
    )
    assert 'id="remember-session"' in response.text
    assert re.search(r'src="[^"]*/static/js/signin\.js"', response.text)


def test_authenticated_shell_renders_accessible_passkey_manager(client: TestClient):
    _login(client)
    response = client.get("/")

    assert response.status_code == 200
    assert 'id="passkey-manager-trigger"' in response.text
    assert 'id="passkey-manager-modal"' in response.text
    assert 'role="dialog"' in response.text
    assert 'aria-modal="true"' in response.text
    assert 'aria-labelledby="passkey-manager-title"' in response.text
    assert 'autocomplete="current-password"' in response.text
    assert 'id="passkey-credential-list"' in response.text


def test_passkey_client_assets_are_local_modules_with_no_embedded_secret():
    root = Path(__file__).resolve().parents[1]
    webauthn_client = (root / "static/js/webauthn-client.js").read_text(
        encoding="utf-8"
    )
    manager = (root / "static/js/passkey-manager.js").read_text(encoding="utf-8")
    signin = (root / "static/js/signin.js").read_text(encoding="utf-8")

    assert "navigator.credentials.create" in webauthn_client
    assert "navigator.credentials.get" in webauthn_client
    assert "credentials: 'same-origin'" in webauthn_client
    assert "X-CSRF-Token" in webauthn_client
    assert "innerHTML = credential" not in manager
    assert "vnpt-soc-2026" not in webauthn_client + manager + signin
