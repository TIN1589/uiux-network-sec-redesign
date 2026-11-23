"""Security regressions for discoverable passkey login and credential management."""

from __future__ import annotations

import base64
import json
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from webauthn.helpers.exceptions import InvalidAuthenticationResponse
from webauthn.helpers.structs import CredentialDeviceType

from app import main
from app.auth_store import AuthStore


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _assertion(
    challenge: str,
    credential_id: str,
    *,
    origin: str = "http://localhost:8000",
) -> dict:
    client_data = _encode(
        json.dumps(
            {
                "type": "webauthn.get",
                "challenge": challenge,
                "origin": origin,
            },
            separators=(",", ":"),
        ).encode()
    )
    return {
        "id": credential_id,
        "rawId": credential_id,
        "type": "public-key",
        "response": {
            "authenticatorData": "AA",
            "clientDataJSON": client_data,
            "signature": "AA",
            "userHandle": None,
        },
        "clientExtensionResults": {},
    }


def _verified(
    credential_id: bytes,
    *,
    sign_count: int = 1,
    device_type: CredentialDeviceType = CredentialDeviceType.SINGLE_DEVICE,
    backed_up: bool = False,
) -> SimpleNamespace:
    return SimpleNamespace(
        credential_id=credential_id,
        new_sign_count=sign_count,
        credential_device_type=device_type,
        credential_backed_up=backed_up,
        user_verified=True,
    )


def _public_headers(client: TestClient) -> dict[str, str]:
    token = client.get("/api/auth/csrf-token").json()["csrf_token"]
    return {"X-CSRF-Token": token}


def _authentication_options(client: TestClient, headers: dict[str, str]) -> dict:
    response = client.post(
        "/api/auth/webauthn/authenticate/options",
        headers=headers,
    )
    assert response.status_code == 200, response.text
    return response.json()


def _password_login(client: TestClient) -> None:
    public_csrf = client.get("/api/auth/csrf-token").json()["csrf_token"]
    response = client.post(
        "/api/auth/login",
        data={
            "username": "admin",
            "password": "vnpt-soc-2026",
            "csrf_token": public_csrf,
        },
    )
    assert response.status_code == 200
    session_csrf = client.get("/api/auth/csrf-token").json()["csrf_token"]
    client.headers["X-CSRF-Token"] = session_csrf


@pytest.fixture
def authentication_context(tmp_path, monkeypatch):
    store = AuthStore(
        tmp_path / "authentication.sqlite3",
        idle_timeout_seconds=600,
        absolute_timeout_seconds=3600,
        touch_interval_seconds=0,
        password_iterations=100_000,
    )
    store.ensure_demo_users(main._DEMO_ACCOUNTS)
    credential_bytes = b"passkey-authentication-id"
    credential_id = _encode(credential_bytes)
    store.store_credential(
        credential_id,
        "admin",
        b"cose-public-key",
        transports=["internal"],
        device_label="Primary workstation",
    )
    monkeypatch.setattr(main, "_AUTH_STORE", store)
    monkeypatch.setattr(main, "AUDIT_LOGS", [])
    with TestClient(main.app) as client:
        yield client, store, credential_bytes, credential_id
    store.close()


def test_authentication_options_require_public_csrf_and_hide_usernames(
    authentication_context,
):
    client, _, _, _ = authentication_context

    rejected = client.post("/api/auth/webauthn/authenticate/options")
    options = _authentication_options(client, _public_headers(client))

    assert rejected.status_code == 403
    assert options["rpId"] == "localhost"
    assert options["allowCredentials"] == []
    assert options["userVerification"] == "required"
    assert "user" not in options


def test_unknown_credential_is_generic_and_skips_crypto_verification(
    authentication_context,
    monkeypatch,
):
    client, _, _, _ = authentication_context
    headers = _public_headers(client)
    challenge = _authentication_options(client, headers)["challenge"]

    def unexpected_verify(**kwargs):
        pytest.fail("Unknown credentials must fail before signature verification")

    monkeypatch.setattr(main, "verify_authentication_response", unexpected_verify)
    response = client.post(
        "/api/auth/webauthn/authenticate/verify",
        headers=headers,
        json={"credential": _assertion(challenge, _encode(b"unknown"))},
    )

    assert response.status_code == 401
    assert response.json() == {"detail": "Passkey authentication failed"}


def test_verified_assertion_updates_counter_and_creates_server_session(
    authentication_context,
    monkeypatch,
):
    client, store, credential_bytes, credential_id = authentication_context
    headers = _public_headers(client)
    challenge = _authentication_options(client, headers)["challenge"]
    captured = {}

    def verify(**kwargs):
        captured.update(kwargs)
        return _verified(credential_bytes)

    monkeypatch.setattr(main, "verify_authentication_response", verify)
    response = client.post(
        "/api/auth/webauthn/authenticate/verify",
        headers=headers,
        json={
            "credential": _assertion(challenge, credential_id),
            "remember": True,
        },
    )

    assert response.status_code == 200, response.text
    assert captured["expected_rp_id"] == "localhost"
    assert captured["expected_origin"] == ["http://localhost:8000"]
    assert captured["credential_public_key"] == b"cose-public-key"
    assert captured["credential_current_sign_count"] == 0
    assert captured["require_user_verification"] is True
    assert store.get_credential(credential_id)["sign_count"] == 1
    assert store.get_credential(credential_id)["last_used_at"] is not None
    assert client.get("/api/auth/me").json() == {
        "authenticated": True,
        "username": "admin",
        "role": "admin",
    }
    assert main.AUDIT_LOGS[-1]["activityType"] == "PASSKEY_LOGIN_SUCCESS"

    replay = client.post(
        "/api/auth/webauthn/authenticate/verify",
        headers=headers,
        json={"credential": _assertion(challenge, credential_id)},
    )
    assert replay.status_code == 409


def test_origin_failure_leaves_authentication_challenge_unused(
    authentication_context,
    monkeypatch,
):
    client, store, _, credential_id = authentication_context
    headers = _public_headers(client)
    challenge = _authentication_options(client, headers)["challenge"]

    def reject_origin(**kwargs):
        assert kwargs["expected_origin"] == ["http://localhost:8000"]
        raise InvalidAuthenticationResponse("Unexpected client data origin")

    monkeypatch.setattr(main, "verify_authentication_response", reject_origin)
    response = client.post(
        "/api/auth/webauthn/authenticate/verify",
        headers=headers,
        json={
            "credential": _assertion(
                challenge,
                credential_id,
                origin="https://evil.example",
            )
        },
    )

    assert response.status_code == 401
    assert response.json() == {"detail": "Passkey authentication failed"}
    assert store.get_challenge(challenge, "authentication") is not None


def test_expired_authentication_challenge_is_rejected_before_verification(
    authentication_context,
    monkeypatch,
):
    client, store, _, credential_id = authentication_context
    headers = _public_headers(client)
    challenge = _authentication_options(client, headers)["challenge"]
    with store._lock, store._connection:
        store._connection.execute(
            "UPDATE webauthn_challenges SET created_at = 0, expires_at = 1"
        )

    def unexpected_verify(**kwargs):
        pytest.fail("Expired challenges must fail before signature verification")

    monkeypatch.setattr(main, "verify_authentication_response", unexpected_verify)
    response = client.post(
        "/api/auth/webauthn/authenticate/verify",
        headers=headers,
        json={"credential": _assertion(challenge, credential_id)},
    )

    assert response.status_code == 409


def test_backup_eligibility_change_is_rejected_without_consuming_challenge(
    authentication_context,
    monkeypatch,
):
    client, store, credential_bytes, credential_id = authentication_context
    headers = _public_headers(client)
    challenge = _authentication_options(client, headers)["challenge"]
    monkeypatch.setattr(
        main,
        "verify_authentication_response",
        lambda **kwargs: _verified(
            credential_bytes,
            device_type=CredentialDeviceType.MULTI_DEVICE,
            backed_up=True,
        ),
    )

    response = client.post(
        "/api/auth/webauthn/authenticate/verify",
        headers=headers,
        json={"credential": _assertion(challenge, credential_id)},
    )

    assert response.status_code == 401
    assert store.get_challenge(challenge, "authentication") is not None


def test_regressed_counter_rejects_login_after_consuming_assertion(
    authentication_context,
    monkeypatch,
):
    client, store, credential_bytes, credential_id = authentication_context
    store.update_sign_counter(credential_id, 5)
    headers = _public_headers(client)
    challenge = _authentication_options(client, headers)["challenge"]
    monkeypatch.setattr(
        main,
        "verify_authentication_response",
        lambda **kwargs: _verified(credential_bytes, sign_count=4),
    )

    response = client.post(
        "/api/auth/webauthn/authenticate/verify",
        headers=headers,
        json={"credential": _assertion(challenge, credential_id)},
    )

    assert response.status_code == 401
    assert store.get_challenge(challenge, "authentication") is None
    assert client.get("/api/auth/me").json() == {"authenticated": False}


def test_credential_management_lists_safely_and_requires_reauth_to_revoke(
    authentication_context,
):
    client, store, _, credential_id = authentication_context
    store.store_credential(
        _encode(b"other-user-credential"),
        "tier1",
        b"other-public-key",
    )
    _password_login(client)

    listed = client.get("/api/auth/webauthn/credentials")
    assert listed.status_code == 200
    assert listed.json()["credentials"] == [
        {
            "id": credential_id,
            "device_label": "Primary workstation",
            "transports": ["internal"],
            "backup_state": False,
            "backup_eligible": False,
            "created_at": listed.json()["credentials"][0]["created_at"],
            "last_used_at": None,
        }
    ]
    assert "public_key" not in listed.text
    assert "username" not in listed.text

    wrong_password = client.request(
        "DELETE",
        f"/api/auth/webauthn/credentials/{credential_id}",
        json={"password": "wrong-password"},
    )
    assert wrong_password.status_code == 401
    assert store.get_credential(credential_id) is not None

    other_user = client.request(
        "DELETE",
        f"/api/auth/webauthn/credentials/{_encode(b'other-user-credential')}",
        json={"password": "vnpt-soc-2026"},
    )
    assert other_user.status_code == 404

    revoked = client.request(
        "DELETE",
        f"/api/auth/webauthn/credentials/{credential_id}",
        json={"password": "vnpt-soc-2026"},
    )
    assert revoked.status_code == 200
    assert store.get_credential(credential_id) is None
    assert main.AUDIT_LOGS[-1]["activityType"] == "PASSKEY_REVOKED"
