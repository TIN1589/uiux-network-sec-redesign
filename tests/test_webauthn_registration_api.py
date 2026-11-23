"""Security regressions for authenticated WebAuthn registration."""

from __future__ import annotations

import base64
import json
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from webauthn.helpers.exceptions import InvalidRegistrationResponse
from webauthn.helpers.structs import CredentialDeviceType

from app import main
from app.auth_store import AuthStore


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _client_data(challenge: str, origin: str = "http://localhost:8000") -> str:
    return _encode(
        json.dumps(
            {
                "type": "webauthn.create",
                "challenge": challenge,
                "origin": origin,
            },
            separators=(",", ":"),
        ).encode()
    )


def _credential(challenge: str, *, origin: str = "http://localhost:8000") -> dict:
    return {
        "id": "Y3JlZGVudGlhbC1vbmU",
        "rawId": "Y3JlZGVudGlhbC1vbmU",
        "type": "public-key",
        "response": {
            "attestationObject": "AA",
            "clientDataJSON": _client_data(challenge, origin),
            "transports": ["internal", "hybrid"],
        },
        "clientExtensionResults": {},
    }


def _verified(credential_id: bytes = b"credential-one") -> SimpleNamespace:
    return SimpleNamespace(
        credential_id=credential_id,
        credential_public_key=b"cose-public-key",
        sign_count=0,
        user_verified=True,
        credential_device_type=CredentialDeviceType.MULTI_DEVICE,
        credential_backed_up=True,
    )


def _authenticate(client: TestClient, username: str = "admin") -> None:
    public_csrf = client.get("/api/auth/csrf-token").json()["csrf_token"]
    login = client.post(
        "/api/auth/login",
        data={
            "username": username,
            "password": "vnpt-soc-2026",
            "csrf_token": public_csrf,
        },
    )
    assert login.status_code == 200
    session_csrf = client.get("/api/auth/csrf-token").json()["csrf_token"]
    client.headers.update({"X-CSRF-Token": session_csrf})


def _options(client: TestClient) -> dict:
    response = client.post(
        "/api/auth/webauthn/register/options",
        json={"password": "vnpt-soc-2026"},
    )
    assert response.status_code == 200, response.text
    return response.json()


@pytest.fixture
def registration_context(tmp_path, monkeypatch):
    store = AuthStore(
        tmp_path / "registration.sqlite3",
        idle_timeout_seconds=600,
        absolute_timeout_seconds=3600,
        touch_interval_seconds=0,
        password_iterations=100_000,
    )
    store.ensure_demo_users(main._DEMO_ACCOUNTS)
    monkeypatch.setattr(main, "_AUTH_STORE", store)
    monkeypatch.setattr(main, "AUDIT_LOGS", [])
    with TestClient(main.app) as client:
        yield client, store
    store.close()


def test_registration_options_require_authentication(registration_context):
    client, _ = registration_context

    response = client.post(
        "/api/auth/webauthn/register/options",
        json={"password": "vnpt-soc-2026"},
    )

    assert response.status_code == 401
    assert response.json() == {"detail": "Authentication required"}


@pytest.mark.parametrize("csrf_header", [None, "invalid-token"])
def test_registration_options_require_session_csrf(
    registration_context,
    csrf_header,
):
    client, _ = registration_context
    _authenticate(client)
    if csrf_header is None:
        del client.headers["X-CSRF-Token"]
    else:
        client.headers["X-CSRF-Token"] = csrf_header

    response = client.post(
        "/api/auth/webauthn/register/options",
        json={"password": "vnpt-soc-2026"},
    )

    assert response.status_code == 403
    assert response.json() == {"detail": "Invalid CSRF token"}


def test_registration_options_require_fresh_password_and_hardened_policy(
    registration_context,
):
    client, _ = registration_context
    _authenticate(client)

    rejected = client.post(
        "/api/auth/webauthn/register/options",
        json={"password": "wrong-password"},
    )
    options = _options(client)

    assert rejected.status_code == 401
    assert options["rp"] == {"id": "localhost", "name": "VNPT SOC Command Center"}
    assert options["authenticatorSelection"]["residentKey"] == "required"
    assert options["authenticatorSelection"]["requireResidentKey"] is True
    assert options["authenticatorSelection"]["userVerification"] == "required"
    assert options["attestation"] == "none"
    assert len(options["challenge"]) >= 43
    assert main.AUDIT_LOGS[-1]["activityType"] == "PASSKEY_REGISTRATION_STARTED"


def test_registration_verify_requires_csrf_after_options(
    registration_context,
    monkeypatch,
):
    client, _ = registration_context
    _authenticate(client)
    challenge = _options(client)["challenge"]
    del client.headers["X-CSRF-Token"]

    def unexpected_verify(**kwargs):
        pytest.fail("CSRF rejection must happen before cryptographic verification")

    monkeypatch.setattr(main, "verify_registration_response", unexpected_verify)
    response = client.post(
        "/api/auth/webauthn/register/verify",
        json={"credential": _credential(challenge)},
    )

    assert response.status_code == 403
    assert response.json() == {"detail": "Invalid CSRF token"}


def test_verify_passes_exact_rp_origin_and_persists_verified_metadata(
    registration_context,
    monkeypatch,
):
    client, store = registration_context
    _authenticate(client)
    options = _options(client)
    captured = {}

    def verify(**kwargs):
        captured.update(kwargs)
        return _verified()

    monkeypatch.setattr(main, "verify_registration_response", verify)
    response = client.post(
        "/api/auth/webauthn/register/verify",
        json={
            "credential": _credential(options["challenge"]),
            "device_label": "Work laptop",
        },
    )

    assert response.status_code == 200, response.text
    assert captured["expected_rp_id"] == "localhost"
    assert captured["expected_origin"] == ["http://localhost:8000"]
    assert captured["require_user_verification"] is True
    stored = store.get_credential("Y3JlZGVudGlhbC1vbmU")
    assert stored["username"] == "admin"
    assert stored["transports"] == ["hybrid", "internal"]
    assert stored["backup_state"] is True
    assert stored["backup_eligible"] is True
    assert stored["device_label"] == "Work laptop"
    assert main.AUDIT_LOGS[-1]["activityType"] == "PASSKEY_REGISTERED"

    next_options = _options(client)
    assert next_options["excludeCredentials"][0]["id"] == stored["credential_id"]


def test_origin_failure_does_not_consume_challenge(
    registration_context,
    monkeypatch,
):
    client, store = registration_context
    _authenticate(client)
    challenge = _options(client)["challenge"]

    def reject_wrong_origin(**kwargs):
        assert kwargs["expected_origin"] == ["http://localhost:8000"]
        assert kwargs["expected_rp_id"] == "localhost"
        raise InvalidRegistrationResponse("Unexpected client data origin")

    monkeypatch.setattr(main, "verify_registration_response", reject_wrong_origin)
    response = client.post(
        "/api/auth/webauthn/register/verify",
        json={"credential": _credential(challenge, origin="https://evil.example")},
    )

    assert response.status_code == 400
    assert response.json() == {"detail": "Invalid passkey registration response"}
    assert (
        store.get_challenge(
            challenge,
            "registration",
            username="admin",
            session_id=client.cookies["session_id"],
        )
        is not None
    )


def test_challenge_rejects_another_session_before_crypto_verification(
    registration_context,
    monkeypatch,
):
    first_client, _ = registration_context
    _authenticate(first_client)
    challenge = _options(first_client)["challenge"]
    verifier_called = False

    def verify(**kwargs):
        nonlocal verifier_called
        verifier_called = True
        return _verified()

    monkeypatch.setattr(main, "verify_registration_response", verify)
    with TestClient(main.app) as second_client:
        _authenticate(second_client)
        response = second_client.post(
            "/api/auth/webauthn/register/verify",
            json={"credential": _credential(challenge)},
        )

    assert response.status_code == 409
    assert verifier_called is False


def test_expired_challenge_is_rejected_before_crypto_verification(
    registration_context,
    monkeypatch,
):
    client, store = registration_context
    _authenticate(client)
    challenge = _options(client)["challenge"]
    with store._lock, store._connection:
        store._connection.execute(
            "UPDATE webauthn_challenges SET created_at = 0, expires_at = 1"
        )

    def unexpected_verify(**kwargs):
        pytest.fail("Expired challenges must be rejected before verification")

    monkeypatch.setattr(main, "verify_registration_response", unexpected_verify)
    response = client.post(
        "/api/auth/webauthn/register/verify",
        json={"credential": _credential(challenge)},
    )

    assert response.status_code == 409


def test_successful_challenge_cannot_be_replayed_or_reused_for_duplicate(
    registration_context,
    monkeypatch,
):
    client, store = registration_context
    _authenticate(client)
    monkeypatch.setattr(
        main,
        "verify_registration_response",
        lambda **kwargs: _verified(),
    )
    first_challenge = _options(client)["challenge"]
    payload = {"credential": _credential(first_challenge)}

    created = client.post("/api/auth/webauthn/register/verify", json=payload)
    replayed = client.post("/api/auth/webauthn/register/verify", json=payload)

    assert created.status_code == 200
    assert replayed.status_code == 409
    assert len(store.list_credentials("admin")) == 1

    second_challenge = _options(client)["challenge"]
    duplicate = client.post(
        "/api/auth/webauthn/register/verify",
        json={"credential": _credential(second_challenge)},
    )
    assert duplicate.status_code == 409
    assert duplicate.json() == {
        "detail": "WebAuthn credential ID is already registered."
    }
    assert len(store.list_credentials("admin")) == 1


def test_webauthn_configuration_rejects_unsafe_or_cross_rp_values(monkeypatch):
    with pytest.raises(RuntimeError, match="hostname"):
        main._webauthn_rp_id("https://soc.example.com")
    with pytest.raises(RuntimeError, match="outside RP ID"):
        main._webauthn_origins("https://evil.example", "soc.example.com")

    monkeypatch.setattr(main, "ENV", "production")
    with pytest.raises(RuntimeError, match="require HTTPS"):
        main._webauthn_origins("http://localhost:8000", "localhost")
