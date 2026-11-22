"""Authorization and CSRF regressions for sensitive SOC routes."""

import re
from copy import deepcopy

import pytest
from fastapi.testclient import TestClient

from app import alerts_store, app, scenarios_store


def _public_csrf_token(client: TestClient) -> str:
    """Read the signed public-auth CSRF token rendered by the login form."""
    response = client.get("/login")
    match = re.search(r'name="csrf_token" value="([^"]+)"', response.text)
    assert match, "Login page did not render a CSRF token"
    return match.group(1)


def _authenticate(client: TestClient, username: str) -> str:
    """Create a real session and configure the matching CSRF request header."""
    response = client.post(
        "/login",
        data={
            "username": username,
            "password": "vnpt-soc-2026",
            "csrf_token": _public_csrf_token(client),
        },
        follow_redirects=False,
    )
    assert response.status_code == 303
    token_response = client.get("/api/auth/csrf-token")
    assert token_response.status_code == 200
    token = token_response.json().get("csrf_token")
    assert token
    client.headers.update({"X-CSRF-Token": token})
    return token


@pytest.fixture
def client() -> TestClient:
    """Return an isolated HTTP client for each authorization scenario."""
    with TestClient(app) as test_client:
        yield test_client


@pytest.mark.parametrize("path", ["/", "/alerts", "/devices", "/scenarios"])
def test_anonymous_full_pages_redirect_to_login(client: TestClient, path: str):
    """Every Dynamic dashboard page must reject an anonymous navigation."""
    response = client.get(path, follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/login"


@pytest.mark.parametrize(
    "path",
    [
        "/views/overview",
        "/views/alerts",
        "/views/devices",
        "/views/scenarios",
        "/api/overview/stats",
        "/api/alerts/filter",
        f"/api/alerts/{alerts_store[0]['eventId']}/drawer",
        "/api/live-status",
    ],
)
def test_anonymous_htmx_reads_receive_login_redirect_header(
    client: TestClient,
    path: str,
):
    """Protected HTMX reads fail with a machine-actionable login redirect."""
    response = client.get(path, headers={"HX-Request": "true"})

    assert response.status_code == 401
    assert response.headers["HX-Redirect"] == "/login"


@pytest.mark.parametrize(
    "path",
    [
        "/api/audit-logs",
        "/api/mitre/matrix",
        "/api/scenarios/calculate-delta?linked_id=EVT-2610-099",
        f"/api/scenarios/{scenarios_store[0]['id']}/edit",
        f"/api/alerts/{alerts_store[0]['eventId']}/drawer",
        "/api/export/alerts.csv",
        "/api/export/scenarios.csv",
    ],
)
def test_anonymous_read_apis_return_json_401(client: TestClient, path: str):
    """Direct API reads must not disclose SOC data to anonymous clients."""
    response = client.get(path)

    assert response.status_code == 401
    assert response.json() == {"detail": "Authentication required"}


@pytest.mark.parametrize(
    "path",
    [
        "/",
        "/alerts",
        "/devices",
        "/scenarios",
        "/views/overview",
        "/views/alerts",
        "/views/devices",
        "/views/scenarios",
        "/api/overview/stats",
        "/api/alerts/filter",
        f"/api/alerts/{alerts_store[0]['eventId']}/drawer",
        "/api/mitre/matrix",
        "/api/scenarios/calculate-delta?linked_id=EVT-2610-099",
        "/api/live-status",
    ],
)
def test_authenticated_tier1_can_read_dashboard_surfaces(
    client: TestClient,
    path: str,
):
    """A real authenticated session retains read access across the dashboard."""
    _authenticate(client, "tier1")

    assert client.get(path).status_code == 200


@pytest.mark.parametrize(
    "path",
    [
        "/login",
        "/auth/forgot",
        "/api/auth/csrf-token",
        "/api/auth/me",
        "/ui/log-feed",
        "/manifest.webmanifest",
    ],
)
def test_auth_bootstrap_and_static_shell_routes_remain_public(
    client: TestClient,
    path: str,
):
    """The narrow authentication/bootstrap allowlist remains reachable."""
    assert client.get(path).status_code == 200


def test_removed_dynamic_guest_entry_cannot_open_dashboard(client: TestClient):
    """The former guest endpoint may not mint or bypass a Dynamic session."""
    response = client.post("/auth/guest", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/login"
    assert "session_id" not in response.cookies


def test_anonymous_request_cannot_mutate_alert_state(client: TestClient):
    """An anonymous POST must return 401 and leave the alert unchanged."""
    alert = alerts_store[0]
    original = deepcopy(alert)
    try:
        response = client.post(
            f"/api/alerts/{alert['eventId']}/state",
            data={"state": "Investigating"},
        )
        assert response.status_code == 401
        assert alert == original
    finally:
        alert.clear()
        alert.update(original)


def test_authenticated_mutation_rejects_missing_csrf(client: TestClient):
    """A valid Tier-2 session without its CSRF header must return 403."""
    _authenticate(client, "tier2")
    alert = alerts_store[0]
    original = deepcopy(alert)
    try:
        response = client.post(
            f"/api/alerts/{alert['eventId']}/resolve",
            data={"disposition": "True Positive - Malicious"},
            headers={"X-CSRF-Token": ""},
        )
        assert response.status_code == 403
        assert alert == original
    finally:
        alert.clear()
        alert.update(original)


def test_tier1_cannot_execute_tier2_containment(client: TestClient):
    """Tier-1 may acknowledge alerts but must not execute containment actions."""
    _authenticate(client, "tier1")
    event_id = alerts_store[0]["eventId"]

    acknowledge = client.post(f"/api/alerts/{event_id}/ack")
    containment = client.post(f"/api/alerts/{event_id}/action/quarantine-port")

    assert acknowledge.status_code == 200
    assert containment.status_code == 403


def test_tier2_cannot_create_admin_attack_scenario(client: TestClient):
    """Tier-2 must not create attack-scenario records reserved for Admin."""
    original = deepcopy(scenarios_store)
    _authenticate(client, "tier2")
    try:
        response = client.post(
            "/api/scenarios",
            data={
                "code": "T1046",
                "tool": "Nmap",
                "rule": "100001",
                "linkedEventId": alerts_store[0]["eventId"],
                "notes": "authorization regression",
            },
        )
        assert response.status_code == 403
        assert scenarios_store == original
    finally:
        scenarios_store[:] = original


def test_admin_can_read_audit_log_and_manage_scenarios(client: TestClient):
    """Admin retains access to audit data and scenario management with CSRF."""
    original = deepcopy(scenarios_store)
    _authenticate(client, "admin")
    try:
        audit_response = client.get("/api/audit-logs")
        scenario_response = client.post(
            "/api/scenarios",
            data={
                "code": "T1046",
                "tool": "Nmap",
                "rule": "100001",
                "linkedEventId": alerts_store[0]["eventId"],
                "notes": "authorized regression",
            },
        )
        assert audit_response.status_code == 200
        assert scenario_response.status_code == 200
        assert len(scenarios_store) == len(original) + 1
    finally:
        scenarios_store[:] = original
