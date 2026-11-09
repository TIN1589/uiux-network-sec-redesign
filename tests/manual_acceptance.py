"""Automated counterpart of the Sprint 3 manual acceptance checklist.

This module is deliberately named ``manual_acceptance.py`` instead of
``test_*.py``. It is a release-level suite with a large browser matrix and is
run explicitly through ``python scripts/run_manual_acceptance.py``; ordinary
unit/regression runs stay fast.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from urllib.parse import urlparse

import pytest
from playwright.sync_api import Browser, BrowserContext, Page, expect, sync_playwright

BASE_URL = os.getenv("MANUAL_ACCEPTANCE_BASE_URL", "http://127.0.0.1:8000").rstrip("/")
EVIDENCE_ROOT = Path(
    os.getenv("MANUAL_ACCEPTANCE_EVIDENCE_DIR", "evidence/manual_acceptance_auto/adhoc")
)
HEADLESS = os.getenv("MANUAL_ACCEPTANCE_HEADED", "0") != "1"
STANDALONE_URL = Path("index.html").resolve().as_uri()
LOCAL_HOSTS = {"127.0.0.1", "localhost", None}

ROUTES = {
    "overview": ("/", "Overview"),
    "alerts": ("/alerts", "Alert queue"),
    "devices": ("/devices", "Devices"),
    "scenarios": ("/scenarios", "Attack scenarios"),
}
VIEWPORTS = {
    "desktop": {"width": 1440, "height": 900},
    "tablet": {"width": 1024, "height": 768},
    "mobile390": {"width": 390, "height": 844},
    "mobile360": {"width": 360, "height": 844},
}


@pytest.fixture(scope="module")
def browser_instance() -> Browser:
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=HEADLESS)
        yield browser
        browser.close()


def _browser_page(
    browser: Browser,
    viewport: dict[str, int] | None = None,
) -> tuple[BrowserContext, Page, dict[str, list[str]]]:
    context = browser.new_context(viewport=viewport or VIEWPORTS["desktop"])
    page = context.new_page()
    issues: dict[str, list[str]] = {"console": [], "page": [], "external": []}

    page.on(
        "console",
        lambda message: issues["console"].append(message.text)
        if message.type == "error"
        else None,
    )
    page.on("pageerror", lambda error: issues["page"].append(str(error)))

    def guard_external_requests(route) -> None:
        parsed = urlparse(route.request.url)
        if parsed.scheme in {"http", "https"} and parsed.hostname not in LOCAL_HOSTS:
            issues["external"].append(route.request.url)
            route.abort()
            return
        route.continue_()

    context.route("**/*", guard_external_requests)
    return context, page, issues


def _guest_init(context: BrowserContext, theme: str = "light") -> None:
    context.add_init_script(
        f"""
        sessionStorage.setItem('soc_guest_mode', 'true');
        localStorage.setItem('soc-theme', {theme!r});
        document.documentElement.setAttribute('data-theme', {theme!r});
        """
    )


def _wait_dashboard(page: Page) -> None:
    page.wait_for_selector("#main-content", state="visible", timeout=10000)
    if page.locator("#pwa-splash-overlay").count():
        page.wait_for_selector("#pwa-splash-overlay", state="detached", timeout=5000)
    page.wait_for_timeout(300)


def _goto_dashboard(page: Page, path: str) -> None:
    separator = "&" if "?" in path else "?"
    page.goto(f"{BASE_URL}{path}{separator}guest=1", wait_until="domcontentloaded")
    _wait_dashboard(page)


def _capture(page: Page, name: str) -> None:
    EVIDENCE_ROOT.mkdir(parents=True, exist_ok=True)
    page.screenshot(path=str(EVIDENCE_ROOT / f"{name}.png"), full_page=False)


def _assert_runtime_clean(issues: dict[str, list[str]]) -> None:
    assert not issues["external"], f"External/CDN requests detected: {issues['external']}"
    assert not issues["page"], f"Uncaught page errors: {issues['page']}"
    assert not issues["console"], f"Console errors: {issues['console']}"


def _login_admin(page: Page) -> None:
    page.goto(f"{BASE_URL}/login", wait_until="domcontentloaded")
    page.fill("#field-username", "admin")
    page.fill("#field-password", "vnpt-soc-2026")
    page.click("#signin-btn")
    page.wait_for_url(f"{BASE_URL}/", timeout=10000)
    _wait_dashboard(page)


def _assert_no_horizontal_scroll(page: Page) -> None:
    overflow = page.evaluate(
        "() => document.documentElement.scrollWidth > document.documentElement.clientWidth + 1"
    )
    assert not overflow, "The page has unexpected horizontal scrolling."


def test_invalid_demo_admin_history_and_guest_login(browser_instance: Browser) -> None:
    context, page, issues = _browser_page(browser_instance)
    page.goto(f"{BASE_URL}/login", wait_until="domcontentloaded")

    page.fill("#field-username", "admin")
    page.fill("#field-password", "wrong-password")
    page.click("#signin-btn")
    expect(page.locator(".auth-alert")).to_be_visible(timeout=10000)
    expect(page.locator("#signin-btn")).to_be_enabled()
    assert page.locator("#signin-btn").get_attribute("aria-busy") is None

    page.locator("details.demo summary").click()
    page.locator('.demo__chip[data-demo-user="admin"]').click()
    expect(page.locator("#field-username")).to_have_value("admin")
    expect(page.locator("#field-password")).to_have_value("vnpt-soc-2026")
    page.click("#signin-btn")
    page.wait_for_url(f"{BASE_URL}/", timeout=10000)
    _wait_dashboard(page)

    page.go_back(wait_until="domcontentloaded")
    page.wait_for_url(f"{BASE_URL}/", timeout=10000)
    _wait_dashboard(page)
    assert page.locator("#signin-btn").count() == 0
    page.go_forward(wait_until="domcontentloaded")
    page.wait_for_timeout(250)
    assert page.url.startswith(f"{BASE_URL}/")
    assert page.locator("#signin-btn").count() == 0
    _capture(page, "auth-admin-history")
    _assert_runtime_clean(issues)
    context.close()

    guest_context, guest_page, guest_issues = _browser_page(browser_instance)
    guest_page.goto(f"{BASE_URL}/login", wait_until="domcontentloaded")
    guest_page.locator(".auth-guest-form button").click()
    guest_page.wait_for_url(re.compile(rf"^{re.escape(BASE_URL)}/\?guest=1"), timeout=10000)
    _wait_dashboard(guest_page)
    expect(guest_page.locator("#topbar-analyst-name")).to_have_text("Guest")
    _capture(guest_page, "auth-guest")
    _assert_runtime_clean(guest_issues)
    guest_context.close()


def test_guest_is_read_only_in_ui_and_server(browser_instance: Browser) -> None:
    context, page, issues = _browser_page(browser_instance)
    _guest_init(context)
    _goto_dashboard(page, "/alerts")

    visible_privileged = page.locator(
        '[data-min-role="tier2"]:visible, [data-min-role="admin"]:visible'
    ).count()
    response = page.request.post(
        f"{BASE_URL}/api/alerts/DOES-NOT-EXIST/state",
        form={"state": "New"},
    )
    _capture(page, "guest-read-only-gate")
    _assert_runtime_clean(issues)
    context.close()

    assert visible_privileged == 0, (
        f"Guest can see {visible_privileged} Tier-2/Admin mutation controls."
    )
    assert response.status in {401, 403}, (
        "Unauthenticated mutation was not rejected; "
        f"POST returned HTTP {response.status}."
    )


@pytest.mark.parametrize("theme", ["light", "dark"])
@pytest.mark.parametrize("viewport_name", list(VIEWPORTS))
@pytest.mark.parametrize("route_name", list(ROUTES))
def test_dynamic_route_theme_responsive_matrix(
    browser_instance: Browser,
    route_name: str,
    viewport_name: str,
    theme: str,
) -> None:
    viewport = VIEWPORTS[viewport_name]
    path, heading = ROUTES[route_name]
    context, page, issues = _browser_page(browser_instance, viewport)
    _guest_init(context, theme)
    _goto_dashboard(page, path)

    expect(page.get_by_role("heading", name=heading, exact=True)).to_be_visible()
    assert page.locator("html").get_attribute("data-theme") == theme
    assert page.locator(f"#nav-{route_name}").get_attribute("aria-current") == "page"
    assert page.locator(f"#mob-nav-{route_name}").get_attribute("aria-current") == "page"
    assert page.locator("#app-sidebar .local-icon").count() >= 4
    _assert_no_horizontal_scroll(page)

    if route_name == "overview":
        assert page.locator("canvas").count() >= 2
    if viewport_name == "tablet":
        sidebar_width = page.locator("#app-sidebar").evaluate(
            "element => element.getBoundingClientRect().width"
        )
        visible_labels = page.locator("#app-sidebar .nav-label:visible").count()
        assert sidebar_width >= 240
        assert visible_labels >= 4
    if route_name == "alerts" and viewport["width"] < 1280:
        expect(page.locator(".mobile-alerts-list")).to_be_visible()

    page.reload(wait_until="domcontentloaded")
    _wait_dashboard(page)
    assert page.locator("html").get_attribute("data-theme") == theme
    _capture(page, f"dynamic-{route_name}-{theme}-{viewport_name}")
    _assert_runtime_clean(issues)
    context.close()


def test_alert_filters_drawer_actions_bulk_keyboard_and_csv(browser_instance: Browser) -> None:
    context, page, issues = _browser_page(browser_instance)
    _login_admin(page)
    page.goto(f"{BASE_URL}/alerts", wait_until="domcontentloaded")
    _wait_dashboard(page)

    first_event = page.locator("#al-table-body .alert-row-checkbox").first.get_attribute(
        "data-event-id"
    )
    assert first_event
    page.fill("#al-search", first_event)
    page.wait_for_timeout(500)
    expect(page.locator("#al-table-body")).to_contain_text(first_event)

    page.get_by_role("button", name=re.compile(r"^New\b")).click()
    page.wait_for_timeout(400)
    assert page.locator("#al-state-hidden").input_value() == "New"
    assert page.locator(".state-pill.active").inner_text().strip().startswith("New")

    page.goto(f"{BASE_URL}/alerts?technique=T1046", wait_until="domcontentloaded")
    _wait_dashboard(page)
    expect(page.locator("#mitre-active-filter-banner")).to_contain_text("T1046")

    page.goto(f"{BASE_URL}/alerts", wait_until="domcontentloaded")
    _wait_dashboard(page)
    page.keyboard.press("/")
    assert page.evaluate("document.activeElement === document.getElementById('al-search')")
    page.keyboard.press("Escape")
    page.keyboard.press("j")
    expect(page.locator("#al-table-body tr.kb-active-row")).to_have_count(1)
    page.keyboard.press("Enter")
    expect(page.locator("#alert-drawer-backdrop")).to_have_class(re.compile(r"\bactive\b"))
    page.keyboard.press("Escape")
    expect(page.locator("#alert-drawer-backdrop")).not_to_have_class(re.compile(r"\bactive\b"))

    page.evaluate("window.openAlertDrawer('EVT-2610-089')")
    expect(page.locator("#alert-drawer-backdrop")).to_have_class(re.compile(r"\bactive\b"))
    if page.locator(".drawer-btn-ack").count():
        page.locator(".drawer-btn-ack").click()
        expect(page.locator(".drawer-btn-investigate")).to_be_visible()
    page.locator(".drawer-btn-investigate").click()
    expect(page.locator(".drawer-btn-resolve")).to_be_visible()
    page.locator("#dw-disposition-trigger").click()
    page.locator('#dw-disposition-menu [data-value="False Positive - Benign"]').click()
    page.locator(".drawer-btn-resolve").click()
    expect(page.locator(".drawer-resolved-banner")).to_be_visible()
    expect(page.locator(".soc-activity-trail")).to_be_visible()
    page.keyboard.press("Escape")

    checkboxes = page.locator("#al-table-body .alert-row-checkbox")
    checkboxes.nth(0).check()
    checkboxes.nth(1).check()
    expect(page.locator("#bulk-action-bar")).to_be_visible()
    expect(page.locator("#bulk-count-text")).to_have_text("2 selected")
    page.get_by_role("button", name="Mark investigating").click()
    expect(page.locator("#bulk-action-bar")).to_be_hidden(timeout=10000)

    with page.expect_download() as download_info:
        page.get_by_role("link", name="Export CSV").click()
    assert download_info.value.suggested_filename.endswith(".csv")
    _capture(page, "alerts-workflow-complete")
    _assert_runtime_clean(issues)
    context.close()


@pytest.mark.parametrize("width", [390, 360])
def test_mobile_bulk_bar_floats_without_shifting_content(
    browser_instance: Browser,
    width: int,
) -> None:
    context, page, issues = _browser_page(
        browser_instance,
        {"width": width, "height": 844},
    )
    _guest_init(context)
    _goto_dashboard(page, "/alerts")
    card = page.locator(".mobile-alert-card").first
    checkbox = card.locator(".alert-row-checkbox")
    checkbox.scroll_into_view_if_needed()
    before = card.evaluate("element => element.getBoundingClientRect().top")
    checkbox.check()
    expect(page.locator("#bulk-action-bar")).to_be_visible()
    after = card.evaluate("element => element.getBoundingClientRect().top")
    positions = page.evaluate(
        """() => ({
          bulkBottom: document.getElementById('bulk-action-bar').getBoundingClientRect().bottom,
          navTop: document.getElementById('mobile-bottom-nav').getBoundingClientRect().top
        })"""
    )
    assert abs(after - before) <= 1
    assert positions["bulkBottom"] <= positions["navTop"] + 1
    _capture(page, f"alerts-mobile-bulk-{width}")
    _assert_runtime_clean(issues)
    context.close()


def test_devices_status_layout_and_alert_link(browser_instance: Browser) -> None:
    context, page, issues = _browser_page(browser_instance, VIEWPORTS["mobile360"])
    _guest_init(context)
    _goto_dashboard(page, "/devices")
    expect(page.locator(".badge-reporting").first).to_be_visible()
    expect(page.locator(".badge-silent").first).to_be_visible()
    assert page.locator(".device-card").count() >= 2
    _assert_no_horizontal_scroll(page)

    device_card = page.locator(".device-card").first
    hostname = device_card.locator(".font-mono").first
    dimensions = hostname.evaluate(
        "element => ({client: element.clientWidth, scroll: element.scrollWidth})"
    )
    assert dimensions["client"] > 0
    assert dimensions["scroll"] >= dimensions["client"]
    link = device_card.get_by_role("link", name=re.compile("View alerts"))
    href = link.get_attribute("href")
    assert href and href.startswith("/alerts?asset=")
    link.click()
    page.wait_for_url(re.compile(r"/alerts\?asset="), timeout=10000)
    expect(page.get_by_role("heading", name="Alert queue", exact=True)).to_be_visible()
    _capture(page, "devices-to-filtered-alerts")
    _assert_runtime_clean(issues)
    context.close()


def test_scenario_admin_create_edit_delete(browser_instance: Browser) -> None:
    context, page, issues = _browser_page(browser_instance)
    _login_admin(page)
    page.goto(f"{BASE_URL}/scenarios", wait_until="domcontentloaded")
    _wait_dashboard(page)

    token = "acceptance-auto-unique"
    updated_token = f"{token}-updated"
    page.fill("#sc-tool", token)
    page.fill("#sc-notes", "Automated acceptance create")
    page.click("#sc-submit-btn")
    created_row = page.locator("#sc-results-tbody tr").filter(has_text=token).first
    expect(created_row).to_be_visible(timeout=10000)

    created_row.get_by_role("button", name=re.compile("Actions for test")).click()
    created_row.get_by_role("menuitem", name=re.compile("Edit")).click()
    expect(page.locator("#sc-submit-btn")).to_have_text("Update test")
    page.fill("#sc-tool", updated_token)
    page.fill("#sc-notes", "Automated acceptance update")
    page.click("#sc-submit-btn")
    updated_row = page.locator("#sc-results-tbody tr").filter(has_text=updated_token).first
    expect(updated_row).to_be_visible(timeout=10000)

    updated_row.get_by_role("button", name=re.compile("Actions for test")).click()
    updated_row.get_by_role("menuitem", name=re.compile("Delete")).click()
    expect(page.locator("#sc-results-tbody")).not_to_contain_text(updated_token, timeout=10000)
    _capture(page, "scenarios-crud-complete")
    _assert_runtime_clean(issues)
    context.close()


@pytest.mark.parametrize("theme", ["light", "dark"])
@pytest.mark.parametrize("viewport_name", ["desktop", "mobile390"])
@pytest.mark.parametrize("tab", list(ROUTES))
def test_standalone_tab_theme_responsive_offline_assets(
    browser_instance: Browser,
    tab: str,
    viewport_name: str,
    theme: str,
) -> None:
    context, page, issues = _browser_page(browser_instance, VIEWPORTS[viewport_name])
    _guest_init(context, theme)
    page.goto(STANDALONE_URL, wait_until="domcontentloaded")
    page.wait_for_function("typeof window.switchTab === 'function'")
    page.evaluate(
        """tab => {
          const modal = document.getElementById('signin-modal');
          if (modal) modal.classList.remove('active');
          window.switchTab(tab);
        }""",
        tab,
    )
    page.wait_for_timeout(200)

    expect(page.locator(f"#tab-{tab}")).to_be_visible()
    assert page.locator(f"#nav-{tab}").get_attribute("aria-current") == "page"
    assert page.locator(f"#mob-nav-{tab}").get_attribute("aria-current") == "page"
    assert page.locator("html").get_attribute("data-theme") == theme
    assert page.locator("svg.local-icon").count() >= 4
    _assert_no_horizontal_scroll(page)
    _capture(page, f"standalone-{tab}-{theme}-{viewport_name}")
    _assert_runtime_clean(issues)
    context.close()


@pytest.mark.parametrize("path", ["/", "/alerts"])
def test_pwa_offline_reload_has_local_shell_and_query_cache(
    browser_instance: Browser,
    path: str,
) -> None:
    context, page, issues = _browser_page(browser_instance, VIEWPORTS["mobile390"])
    _guest_init(context)
    _goto_dashboard(page, path)
    service_worker = page.evaluate(
        """async () => {
          if (!('serviceWorker' in navigator)) return false;
          await navigator.serviceWorker.ready;
          return true;
        }"""
    )
    assert service_worker
    page.evaluate(
        """async () => {
          const response = await fetch('/static/css/style.css?v=acceptance-query');
          if (!response.ok) throw new Error(`warm cache failed: ${response.status}`);
        }"""
    )

    context.set_offline(True)
    try:
        page.reload(wait_until="domcontentloaded", timeout=15000)
        expect(page.locator(".offline-card")).to_be_visible(timeout=10000)
        expect(page.locator(".offline-card svg")).to_be_visible()
        assert page.locator("body").inner_text().strip()
        cached = page.evaluate(
            """async () => {
              const response = await fetch('/static/css/style.css?v=offline-query');
              return response.ok && (await response.text()).length > 100;
            }"""
        )
        assert cached, "Query-string static asset was not served from the offline cache."
        _capture(page, f"pwa-offline-{path.strip('/') or 'overview'}")
    finally:
        context.set_offline(False)
    _assert_runtime_clean(issues)
    context.close()
