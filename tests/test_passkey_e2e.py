"""Real Chromium WebAuthn ceremony using a CDP virtual authenticator."""

from playwright.sync_api import expect, sync_playwright

BASE_URL = "http://localhost:8000"


def _wait_dashboard(page) -> None:
    page.wait_for_selector("#main-content", state="visible", timeout=10000)
    if page.locator("#pwa-splash-overlay").count():
        page.wait_for_selector("#pwa-splash-overlay", state="detached", timeout=5000)


def _password_login(page) -> None:
    page.goto(f"{BASE_URL}/login", wait_until="networkidle")
    page.fill("#field-username", "admin")
    page.fill("#field-password", "vnpt-soc-2026")
    page.click("#signin-btn")
    page.wait_for_url(f"{BASE_URL}/", timeout=10000)
    _wait_dashboard(page)


def _logout(page) -> None:
    result = page.evaluate(
        """async () => {
          const csrf = await fetch('/api/auth/csrf-token', {
            credentials: 'same-origin', cache: 'no-store'
          }).then((response) => response.json());
          const response = await fetch('/api/auth/logout', {
            method: 'POST',
            credentials: 'same-origin',
            headers: {'X-CSRF-Token': csrf.csrf_token}
          });
          return response.status;
        }"""
    )
    assert result == 200


def test_passkey_register_login_manage_and_revoke_in_real_chromium():
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        context = browser.new_context(viewport={"width": 1280, "height": 900})
        page = context.new_page()
        cdp = context.new_cdp_session(page)
        cdp.send("WebAuthn.enable")
        authenticator = cdp.send(
            "WebAuthn.addVirtualAuthenticator",
            {
                "options": {
                    "protocol": "ctap2",
                    "transport": "internal",
                    "hasResidentKey": True,
                    "hasUserVerification": True,
                    "isUserVerified": True,
                    "automaticPresenceSimulation": True,
                }
            },
        )

        _password_login(page)
        page.click("#analyst-avatar-btn")
        page.click("#passkey-manager-trigger")
        expect(page.locator("#passkey-manager-modal")).to_be_visible()

        page.fill("#passkey-device-label", "E2E virtual authenticator")
        page.fill("#passkey-current-password", "vnpt-soc-2026")
        page.click("#passkey-register-btn")
        expect(page.locator("#passkey-manager-feedback")).to_have_text(
            "Passkey added successfully.", timeout=10000
        )
        card = page.locator(".passkey-card").filter(
            has_text="E2E virtual authenticator"
        )
        expect(card).to_be_visible()
        credentials = cdp.send(
            "WebAuthn.getCredentials",
            {"authenticatorId": authenticator["authenticatorId"]},
        )
        assert len(credentials["credentials"]) == 1

        page.click("#passkey-manager-close")
        _logout(page)
        page.goto(f"{BASE_URL}/login", wait_until="networkidle")
        page.click("#passkey-signin-btn")
        page.wait_for_url(f"{BASE_URL}/", timeout=10000)
        _wait_dashboard(page)

        page.click("#analyst-avatar-btn")
        page.click("#passkey-manager-trigger")
        expect(card).to_be_visible()
        page.fill("#passkey-current-password", "vnpt-soc-2026")
        page.once("dialog", lambda dialog: dialog.accept())
        card.locator(".passkey-remove-btn").click()
        expect(page.locator("#passkey-manager-feedback")).to_have_text(
            "Passkey removed.", timeout=10000
        )
        expect(card).to_have_count(0)

        page.click("#passkey-manager-close")
        _logout(page)
        page.goto(f"{BASE_URL}/login", wait_until="networkidle")
        page.click("#passkey-signin-btn")
        expect(page.locator("#auth-feedback")).to_contain_text(
            "Passkey authentication failed", timeout=10000
        )
        assert page.url == f"{BASE_URL}/login"

        cdp.send(
            "WebAuthn.removeVirtualAuthenticator",
            {"authenticatorId": authenticator["authenticatorId"]},
        )
        context.close()
        browser.close()


def test_passkey_manager_is_keyboard_and_mobile_safe_in_real_chromium():
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        context = browser.new_context(viewport={"width": 390, "height": 844})
        context.add_init_script("localStorage.setItem('soc-theme', 'dark');")
        page = context.new_page()
        _password_login(page)
        page.click("#analyst-avatar-btn")
        page.click("#passkey-manager-trigger")
        modal = page.locator("#passkey-manager-modal")
        expect(modal).to_be_visible()

        metrics = page.evaluate(
            """() => {
              const panel = document.querySelector('.passkey-manager__panel');
              const rect = panel.getBoundingClientRect();
              const style = getComputedStyle(panel);
              return {
                left: rect.left,
                right: rect.right,
                width: rect.width,
                viewport: document.documentElement.clientWidth,
                overflow: panel.scrollWidth > panel.clientWidth + 1,
                background: style.backgroundColor,
                color: style.color,
              };
            }"""
        )
        assert metrics["left"] >= 0
        assert metrics["right"] <= metrics["viewport"] + 1
        assert metrics["width"] <= 390
        assert not metrics["overflow"]
        assert metrics["background"] != metrics["color"]

        page.keyboard.press("Escape")
        expect(modal).to_be_hidden()
        assert page.evaluate("document.activeElement.id") == "analyst-avatar-btn"
        context.close()
        browser.close()
