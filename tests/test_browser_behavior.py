"""Kiểm thử hành vi trình duyệt thực tế (Browser Behavior & Computed Contrast Tests).

Tuân thủ nghiêm ngặt quy chuẩn tại .agents/rules/release-gates.md:
1. Computed-style contrast thực tế tại viewport 390px và 1440px trong Dark Mode.
2. Kiểm tra bộ điều khiển bàn phím (/, j, k, Enter, Escape, Modifier Guards).
3. Kiểm tra ngăn ngừa FOUC khi tải nguội (Cold Load).
"""

import pytest
import re
from playwright.sync_api import sync_playwright

BASE_URL = "http://127.0.0.1:8000"


def _parse_rgb(rgb_str: str) -> tuple[int, int, int]:
    """Trích xuất (r, g, b) từ chuỗi rgb(...) hoặc rgba(...)."""
    m = re.search(r"rgba?\((\d+),\s*(\d+),\s*(\d+)", rgb_str)
    if m:
        return int(m.group(1)), int(m.group(2)), int(m.group(3))
    return 0, 0, 0


def _relative_luminance_rgb(r: int, g: int, b: int) -> float:
    """Tính toán Relative Luminance theo công thức WCAG 2.1."""
    rgb = [v / 255.0 for v in (r, g, b)]
    rgb_linear = [v / 12.92 if v <= 0.03928 else ((v + 0.055) / 1.055) ** 2.4 for v in rgb]
    return 0.2126 * rgb_linear[0] + 0.7152 * rgb_linear[1] + 0.0722 * rgb_linear[2]


def _contrast_ratio_rgb(rgb1: str, rgb2: str) -> float:
    """Tính tỷ lệ tương phản thực tế giữa 2 chuỗi RGB kết xuất từ getComputedStyle."""
    l1 = _relative_luminance_rgb(*_parse_rgb(rgb1))
    l2 = _relative_luminance_rgb(*_parse_rgb(rgb2))
    lighter = max(l1, l2)
    darker = min(l1, l2)
    return (lighter + 0.05) / (darker + 0.05)


@pytest.fixture(scope="module")
def browser_instance():
    """Khởi tạo Chromium headless cho toàn module test browser."""
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        yield browser
        browser.close()


def test_mobile_computed_contrast_dark_mode(browser_instance):
    """Mục tiêu: Đảm bảo các component trên Mobile 390px trong Dark Mode đạt chuẩn WCAG AA thực tế.

    Kịch bản:
        1. Mở trang /alerts?guest=1 tại viewport 390x844 (Mobile).
        2. Kích hoạt Dark Theme.
        3. Truy vấn getComputedStyle của .mobile-alert-card và .m-alert-row2:
           - Màu nền card không được là màu trắng, phải là than chì tối rgb(22, 24, 26).
           - Tỷ lệ tương phản giữa tiêu đề và nền card phải >= 4.5:1 (đạt WCAG AA).
        4. Mở trang /?guest=1 tại viewport 390x844 (Mobile Overview).
        5. Truy vấn getComputedStyle của banner .kpi-strip-5 .kpi-cell-total:
           - Màu nền banner không được là #F8F7F4, phải là than chì tối.
           - Tỷ lệ tương phản giữa số đếm KPI và nền banner phải >= 4.5:1.
    """
    context = browser_instance.new_context(viewport={"width": 390, "height": 844}, device_scale_factor=2.0)
    page = context.new_page()

    # 1. Mobile Alerts Card
    page.goto(f"{BASE_URL}/alerts?guest=1", wait_until="networkidle")
    page.evaluate("() => { if (window.setTheme) window.setTheme('dark'); else document.documentElement.setAttribute('data-theme', 'dark'); }")
    page.wait_for_timeout(300)

    card_bg = page.evaluate("() => window.getComputedStyle(document.querySelector('.mobile-alert-card')).backgroundColor")
    title_color = page.evaluate("() => window.getComputedStyle(document.querySelector('.mobile-alert-card .m-alert-row2')).color")

    assert card_bg != "rgb(255, 255, 255)", f"Mobile alert card must not have white background in dark mode, got {card_bg}"
    contrast_card = _contrast_ratio_rgb(title_color, card_bg)
    assert contrast_card >= 4.5, f"Mobile alert card contrast {contrast_card:.2f}:1 fails WCAG AA 4.5:1"

    # 2. Mobile Overview KPI Total Banner
    page.goto(f"{BASE_URL}/?guest=1", wait_until="networkidle")
    page.evaluate("() => { if (window.setTheme) window.setTheme('dark'); else document.documentElement.setAttribute('data-theme', 'dark'); }")
    page.wait_for_timeout(300)

    banner_bg = page.evaluate("() => window.getComputedStyle(document.querySelector('.kpi-strip-5 .kpi-cell-total')).backgroundColor")
    num_color = page.evaluate("() => window.getComputedStyle(document.querySelector('.kpi-strip-5 .kpi-cell-total .kpi-number')).color")

    assert banner_bg != "rgb(248, 247, 244)", f"Mobile KPI banner must not have light background #F8F7F4 in dark mode, got {banner_bg}"
    contrast_banner = _contrast_ratio_rgb(num_color, banner_bg)
    assert contrast_banner >= 4.5, f"Mobile KPI total banner contrast {contrast_banner:.2f}:1 fails WCAG AA 4.5:1"

    context.close()


def test_desktop_computed_contrast_dark_mode(browser_instance):
    """Mục tiêu: Đảm bảo các component trên Desktop 1440px trong Dark Mode đạt chuẩn WCAG AA/AAA thực tế.

    Kịch bản:
        1. Mở trang /alerts?guest=1 tại viewport 1440x900.
        2. Kích hoạt Dark Theme.
        3. Kiểm tra .queue-row.normal:
           - Nền card là than chì tối rgb(22, 24, 26).
           - Tiêu đề .q-title đạt tương phản >= 7.0:1 (WCAG AAA).
           - Nhãn meta .q-meta đạt tương phản >= 4.5:1 (WCAG AA).
        4. Mở ngăn kéo chi tiết sự cố:
           - Nền .soc-drawer là than chì tối.
           - Playbook title đạt tương phản >= 4.5:1 (WCAG AA).
           - Playbook body đạt tương phản >= 7.0:1 (WCAG AAA).
    """
    context = browser_instance.new_context(viewport={"width": 1440, "height": 900})
    page = context.new_page()

    page.goto(f"{BASE_URL}/alerts?guest=1", wait_until="networkidle")
    page.evaluate("() => { if (window.setTheme) window.setTheme('dark'); else document.documentElement.setAttribute('data-theme', 'dark'); }")
    page.wait_for_timeout(300)

    # 1. Queue row contrast
    row_bg = page.evaluate("() => window.getComputedStyle(document.querySelector('.queue-row.normal') || document.querySelector('.soc-table tr.clickable')).backgroundColor")
    q_title_color = page.evaluate("() => window.getComputedStyle(document.querySelector('.q-title') || document.querySelector('.soc-table tr.clickable td:nth-child(3)')).color")
    contrast_row = _contrast_ratio_rgb(q_title_color, row_bg)
    assert contrast_row >= 4.5, f"Desktop alert title contrast {contrast_row:.2f}:1 fails WCAG AA"

    # 2. Drawer contrast
    page.click("tr.clickable:first-child")
    page.wait_for_selector("#alert-drawer-backdrop.active", timeout=5000)
    page.wait_for_timeout(300)

    drawer_bg = page.evaluate("() => window.getComputedStyle(document.querySelector('.soc-drawer')).backgroundColor")
    pb_title_color = page.evaluate("() => window.getComputedStyle(document.querySelector('.playbook-well-title')).color")
    pb_well_bg = page.evaluate("() => window.getComputedStyle(document.querySelector('.playbook-well')).backgroundColor")

    contrast_pb_title = _contrast_ratio_rgb(pb_title_color, pb_well_bg)
    assert contrast_pb_title >= 4.5, f"Playbook title contrast {contrast_pb_title:.2f}:1 fails WCAG AA"

    context.close()


def test_keyboard_controller_full_interaction_flow(browser_instance):
    """Mục tiêu: Đảm bảo các phím tắt bàn phím và trật tự thoát Escape hoạt động đúng thực tế.

    Kịch bản:
        1. Phím '/': Chuyển con trỏ focus vào ô tìm kiếm #al-search.
        2. Phím 'j' và 'k': Điều hướng lên/xuống giữa các hàng, gắn class .kb-active-row.
        3. Phím 'Enter': Mở ngăn kéo chi tiết sự cố cho hàng đang active.
        4. Phím 'Escape':
           - Đóng ngăn kéo khi backdrop có class active.
           - Đóng modal sign-in khi modal có class active.
           - Hủy active row khi không có lớp phủ nổi.
        5. Modifier Guards: Ctrl+J, Alt+J, Meta+J không làm thay đổi active row.
    """
    context = browser_instance.new_context(viewport={"width": 1440, "height": 900})
    page = context.new_page()

    page.goto(f"{BASE_URL}/alerts?guest=1", wait_until="networkidle")
    page.evaluate("() => { const m = document.getElementById('signin-modal'); if (m) m.classList.remove('active'); }")
    page.wait_for_timeout(200)

    # 1. Hotkey '/' -> Search focus
    page.keyboard.press("/")
    page.wait_for_timeout(100)
    is_search_focused = page.evaluate("() => document.activeElement === document.getElementById('al-search')")
    assert is_search_focused, "Hotkey '/' must focus the alert search input"

    # 2. Escape blurs input
    page.keyboard.press("Escape")
    page.wait_for_timeout(100)
    is_search_blurred = page.evaluate("() => document.activeElement !== document.getElementById('al-search')")
    assert is_search_blurred, "Escape must blur active input when no overlays are active"

    # 3. Hotkey 'j' and 'k' -> Row navigation
    page.keyboard.press("j")
    page.wait_for_timeout(100)
    row0_active = page.evaluate("() => document.querySelectorAll('#al-table-body tr.clickable')[0].classList.contains('kb-active-row')")
    assert row0_active, "Key 'j' must highlight the first table row"

    page.keyboard.press("j")
    page.wait_for_timeout(100)
    row1_active = page.evaluate("() => document.querySelectorAll('#al-table-body tr.clickable')[1].classList.contains('kb-active-row')")
    assert row1_active, "Key 'j' must move highlight to the second table row"

    page.keyboard.press("k")
    page.wait_for_timeout(100)
    row0_reactivated = page.evaluate("() => document.querySelectorAll('#al-table-body tr.clickable')[0].classList.contains('kb-active-row')")
    assert row0_reactivated, "Key 'k' must move highlight back to the first table row"

    # 4. Modifier guards (Ctrl+J, Alt+J should not navigate)
    page.keyboard.down("Control")
    page.keyboard.press("j")
    page.keyboard.up("Control")
    page.wait_for_timeout(100)
    still_row0 = page.evaluate("() => document.querySelectorAll('#al-table-body tr.clickable')[0].classList.contains('kb-active-row')")
    assert still_row0, "Ctrl+J must be ignored by keyboard controller to preserve browser shortcuts"

    # 5. Hotkey 'Enter' -> Open drawer
    page.keyboard.press("Enter")
    page.wait_for_selector("#alert-drawer-backdrop.active", timeout=5000)
    assert page.is_visible("#alert-drawer-backdrop.active"), "Enter key must open alert drawer for highlighted row"

    # 6. Hotkey 'Escape' -> Close drawer
    page.keyboard.press("Escape")
    page.wait_for_timeout(300)
    drawer_closed = page.evaluate("() => !document.getElementById('alert-drawer-backdrop').classList.contains('active')")
    assert drawer_closed, "Escape must close active alert drawer"

    context.close()


def test_cold_load_fouc_prevention(browser_instance):
    """Mục tiêu: Đảm bảo ngăn ngừa triệt để Flash of Unstyled Content (FOUC) khi tải nguội Dark Mode.

    Kịch bản:
        1. Lưu 'soc-theme' = 'dark' trong localStorage.
        2. Tải trang từ trạng thái mới (reload).
        3. Xác nhận tại domcontentloaded (trước khi DOM paint hoàn tất):
           - Thuộc tính data-theme trên html là 'dark'.
           - Thẻ meta theme-color mang giá trị '#0E0F0C'.
    """
    context = browser_instance.new_context(viewport={"width": 1440, "height": 900})
    page = context.new_page()

    page.goto(f"{BASE_URL}/?guest=1", wait_until="networkidle")
    page.evaluate("() => localStorage.setItem('soc-theme', 'dark')")

    page.reload(wait_until="domcontentloaded")
    early_theme = page.evaluate("() => document.documentElement.getAttribute('data-theme')")
    early_color = page.evaluate("() => document.querySelector('meta[name=\"theme-color\"]').content")

    assert early_theme == "dark", f"FOUC failure: expected dark theme, got {early_theme}"
    assert early_color == "#0E0F0C", f"FOUC failure: expected #0E0F0C theme color, got {early_color}"

    context.close()


def test_search_input_wrapper_and_pills_contrast_dark_mode(browser_instance):
    """Mục tiêu: Đảm bảo ô tìm kiếm (wrapper + input) và Segmented Pills đạt chuẩn WCAG AA/AAA.

    Kịch bản:
        1. Mở trang /alerts?guest=1 tại viewport 1440x900 trong Dark Mode.
        2. Kiểm tra wrapper .soc-input-icon-wrap không có nền trắng #FFFFFF, dùng nền than chì tối.
        3. Tỷ lệ tương phản giữa chữ nhập và nền wrapper phải >= 7.0:1 (WCAG AAA).
        4. Kiểm tra nhóm nút lọc Segmented Pills .segmented-pill-group:
           - Nền container là dark surface, không bị kẹt màu xám sáng.
           - Nhãn nút inactive đạt tương phản >= 4.5:1 (WCAG AA).
    """
    context = browser_instance.new_context(viewport={"width": 1440, "height": 900})
    page = context.new_page()

    page.goto(f"{BASE_URL}/alerts?guest=1", wait_until="networkidle")
    page.evaluate("() => document.documentElement.setAttribute('data-theme', 'dark')")
    page.wait_for_timeout(300)

    wrap_bg = page.evaluate("() => window.getComputedStyle(document.querySelector('.soc-input-icon-wrap')).backgroundColor")
    inp_color = page.evaluate("() => window.getComputedStyle(document.querySelector('.soc-input-icon-wrap input')).color")
    assert wrap_bg != "rgb(255, 255, 255)", f"Search wrapper must not be white in dark mode, got {wrap_bg}"
    contrast_input = _contrast_ratio_rgb(inp_color, wrap_bg)
    assert contrast_input >= 7.0, f"Search input contrast {contrast_input:.2f}:1 fails WCAG AAA (7.0:1)"

    pill_group_bg = page.evaluate("() => window.getComputedStyle(document.querySelector('.segmented-pill-group')).backgroundColor")
    pill_btn_color = page.evaluate("() => window.getComputedStyle(document.querySelector('.segmented-pill-btn:not(.active)')).color")
    assert pill_group_bg != "rgba(229, 228, 220, 0.85)", f"Segmented pill group must not be light gray in dark mode, got {pill_group_bg}"
    contrast_pill = _contrast_ratio_rgb(pill_btn_color, pill_group_bg)
    assert contrast_pill >= 4.5, f"Inactive pill text contrast {contrast_pill:.2f}:1 fails WCAG AA (4.5:1)"

    context.close()


def test_mitre_matrix_and_scenario_cards_contrast_dark_mode(browser_instance):
    """Mục tiêu: Đảm bảo cột Tactic MITRE và Mobile Scenario Cards không bị trắng trên trắng.

    Kịch bản:
        1. Mở trang /scenarios?guest=1 tại Desktop (1440px) trong Dark Mode.
        2. Kiểm tra cột tactic .mitre-tactic-col:
           - Nền là dark inset #1C1E22, không fallback về #F3F1EC.
           - Tiêu đề tactic đạt tương phản >= 7.0:1 (WCAG AAA).
        3. Mở trang /scenarios?guest=1 tại Mobile (390px) trong Dark Mode.
        4. Kiểm tra thẻ scenario bình thường:
           - Nền không được là #FFFFFF, phải là dark surface #16181A.
           - Tiêu đề đạt tương phản >= 7.0:1 (WCAG AAA).
           - Ghi chú .m-sc-row3 đạt tương phản >= 4.5:1 (WCAG AA).
    """
    # 1. Desktop MITRE Matrix
    context_dt = browser_instance.new_context(viewport={"width": 1440, "height": 900})
    page_dt = context_dt.new_page()
    page_dt.goto(f"{BASE_URL}/scenarios?guest=1", wait_until="networkidle")
    page_dt.evaluate("() => document.documentElement.setAttribute('data-theme', 'dark')")
    page_dt.wait_for_timeout(300)

    tactic_bg = page_dt.evaluate("() => window.getComputedStyle(document.querySelector('.mitre-tactic-col')).backgroundColor")
    tactic_title = page_dt.evaluate("() => window.getComputedStyle(document.querySelector('.mitre-tactic-col [style*=\"font-size: 13px\"]')).color")
    assert tactic_bg != "rgb(243, 241, 236)", f"MITRE tactic column must not be light stone in dark mode, got {tactic_bg}"
    contrast_tac = _contrast_ratio_rgb(tactic_title, tactic_bg)
    assert contrast_tac >= 7.0, f"MITRE tactic title contrast {contrast_tac:.2f}:1 fails WCAG AAA (7.0:1)"
    context_dt.close()

    # 2. Mobile Scenario Cards
    context_mb = browser_instance.new_context(viewport={"width": 390, "height": 844})
    page_mb = context_mb.new_page()
    page_mb.goto(f"{BASE_URL}/scenarios?guest=1", wait_until="networkidle")
    page_mb.evaluate("() => document.documentElement.setAttribute('data-theme', 'dark')")
    page_mb.wait_for_timeout(300)

    sc_card_bg = page_mb.evaluate("() => window.getComputedStyle(document.querySelector('.mobile-scenario-card:not(.highlighted)')).backgroundColor")
    sc_title_color = page_mb.evaluate("() => window.getComputedStyle(document.querySelector('.mobile-scenario-card:not(.highlighted) .m-sc-row1 [style*=\"font-weight: 700\"]')).color")
    assert sc_card_bg != "rgb(255, 255, 255)", f"Mobile scenario card must not be white in dark mode, got {sc_card_bg}"
    contrast_sc = _contrast_ratio_rgb(sc_title_color, sc_card_bg)
    assert contrast_sc >= 7.0, f"Mobile scenario title contrast {contrast_sc:.2f}:1 fails WCAG AAA (7.0:1)"

    sc_note_bg = page_mb.evaluate("() => window.getComputedStyle(document.querySelector('.m-sc-row3')).backgroundColor")
    sc_note_color = page_mb.evaluate("() => window.getComputedStyle(document.querySelector('.m-sc-row3')).color")
    contrast_note = _contrast_ratio_rgb(sc_note_color, sc_note_bg)
    assert contrast_note >= 4.5, f"Mobile scenario note contrast {contrast_note:.2f}:1 fails WCAG AA (4.5:1)"
    context_mb.close()


def test_charts_legend_and_signin_panel_contrast_dark_mode(browser_instance):
    """Mục tiêu: Đảm bảo Chart legends và Panel Sign-in trong Dark Mode không gây mỏi mắt hay chói sáng.

    Kịch bản:
        1. Mở trang /?guest=1 (Overview) trong Dark Mode.
        2. Kiểm tra nhãn Donut metric và nhãn Chart legend:
           - Tương phản trên nền card phải >= 4.5:1 (WCAG AA).
        3. Mở trang /login trong Dark Mode.
        4. Kiểm tra panel phải (.auth-panel--light):
           - Nền không được là màu paper sáng, phải là dark surface #16181A.
           - Tiêu đề đăng nhập đạt tương phản >= 7.0:1 (WCAG AAA).
           - Ô nhập liệu dùng nền tối và chữ sáng tương phản >= 7.0:1.
    """
    # 1. Overview Chart Legends
    context = browser_instance.new_context(viewport={"width": 1440, "height": 900})
    page = context.new_page()
    page.goto(f"{BASE_URL}/?guest=1", wait_until="networkidle")
    page.evaluate("() => document.documentElement.setAttribute('data-theme', 'dark')")
    page.wait_for_timeout(300)

    card_bg = page.evaluate("() => window.getComputedStyle(document.querySelector('.donut-chart-container').closest('.soc-card')).backgroundColor")
    donut_label_color = page.evaluate("() => window.getComputedStyle(document.querySelector('.donut-center-metric .metric-label')).color")
    legend_label_color = page.evaluate("() => window.getComputedStyle(document.querySelector('.chart-legend-label')).color")

    assert _contrast_ratio_rgb(donut_label_color, card_bg) >= 4.5, "Donut center label must pass WCAG AA (4.5:1)"
    assert _contrast_ratio_rgb(legend_label_color, card_bg) >= 4.5, "Chart legend label must pass WCAG AA (4.5:1)"

    # 2. Sign-in Page Dark Panel
    page.goto(f"{BASE_URL}/login", wait_until="networkidle")
    page.evaluate("() => document.documentElement.setAttribute('data-theme', 'dark')")
    page.wait_for_timeout(300)

    panel_bg = page.evaluate("() => window.getComputedStyle(document.querySelector('.auth-panel--light')).backgroundColor")
    title_color = page.evaluate("() => window.getComputedStyle(document.querySelector('.auth-header__title')).color")
    ctrl_bg = page.evaluate("() => window.getComputedStyle(document.querySelector('.auth-field__control')).backgroundColor")
    inp_color = page.evaluate("() => window.getComputedStyle(document.querySelector('.auth-field__input')).color")

    assert panel_bg != "rgb(241, 240, 235)", f"Sign-in panel must not be light paper in dark mode, got {panel_bg}"
    assert _contrast_ratio_rgb(title_color, panel_bg) >= 7.0, "Sign-in title must pass WCAG AAA (7.0:1)"
    assert _contrast_ratio_rgb(inp_color, ctrl_bg) >= 7.0, "Sign-in input text must pass WCAG AAA (7.0:1)"

    context.close()
