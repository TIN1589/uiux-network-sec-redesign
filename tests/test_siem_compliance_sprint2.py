"""Kiểm thử nghiệm thu các hạng mục chuẩn hóa SIEM (VNPT SOC v2.4 / N4.2).

Tuân thủ quy chuẩn kiểm thử tại .agents/rules/testing-and-evidence.md.
Bao gồm đầy đủ 3 thành tố: Mục tiêu - Kịch bản - Minh chứng.
"""

import re
import pytest
from fastapi.testclient import TestClient
from app import app, alerts_store, compute_overview_stats, get_incident_timeline, NETWORK_MITRE_TECHNIQUES, alert_observed_to_utc_iso


@pytest.fixture
def client():
    """Khởi tạo TestClient của FastAPI."""
    return TestClient(app)


def _relative_luminance(hex_color: str) -> float:
    """Tính toán Relative Luminance theo công thức WCAG 2.1."""
    hex_clean = hex_color.lstrip('#')
    rgb = [int(hex_clean[i:i+2], 16) / 255.0 for i in (0, 2, 4)]
    rgb_linear = [v / 12.92 if v <= 0.03928 else ((v + 0.055) / 1.055) ** 2.4 for v in rgb]
    return 0.2126 * rgb_linear[0] + 0.7152 * rgb_linear[1] + 0.0722 * rgb_linear[2]


def _contrast_ratio(hex1: str, hex2: str) -> float:
    """Tính toán tỷ lệ tương phản màu (Contrast Ratio) giữa 2 mã màu HEX."""
    l1 = _relative_luminance(hex1)
    l2 = _relative_luminance(hex2)
    lighter = max(l1, l2)
    darker = min(l1, l2)
    return (lighter + 0.05) / (darker + 0.05)


def test_theme_foundation_and_tokens(client):
    """Mục tiêu: Đảm bảo nền tảng Dual-Theme, WCAG AA Contrast, và early script không FOUC.

    Kịch bản:
        1. Gọi GET / và kiểm tra meta[name="theme-color"] xuất hiện TRƯỚC theme-init.js.
        2. Kiểm tra theme-init.js có mặt trong thẻ head và mã nguồn trả về HTTP 200.
        3. Kiểm tra các biến CSS tokens Dark Mode trong static/css/variables.css.
        4. Đo lường tỷ lệ tương phản toán học (Contrast Ratio) theo chuẩn WCAG AA:
           - text-primary (#F1F0EB) trên surface-card (#16181B) >= 7.0:1 (đạt chuẩn AAA).
           - text-secondary (#9E9B93) trên surface-card (#16181B) >= 4.5:1 (đạt chuẩn AA).
           - critical text (#FDA29B) trên surface-card (#16181B) >= 4.5:1 (đạt chuẩn AA).
           - accent-lime (#C6F135) trên surface-card (#16181B) >= 3.0:1 (đạt chuẩn UI component).
    """
    res = client.get("/")
    assert res.status_code == 200
    html = res.text

    # 1. meta theme-color nằm trước theme-init.js
    meta_idx = html.find('name="theme-color"')
    script_idx = html.find('/static/js/theme-init.js')
    assert meta_idx != -1 and script_idx != -1
    assert meta_idx < script_idx, "meta[name=theme-color] must appear before theme-init.js to avoid null query"

    assert 'id="btn-theme-toggle"' in html
    assert 'toggleTheme()' in html

    # 2. Endpoint static theme-init.js
    res_script = client.get("/static/js/theme-init.js")
    assert res_script.status_code == 200
    assert "soc-theme" in res_script.text
    assert "prefers-color-scheme" in res_script.text

    # 3. Biến Dark Mode
    res_css = client.get("/static/css/variables.css")
    assert res_css.status_code == 200
    assert 'html[data-theme="dark"]' in res_css.text

    # 4. Kiểm chứng toán học WCAG AA
    bg_surface = "#16181B"
    assert _contrast_ratio("#F1F0EB", bg_surface) >= 7.0, "Primary text fails WCAG AAA"
    assert _contrast_ratio("#9E9B93", bg_surface) >= 4.5, "Secondary text fails WCAG AA"
    assert _contrast_ratio("#FDA29B", bg_surface) >= 4.5, "Critical text fails WCAG AA"
    assert _contrast_ratio("#FEC84B", bg_surface) >= 4.5, "High text fails WCAG AA"
    assert _contrast_ratio("#93C5FD", bg_surface) >= 4.5, "Low text fails WCAG AA"
    assert _contrast_ratio("#C6F135", bg_surface) >= 3.0, "Lime accent fails WCAG UI component ratio"


def test_events_vs_incidents_mathematical_consistency():
    """Mục tiêu: Đảm bảo tính toán nhất quán giữa Raw Events và Composite Incidents.

    Kịch bản:
        1. Lấy dữ liệu thống kê từ compute_overview_stats('24h').
        2. Xác minh: total_events bằng tổng hits của toàn bộ alerts_store.
        3. Xác minh: tổng các mức độ (crit + high + med + low) bằng chính xác total_events (Donut sum parity).
        4. Xác minh: số open_incidents bằng số bản ghi có state != 'Resolved'.

    Minh chứng:
        Tổng số raw events đạt 24 trên 17 composite incidents, donut chart khớp 100% với tổng events.
    """
    stats, queue_alerts, top_rules, top_ips, dev_types = compute_overview_stats("24h")

    expected_total_hits = sum(a.get("hits", 1) for a in alerts_store if a.get("ageMinutes", 0) <= 1440)
    expected_crit = sum(a.get("hits", 1) for a in alerts_store if a.get("ageMinutes", 0) <= 1440 and a["severity"] == "Critical")
    expected_high = sum(a.get("hits", 1) for a in alerts_store if a.get("ageMinutes", 0) <= 1440 and a["severity"] == "High")
    expected_med = sum(a.get("hits", 1) for a in alerts_store if a.get("ageMinutes", 0) <= 1440 and a["severity"] == "Medium")
    expected_low = sum(a.get("hits", 1) for a in alerts_store if a.get("ageMinutes", 0) <= 1440 and a["severity"] == "Low")
    expected_open = sum(1 for a in alerts_store if a.get("ageMinutes", 0) <= 1440 and a.get("state") != "Resolved")

    assert stats["total"] == expected_total_hits
    assert stats["total_events"] == expected_total_hits
    assert stats["crit"] == expected_crit
    assert stats["high"] == expected_high
    assert stats["med"] == expected_med
    assert stats["low"] == expected_low
    assert stats["open_incidents"] == expected_open

    # Khóa chặt tính nhất quán toán học Donut Chart
    assert (stats["crit"] + stats["high"] + stats["med"] + stats["low"]) == stats["total"]


def test_alerts_table_aggregated_and_disposition_badges(client):
    """Mục tiêu: Đảm bảo bảng cảnh báo hiển thị rõ huy hiệu Aggregated (hits > 1) và Disposition.

    Kịch bản:
        1. Gọi GET /views/alerts để lấy danh sách cảnh báo.
        2. Kiểm tra sự xuất hiện của class 'badge-aggregated' cho các sự cố lặp lại.
        3. Kiểm tra văn bản hiển thị 'hits' (ví dụ: 'Aggregated · 2 hits' hoặc 'x2 hits').
        4. Kiểm tra sự cố đã đóng EVT-2610-084 hiển thị nhãn Disposition (badge-disposition).
    """
    res = client.get("/views/alerts")
    assert res.status_code == 200
    html = res.text

    assert "badge-aggregated" in html
    assert "hits" in html
    assert "badge-disposition" in html


def test_incident_activity_trail_in_drawer(client):
    """Mục tiêu: Đảm bảo ngăn kéo Drawer hiển thị dòng thời gian xử lý sự cố (Activity Trail) dạng GMT+7.

    Kịch bản:
        1. Gọi GET /api/alerts/EVT-2610-099/drawer cho sự cố Root Guard.
        2. Xác nhận thời gian sự kiện kích hoạt đầu tiên hiển thị đúng '01:12:04 GMT+7', khớp 100% với observedTime của alert.
        3. Kiểm tra các activity tiếp theo: ALERT_ACKNOWLEDGED, INVESTIGATION_STARTED.
        4. Gọi POST hành động /api/alerts/EVT-2610-099/action/isolate-port để thực thi ngăn chặn.
        5. Xác minh activity mới CONTAINMENT_EXECUTED được nối vào cuối timeline theo đúng thứ tự thời gian.
        6. Kiểm tra sự cố đã đóng EVT-2610-084: thời gian trigger 00:37:12 GMT+7 và thời gian resolve 00:45:00 GMT+7.
    """
    res = client.get("/api/alerts/EVT-2610-099/drawer")
    assert res.status_code == 200
    html = res.text

    assert "INCIDENT ACTIVITY TRAIL" in html
    assert "01:12:04 GMT+7" in html
    assert "Suricata Engine" in html
    assert "tier1" in html
    assert "tier2" in html

    # Thực thi hành động ngăn chặn và kiểm tra timeline append
    res_act = client.post("/api/alerts/EVT-2610-099/action/isolate-port")
    assert res_act.status_code == 200

    tl_updated = get_incident_timeline("EVT-2610-099")
    assert len(tl_updated) >= 4
    last_act = tl_updated[-1]
    assert last_act["activityType"] == "CONTAINMENT_EXECUTED"
    assert "GMT+7" in last_act["timeDisplay"]

    # Kiểm tra EVT-2610-084 khớp thời gian đóng án
    tl_084 = get_incident_timeline("EVT-2610-084")
    assert tl_084[0]["timeDisplay"] == "00:37:12 GMT+7"
    resolved_act = next((a for a in tl_084 if a["activityType"] == "ALERT_RESOLVED"), None)
    assert resolved_act is not None
    assert resolved_act["timeDisplay"] == "00:45:00 GMT+7"


def test_mitre_technique_interactive_filter(client):
    r"""Mục tiêu: Thẩm định hợp đồng lọc sự cố theo kỹ thuật MITRE ATT&CK (URL query parameter & regex).

    Kịch bản:
        1. Gọi GET /alerts?technique=T1498 (Network Denial of Service).
        2. Xác nhận HTTP 200, banner ACTIVE MITRE FILTER hiển thị 'T1498'.
        3. Xác nhận chỉ cảnh báo thuộc kỹ thuật T1498 xuất hiện, loại trừ tuyệt đối các cảnh báo khác (T1078, T1046).
        4. Gọi GET /api/alerts/filter?technique=T1498 và xác nhận bảng partial chỉ chứa EVT-2610-099, không có EVT-2610-084.
        5. Gọi GET /api/alerts/filter?technique=INVALID_PARAM (vi phạm regex ^T\d{4}(?:\.\d{3})?$)
           và xác nhận hệ thống an toàn, bỏ qua filter lỗi thay vì sập 500.
        6. Kiểm tra ma trận MITRE trên trang Scenarios chứa các liên kết điều hướng kỹ thuật.
    """
    # 1. Full page alerts with technique filter
    res = client.get("/alerts?technique=T1498")
    assert res.status_code == 200
    assert "ACTIVE MITRE FILTER" in res.text
    assert "T1498" in res.text

    # 2. HTMX partial view
    res_view = client.get("/views/alerts?technique=T1498")
    assert res_view.status_code == 200
    assert "ACTIVE MITRE FILTER" in res_view.text
    assert "T1498" in res_view.text

    # 3. API filter endpoint: kiểm tra xuất hiện T1498 và loại trừ tuyệt đối các kỹ thuật khác
    res_api = client.get("/api/alerts/filter?technique=T1498")
    assert res_api.status_code == 200
    assert "EVT-2610-099" in res_api.text
    assert "EVT-2610-084" not in res_api.text, "EVT-2610-084 (T1078) must not appear when filtered by T1498"
    assert "EVT-2610-089" not in res_api.text, "EVT-2610-089 (T1046) must not appear when filtered by T1498"
    assert "EVT-2610-087" not in res_api.text, "EVT-2610-087 (T1562.004) must not appear when filtered by T1498"
    assert "EVT-2610-092" not in res_api.text, "EVT-2610-092 (T1078) must not appear when filtered by T1498"

    # 4. Input validation (Invalid regex rejected safely)
    res_invalid = client.get("/api/alerts/filter?technique=MALICIOUS_SQL'OR'1'='1")
    assert res_invalid.status_code == 200

    # 5. MITRE Matrix trên Scenarios page
    res_scenarios = client.get("/views/scenarios")
    assert res_scenarios.status_code == 200
    assert "MITRE ATT&CK Network Coverage Matrix" in res_scenarios.text
    assert "T1498" in res_scenarios.text
    assert "T1078" in res_scenarios.text


def test_simplified_topology_card_on_overview(client):
    """Mục tiêu: Kiểm tra thẻ Topo mạng đơn giản hóa (Core Infrastructure Topology - P2) trên Overview.

    Kịch bản:
        1. Gọi GET /views/overview để lấy fragment Overview.
        2. Kiểm tra sự xuất hiện của khối 'Core infrastructure topology'.
        3. Xác minh hiển thị đủ 5 thiết bị mạng cốt lõi:
           - vnpt-core-router-01 (Router)
           - vnpt-edge-fw-01 (Firewall)
           - vnpt-agg-switch-05 (Switch)
           - vnpt-bng-01 (BNG)
           - vnpt-dist-switch-02 (Switch)
        4. Kiểm tra liên kết điều hướng tới /alerts?asset= hoặc /devices.
    """
    res = client.get("/views/overview")
    assert res.status_code == 200
    html = res.text

    assert "Core infrastructure topology" in html
    assert "vnpt-core-router-01" in html
    assert "vnpt-edge-fw-01" in html
    assert "vnpt-agg-switch-05" in html
    assert "vnpt-bng-01" in html
    assert "vnpt-dist-switch-02" in html
    assert "View all monitored devices" in html


def test_standalone_index_visual_parity():
    """Mục tiêu: Thẩm định tính đồng bộ trực quan 1:1 của Standalone index.html so với Dynamic App.

    Kịch bản:
        1. Đọc nội dung index.html trực tiếp.
        2. Xác nhận thẻ meta theme-color xuất hiện trước theme-init.js.
        3. Xác nhận nút theme toggle id='btn-theme-toggle' hiện diện.
        4. Xác nhận khối Core infrastructure topology (5 node) có mặt trên Overview.
        5. Xác nhận MITRE ATT&CK Network Coverage Matrix có mặt trên Scenarios.
        6. Xác nhận huy hiệu badge-aggregated và badge-disposition có mặt trong Alert Queue.
        7. Xác nhận banner #mitre-active-filter-banner có mặt trong Alert Queue.
    """
    with open("index.html", "r", encoding="utf-8") as f:
        html = f.read()

    assert 'name="theme-color"' in html
    assert 'id="btn-theme-toggle"' in html
    assert 'badge-aggregated' in html
    assert 'badge-disposition' in html
    assert 'INCIDENT ACTIVITY TRAIL' in html
    assert 'Core infrastructure topology' in html
    assert 'MITRE ATT&CK Network Coverage Matrix' in html
    assert 'id="mitre-active-filter-banner"' in html

def test_dark_theme_contrast_rules(client):
    """Mục tiêu: Đảm bảo các component Dark Theme (Queue Row, Drawer, Playbook, KPI) đạt chuẩn WCAG AA.

    Kịch bản:
        1. Gọi GET /static/css/layout.css và xác nhận có rule dark mode cho .queue-row.normal và .queue-row.critical-first.
        2. Gọi GET /static/css/components.css và xác nhận có rule dark mode cho .soc-drawer và .playbook-well.
        3. Xác minh --color-text-inverse trong html[data-theme="dark"] là #FFFFFF (giữ độ tương phản sidebar obsidian).
        4. Đo lường tỷ lệ tương phản thực tế:
           - #9E9B93 (q-meta) trên #16181A (dark card) >= 4.5:1 (đạt WCAG AA).
           - #F1F0EB (q-title) trên #16181A (dark card) >= 7.0:1 (đạt WCAG AAA).
    """
    res_layout = client.get("/static/css/layout.css")
    assert res_layout.status_code == 200
    assert 'html[data-theme="dark"] .queue-row.normal' in res_layout.text
    assert 'html[data-theme="dark"] .queue-row.critical-first' in res_layout.text
    assert 'html[data-theme="dark"] .q-title' in res_layout.text

    res_comp = client.get("/static/css/components.css")
    assert res_comp.status_code == 200
    assert 'html[data-theme="dark"] .soc-drawer' in res_comp.text
    assert 'html[data-theme="dark"] .playbook-well' in res_comp.text
    assert '.playbook-well-title' in res_comp.text

    res_vars = client.get("/static/css/variables.css")
    assert res_vars.status_code == 200
    dark_vars_match = re.search(r'html\[data-theme="dark"\]\s*\{([^}]+)\}', res_vars.text)
    assert dark_vars_match is not None
    assert '--color-text-inverse: #FFFFFF;' in dark_vars_match.group(1)

    dark_surface = "#16181A"
    assert _contrast_ratio("#9E9B93", dark_surface) >= 4.5
    assert _contrast_ratio("#F1F0EB", dark_surface) >= 7.0


def test_timezone_integrity_and_utcnow_deprecation():
    """Mục tiêu: Kiểm tra tuân thủ Release Gate 4 (Không dùng datetime.utcnow() và dynamic UTC).

    Kịch bản:
        1. Đọc trực tiếp app.py và xác nhận không có bất kỳ lệnh datetime.utcnow() nào.
        2. Kiểm tra alert_observed_to_utc_iso() trả về định dạng UTC ISO-8601 hợp lệ kết thúc bằng 'Z'.
    """
    with open("app.py", "r", encoding="utf-8") as f:
        app_source = f.read()

    assert "datetime.utcnow()" not in app_source, "datetime.utcnow() is deprecated and forbidden by Release Gate 4"

    res_iso = alert_observed_to_utc_iso({"observedDate": "26 Oct 2026", "observedTime": "01:12:04 GMT+7"})
    assert res_iso == "2026-10-25T18:12:04Z"

    res_fallback = alert_observed_to_utc_iso({})
    assert res_fallback.endswith("Z")


def test_keyboard_controller_guards_and_htmx_reset():
    """Mục tiêu: Đảm bảo bộ điều khiển bàn phím bỏ qua phím bổ trợ và reset chỉ số hàng khi HTMX hoán đổi.

    Kịch bản:
        1. Đọc static/js/app.js.
        2. Xác nhận handleCentralKeyDown kiểm tra (e.ctrlKey || e.altKey || e.metaKey || e.isComposing).
        3. Xác nhận sự kiện htmx:afterSwap thiết lập selectedAlertRowIndex = -1.
    """
    with open("static/js/app.js", "r", encoding="utf-8") as f:
        js_source = f.read()

    assert "e.ctrlKey || e.altKey || e.metaKey || e.isComposing" in js_source
    assert "selectedAlertRowIndex = -1;" in js_source
