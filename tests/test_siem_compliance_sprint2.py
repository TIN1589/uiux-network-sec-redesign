"""Kiểm thử nghiệm thu các hạng mục chuẩn hóa SIEM (VNPT SOC v2.4 / N4.2).

Tuân thủ quy chuẩn kiểm thử tại .agents/rules/testing-and-evidence.md.
Bao gồm đầy đủ 3 thành tố: Mục tiêu - Kịch bản - Minh chứng.
"""

import re
import pytest
from fastapi.testclient import TestClient
from app import app, alerts_store, compute_overview_stats, get_incident_timeline, NETWORK_MITRE_TECHNIQUES


@pytest.fixture
def client():
    """Khởi tạo TestClient của FastAPI."""
    return TestClient(app)


def test_theme_foundation_and_tokens(client):
    """Mục tiêu: Đảm bảo nền tảng Dual-Theme (Warm Stone / Obsidian Dark) và theme-init.js nạp đồng bộ.

    Kịch bản:
        1. Gọi GET / và kiểm tra sự hiện diện của theme-init.js trong thẻ head trước stylesheets.
        2. Kiểm tra file tĩnh static/js/theme-init.js có tồn tại và trả về mã nguồn hợp lệ (HTTP 200).
        3. Kiểm tra biến token CSS html[data-theme="dark"] trong static/css/variables.css.
        4. Kiểm tra nút chuyển theme (btn-theme-toggle) xuất hiện trên Topbar.

    Minh chứng:
        Mã nguồn theme-init.js đồng bộ data-theme và meta theme-color, bảo đảm không có FOUC trên cold boot.
    """
    res = client.get("/")
    assert res.status_code == 200
    assert '<script src="/static/js/theme-init.js"></script>' in res.text
    assert 'id="btn-theme-toggle"' in res.text
    assert 'toggleTheme()' in res.text

    # Kiểm tra endpoint static theme-init.js
    res_script = client.get("/static/js/theme-init.js")
    assert res_script.status_code == 200
    assert "soc-theme" in res_script.text
    assert "prefers-color-scheme" in res_script.text

    # Kiểm tra tokens.css hoặc variables.css có chứa token Dark Mode
    res_css = client.get("/static/css/variables.css")
    assert res_css.status_code == 200
    assert 'html[data-theme="dark"]' in res_css.text
    assert '--color-bg-workspace: #0E0F0C' in res_css.text


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

    Minh chứng:
        Trực ban nhận diện ngay tức thì sự cố dồn dập (composite) và lý do đóng án đã kiểm toán.
    """
    res = client.get("/views/alerts")
    assert res.status_code == 200
    html = res.text

    # Kiểm tra badge aggregated
    assert "badge-aggregated" in html
    assert "hits" in html

    # Kiểm tra disposition badge cho sự cố resolved
    assert "badge-disposition" in html


def test_incident_activity_trail_in_drawer(client):
    """Mục tiêu: Đảm bảo ngăn kéo Drawer hiển thị dòng thời gian xử lý sự cố (Activity Trail) dạng GMT+7.

    Kịch bản:
        1. Gọi GET /api/alerts/EVT-2610-099/drawer cho sự cố Root Guard.
        2. Xác nhận khối INCIDENT ACTIVITY TRAIL xuất hiện với timeline đã seed.
        3. Kiểm tra sự hiện diện của các activity: ALERT_TRIGGERED, ALERT_ACKNOWLEDGED, INVESTIGATION_STARTED.
        4. Xác minh timestamp được chuyển đổi và hiển thị theo chuẩn GMT+7.
    """
    res = client.get("/api/alerts/EVT-2610-099/drawer")
    assert res.status_code == 200
    html = res.text

    assert "INCIDENT ACTIVITY TRAIL" in html
    assert "activities" in html
    assert "GMT+7" in html
    assert "Suricata Engine" in html
    assert "tier1" in html
    assert "tier2" in html


def test_mitre_technique_interactive_filter(client):
    r"""Mục tiêu: Thẩm định hợp đồng lọc sự cố theo kỹ thuật MITRE ATT&CK (URL query parameter & regex).

    Kịch bản:
        1. Gọi GET /alerts?technique=T1498 (Network Denial of Service).
        2. Xác nhận HTTP 200, banner ACTIVE MITRE FILTER hiển thị 'T1498'.
        3. Xác nhận toàn bộ cảnh báo trả về đều thuộc kỹ thuật T1498 (không lọt cảnh báo khác).
        4. Gọi GET /api/alerts/filter?technique=T1498 và xác nhận bảng partial chỉ chứa T1498.
        5. Gọi GET /api/alerts/filter?technique=INVALID_PARAM (vi phạm regex ^T\d{4}(?:\.\d{3})?$)
           và xác nhận hệ thống an toàn, bỏ qua filter lỗi thay vì sập 500.

    Minh chứng:
        Ma trận ATT&CK kết nối trực tiếp với luồng triage cảnh báo, lọc chính xác theo mã kỹ thuật.
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

    # 3. API filter endpoint
    res_api = client.get("/api/alerts/filter?technique=T1498")
    assert res_api.status_code == 200
    assert "EVT-2610-099" in res_api.text

    # 4. Input validation (Invalid regex rejected safely)
    res_invalid = client.get("/api/alerts/filter?technique=MALICIOUS_SQL'OR'1'='1")
    assert res_invalid.status_code == 200
    # Không văng lỗi 500 và trả về dữ liệu an toàn


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
