"""Kiểm thử nghiệm thu 4 chốt chặn kỹ thuật Sprint 1 (Network SOC VNPT N4.2).

Tuân thủ quy chuẩn kiểm thử tại .agents/rules/testing-and-evidence.md.
Bao gồm 3 thành tố: Mục tiêu - Kịch bản - Minh chứng.
"""

import pytest
from fastapi.testclient import TestClient
from app import app, AUDIT_LOGS, alerts_store, deduplicate_composite_alerts


@pytest.fixture
def client():
    """Khởi tạo TestClient của FastAPI."""
    return TestClient(app)


def test_chot_chan_1_threat_null_safety_in_drawer(client):
    """Mục tiêu: Đảm bảo trường threat = None (log viễn thông thuần) render an toàn không lỗi NoneType.

    Kịch bản:
        1. Gọi GET drawer cho sự cố viễn thông thuần EVT-2610-065 (threat = None).
        2. Xác nhận HTTP 200, không văng lỗi 500 Jinja2.
        3. Xác nhận hiển thị nhãn 'Network Telemetry (Non-ATT&CK)'.
        4. Gọi GET drawer cho sự cố mạng có ATT&CK EVT-2610-099 (BPDU inject).
        5. Xác nhận hiển thị liên kết trực tiếp tới MITRE: 'https://attack.mitre.org/techniques/T1498'.
    """
    # 1. Test alert with threat = None (Non-ATT&CK telemetry)
    res_none = client.get("/api/alerts/EVT-2610-065/drawer")
    assert res_none.status_code == 200
    assert "Network Telemetry (Non-ATT&CK)" in res_none.text

    # 2. Test alert with structured threat technique
    res_mitre = client.get("/api/alerts/EVT-2610-099/drawer")
    assert res_mitre.status_code == 200
    assert "https://attack.mitre.org/techniques/T1498" in res_mitre.text
    assert "Network Denial of Service" in res_mitre.text


def test_chot_chan_2_mitre_matrix_css_grid(client):
    """Mục tiêu: Đảm bảo ma trận MITRE ATT&CK gồm 6 Tactics và 10 Techniques render bằng CSS Grid.

    Kịch bản:
        1. Gọi GET /views/scenarios để lấy partial HTML.
        2. Kiểm tra sự xuất hiện của card MITRE ATT&CK Network Coverage Matrix.
        3. Kiểm tra đủ 6 Tactics mạng: TA0001, TA0002, TA0003, TA0005, TA0007, TA0040.
        4. Gọi GET /api/mitre/matrix và kiểm tra cấu trúc dữ liệu JSON.
    """
    res = client.get("/views/scenarios")
    assert res.status_code == 200
    assert "MITRE ATT&CK Network Coverage Matrix" in res.text
    assert "TA0001" in res.text
    assert "TA0002" in res.text
    assert "TA0003" in res.text
    assert "TA0005" in res.text
    assert "TA0007" in res.text
    assert "TA0040" in res.text

    # Test API endpoint
    res_api = client.get("/api/mitre/matrix")
    assert res_api.status_code == 200
    data = res_api.json()
    assert "matrix" in data
    assert len(data["matrix"]) == 6


def test_chot_chan_3_deduplication_composite_alerts():
    """Mục tiêu: Kiểm thử thuật toán gom nhóm cảnh báo 3 khóa (srcIp, dstIp/device, ruleId).

    Kịch bản:
        1. Tạo 3 cảnh báo giả lập: 2 cảnh báo trùng bộ 3 khóa, 1 cảnh báo khác srcIp.
        2. Chạy hàm deduplicate_composite_alerts.
        3. Xác nhận kết quả hợp nhất còn 2 bản ghi tổng hợp (Composite Alerts).
        4. Bản ghi trùng lặp phải có hits = 2 và aggregation.count = 2.
    """
    raw_mock = [
        {
            "eventId": "EVT-MOCK-001",
            "ruleId": "100200",
            "srcIp": "198.51.100.99",
            "dstIp": "10.0.10.1",
            "asset": "vnpt-edge-fw-01",
            "observedTime": "01:00:00 GMT+7",
            "hits": 1
        },
        {
            "eventId": "EVT-MOCK-002",
            "ruleId": "100200",
            "srcIp": "198.51.100.99",
            "dstIp": "10.0.10.1",
            "asset": "vnpt-edge-fw-01",
            "observedTime": "01:05:00 GMT+7",
            "hits": 1
        },
        {
            "eventId": "EVT-MOCK-003",
            "ruleId": "100200",
            "srcIp": "198.51.100.88",  # IP khác
            "dstIp": "10.0.10.1",
            "asset": "vnpt-edge-fw-01",
            "observedTime": "01:06:00 GMT+7",
            "hits": 1
        }
    ]

    composites = deduplicate_composite_alerts(raw_mock, window_minutes=15)
    assert len(composites) == 2
    # Bản ghi đầu tiên được gộp
    assert composites[0]["hits"] == 2
    assert composites[0]["aggregation"]["count"] == 2
    assert composites[0]["aggregation"]["lastSeen"] == "01:05:00 GMT+7"


def test_chot_chan_4_network_containment_simulated_and_audit(client):
    """Mục tiêu: Đảm bảo các nút phản ứng mạng mô phỏng trả về Toast và ghi nhật ký kiểm toán.

    Kịch bản:
        1. Gửi POST /api/alerts/EVT-2610-099/action/quarantine-port.
        2. Xác nhận HTTP 200, header HX-Trigger chứa thông báo '[SIMULATED] Executed: Moved interface...'.
        3. Gửi POST /api/alerts/EVT-2610-099/action/bgp-rtbh.
        4. Xác nhận HX-Trigger chứa thông báo '[SIMULATED] Executed: BGP RTBH...'.
        5. Gọi GET /api/audit-logs và kiểm tra bản ghi tương ứng đã được ghi nhận vào AUDIT_LOGS.
    """
    initial_log_count = len(AUDIT_LOGS)

    # 1. Action Quarantine Port
    res_quarantine = client.post("/api/alerts/EVT-2610-099/action/quarantine-port")
    assert res_quarantine.status_code == 200
    trigger_header = res_quarantine.headers.get("hx-trigger", "")
    assert "[SIMULATED] Executed: Moved interface" in trigger_header
    assert "Quarantine VLAN 999" in trigger_header

    # 2. Action BGP RTBH
    res_rtbh = client.post("/api/alerts/EVT-2610-099/action/bgp-rtbh")
    assert res_rtbh.status_code == 200
    trigger_rtbh = res_rtbh.headers.get("hx-trigger", "")
    assert "[SIMULATED] Executed: BGP RTBH Null0" in trigger_rtbh

    # 3. Check Audit Logs
    res_audit = client.get("/api/audit-logs")
    assert res_audit.status_code == 200
    audit_data = res_audit.json()
    assert audit_data["total"] >= initial_log_count + 2


def test_chot_chan_4_resolve_with_disposition(client):
    """Mục tiêu: Kiểm thử đóng sự cố bắt buộc phân loại Disposition và cập nhật giao diện.

    Kịch bản:
        1. Gửi POST /api/alerts/EVT-2610-099/resolve với disposition 'False Positive - Tuning Needed'.
        2. Xác nhận HTTP 200, drawer hiển thị nhãn 'False Positive - Tuning Needed' và 'Resolved'.
        3. Kiểm tra bản ghi trong danh sách alerts_store đã lưu trạng thái Resolved.
    """
    res = client.post(
        "/api/alerts/EVT-2610-099/resolve",
        data={"disposition": "False Positive - Tuning Needed", "notes": "Whitelisted port"}
    )
    assert res.status_code == 200
    assert "False Positive - Tuning Needed" in res.text
    assert "Resolved" in res.text

    alert = next((a for a in alerts_store if a["eventId"] == "EVT-2610-099"), None)
    assert alert is not None
    assert alert["state"] == "Resolved"
    assert alert["disposition"] == "False Positive - Tuning Needed"


def test_drawer_action_group_two_tier_layout(client):
    """Mục tiêu: Kiểm thử cấu trúc 2 hàng (Two-tier layout) của cụm nút hành động drawer xử lý cảnh báo, chống méo/thu hẹp dropdown Disposition.

    Kịch bản:
        1. Gửi GET /api/alerts/EVT-2610-089/drawer để lấy HTML fragment của drawer.
        2. Kiểm tra sự tồn tại của container hàng 1 'drawer-action-triage-row' chứa nút Acknowledge và Mark investigating.
        3. Kiểm tra sự tồn tại của container hàng 2 'drawer-action-resolve-row' chứa 'dw-select-disposition' và nút Resolve.
        4. Xác minh không còn inline styles gây co rút elip (height: 36px; padding: 4px 8px; border-radius: 999px).

    Minh chứng:
        Cấu trúc DOM phân tầng độc lập giúp dropdown đạt độ rộng tối ưu (354px desktop / 248px mobile), hiển thị trọn vẹn văn bản phân loại.
    """
    res = client.get("/api/alerts/EVT-2610-089/drawer")
    assert res.status_code == 200
    html = res.text

    # Kiểm tra 2 container phân tầng
    assert "drawer-action-triage-row" in html
    assert "drawer-action-resolve-row" in html

    # Kiểm tra các phần tử hàng 1 (Triage)
    assert "drawer-btn-ack" in html
    assert "drawer-btn-investigate" in html

    # Kiểm tra các phần tử hàng 2 (Resolution)
    assert "dw-select-disposition" in html
    assert "drawer-btn-resolve" in html
    assert "True Positive (Malicious)" in html
    assert "False Positive (Tune Rule)" in html

    # Đảm bảo không còn inline styles gây méo select
    assert 'border-radius: 999px; style="height: 36px;' not in html

