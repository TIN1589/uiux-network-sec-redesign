"""Kiểm thử dịch vụ dòng log SOC công khai tuân thủ RFC 5737 và các ràng buộc bảo mật."""

import re

import pytest
from fastapi.testclient import TestClient

from app.ui import mock_feed


@pytest.fixture
def client():
    """Tạo client kiểm thử FastAPI chuẩn phục vụ kiểm tra endpoint dòng log.

    Returns:
        TestClient: Phiên client kiểm thử HTTP.
    """
    from app import app
    return TestClient(app)


def test_log_feed_clamping_size(client):
    """Mục tiêu: Đảm bảo tham số size luôn được kẹp trong ngưỡng an toàn 1..5.

    Kịch bản:
        1. Gọi GET /ui/log-feed?size=10 (vượt ngưỡng trên).
        2. Xác nhận chỉ trả về tối đa 5 phần tử log-row.
        3. Gọi GET /ui/log-feed?size=0 hoặc -3 (dưới ngưỡng dưới).
        4. Xác nhận trả về tối thiểu 1 phần tử log-row.
    """
    res_large = client.get("/ui/log-feed?size=10")
    assert res_large.status_code == 200
    assert res_large.text.count('<div class="log-row') == 5

    res_small = client.get("/ui/log-feed?size=-2")
    assert res_small.status_code == 200
    assert res_small.text.count('<div class="log-row') == 1


def test_log_feed_last_line_has_is_new_and_cursor(client):
    """Mục tiêu: Dòng log cuối cùng phải mang class 'is-new' và con trỏ nhấp nháy 'cursor'."""
    res = client.get("/ui/log-feed?size=5")
    assert res.status_code == 200
    assert "is-new" in res.text
    assert 'class="cursor"' in res.text
    # Chỉ dòng cuối cùng mới có is-new
    assert res.text.count("is-new") == 1


def test_log_feed_cache_control_and_robot_headers(client):
    """Mục tiêu: Header phản hồi phải cấm cache và chặn bot tìm kiếm lập chỉ mục."""
    res = client.get("/ui/log-feed?size=3")
    assert res.status_code == 200
    cc = res.headers.get("cache-control", "").lower()
    assert "no-store" in cc
    assert "no-cache" in cc
    assert res.headers.get("x-robots-tag") == "noindex, nofollow"


def test_all_mock_ips_in_test_net_range():
    """Mục tiêu: Bảo mật tuyệt đối - Mọi địa chỉ IP phải nằm trong dải TEST-NET theo RFC 5737.

    Các dải chuẩn bao gồm:
    - 192.0.2.0/24 (TEST-NET-1)
    - 198.51.100.0/24 (TEST-NET-2)
    - 203.0.113.0/24 (TEST-NET-3)
    """
    # Lấy mẫu 100 dòng ngẫu nhiên qua các tick
    ip_pattern = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")

    for tick in range(100):
        line = mock_feed.make_line(tick)
        matches = ip_pattern.findall(line["text"])
        for ip in matches:
            is_valid_test_net = ip.startswith(("192.0.2.", "198.51.100.", "203.0.113."))
            assert is_valid_test_net, f"IP {ip} không thuộc dải TEST-NET RFC 5737!"


def test_deterministic_output_for_same_tick():
    """Mục tiêu: Tính xác định theo thời gian - Cùng một tick cho cùng một dòng log."""
    line1 = mock_feed.make_line(42)
    line2 = mock_feed.make_line(42)
    assert line1 == line2
