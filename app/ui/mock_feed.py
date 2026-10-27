"""Bộ phát dữ liệu giả lập phục vụ trang giám sát công khai VNPT SOC.

Tuân thủ nghiêm ngặt nguyên tắc dữ liệu công khai:
Mọi địa chỉ IP chỉ nằm trong các dải TEST-NET được bảo lưu theo chuẩn RFC 5737
(192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24). Tuyệt đối không đọc từ CSDL thật.
"""

from datetime import datetime
import random
from zoneinfo import ZoneInfo

TICK = 2.4
POOL = [
    ("ALERT", "IDS-03 · signature match on 192.0.2.{n}"),
    ("BLOCK", "FW-01 · deny tcp 192.0.2.{n} → :445"),
    ("WARN", "SW-CORE-02 · link flap Gi1/0/12"),
    ("WARN", "RT-EDGE-02 · CPU 87% over 5 min"),
    ("INFO", "RT-EDGE-01 · BGP neighbor established"),
    ("BLOCK", "FW-02 · deny udp 198.51.100.{n} → :161"),
    ("INFO", "SW-ACC-14 · port Gi0/7 up"),
    ("ALERT", "FW-01 · repeated login failures from 203.0.113.{n}"),
    ("INFO", "SYSLOG · collector heartbeat ok"),
]


def make_line(tick: int) -> dict:
    """Tạo một dòng nhật ký giả lập xác định theo giá trị thời điểm tick.

    Args:
        tick: Số nguyên đại diện cho bước thời gian chu kỳ.

    Returns:
        dict: Chứa các trường 'tag', 'text', 'time' theo múi giờ Asia/Ho_Chi_Minh.
    """
    tag, tpl = POOL[tick % len(POOL)]
    n = 2 + random.Random(tick).randrange(240)
    ts = datetime.fromtimestamp(tick * TICK, ZoneInfo("Asia/Ho_Chi_Minh"))
    return {"tag": tag, "text": tpl.format(n=n), "time": ts.strftime("%H:%M:%S")}


def log_lines(now: float, size: int) -> list[dict]:
    """Sinh danh sách dòng nhật ký dựa trên timestamp hiện tại.

    Args:
        now: Timestamp hiện tại tính bằng giây (epoch seconds).
        size: Số lượng dòng yêu cầu (được kẹp chặt trong khoảng từ 1 đến 5).

    Returns:
        list[dict]: Danh sách các bản ghi nhật ký giả lập.
    """
    clamped_size = max(1, min(5, size))
    tick = int(now // TICK)
    return [make_line(t) for t in range(tick - clamped_size + 1, tick + 1)]


def stats() -> dict:
    """Trả về bộ chỉ số thống kê giả lập ban đầu cho màn hình đăng nhập.

    Returns:
        dict: Thống kê số lượng cảnh báo 24h, sự cố critical và thiết bị online.
    """
    return {
        "alerts_24h": 128,
        "critical": 4,
        "devices_online": 42,
    }
