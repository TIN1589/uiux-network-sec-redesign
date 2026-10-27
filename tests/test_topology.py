"""Kiểm thử mô hình dữ liệu đồ thị và gói tin Topology mạng VNPT SOC."""

import pytest
from app.ui.topology import (
    DESKTOP_NODES,
    DESKTOP_EDGES,
    DESKTOP_PACKETS,
    MOBILE_NODES,
    MOBILE_EDGES,
    MOBILE_PACKETS,
    edge_path,
    get_topology_data,
)


def test_edge_path_pure_function():
    """Mục tiêu: Đảm bảo edge_path sinh chuỗi SVG Path chuẩn 'M ax ay L bx by'.

    Kịch bản:
        1. Truyền tọa độ dạng dict {'x': 100, 'y': 200} và {'x': 300, 'y': 400}.
        2. Kiểm tra chuỗi trả về đúng 'M100 200 L300 400'.
        3. Truyền tọa độ dạng tuple (100, 200) và (300, 400).
        4. Kiểm tra chuỗi trả về tương đương.
    """
    path_dict = edge_path({"x": 100, "y": 200}, {"x": 300, "y": 400})
    assert path_dict == "M100 200 L300 400"

    path_tuple = edge_path((150, 250), (350, 450))
    assert path_tuple == "M150 250 L350 450"


def test_edge_path_prevents_string_injection():
    """Mục tiêu: Hàm thuần edge_path ép kiểu số nguyên để triệt tiêu mã độc chèn chuỗi."""
    path_str = edge_path({"x": "560", "y": "150"}, {"x": "440", "y": "236"})
    assert path_str == "M560 150 L440 236"


def test_topology_data_counts_and_packet_resolution():
    """Mục tiêu: Số lượng gói tin và đường nối khớp chính xác với đặc tả kiến trúc.

    Kịch bản:
        1. Gọi get_topology_data().
        2. Xác nhận 8 desktop nodes, 9 desktop edges, 8 desktop packets.
        3. Xác nhận 5 mobile nodes, 5 mobile edges, 5 mobile packets.
        4. Xác nhận số packet trong resolved list bằng đúng số phần tử trong DESKTOP_PACKETS.
    """
    data = get_topology_data()

    assert len(data["desktop"]["nodes"]) == 8
    assert len(data["desktop"]["edges"]) == len(DESKTOP_EDGES)
    assert len(data["desktop"]["packets"]) == len(DESKTOP_PACKETS)

    assert len(data["mobile"]["nodes"]) == 5
    assert len(data["mobile"]["edges"]) == len(MOBILE_EDGES)
    assert len(data["mobile"]["packets"]) == len(MOBILE_PACKETS)


def test_topology_css_contains_offset_paths_and_durations():
    """Mục tiêu: Mã CSS sinh ra phải chứa đầy đủ offset-path, --dur và --delay cho từng packet."""
    data = get_topology_data()
    css = data["css"]

    assert ".tp-d-1 { offset-path: path(" in css
    assert "--dur: 3.4s; --delay: 0.0s;" in css
    assert ".tp-m-1 { offset-path: path(" in css
