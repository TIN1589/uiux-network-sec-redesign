"""Kiểm thử mô hình dữ liệu đồ thị và gói tin Topology mạng VNPT SOC."""

from app.ui.topology import (
    DESKTOP_EDGES,
    DESKTOP_PACKETS,
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


def test_motion_css_multi_tier_topology_animations():
    """Mục tiêu: Đảm bảo motion.css chứa đầy đủ 3 tầng hiệu ứng chuyển động vi mô.

    Kịch bản:
        1. Đọc nội dung tệp static/css/motion.css.
        2. Kiểm tra Tầng 1 (Constellation Drift): will-change, keyframes desktop và mobile.
        3. Kiểm tra Tầng 2A (Edge Breathing): keyframe edge-breathe với stroke lime.
        4. Kiểm tra Tầng 2B (Light Twinkle & Beacon Glow): node-twinkle, node-core-beacon, node-alert-double-flash.
        5. Kiểm tra Cơ chế Staggered Delays và Accessibility prefers-reduced-motion.
    """
    import os
    css_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "static", "css", "motion.css")
    with open(css_path, "r", encoding="utf-8") as f:
        content = f.read()

    # Tầng 1: Constellation Drift
    assert "will-change: transform" in content
    assert "@keyframes constellation-drift-desktop" in content
    assert "@keyframes constellation-drift-mobile" in content
    assert "translate3d" in content

    # Tầng 2A: Micro Edge Breathing
    assert "@keyframes edge-breathe" in content
    assert "rgba(198, 241, 53, 0.32)" in content

    # Tầng 2B: Light Twinkle & Beacon Glow
    assert "transform-box: fill-box;" in content
    assert "transform-origin: center;" in content
    assert "will-change: opacity, filter, transform;" in content

    # Node twinkle (đốm thường)
    assert "@keyframes node-twinkle-desktop" in content
    assert "@keyframes node-twinkle-mobile" in content
    assert "drop-shadow(0 0 7px var(--accent))" in content
    assert "brightness(1.25)" in content

    # Node core (máy chủ trung tâm 2 tầng hào quang trên desktop)
    assert "@keyframes node-core-beacon-desktop" in content
    assert "@keyframes node-core-beacon-mobile" in content
    assert "drop-shadow(0 0 10px var(--accent)) drop-shadow(0 0 20px rgba(198, 241, 53, 0.35))" in content

    # Node alert (chớp kép double flash)
    assert "@keyframes node-alert-double-flash-desktop" in content
    assert "@keyframes node-alert-double-flash-mobile" in content
    assert "drop-shadow(0 0 8px var(--warn))" in content

    # Staggered Delays trên Desktop (8 trạm)
    assert ".node--core" in content
    assert "animation-delay: 0.2s;" in content
    assert "animation-delay: 1.4s;" in content
    assert "animation-delay: 2.5s;" in content
    assert "animation-delay: 0.7s;" in content
    assert "animation-delay: 3.1s;" in content
    assert "animation-delay: 1.8s;" in content
    assert "animation-delay: 2.9s;" in content

    # Staggered Delays trên Mobile (5 trạm)
    assert "animation-delay: 0.9s;" in content
    assert "animation-delay: 2.7s;" in content
    assert "animation-delay: 1.3s;" in content

    # Accessibility: prefers-reduced-motion
    assert "prefers-reduced-motion: reduce" in content
