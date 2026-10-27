"""Mô hình dữ liệu và thuật toán đồ thị Topology mạng VNPT SOC.

Nguồn sự thật duy nhất (Single Source of Truth) định nghĩa tọa độ trạm mạng,
đường nối quang/cáp và gói tin dữ liệu chuyển động.
"""

from typing import Any


def edge_path(a: Any, b: Any) -> str:
    """Tạo chuỗi đường dẫn SVG Path 'M{ax} {ay} L{bx} {by}' nối giữa hai trạm mạng.

    Ép kiểu số thực/số nguyên (float/int) nhằm triệt tiêu rủi ro Injection vào chuỗi SVG.

    Args:
        a: Tọa độ trạm đầu (hỗ trợ dict hoặc tuple/object có x, y).
        b: Tọa độ trạm đích.

    Returns:
        str: Chuỗi SVG Path chuẩn 'M ax ay L bx by'.
    """
    ax = int(a["x"] if isinstance(a, dict) else a[0])
    ay = int(a["y"] if isinstance(a, dict) else a[1])
    bx = int(b["x"] if isinstance(b, dict) else b[0])
    by = int(b["y"] if isinstance(b, dict) else b[1])
    return f"M{ax} {ay} L{bx} {by}"


# Dữ liệu Topology cho Desktop (viewBox: 0 0 720 900)
DESKTOP_NODES = {
    "core": {"x": 560, "y": 150, "r": 8, "kind": "core"},
    "n1": {"x": 440, "y": 236, "r": 6, "kind": "normal"},
    "n2": {"x": 646, "y": 262, "r": 6, "kind": "normal"},
    "n3": {"x": 650, "y": 96, "r": 5, "kind": "normal"},
    "n4": {"x": 360, "y": 130, "r": 5, "kind": "normal"},
    "n5": {"x": 330, "y": 330, "r": 5, "kind": "normal"},
    "n6": {"x": 600, "y": 430, "r": 5, "kind": "normal"},
    "alert": {"x": 520, "y": 352, "r": 6, "kind": "alert"},
}

DESKTOP_EDGES = [
    ("core", "n1"),
    ("core", "n2"),
    ("core", "n3"),
    ("n1", "alert"),
    ("n2", "alert"),
    ("n1", "n4"),
    ("n4", "core"),
    ("alert", "n6"),
    ("n1", "n5"),
]

DESKTOP_PACKETS = [
    {"edge": ("core", "n1"), "dur": 3.4, "delay": 0.0, "kind": "normal"},
    {"edge": ("core", "n2"), "dur": 4.2, "delay": 0.8, "kind": "normal"},
    {"edge": ("n1", "alert"), "dur": 3.8, "delay": 1.5, "kind": "normal"},
    {"edge": ("n2", "alert"), "dur": 4.6, "delay": 0.3, "kind": "normal"},
    {"edge": ("n4", "core"), "dur": 5.0, "delay": 2.0, "kind": "normal"},
    {"edge": ("core", "n3"), "dur": 3.0, "delay": 1.9, "kind": "normal"},
    {"edge": ("n1", "n5"), "dur": 4.0, "delay": 2.4, "kind": "normal"},
    {"edge": ("alert", "n6"), "dur": 3.0, "delay": 1.0, "kind": "warn"},
]

# Dữ liệu Topology cho Mobile (viewBox: 0 0 390 300)
MOBILE_NODES = {
    "core": {"x": 300, "y": 40, "r": 7, "kind": "core"},
    "n1": {"x": 236, "y": 92, "r": 5, "kind": "normal"},
    "n2": {"x": 352, "y": 104, "r": 5, "kind": "normal"},
    "n4": {"x": 180, "y": 36, "r": 4, "kind": "normal"},
    "alert": {"x": 300, "y": 168, "r": 5, "kind": "alert"},
}

MOBILE_EDGES = [
    ("core", "n1"),
    ("core", "n2"),
    ("n1", "alert"),
    ("n2", "alert"),
    ("n4", "n1"),
]

MOBILE_PACKETS = [
    {"edge": ("core", "n1"), "dur": 3.2, "delay": 0.0, "kind": "normal"},
    {"edge": ("core", "n2"), "dur": 3.8, "delay": 0.7, "kind": "normal"},
    {"edge": ("n1", "alert"), "dur": 3.4, "delay": 1.4, "kind": "normal"},
    {"edge": ("n2", "alert"), "dur": 4.0, "delay": 0.3, "kind": "normal"},
    {"edge": ("n4", "n1"), "dur": 3.6, "delay": 1.8, "kind": "normal"},
]


def get_topology_data() -> dict:
    """Tổng hợp toàn bộ dữ liệu đồ thị mạng và sinh mã CSS offset-path an toàn CSP.

    Returns:
        dict: Chứa cấu trúc nodes, edges, packets và generated_css cho Desktop và Mobile.
    """
    css_rules = []

    # Sinh quy tắc CSS offset-path cho Desktop packets
    desktop_resolved_packets = []
    for idx, p in enumerate(DESKTOP_PACKETS, start=1):
        src, dst = p["edge"]
        p_path = edge_path(DESKTOP_NODES[src], DESKTOP_NODES[dst])
        cls_name = f"tp-d-{idx}"
        css_rules.append(f".{cls_name} {{ offset-path: path('{p_path}'); --dur: {p['dur']}s; --delay: {p['delay']}s; }}")
        desktop_resolved_packets.append({
            "cls": cls_name,
            "kind": p["kind"],
        })

    # Sinh quy tắc CSS offset-path cho Mobile packets
    mobile_resolved_packets = []
    for idx, p in enumerate(MOBILE_PACKETS, start=1):
        src, dst = p["edge"]
        p_path = edge_path(MOBILE_NODES[src], MOBILE_NODES[dst])
        cls_name = f"tp-m-{idx}"
        css_rules.append(f".{cls_name} {{ offset-path: path('{p_path}'); --dur: {p['dur']}s; --delay: {p['delay']}s; }}")
        mobile_resolved_packets.append({
            "cls": cls_name,
            "kind": p["kind"],
        })

    # Gom các cạnh (edges) kèm chuỗi SVG path
    desktop_edges_rendered = [
        {"path": edge_path(DESKTOP_NODES[src], DESKTOP_NODES[dst])}
        for src, dst in DESKTOP_EDGES
    ]
    mobile_edges_rendered = [
        {"path": edge_path(MOBILE_NODES[src], MOBILE_NODES[dst])}
        for src, dst in MOBILE_EDGES
    ]

    return {
        "desktop": {
            "viewBox": "0 0 720 900",
            "nodes": DESKTOP_NODES,
            "edges": desktop_edges_rendered,
            "packets": desktop_resolved_packets,
        },
        "mobile": {
            "viewBox": "0 0 390 300",
            "nodes": MOBILE_NODES,
            "edges": mobile_edges_rendered,
            "packets": mobile_resolved_packets,
        },
        "css": "\n".join(css_rules),
    }
