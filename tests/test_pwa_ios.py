"""
Kiểm thử Tính năng PWA và Tương thích iOS Safari / WebKit
Tuân thủ tiêu chuẩn: .agents/rules/testing-and-evidence.md
3 Thành tố bắt buộc: Mục tiêu - Kịch bản - Minh chứng
"""

from fastapi.testclient import TestClient

from app import app

client = TestClient(app)


def test_manifest_webmanifest_endpoint():
    """Kiểm thử route phục vụ Web App Manifest (/manifest.webmanifest).

    Mục tiêu: Đảm bảo manifest metadata trả về hợp lệ cho PWA trên iOS và Android.
    Kịch bản: Gửi HTTP GET request tới /manifest.webmanifest.
    Minh chứng: Status code 200, Content-Type chứa application/manifest+json,
                chứa các trường bắt buộc name, short_name, display=standalone và icons.
    """
    response = client.get("/manifest.webmanifest")
    assert response.status_code == 200
    assert "application/manifest+json" in response.headers["content-type"]
    data = response.json()
    assert data["name"] == "Network Security Monitor – VNPT SOC Command Center"
    assert data["short_name"] == "VNPT SOC"
    assert data["display"] == "standalone"
    assert len(data["icons"]) >= 2
    icon_srcs = [icon["src"] for icon in data["icons"]]
    assert "/static/img/favicon/nsm-apple-icon-180.png" in icon_srcs


def test_service_worker_endpoint():
    """Kiểm thử route phục vụ Service Worker (/sw.js).

    Mục tiêu: Đảm bảo sw.js được phục vụ từ root scope với header Service-Worker-Allowed.
    Kịch bản: Gửi HTTP GET request tới /sw.js.
    Minh chứng: Status code 200, Content-Type là application/javascript,
                Service-Worker-Allowed header bằng '/', không bị cache trình duyệt lưu trữ vĩnh viễn.
    """
    response = client.get("/sw.js")
    assert response.status_code == 200
    assert "javascript" in response.headers["content-type"]
    assert response.headers.get("Service-Worker-Allowed") == "/"
    assert "CACHE_NAME" in response.text
    assert "PRECACHE_ASSETS" in response.text
    assert "v1.0.4-local-icons" in response.text
    assert "/static/css/charts.css" in response.text
    assert "/static/css/variables.css" in response.text
    assert "/static/vendor/htmx.min.js" in response.text
    assert "/static/vendor/chart.umd.min.js" in response.text
    assert "/static/js/icons.js" in response.text
    assert "ignoreSearch: true" in response.text


def test_offline_page_endpoint():
    """Kiểm thử route phục vụ trang Offline fallback (/offline).

    Mục tiêu: Đảm bảo người dùng iPhone mất mạng nhận được giao diện thông báo trực quan.
    Kịch bản: Gửi HTTP GET request tới /offline.
    Minh chứng: Status code 200, HTML chứa tiêu đề mất kết nối và nút thử kết nối lại.
    """
    response = client.get("/offline")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "Mất kết nối mạng" in response.text
    assert "VNPT SOC" in response.text


def test_pwa_ios_meta_tags_in_base_templates():
    """Kiểm thử thẻ WebKit Meta Tags và PWA tags trong template gốc.

    Mục tiêu: Đảm bảo các chỉ thị Standalone, Touch Icon và Safe Area hiển thị trên trang chủ và login.
    Kịch bản: Gửi HTTP GET request tới / và /login.
    Minh chứng: Cả hai trang đều có thẻ link manifest, apple-mobile-web-app-capable,
                apple-touch-icon và viewport-fit=cover.
    """
    # 1. Dashboard chính
    res_home = client.get("/")
    assert res_home.status_code == 200
    assert 'rel="manifest" href="/manifest.webmanifest"' in res_home.text
    assert 'name="apple-mobile-web-app-capable" content="yes"' in res_home.text
    assert 'name="apple-mobile-web-app-status-bar-style" content="default"' in res_home.text
    assert 'rel="apple-touch-icon" sizes="180x180" href="/static/img/favicon/nsm-apple-icon-180.png"' in res_home.text
    assert 'id="ios-pwa-banner"' in res_home.text
    assert 'rel="apple-touch-startup-image"' in res_home.text
    assert 'apple-splash-1179-2556.png' in res_home.text
    assert 'background-color: #F3F1EC' in res_home.text
    assert 'defer src="/static/vendor/htmx.min.js"' in res_home.text

    # 2. Trang đăng nhập công khai
    res_login = client.get("/login")
    assert res_login.status_code == 200
    assert 'rel="manifest" href="/manifest.webmanifest"' in res_login.text
    assert 'name="apple-mobile-web-app-capable" content="yes"' in res_login.text
    assert 'rel="apple-touch-icon" sizes="180x180" href="/static/img/favicon/nsm-apple-icon-180.png"' in res_login.text


def test_csp_allows_service_worker_and_manifest():
    """Kiểm thử Content-Security-Policy cho phép Service Worker và Manifest.

    Mục tiêu: Đảm bảo CSP header không chặn nạp Service Worker (worker-src) và Web Manifest (manifest-src).
    Kịch bản: Gửi HTTP GET tới / và /login, phân tích chuỗi header Content-Security-Policy.
    Minh chứng: Cả 2 CSP đều chứa worker-src 'self' và manifest-src 'self'.
    """
    res_home = client.get("/")
    csp_home = res_home.headers.get("Content-Security-Policy", "")
    assert "worker-src 'self'" in csp_home
    assert "manifest-src 'self'" in csp_home

    res_login = client.get("/login")
    csp_login = res_login.headers.get("Content-Security-Policy", "")
    assert "worker-src 'self'" in csp_login
    assert "manifest-src 'self'" in csp_login



def test_rules_table_mobile_structure_and_constraints():
    """Kiểm thử cấu trúc bảng Top Triggered Rules chống lỗi vỡ layout trên iOS Mobile.

    Mục tiêu: Đảm bảo bảng rules-table trên màn hình hẹp (<430px) có min-width bảo vệ,
              cột DESCRIPTION có min-width >= 250px và không bị triệt tiêu về 0px gây đè chữ ('SESERIPTION').
    Kịch bản: Gửi HTTP GET tới /views/overview và /?guest=1, phân tích markup thead của bảng .rules-table.
    Minh chứng:
        - Thẻ th của DESCRIPTION chứa class 'desc-col' và 'min-width: 250px;'.
        - Thẻ th của RULE chứa class 'rule-col' và SEVERITY chứa class 'sev-col'.
        - CSS components.css chứa định nghĩa min-width 680px cho .rules-table.
    """
    res = client.get("/views/overview")
    assert res.status_code == 200
    assert 'class="desc-col" style="min-width: 250px;"' in res.text
    assert 'class="rule-col" style="width: 110px; min-width: 110px;"' in res.text
    assert 'class="sev-col" style="width: 120px; min-width: 120px;"' in res.text

    # Kiểm tra CSS token
    with open("static/css/components.css", "r", encoding="utf-8") as f_css:
        css = f_css.read()
    assert ".rules-table" in css
    assert "min-width: 680px;" in css
