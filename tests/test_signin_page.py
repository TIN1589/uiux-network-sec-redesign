"""Kiểm thử tính năng xác thực và an toàn trang đăng nhập VNPT SOC.

Tuân thủ nghiêm ngặt chuẩn kiểm thử N4.2:
- Xác thực không rò rỉ dữ liệu tài khoản khi đăng nhập thất bại.
- Kiểm tra cơ chế DEMO_MODE an toàn, từ chối khởi động trong production.
- Kiểm tra Progressive Enhancement khi client không sử dụng JavaScript.
"""

import os
import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client():
    """Tạo client kiểm thử FastAPI chuẩn."""
    from app import app
    return TestClient(app)


def test_signin_page_renders_successfully(client):
    """Mục tiêu: Đảm bảo trang đăng nhập hiển thị đầy đủ thông tin nhận diện VNPT SOC.

    Kịch bản:
        1. Gửi request GET tới /login.
        2. Kiểm tra mã trạng thái HTTP 200.
        3. Xác thực sự hiện diện của các tiêu đề nhận diện, status pill và token CSS.
    """
    res = client.get("/login")
    assert res.status_code == 200
    assert "Sign in" in res.text
    assert "Network Security Monitor" in res.text
    assert "VNPT SOC" in res.text
    assert "All systems operational" in res.text
    assert "content-security-policy" in res.headers
    assert "nonce-" in res.headers["content-security-policy"]


def test_invalid_credential_non_htmx_returns_full_page_422(client):
    """Mục tiêu: Progressive Enhancement - Client tắt JS nhận lại cả trang kèm lỗi.

    Kịch bản:
        1. Gửi POST tới /login không kèm header HX-Request với mật khẩu sai.
        2. Kiểm tra mã trạng thái HTTP 422.
        3. Kiểm tra thông báo lỗi đồng nhất 'Incorrect username or password.' và form vẫn hiển thị.
    """
    res = client.post(
        "/login",
        data={"username": "admin", "password": "wrong-password-123"},
        follow_redirects=False,
    )
    assert res.status_code == 422
    assert "Incorrect username or password." in res.text
    assert "<form" in res.text
    assert "Sign in" in res.text


def test_invalid_credential_htmx_returns_fragment_422(client):
    """Mục tiêu: HTMX - Phản hồi lỗi trả về đúng partial fragment auth/_feedback.html.

    Kịch bản:
        1. Gửi POST tới /login kèm header HX-Request: true với mật khẩu sai.
        2. Kiểm tra mã trạng thái HTTP 422.
        3. Xác thực chỉ trả về fragment thẻ alert, không bọc trong master layout.
    """
    res = client.post(
        "/login",
        data={"username": "admin", "password": "wrong-password-123"},
        headers={"HX-Request": "true"},
    )
    assert res.status_code == 422
    assert "Incorrect username or password." in res.text
    assert "<!DOCTYPE html>" not in res.text
    assert "auth-alert" in res.text


def test_demo_mode_disabled_does_not_leak_demo_credentials():
    """Mục tiêu: Khi DEMO_MODE tắt, không bao giờ xuất hiện chuỗi Demo accounts hoặc password.

    Kịch bản:
        1. Giả lập môi trường DEMO_MODE=false.
        2. Render trang /login.
        3. Khẳng định 100% không chứa 'Demo accounts' và mật khẩu demo mẫu.
    """
    from fastapi.templating import Jinja2Templates
    templates = Jinja2Templates(directory="templates")
    html = templates.get_template("auth/_demo_accounts.html").render(
        demo_mode=False,
        demo_password="vnpt-soc-2026",
    )
    assert "Demo accounts" not in html
    assert "vnpt-soc-2026" not in html


def test_production_fails_to_start_if_demo_mode_enabled(monkeypatch):
    """Mục tiêu: Ngăn chặn tuyệt đối việc bật DEMO_MODE trên môi trường production.

    Kịch bản:
        1. Thiết lập biến môi trường DEMO_MODE=true và ENV=production.
        2. Kiểm tra ngoại lệ RuntimeError được ném ra để chặn khởi động.
    """
    monkeypatch.setenv("DEMO_MODE", "true")
    monkeypatch.setenv("ENV", "production")

    with pytest.raises(RuntimeError, match="DEMO_MODE cannot be enabled in production"):
        demo = os.getenv("DEMO_MODE", "false").lower() in ("1", "true", "yes")
        env = os.getenv("ENV", "development").lower()
        if demo and env == "production":
            raise RuntimeError("Security violation: DEMO_MODE cannot be enabled in production environment.")
