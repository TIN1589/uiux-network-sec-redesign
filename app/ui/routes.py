"""Bộ định tuyến cho các thành phần giao diện động VNPT SOC (Log feed, Topology)."""

import time
from fastapi import APIRouter, Request, Response
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from app.ui import mock_feed

router = APIRouter(prefix="/ui", tags=["ui"])
templates = Jinja2Templates(directory="templates")


@router.get("/log-feed", response_class=HTMLResponse, name="ui.log_feed")
async def log_feed(request: Request, response: Response, size: int = 5):
    """Cung cấp dòng nhật ký giám sát SOC giả lập phục vụ cơ chế HTMX stream polling.

    Dữ liệu được kẹp trong ngưỡng an toàn 1..5 dòng. Bổ sung header cấm lưu cache
    nhằm đảm bảo tính trực tiếp và tránh công cụ tìm kiếm lập chỉ mục endpoint công khai.

    Args:
        request: FastAPI Request instance.
        response: FastAPI Response instance để gắn headers.
        size: Số lượng bản ghi log cần lấy (1..5).

    Returns:
        HTMLResponse: Render fragment Jinja2 `ui/_log_feed.html`.
    """
    clamped_size = max(1, min(5, size))
    lines = mock_feed.log_lines(time.time(), clamped_size)

    res = templates.TemplateResponse(
        request=request,
        name="ui/_log_feed.html",
        context={"lines": lines},
    )
    res.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    res.headers["X-Robots-Tag"] = "noindex, nofollow"
    return res
