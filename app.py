"""
Network Security Monitor – SOC Command Center
Backend Architecture: FastAPI + Jinja2 + HTMX
"""

import csv
import hashlib
import hmac
import io
import os
import re
import secrets
import time
import urllib.parse
from datetime import datetime

from fastapi import Cookie, FastAPI, Form, Request, Response
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

# Cấu hình môi trường vận hành an toàn VNPT SOC
DEMO_MODE = os.getenv("DEMO_MODE", "true").lower() in ("1", "true", "yes")
ENV = os.getenv("ENV", "development").lower()
SHOW_BUILD_VERSION = os.getenv("SHOW_BUILD_VERSION", "false").lower() in ("1", "true", "yes")

# Tiêu chuẩn an ninh nghiêm ngặt: Từ chối khởi động nếu DEMO_MODE bật trong môi trường production
if DEMO_MODE and ENV == "production":
    raise RuntimeError("Security violation: DEMO_MODE cannot be enabled in production environment.")

# Auth config — ASSUMPTION-02
_SECRET_KEY = secrets.token_hex(32)          # Random mỗi lần khởi động (demo mode)
_SESSION_MAX_AGE = 8 * 3600                  # 8 hours in seconds
_CSRF_MAX_AGE = 3600                         # 1 hour
_SERIALIZER = URLSafeTimedSerializer(_SECRET_KEY)

# Demo credentials cho môi trường kiểm thử/nghiệm thu VNPT SOC N4.2
# Hỗ trợ 3 vai trò: SecOps Admin, Tier-2 Analyst, Tier-1 Responder
_DEMO_ACCOUNTS = {
    "admin": {"role": "admin", "password": "vnpt-soc-2026", "label": "SecOps Admin"},
    "tier2": {"role": "tier2", "password": "vnpt-soc-2026", "label": "Tier-2 Analyst"},
    "tier1": {"role": "tier1", "password": "vnpt-soc-2026", "label": "Tier-1 Responder"},
}
_ADMIN_USERNAME = "admin"
_ADMIN_PWD_PLAIN = "vnpt-soc-2026"          # Backward compatibility

# In-memory session store: {session_id: {username, role, created_at}}
_sessions: dict = {}

app = FastAPI(title="Network Security Monitor – SOC Command Center")

# Content Security Policy Middleware: Cấp phát CSP Nonce ngẫu nhiên cho từng request
@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    """Middleware áp dụng Content Security Policy và cấp phát CSP Nonce ngẫu nhiên cho từng request.

    Args:
        request: FastAPI Request instance.
        call_next: Hàm điều phối tiếp theo trong chuỗi xử lý HTTP middleware.

    Returns:
        Response: HTTP response có gắn kèm header Content-Security-Policy phù hợp.
    """
    nonce = secrets.token_urlsafe(16)
    request.state.csp_nonce = nonce
    response = await call_next(request)

    path = request.url.path
    if path.startswith(("/login", "/auth", "/ui")):
        # Strict CSP cho trang đăng nhập công khai mới (triệt tiêu inline scripts và style attributes)
        csp = (
            f"default-src 'self'; "
            f"script-src 'self' 'nonce-{nonce}'; "
            f"style-src 'self' 'nonce-{nonce}'; "
            f"font-src 'self'; "
            f"img-src 'self' data:; "
            f"connect-src 'self'; "
            f"worker-src 'self'; "
            f"manifest-src 'self'; "
            f"frame-ancestors 'none'; "
            f"base-uri 'self'; "
            f"form-action 'self';"
        )
    else:
        # Tương thích ngược cho các trang dashboard SOC hiện hữu (không chèn nonce để trình duyệt không vô hiệu hóa unsafe-inline)
        csp = (
            f"default-src 'self'; "
            f"script-src 'self' 'unsafe-inline' https://unpkg.com https://cdn.jsdelivr.net; "
            f"style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://fonts.googleapis.com; "
            f"font-src 'self' https://cdnjs.cloudflare.com https://fonts.gstatic.com; "
            f"img-src 'self' data:; "
            f"connect-src 'self'; "
            f"worker-src 'self'; "
            f"manifest-src 'self'; "
            f"frame-ancestors 'none'; "
            f"base-uri 'self'; "
            f"form-action 'self';"
        )
    response.headers["Content-Security-Policy"] = csp
    return response

# Mount Static Assets (CSS, JS, Icons)
app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    """Phục vụ file favicon.ico gốc cho các trình duyệt tự động truy vấn."""
    return FileResponse("static/img/favicon/favicon.ico")

@app.get("/manifest.webmanifest", include_in_schema=False)
async def webmanifest():
    """Phục vụ file Web App Manifest chuẩn cho PWA trên iOS và Android."""
    return FileResponse("static/manifest.webmanifest", media_type="application/manifest+json")

@app.get("/sw.js", include_in_schema=False)
async def service_worker():
    """Phục vụ Service Worker tại root scope để có toàn quyền điều phối cache và offline."""
    return FileResponse(
        "static/sw.js",
        media_type="application/javascript",
        headers={
            "Cache-Control": "no-cache, no-store, must-revalidate",
            "Service-Worker-Allowed": "/",
        },
    )

@app.get("/offline", include_in_schema=False)
async def offline_page():
    """Phục vụ trang thông báo mất kết nối mạng khi thiết bị offline hoàn toàn."""
    return FileResponse("static/offline.html")

# Configure Jinja2 Template Engine
templates = Jinja2Templates(directory="templates")

# Jinja2 URL generator tương thích ngược cho cả Path parameters và Query parameters
def _jinja_url_for(name: str, **params) -> str:
    """Tạo URL trong Jinja2 hỗ trợ tương thích ngược cả path params và query params.

    Args:
        name: Tên route hoặc alias cần phân giải (ví dụ: 'auth.login', 'static').
        **params: Các tham số truyền vào (path parameters hoặc query string).

    Returns:
        str: Chuỗi đường dẫn URL hoàn chỉnh.
    """
    route = next((r for r in app.routes if getattr(r, "name", None) == name), None)
    if not route:
        mappings = {
            "auth.login": "/login",
            "auth.guest": "/auth/guest",
            "auth.forgot": "/auth/forgot",
            "ui.log_feed": "/ui/log-feed",
        }
        base_url = mappings.get(name, f"/{name.replace('.', '/')}")
        if params:
            return f"{base_url}?{urllib.parse.urlencode(params)}"
        return base_url
    path_param_names = getattr(route, "param_convertors", {}).keys()
    path_params = {k: v for k, v in params.items() if k in path_param_names}
    query_params = {k: v for k, v in params.items() if k not in path_param_names}
    url = app.url_path_for(name, **path_params)
    if query_params:
        return f"{url}?{urllib.parse.urlencode(query_params)}"
    return str(url)

def _jinja_csrf_token() -> str:
    """Tạo mã CSRF token ngẫu nhiên bảo vệ biểu mẫu công khai trong Jinja2 context.

    Returns:
        str: Chuỗi token CSRF đã ký và mã hóa an toàn.
    """
    return _generate_csrf_token("public_auth_session")

templates.env.globals["url_for"] = _jinja_url_for
templates.env.globals["csrf_token"] = _jinja_csrf_token
templates.env.globals["demo_mode"] = DEMO_MODE
templates.env.globals["demo_password"] = _ADMIN_PWD_PLAIN if DEMO_MODE else ""
templates.env.globals["show_build_version"] = SHOW_BUILD_VERSION

# In-memory SOC data repository

INITIAL_ALERTS = [
    {
        "eventId": "EVT-2610-099",
        "ruleId": "100999",
        "title": "Unauthorized Spanning-Tree Root Bridge BPDU inject",
        "severity": "Critical",
        "state": "New",
        "srcIp": "10.254.0.99",
        "dstIp": "10.0.20.5",
        "asset": "vnpt-agg-switch-05",
        "assetType": "Switch",
        "observedRel": "just now",
        "ageMinutes": 0,
        "observedDate": "26 Oct 2026",
        "observedTime": "01:12:04 GMT+7",
        "mitre": "T1557 · Adversary-in-the-Middle",
        "hits": 1,
        "testStartTs": "01:12:03.2",
        "testObsTs": "01:12:04.6",
        "testDeltaSec": 1.4,
        "rawSyslog": "Oct 26 01:12:04 vnpt-agg-switch-05 %SPANTREE-2-ROOTGUARD_BLOCK: Root guard blocking port Gi0/24 on VLAN0010. Superior BPDU received from 10.254.0.99 (MAC 00:1c:73:aa:bb:09, Priority 0).",
        "playbook": "1. Verify BPDU Guard & Root Guard status on vnpt-agg-switch-05 port Gi0/24.\n2. Shut down rogue port Gi0/24 and isolate MAC 00:1c:73:aa:bb:09.\n3. Confirm topology stability across VLAN 10."
    },
    {
        "eventId": "EVT-2610-095",
        "ruleId": "100201",
        "title": "BGP Neighbor Flapping detected on Core Uplink",
        "severity": "Critical",
        "state": "Investigating",
        "srcIp": "203.0.113.195",
        "dstIp": "10.0.0.1",
        "asset": "vnpt-core-router-01",
        "assetType": "Router",
        "observedRel": "2 min ago",
        "ageMinutes": 2,
        "observedDate": "26 Oct 2026",
        "observedTime": "01:10:15 GMT+7",
        "mitre": "T1498 · Network Denial of Service",
        "hits": 1,
        "testStartTs": "01:10:13.4",
        "testObsTs": "01:10:15.0",
        "testDeltaSec": 1.6,
        "rawSyslog": "Oct 26 01:10:15 vnpt-core-router-01 %BGP-5-ADJCHANGE: neighbor 203.0.113.195 Up/Down Hold Timer Expired (AS 45899). Subcode: Cease/Connection Reset.",
        "playbook": "1. Inspect BGP peer 203.0.113.195 hold-timer & MD5 authentication logs.\n2. Verify optical transceiver light levels on TenGigE0/0/0.\n3. Apply route-flap damping policy if peer instability continues."
    },
    {
        "eventId": "EVT-2610-092",
        "ruleId": "100210",
        "title": "SSH Brute-force attempt against edge gateway",
        "severity": "High",
        "state": "New",
        "srcIp": "198.51.100.44",
        "dstIp": "10.0.10.1",
        "asset": "vnpt-edge-fw-01",
        "assetType": "Firewall",
        "observedRel": "5 min ago",
        "ageMinutes": 5,
        "observedDate": "26 Oct 2026",
        "observedTime": "01:07:11 GMT+7",
        "mitre": "T1110 · Brute Force",
        "hits": 1,
        "testStartTs": "01:07:09.9",
        "testObsTs": "01:07:11.4",
        "testDeltaSec": 1.5,
        "rawSyslog": "Oct 26 01:07:11 vnpt-edge-fw-01 sshd[29104]: Failed password for invalid user admin from 198.51.100.44 port 51922 ssh2 [preauth] (45 attempts in 20s).",
        "playbook": "1. Confirm automatic block of 198.51.100.44 in edge firewall blocklist.\n2. Verify SSH management access is restricted to Out-of-Band jump hosts.\n3. Audit recent successful logins on vnpt-edge-fw-01."
    },
    {
        "eventId": "EVT-2610-090",
        "ruleId": "100205",
        "title": "BGP Origin AS Hijack Anomaly on Core Router",
        "severity": "Critical",
        "state": "New",
        "srcIp": "198.51.100.100",
        "dstIp": "10.0.0.1",
        "asset": "vnpt-core-router-01",
        "assetType": "Router",
        "observedRel": "8 min ago",
        "ageMinutes": 8,
        "observedDate": "26 Oct 2026",
        "observedTime": "01:04:19 GMT+7",
        "mitre": "T1584.004 · Compromise Infrastructure: DNS / Route Hijacking",
        "hits": 1,
        "testStartTs": "01:04:17.5",
        "testObsTs": "01:04:19.2",
        "testDeltaSec": 1.7,
        "rawSyslog": "Oct 26 01:04:19 vnpt-core-router-01 %BGP-3-HIJACK_ALERT: Conflicting origin AS announced for VNPT prefix 123.30.0.0/16 by unauthorized peer AS 64512.",
        "playbook": "1. Verify RPKI ROA validation status on core-router.\n2. Filter unauthorized AS 64512 announcements on upstream eBGP session.\n3. Escalate to VNPT NOC Level 3 routing desk."
    },
    {
        "eventId": "EVT-2610-089",
        "ruleId": "100200",
        "title": "Port scan detected against DMZ subnet",
        "severity": "High",
        "state": "New",
        "srcIp": "203.0.113.45",
        "dstIp": "10.0.10.20",
        "asset": "vnpt-edge-fw-01",
        "assetType": "Firewall",
        "observedRel": "12 min ago",
        "ageMinutes": 12,
        "observedDate": "26 Oct 2026",
        "observedTime": "01:00:47 GMT+7",
        "mitre": "T1046 · Network Service Scanning",
        "hits": 3,
        "testStartTs": "01:00:46.0",
        "testObsTs": "01:00:47.8",
        "testDeltaSec": 1.8,
        "rawSyslog": "Oct 26 01:00:47 vnpt-edge-fw-01 suricata[1082]: [1:100200:3] ET SCAN Nmap SYN Scan Detected {TCP} 203.0.113.45:49210 -> 10.0.10.20:1-1024.",
        "playbook": "1. Block scanning IP 203.0.113.45 at perimeter ACL.\n2. Correlate with E2E Playwright test schedule if sourced from authorized red-team subnet."
    },
    {
        "eventId": "EVT-2610-087",
        "ruleId": "100260",
        "title": "VLAN Hopping double-tagged frame detected",
        "severity": "High",
        "state": "New",
        "srcIp": "10.0.10.66",
        "dstIp": "10.0.99.1",
        "asset": "vnpt-agg-switch-05",
        "assetType": "Switch",
        "observedRel": "20 min ago",
        "ageMinutes": 20,
        "observedDate": "26 Oct 2026",
        "observedTime": "00:52:10 GMT+7",
        "mitre": "T1095 · Non-Application Layer Protocol",
        "hits": 1,
        "testStartTs": "00:52:06.8",
        "testObsTs": "00:52:10.0",
        "testDeltaSec": 3.2,
        "rawSyslog": "Oct 26 00:52:10 vnpt-agg-switch-05 openvswitch: unexpected double-tagged 802.1Q frame on access port Gi0/12 (Outer VLAN 10, Inner VLAN 99).",
        "playbook": "1. Disable DTP negotiation on trunk ports.\n2. Change native VLAN from default VLAN 1 to unused dedicated VLAN 999.\n3. Isolate source MAC on access switch port Gi0/12."
    },
    {
        "eventId": "EVT-2610-084",
        "ruleId": "100280",
        "title": "VPN login from unusual source",
        "severity": "High",
        "state": "Resolved",
        "srcIp": "192.0.2.88",
        "dstIp": "10.0.10.1",
        "asset": "vnpt-edge-fw-01",
        "assetType": "Firewall",
        "observedRel": "35 min ago",
        "ageMinutes": 35,
        "observedDate": "26 Oct 2026",
        "observedTime": "00:37:12 GMT+7",
        "mitre": "T1078 · Valid Accounts",
        "hits": 1,
        "testStartTs": "00:37:10.0",
        "testObsTs": "00:37:12.1",
        "testDeltaSec": 2.1,
        "rawSyslog": "Oct 26 00:37:12 vnpt-edge-fw-01 openvpn[4412]: TLS Auth OK: user=soc_duty_02 rip=192.0.2.88:61023 GeoIP=Unknown-ASN.",
        "playbook": "1. Verify MFA token approval with analyst soc_duty_02.\n2. Revoke active VPN session if unrecognized."
    },
    {
        "eventId": "EVT-2610-081",
        "ruleId": "100710",
        "title": "Broadband Network Gateway (BNG) PPPoE Session Exhaustion",
        "severity": "Critical",
        "state": "New",
        "srcIp": "10.200.1.50",
        "dstIp": "10.200.0.1",
        "asset": "vnpt-bng-01",
        "assetType": "Gateway",
        "observedRel": "45 min ago",
        "ageMinutes": 45,
        "observedDate": "26 Oct 2026",
        "observedTime": "00:27:08 GMT+7",
        "mitre": "T1499 · Endpoint Denial of Service",
        "hits": 1,
        "testStartTs": "00:27:06.1",
        "testObsTs": "00:27:08.5",
        "testDeltaSec": 2.4,
        "rawSyslog": "Oct 26 00:27:08 vnpt-bng-01 %BNG-2-RESOURCE_WARN: PPPoE active subscriber pool exceeded 98% threshold (64,200 active sessions on Slot 0/1). Suspected subscriber flood.",
        "playbook": "1. Apply per-port PPPoE session limit on access OLT uplinks.\n2. Enable subscriber rate-limiting on BNG sub-interfaces.\n3. Inspect RADIUS authentication server latency."
    },
    {
        "eventId": "EVT-2610-079",
        "ruleId": "100305",
        "title": "SYN flood threshold exceeded",
        "severity": "Medium",
        "state": "New",
        "srcIp": "203.0.113.99",
        "dstIp": "10.0.10.15",
        "asset": "vnpt-edge-fw-01",
        "assetType": "Firewall",
        "observedRel": "52 min ago",
        "ageMinutes": 52,
        "observedDate": "26 Oct 2026",
        "observedTime": "00:20:42 GMT+7",
        "mitre": "T1498.001 · Direct Network Flood",
        "hits": 2,
        "testStartTs": "00:20:40.0",
        "testObsTs": "00:20:42.1",
        "testDeltaSec": 2.1,
        "rawSyslog": "Oct 26 00:20:42 vnpt-edge-fw-01 kernel: [UFW SYN-PROXY] SYN rate 14,500 pps from 203.0.113.99 to 10.0.10.15:443 exceeded threshold.",
        "playbook": "1. Enable SYN cookies and rate-limiting on VIP 10.0.10.15:443.\n2. Divert upstream traffic through DDoS scrubbing center."
    },
    {
        "eventId": "EVT-2610-072",
        "ruleId": "100255",
        "title": "Dynamic ARP Inspection (DAI) violation on access segment",
        "severity": "Medium",
        "state": "Investigating",
        "srcIp": "10.0.10.77",
        "dstIp": "10.0.10.1",
        "asset": "vnpt-access-sw-02",
        "assetType": "Switch",
        "observedRel": "1.5 h ago",
        "ageMinutes": 90,
        "observedDate": "25 Oct 2026",
        "observedTime": "23:42:15 GMT+7",
        "mitre": "T1557.002 · ARP Cache Poisoning",
        "hits": 1,
        "testStartTs": "23:42:12.2",
        "testObsTs": "23:42:15.0",
        "testDeltaSec": 2.8,
        "rawSyslog": "Oct 25 23:42:15 vnpt-access-sw-02 %SW_DAI-4-PACKET_BURST_RATE_EXCEEDED: 42 packets received in 100ms on Gi0/7. Dropping rogue ARP replies for gateway 10.0.10.1.",
        "playbook": "1. Validate IP-MAC binding in DHCP Snooping database.\n2. Shut down untrusted access port Gi0/7.\n3. Clear ARP cache on adjacent switches."
    },
    {
        "eventId": "EVT-2610-065",
        "ruleId": "100240",
        "title": "Core fiber interface state flapping",
        "severity": "Medium",
        "state": "Acknowledged",
        "srcIp": "10.0.0.1",
        "dstIp": "10.0.0.2",
        "asset": "vnpt-core-router-01",
        "assetType": "Router",
        "observedRel": "3 h ago",
        "ageMinutes": 180,
        "observedDate": "25 Oct 2026",
        "observedTime": "22:12:08 GMT+7",
        "mitre": "T1498 · Network Denial of Service",
        "hits": 4,
        "testStartTs": "22:12:05.0",
        "testObsTs": "22:12:08.3",
        "testDeltaSec": 3.3,
        "rawSyslog": "Oct 25 22:12:08 vnpt-core-router-01 %LINK-3-UPDOWN: Interface TenGigE0/0/1 changed state to down (Tx optical power dropped to -24dBm).",
        "playbook": "1. Dispatch transmission field team to inspect ODF optical fiber patch.\n2. Switch traffic to secondary protected MPLS path."
    },
    {
        "eventId": "EVT-2610-058",
        "ruleId": "100410",
        "title": "DNS Amplification anomaly querying root zone",
        "severity": "Medium",
        "state": "New",
        "srcIp": "198.51.100.77",
        "dstIp": "10.0.50.53",
        "asset": "vnpt-dns-resolver",
        "assetType": "Server",
        "observedRel": "5.3 h ago",
        "ageMinutes": 320,
        "observedDate": "25 Oct 2026",
        "observedTime": "19:52:14 GMT+7",
        "mitre": "T1498.002 · Reflection Amplification",
        "hits": 2,
        "testStartTs": "19:52:11.8",
        "testObsTs": "19:52:14.0",
        "testDeltaSec": 2.2,
        "rawSyslog": "Oct 25 19:52:14 vnpt-dns-resolver named[1844]: query-errors: rate-limit: 1200 queries/sec for 'ANY .' from 198.51.100.77 exceeded limit.",
        "playbook": "1. Apply Response Rate Limiting (RRL) on BIND named.\n2. Drop open recursive queries from external source IP ranges."
    },
    {
        "eventId": "EVT-2610-051",
        "ruleId": "100220",
        "title": "Administrator login succeeded from jump host",
        "severity": "Low",
        "state": "Resolved",
        "srcIp": "10.0.99.10",
        "dstIp": "10.0.0.1",
        "asset": "vnpt-core-router-01",
        "assetType": "Router",
        "observedRel": "7.5 h ago",
        "ageMinutes": 450,
        "observedDate": "25 Oct 2026",
        "observedTime": "17:42:30 GMT+7",
        "mitre": "T1078 · Valid Accounts",
        "hits": 1,
        "testStartTs": "17:42:29.0",
        "testObsTs": "17:42:30.2",
        "testDeltaSec": 1.2,
        "rawSyslog": "Oct 25 17:42:30 vnpt-core-router-01 %SEC_LOGIN-5-LOGIN_SUCCESS: Login Success [user: netadmin] from 10.0.99.10 via SSH2 (OOB management network).",
        "playbook": "1. Verify planned maintenance ticket ID.\n2. Confirm session logout timestamp after work completion."
    },
    {
        "eventId": "EVT-2610-044",
        "ruleId": "100235",
        "title": "Daily automated configuration backup exported",
        "severity": "Low",
        "state": "Resolved",
        "srcIp": "10.0.99.5",
        "dstIp": "10.0.99.200",
        "asset": "vnpt-agg-switch-05",
        "assetType": "Switch",
        "observedRel": "12 h ago",
        "ageMinutes": 720,
        "observedDate": "25 Oct 2026",
        "observedTime": "13:12:00 GMT+7",
        "mitre": "T1005 · Data from Local System",
        "hits": 1,
        "testStartTs": "13:11:58.5",
        "testObsTs": "13:12:00.0",
        "testDeltaSec": 1.5,
        "rawSyslog": "Oct 25 13:12:00 vnpt-agg-switch-05 %SYS-5-CONFIG_I: Configured from tftp://10.0.99.200/configs/vnpt-agg-switch-05.cfg by cron_backup.",
        "playbook": "1. Verify MD5 hash checksum on central TFTP backup repository."
    },
    {
        "eventId": "EVT-2610-033",
        "ruleId": "100230",
        "title": "Unauthorized device configuration modification",
        "severity": "High",
        "state": "Acknowledged",
        "srcIp": "10.0.99.10",
        "dstIp": "10.0.0.1",
        "asset": "vnpt-core-router-01",
        "assetType": "Router",
        "observedRel": "1.1 d ago",
        "ageMinutes": 1600,
        "observedDate": "24 Oct 2026",
        "observedTime": "22:32:10 GMT+7",
        "mitre": "T1565.001 · Stored Data Manipulation",
        "hits": 1,
        "testStartTs": "22:32:08.0",
        "testObsTs": "22:32:10.5",
        "testDeltaSec": 2.5,
        "rawSyslog": "Oct 24 22:32:10 vnpt-core-router-01 commit: configuration changed by netadmin: route-map RM_BGP_OUT permit 20 modified.",
        "playbook": "1. Diff running-config against golden repository.\n2. Revert unauthorized route-map changes if unapproved."
    },
    {
        "eventId": "EVT-2610-022",
        "ruleId": "100265",
        "title": "DHCP Snooping dropped untrusted rogue DHCP offer",
        "severity": "Low",
        "state": "Resolved",
        "srcIp": "10.0.10.199",
        "dstIp": "255.255.255.255",
        "asset": "vnpt-access-sw-02",
        "assetType": "Switch",
        "observedRel": "1.9 d ago",
        "ageMinutes": 2800,
        "observedDate": "24 Oct 2026",
        "observedTime": "02:30:15 GMT+7",
        "mitre": "T1557 · Adversary-in-the-Middle",
        "hits": 1,
        "testStartTs": "02:30:13.2",
        "testObsTs": "02:30:15.0",
        "testDeltaSec": 1.8,
        "rawSyslog": "Oct 24 02:30:15 vnpt-access-sw-02 %DHCP_SNOOPING-5-DHCP_OFFER_DROPPED: Rogue DHCP OFFER received on untrusted port Gi0/14 from 10.0.10.199.",
        "playbook": "1. Identify rogue DHCP server device plugged into port Gi0/14.\n2. Enable errdisable on port to prevent lease poisoning."
    },
    {
        "eventId": "EVT-2610-015",
        "ruleId": "100615",
        "title": "GPON OLT optical power degradation on PON port",
        "severity": "Medium",
        "state": "Resolved",
        "srcIp": "10.100.0.1",
        "dstIp": "10.100.0.10",
        "asset": "vnpt-olt-01",
        "assetType": "Gateway",
        "observedRel": "3.1 d ago",
        "ageMinutes": 4500,
        "observedDate": "22 Oct 2026",
        "observedTime": "18:10:40 GMT+7",
        "mitre": "T1489 · Service Stop",
        "hits": 1,
        "testStartTs": "18:10:35.4",
        "testObsTs": "18:10:40.0",
        "testDeltaSec": 4.6,
        "rawSyslog": "Oct 22 18:10:40 vnpt-olt-01 %OLT-3-OPTICAL_DEGRADE: PON Port 0/1/4 RX power -29.2 dBm dropped below critical threshold. 32 ONUs affected.",
        "playbook": "1. Dispatch line maintenance crew to clean optical connector at splitter cabinet.\n2. Verify ONU transmit power levels."
    }
]

DEVICES = [
    {
        "name": "vnpt-edge-fw-01",
        "role": "Firewall",
        "icon": "fa-shield-halved",
        "status": "Reporting",
        "lastEventRel": "Last event received 12s ago",
        "lastEventTs": "26 Oct 2026, 01:12:10 GMT+7",
        "note": "Active Wazuh & Suricata syslog stream (410 EPS).",
        "alertCount": 4
    },
    {
        "name": "vnpt-core-router-01",
        "role": "Router",
        "icon": "fa-route",
        "status": "Reporting",
        "lastEventRel": "Last event received 8s ago",
        "lastEventTs": "26 Oct 2026, 01:12:14 GMT+7",
        "note": "Active BGP & NetFlow v9 telemetry stream (520 EPS).",
        "alertCount": 5
    },
    {
        "name": "vnpt-agg-switch-05",
        "role": "Switch",
        "icon": "fa-network-wired",
        "status": "Reporting",
        "lastEventRel": "Last event received just now",
        "lastEventTs": "26 Oct 2026, 01:12:20 GMT+7",
        "note": "Active SNMPv3 trap & L2 STP telemetry stream (195 EPS).",
        "alertCount": 3
    },
    {
        "name": "vnpt-access-sw-02",
        "role": "Switch",
        "icon": "fa-server",
        "status": "Silent",
        "lastEventRel": "Last alert received 2 h ago",
        "lastEventTs": "26 Oct 2026, 00:19:56 GMT+7",
        "note": "No alert in 15 min. This does not always mean the device is offline.",
        "alertCount": 2
    },
    {
        "name": "vnpt-bng-01",
        "role": "Gateway",
        "icon": "fa-network-wired",
        "status": "Reporting",
        "lastEventRel": "Last event received 45s ago",
        "lastEventTs": "26 Oct 2026, 01:11:35 GMT+7",
        "note": "Active RADIUS & PPPoE subscriber telemetry stream (680 EPS).",
        "alertCount": 1
    },
    {
        "name": "vnpt-olt-01",
        "role": "Gateway",
        "icon": "fa-sitemap",
        "status": "Reporting",
        "lastEventRel": "Last event received 2m ago",
        "lastEventTs": "26 Oct 2026, 01:10:00 GMT+7",
        "note": "Active OMCI & GPON optical telemetry stream (140 EPS).",
        "alertCount": 1
    },
    {
        "name": "vnpt-dns-resolver",
        "role": "Server",
        "icon": "fa-database",
        "status": "Reporting",
        "lastEventRel": "Last event received 5s ago",
        "lastEventTs": "26 Oct 2026, 01:12:15 GMT+7",
        "note": "Active BIND named query log telemetry stream (850 QPS).",
        "alertCount": 1
    }
]

SCENARIO_RESULTS = [
    {
        "id": "SC-01",
        "testedTs": "26 Oct, 01:10",
        "code": "T1046",
        "name": "Network Service Scanning",
        "tool": "nmap 7.94",
        "rule": "100200",
        "linkedEventId": "EVT-2610-089",
        "detected": True,
        "delta": 1.8,
        "notes": "Kịch bản kiểm thử E2E tự động hóa Playwright đạt chuẩn nghiệm thu VNPT N4.2.",
        "highlighted": True
    },
    {
        "id": "SC-02",
        "testedTs": "26 Oct, 01:07",
        "code": "T1110",
        "name": "SSH Credential Brute Force",
        "tool": "hydra 9.5",
        "rule": "100210",
        "linkedEventId": "EVT-2610-092",
        "detected": True,
        "delta": 1.5,
        "notes": "Khóa IP 198.51.100.44 tự động trên vnpt-edge-fw-01 sau 1.5 giây.",
        "highlighted": False
    },
    {
        "id": "SC-03",
        "testedTs": "26 Oct, 01:12",
        "code": "T1557",
        "name": "Spanning-Tree BPDU Spoofing",
        "tool": "yersinia 0.8.2",
        "rule": "100999",
        "linkedEventId": "EVT-2610-099",
        "detected": True,
        "delta": 1.4,
        "notes": "Cổng Gi0/24 chuyển sang trạng thái Root-Inconsistent ngay lập tức.",
        "highlighted": False
    },
    {
        "id": "SC-04",
        "testedTs": "26 Oct, 00:20",
        "code": "T1498",
        "name": "SYN Flood DoS Attack",
        "tool": "hping3 3.0",
        "rule": "100305",
        "linkedEventId": "EVT-2610-079",
        "detected": True,
        "delta": 2.1,
        "notes": "Kích hoạt SYN cookies và chuyển hướng dòng lưu lượng qua DDoS scrubber.",
        "highlighted": False
    },
    {
        "id": "SC-05",
        "testedTs": "26 Oct, 00:37",
        "code": "T1078",
        "name": "VPN Login Anomaly",
        "tool": "openvpn-client",
        "rule": "100280",
        "linkedEventId": "EVT-2610-084",
        "detected": True,
        "delta": 2.1,
        "notes": "Xác thực MFA bổ sung và cách ly phiên VPN bất thường từ dải IP lạ.",
        "highlighted": False
    },
    {
        "id": "SC-06",
        "testedTs": "25 Oct, 23:42",
        "code": "T1557.002",
        "name": "ARP Cache Poisoning",
        "tool": "arpspoof 2.4",
        "rule": "100255",
        "linkedEventId": "EVT-2610-072",
        "detected": True,
        "delta": 2.8,
        "notes": "Dynamic ARP Inspection trên switch tầng access ngăn chặn toàn bộ gói tin giả mạo gateway.",
        "highlighted": False
    }
]

alerts_store = [dict(a) for a in INITIAL_ALERTS]
scenarios_store = [dict(s) for s in SCENARIO_RESULTS]

# Helper functions for CSV sanitization and metric calculations

# --- REQ-FR-11: CSV Formula Injection Guard (ASSUMPTION-04) ---
_CSV_INJECT_RE = re.compile(r'^[\s\uFEFF]*[=+\-@|%]')

def csv_safe_cell(value) -> str:
    """Khử độc một ô dữ liệu CSV để phòng chống tấn công CSV/Formula Injection.

    Phòng vệ CSV Injection (Formula Injection / DDE Shell) theo REQ-FR-11:
    Nếu một ô trong file xuất báo cáo bắt đầu bằng ký tự '=', '+', '-', '@', '|', '%',
    Excel hoặc phần mềm bảng tính sẽ tự động thực thi công thức mã độc khi analyst mở file.
    BẮT BUỘC thêm tiền tố dấu nháy đơn (') để ép bảng tính coi đó là chuỗi thuần túy.

    Args:
        value: Giá trị ô cần kiểm tra và xử lý.

    Returns:
        str: Chuỗi an toàn đã được khử độc nếu bắt đầu bằng ký tự đặc biệt.
    """
    s = str(value)
    if _CSV_INJECT_RE.match(s):
        return "'" + s
    return s

def csv_safe_row(row: list) -> list:
    """Áp dụng khử độc công thức CSV cho toàn bộ các phần tử trong một hàng.

    Args:
        row: Danh sách các giá trị trong một hàng của bảng tính.

    Returns:
        list: Danh sách các giá trị an toàn đã được xử lý qua csv_safe_cell.
    """
    return [csv_safe_cell(v) for v in row]

# --- ASSUMPTION-01: 4-State FE ↔ SQLite 2-flag bridge ---
def state_to_db_flags(state: str) -> dict:
    """Chuyển đổi trạng thái giao diện (FE 4-State) sang cờ lưu trữ SQLite (2 Flags).

    Lớp cầu nối chuyển đổi (Bridge layer ASSUMPTION-01) tương thích với SRS SQLite schema:
    - New: acknowledged=0, suppressed=False
    - Investigating: acknowledged=1, suppressed=False
    - Acknowledged: acknowledged=1, suppressed=False
    - Resolved: acknowledged=1, suppressed=True

    Args:
        state: Tên trạng thái hiển thị trên giao diện ('New', 'Investigating', 'Acknowledged', 'Resolved').

    Returns:
        dict: Bộ cờ {'acknowledged': int, 'suppressed': bool}.
    """
    _MAP = {
        "New":          {"acknowledged": 0, "suppressed": False},
        "Investigating": {"acknowledged": 1, "suppressed": False},
        "Acknowledged": {"acknowledged": 1, "suppressed": False},
        "Resolved":     {"acknowledged": 1, "suppressed": True},
    }
    return _MAP.get(state, {"acknowledged": 0, "suppressed": False})

def db_flags_to_state(acknowledged: int, suppressed: bool) -> str:
    """Chuyển đổi cờ SQLite database ngược lại trạng thái hiển thị của Frontend.

    Args:
        acknowledged: Cờ ghi nhận sự cố (0 hoặc 1).
        suppressed: Cờ ẩn/đóng cảnh báo (True/False).

    Returns:
        str: Chuỗi trạng thái ('Resolved', 'Acknowledged' hoặc 'New').
    """
    if suppressed:
        return "Resolved"
    return "Acknowledged" if acknowledged else "New"

# --- Auth helper functions (ASSUMPTION-02) ---
def _verify_password(plain: str, stored_plain: str) -> bool:
    """Xác thực mật khẩu người dùng theo chuẩn PBKDF2-HMAC-SHA256 với cơ chế so sánh an toàn thời gian.

    Chống Timing Attack: Dùng hmac.compare_digest với thời gian so sánh hằng số O(1)
    thay cho toán tử '==' thông thường nhằm ngăn chặn hacker đoán mật khẩu qua độ trễ phản hồi.

    Args:
        plain: Mật khẩu dạng văn bản gốc do người dùng nhập từ form đăng nhập.
        stored_plain: Mật khẩu dạng văn bản gốc chuẩn của tài khoản quản trị demo.

    Returns:
        bool: True nếu khớp mật khẩu, False nếu không hợp lệ.
    """
    return hmac.compare_digest(
        hashlib.pbkdf2_hmac('sha256', plain.encode(), b'vnpt-soc-salt', 260000).hex(),
        hashlib.pbkdf2_hmac('sha256', stored_plain.encode(), b'vnpt-soc-salt', 260000).hex()
    )

def _create_session(username: str, role: str = "admin") -> str:
    """Khởi tạo phiên làm việc (Session) mới và lưu vào in-memory session store.

    Args:
        username: Tên tài khoản người dùng đăng nhập.
        role: Quyền hạn phân vai ('admin', 'tier1', 'tier2').

    Returns:
        str: Session ID ngẫu nhiên an toàn dưới dạng URL-safe token.
    """
    session_id = secrets.token_urlsafe(32)
    _sessions[session_id] = {
        "username": username,
        "role": role,
        "created_at": datetime.utcnow().isoformat()
    }
    return session_id

def _get_session(session_id: str | None) -> dict | None:
    """Kiểm tra và truy xuất thông tin phiên làm việc từ cookie session_id.

    Args:
        session_id: Mã định danh phiên làm việc từ cookie người dùng.

    Returns:
        Optional[dict]: Thông tin phiên nếu hợp lệ, ngược lại None.
    """
    if not session_id:
        return None
    return _sessions.get(session_id)

def _generate_csrf_token(session_id: str) -> str:
    """Tạo mã xác thực CSRF Token ký bằng HMAC gắn liền với session_id.

    Args:
        session_id: Mã định danh phiên làm việc của người dùng.

    Returns:
        str: Chuỗi token bảo vệ CSRF an toàn.
    """
    return _SERIALIZER.dumps(session_id, salt="csrf")

def _validate_csrf_token(token: str, session_id: str) -> bool:
    """Xác thực tính hợp lệ và hạn sử dụng (1 giờ) của CSRF token đối chiếu với session_id.

    Args:
        token: Chuỗi CSRF token cần kiểm tra.
        session_id: Mã phiên làm việc cần đối soát.

    Returns:
        bool: True nếu token hợp lệ và còn hạn sử dụng, ngược lại False.
    """
    try:
        loaded = _SERIALIZER.loads(token, salt="csrf", max_age=_CSRF_MAX_AGE)
        return loaded == session_id
    except (BadSignature, SignatureExpired):
        return False

def get_window_max_minutes(win: str) -> int:
    """Quy đổi chuỗi cửa sổ thời gian sang số phút tối đa để lọc dữ liệu.

    Args:
        win: Tên cửa sổ thời gian ('1h', '24h', '7d', 'Last 1 hour', 'Last 24 hours', 'Last 7 days').

    Returns:
        int: Số phút tối đa (60, 1440, hoặc 10080).
    """
    if win in ('1h', 'Last 1 hour'):
        return 60
    if win in ('7d', 'Last 7 days'):
        return 10080
    return 1440  # 24h

def compute_overview_stats(time_window: str = "24h") -> tuple:
    """Tính toán bộ dữ liệu thống kê và danh sách hiển thị cho trang Overview.

    Args:
        time_window: Khung thời gian cần tổng hợp ('1h', '24h', '7d').

    Returns:
        tuple: (stats_dict, queue_alerts_list, top_rules_list, top_ips_list, dev_types_list).
    """
    max_mins = get_window_max_minutes(time_window)
    active_alerts = [a for a in alerts_store if a.get("ageMinutes", 0) <= max_mins]

    total = len(active_alerts)
    crit = sum(1 for a in active_alerts if a["severity"] == "Critical")
    high = sum(1 for a in active_alerts if a["severity"] == "High")
    med = sum(1 for a in active_alerts if a["severity"] == "Medium")
    low = sum(1 for a in active_alerts if a["severity"] == "Low")

    stats = {
        "total": total,
        "crit": crit,
        "high": high,
        "med": med,
        "low": low
    }

    ip_counts: dict = {}
    for a in active_alerts:
        src = a.get("srcIp")
        if src:
            ip_counts[src] = ip_counts.get(src, 0) + 1
    sorted_ips = sorted(ip_counts.items(), key=lambda item: item[1], reverse=True)[:5]
    top_ips = [
        {"ip": ip, "count": cnt, "pct": round((cnt / total) * 100) if total else 0}
        for ip, cnt in sorted_ips
    ]
    if not top_ips:
        top_ips = [{"ip": "—", "count": 0, "pct": 0}]

    type_counts: dict = {}
    for a in active_alerts:
        t = a.get("assetType", "Other").lower()
        type_counts[t] = type_counts.get(t, 0) + 1
    sorted_types = sorted(type_counts.items(), key=lambda item: item[1], reverse=True)
    dev_types = [
        {"type": t, "count": cnt, "pct": round((cnt / total) * 100) if total else 0}
        for t, cnt in sorted_types
    ]
    if not dev_types:
        dev_types = [{"type": "none", "count": 0, "pct": 0}]

    queue_alerts = active_alerts[:6]
    top_rules = active_alerts[:5]

    return stats, queue_alerts, top_rules, top_ips, dev_types

def compute_scenario_stats() -> dict:
    """Tính toán chỉ số SLA kiểm thử kịch bản tấn công MITRE ATT&CK theo chuẩn VNPT N4.2.

    Returns:
        dict: Thống kê số lần chạy (runs), số phát hiện (detected), tỷ lệ (rate),
            độ trễ delta trung bình (avg), số luật liên quan (rules_count).
    """
    total = len(scenarios_store)
    detected = sum(1 for s in scenarios_store if s["detected"])
    rate = round((detected / total) * 100) if total else 100
    avg = round(sum(s["delta"] for s in scenarios_store) / total, 1) if total else 0.0
    rules_covered = list(dict.fromkeys(s["rule"] for s in scenarios_store))

    return {
        "runs": total,
        "detected": detected,
        "rate": rate,
        "avg": avg,
        "rules_count": len(rules_covered),
        "rules_covered": rules_covered
    }

def filter_alerts(
    q: str = "",
    time_range: str = "Last 24 hours",
    severity: str = "ALL",
    rule: str = "",
    ip: str = "",
    asset: str = "ALL",
    state: str = "ALL"
) -> list:
    """Lọc danh sách cảnh báo SOC theo từ khóa, thời gian, mức độ, luật và thiết bị.

    Args:
        q: Từ khóa tìm kiếm tự do (khớp với tiêu đề, mã rule, asset, IP nguồn, ID sự kiện).
        time_range: Khung thời gian cần lọc ('1h', '24h', '7d').
        severity: Mức độ nghiêm trọng ('ALL', 'Critical', 'High', 'Medium', 'Low').
        rule: Mã định danh luật Suricata/Wazuh cần lọc.
        ip: Địa chỉ IP nguồn cần lọc.
        asset: Tên thiết bị đích cần lọc ('ALL' hoặc tên cụ thể).
        state: Trạng thái xử lý ('ALL', 'New', 'Investigating', 'Acknowledged', 'Resolved').

    Returns:
        list: Danh sách cảnh báo đã lọc thỏa mãn toàn bộ điều kiện.
    """
    max_mins = get_window_max_minutes(time_range)
    q_lower = q.strip().lower()
    rule_lower = rule.strip().lower()
    ip_lower = ip.strip().lower()

    filtered = []
    for a in alerts_store:
        if a.get("ageMinutes", 0) > max_mins:
            continue
        if q_lower and not (
            q_lower in a["title"].lower() or
            q_lower in a["ruleId"].lower() or
            q_lower in a["asset"].lower() or
            q_lower in a["srcIp"].lower() or
            q_lower in a["eventId"].lower()
        ):
            continue
        if severity != "ALL" and a["severity"] != severity:
            continue
        if state != "ALL" and a["state"] != state:
            continue
        if rule_lower and rule_lower not in a["ruleId"].lower():
            continue
        if ip_lower and ip_lower not in a["srcIp"].lower():
            continue
        if asset != "ALL" and a["asset"] != asset:
            continue
        filtered.append(a)
    return filtered

# Full page routes for direct navigation and refresh

@app.get("/", response_class=HTMLResponse)
async def get_overview_page(request: Request, window: str = "24h"):
    """Hiển thị toàn bộ trang Tổng quan (SOC Command Center Overview) kèm Layout Master.

    Args:
        request: FastAPI Request instance.
        window: Khung thời gian phân tích ('1h', '24h', '7d').

    Returns:
        HTMLResponse: Giao diện hoàn chỉnh render từ template `pages/index.html`.
    """
    stats, queue_alerts, top_rules, top_ips, dev_types = compute_overview_stats(window)
    return templates.TemplateResponse(
        request=request,
        name="pages/index.html",
        context={
            "stats": stats,
            "queue_alerts": queue_alerts,
            "top_rules": top_rules,
            "top_ips": top_ips,
            "dev_types": dev_types,
            "current_window": window
        }
    )

@app.get("/alerts", response_class=HTMLResponse)
async def get_alerts_page(request: Request, severity: str | None = "ALL", asset: str | None = "ALL"):
    """Hiển thị toàn bộ trang Hàng đợi cảnh báo (Alert Queue) kèm Layout Master.

    Args:
        request: FastAPI Request instance.
        severity: Bộ lọc mức độ cảnh báo ban đầu (mặc định 'ALL').
        asset: Bộ lọc thiết bị nguồn ban đầu (mặc định 'ALL').

    Returns:
        HTMLResponse: Giao diện hoàn chỉnh render từ template `pages/alerts.html`.
    """
    filtered = filter_alerts(severity=severity or "ALL", asset=asset or "ALL")
    alerts_stats = {
        "total": len(filtered),
        "new": sum(1 for a in filtered if a["state"] == "New"),
        "crit": sum(1 for a in filtered if a["severity"] == "Critical"),
        "high": sum(1 for a in filtered if a["severity"] == "High"),
        "investigating": sum(1 for a in alerts_store if a["state"] == "Investigating"),
        "resolved": sum(1 for a in alerts_store if a["state"] == "Resolved")
    }
    return templates.TemplateResponse(
        request=request,
        name="pages/alerts.html",
        context={
            "alerts": filtered,
            "alerts_stats": alerts_stats,
            "total_count": len(alerts_store),
            "current_severity": severity,
            "current_asset": asset,
            "current_state": "ALL"
        }
    )

@app.get("/devices", response_class=HTMLResponse)
async def get_devices_page(request: Request):
    """Hiển thị toàn bộ trang Giám sát thiết bị mạng (Monitored Devices) kèm Layout Master.

    Args:
        request: FastAPI Request instance.

    Returns:
        HTMLResponse: Giao diện hoàn chỉnh render từ template `pages/devices.html`.
    """
    rep_count = sum(1 for d in DEVICES if d["status"] == "Reporting")
    sil_count = sum(1 for d in DEVICES if d["status"] == "Silent")
    devices_stats = {
        "total": len(DEVICES),
        "reporting": rep_count,
        "silent": sil_count
    }
    return templates.TemplateResponse(
        request=request,
        name="pages/devices.html",
        context={
            "devices": DEVICES,
            "devices_stats": devices_stats
        }
    )

@app.get("/scenarios", response_class=HTMLResponse)
async def get_scenarios_page(request: Request):
    """Hiển thị toàn bộ trang Phòng thí nghiệm kịch bản tấn công MITRE ATT&CK kèm Layout Master.

    Args:
        request: FastAPI Request instance.

    Returns:
        HTMLResponse: Giao diện hoàn chỉnh render từ template `pages/scenarios.html`.
    """
    scenario_stats = compute_scenario_stats()
    return templates.TemplateResponse(
        request=request,
        name="pages/scenarios.html",
        context={
            "scenarios": scenarios_store,
            "scenario_stats": scenario_stats
        }
    )

# HTMX view partials for seamless tab switching

@app.get("/views/overview", response_class=HTMLResponse)
async def get_overview_view(request: Request, window: str = "24h"):
    """Trả về partial nội dung Overview để HTMX hoán đổi mượt mà vào #main-content.

    Args:
        request: FastAPI Request instance.
        window: Khung thời gian lọc ('1h', '24h', '7d').

    Returns:
        HTMLResponse: Đoạn mã HTML render từ `partials/overview_content.html`.
    """
    stats, queue_alerts, top_rules, top_ips, dev_types = compute_overview_stats(window)
    return templates.TemplateResponse(
        request=request,
        name="partials/overview_content.html",
        context={
            "stats": stats,
            "queue_alerts": queue_alerts,
            "top_rules": top_rules,
            "top_ips": top_ips,
            "dev_types": dev_types,
            "current_window": window
        }
    )

@app.get("/views/alerts", response_class=HTMLResponse)
async def get_alerts_view(request: Request, severity: str | None = "ALL", asset: str | None = "ALL"):
    """Trả về partial nội dung Alert Queue để HTMX hoán đổi mượt mà vào #main-content.

    Args:
        request: FastAPI Request instance.
        severity: Bộ lọc mức độ ('ALL', 'Critical'...).
        asset: Bộ lọc thiết bị ('ALL' hoặc tên cụ thể).

    Returns:
        HTMLResponse: Đoạn mã HTML render từ `partials/alerts_content.html`.
    """
    filtered = filter_alerts(severity=severity or "ALL", asset=asset or "ALL")
    alerts_stats = {
        "total": len(filtered),
        "new": sum(1 for a in filtered if a["state"] == "New"),
        "crit": sum(1 for a in filtered if a["severity"] == "Critical"),
        "high": sum(1 for a in filtered if a["severity"] == "High"),
        "investigating": sum(1 for a in alerts_store if a["state"] == "Investigating"),
        "resolved": sum(1 for a in alerts_store if a["state"] == "Resolved")
    }
    return templates.TemplateResponse(
        request=request,
        name="partials/alerts_content.html",
        context={
            "alerts": filtered,
            "alerts_stats": alerts_stats,
            "total_count": len(alerts_store),
            "current_severity": severity,
            "current_asset": asset,
            "current_state": "ALL"
        }
    )

@app.get("/views/devices", response_class=HTMLResponse)
async def get_devices_view(request: Request):
    """Trả về partial danh sách thiết bị để HTMX hoán đổi mượt mà vào #main-content.

    Args:
        request: FastAPI Request instance.

    Returns:
        HTMLResponse: Đoạn mã HTML render từ `partials/devices_content.html`.
    """
    rep_count = sum(1 for d in DEVICES if d["status"] == "Reporting")
    sil_count = sum(1 for d in DEVICES if d["status"] == "Silent")
    devices_stats = {
        "total": len(DEVICES),
        "reporting": rep_count,
        "silent": sil_count
    }
    return templates.TemplateResponse(
        request=request,
        name="partials/devices_content.html",
        context={
            "devices": DEVICES,
            "devices_stats": devices_stats
        }
    )

@app.get("/views/scenarios", response_class=HTMLResponse)
async def get_scenarios_view(request: Request):
    """Trả về partial lab kịch bản tấn công để HTMX hoán đổi mượt mà vào #main-content.

    Args:
        request: FastAPI Request instance.

    Returns:
        HTMLResponse: Đoạn mã HTML render từ `partials/scenarios_content.html`.
    """
    scenario_stats = compute_scenario_stats()
    return templates.TemplateResponse(
        request=request,
        name="partials/scenarios_content.html",
        context={
            "scenarios": scenarios_store,
            "scenario_stats": scenario_stats
        }
    )

# HTMX actions and API endpoints

@app.get("/api/overview/stats", response_class=HTMLResponse)
async def get_overview_stats(request: Request, window: str = "24h"):
    """Tổng hợp số liệu thống kê tổng quan SOC và trả về fragment HTML cho HTMX.

    Args:
        request: FastAPI Request instance.
        window: Khung thời gian thống kê ('1h', '24h', '7d').

    Returns:
        HTMLResponse: Đoạn mã HTML render từ template `partials/overview_content.html`.
    """
    stats, queue_alerts, top_rules, top_ips, dev_types = compute_overview_stats(window)
    return templates.TemplateResponse(
        request=request,
        name="partials/overview_content.html",
        context={
            "stats": stats,
            "queue_alerts": queue_alerts,
            "top_rules": top_rules,
            "top_ips": top_ips,
            "dev_types": dev_types,
            "current_window": window
        }
    )

@app.get("/api/alerts/filter", response_class=HTMLResponse)
async def filter_alerts_endpoint(
    request: Request,
    q: str | None = "",
    time: str | None = "Last 24 hours",
    severity: str | None = "ALL",
    rule: str | None = "",
    ip: str | None = "",
    asset: str | None = "ALL",
    state: str | None = "ALL"
):
    """Lọc danh sách cảnh báo SOC theo tiêu chí tìm kiếm và trả về bảng HTML cho HTMX.

    Args:
        request: FastAPI Request instance.
        q: Từ khóa tìm kiếm nhanh (IP, Event ID, Rule ID, Asset).
        time: Khoảng thời gian phân tích.
        severity: Mức độ nghiêm trọng cần lọc.
        rule: Mã luật cảnh báo.
        ip: Địa chỉ IP nguồn.
        asset: Tên thiết bị mạng nguồn.
        state: Trạng thái xử lý sự cố.

    Returns:
        HTMLResponse: Bảng cảnh báo render từ template `partials/alerts_table.html`.
    """
    filtered = filter_alerts(
        q=q or "",
        time_range=time or "Last 24 hours",
        severity=severity or "ALL",
        rule=rule or "",
        ip=ip or "",
        asset=asset or "ALL",
        state=state or "ALL"
    )
    return templates.TemplateResponse(
        request=request,
        name="partials/alerts_table.html",
        context={
            "alerts": filtered
        }
    )

@app.get("/api/alerts/{event_id}/drawer", response_class=HTMLResponse)
async def get_alert_drawer(request: Request, event_id: str):
    """Lấy thông tin chi tiết của một cảnh báo để hiển thị slide-over drawer bên phải.

    Args:
        request: FastAPI Request instance.
        event_id: Mã định danh sự kiện cảnh báo (ví dụ: 'EVT-2610-099').

    Returns:
        HTMLResponse: Giao diện chi tiết render từ template `partials/drawer_content.html` hoặc 404.
    """
    alert = next((a for a in alerts_store if a["eventId"] == event_id), None)
    if not alert:
        return HTMLResponse("<div class='p-6 text-stone-500'>Alert not found</div>", status_code=404)
    return templates.TemplateResponse(
        request=request,
        name="partials/drawer_content.html",
        context={
            "alert": alert
        }
    )

@app.post("/api/alerts/{event_id}/ack", response_class=HTMLResponse)
async def acknowledge_alert(
    request: Request,
    event_id: str,
    source: str | None = Form(None),
    session_id: str | None = Cookie(None)
):
    """
    Acknowledge an alert. Called from Web UI or Telegram webhook.
    Tracks who acknowledged (ASSUMPTION-05).
    """
    alert = next((a for a in alerts_store if a["eventId"] == event_id), None)
    if alert:
        alert["state"] = "Acknowledged"
        # Determine acker: explicit source param (Telegram) or session username
        session = _get_session(session_id)
        acker = source or (session["username"] if session else "admin")
        alert["ackedBy"] = acker                           # e.g. "admin" or "telegram:84912345678"
        alert["ackedAt"] = datetime.utcnow().isoformat()  # UTC ISO timestamp
    stats, queue_alerts, top_rules, top_ips, dev_types = compute_overview_stats("24h")
    return templates.TemplateResponse(
        request=request,
        name="partials/overview_content.html",
        context={
            "stats": stats,
            "queue_alerts": queue_alerts,
            "top_rules": top_rules,
            "top_ips": top_ips,
            "dev_types": dev_types,
            "current_window": "24h"
        },
        headers={"HX-Trigger": '{"showToast": {"style": "light", "message": "Updated 1 alert to Acknowledged"}}'}
    )

@app.post("/api/alerts/{event_id}/state", response_class=HTMLResponse)
async def update_alert_state(request: Request, event_id: str, state: str = Form(...)):
    """Cập nhật trạng thái xử lý của cảnh báo trong kho lưu trữ in-memory.

    Args:
        request: FastAPI Request instance.
        event_id: Mã định danh sự kiện cảnh báo.
        state: Trạng thái mới ('New', 'Investigating', 'Acknowledged', 'Resolved').

    Returns:
        HTMLResponse: Giao diện drawer cập nhật kèm header HX-Trigger hiển thị thông báo toast.
    """
    alert = next((a for a in alerts_store if a["eventId"] == event_id), None)
    if alert:
        alert["state"] = state
    return templates.TemplateResponse(
        request=request,
        name="partials/drawer_content.html",
        context={
            "alert": alert
        },
        headers={"HX-Trigger": f'{{"showToast": {{"style": "light", "message": "Updated {event_id} to {state}"}}}}'}
    )

@app.post("/api/alerts/bulk-state", response_class=JSONResponse)
async def bulk_update_alerts(state: str = Form(...), event_ids: list[str] = Form(...)):
    """Cập nhật trạng thái hàng loạt cho nhiều sự cố cảnh báo được chọn.

    Args:
        state: Trạng thái mới cần áp dụng cho toàn bộ danh sách.
        event_ids: Danh sách các mã định danh sự kiện được chọn.

    Returns:
        dict: Kết quả cập nhật JSON gồm trạng thái thành công và số bản ghi đã đổi.
    """
    updated_count = 0
    for a in alerts_store:
        if a["eventId"] in event_ids:
            a["state"] = state
            updated_count += 1
    return {"success": True, "updated": updated_count}

@app.post("/api/scenarios", response_class=HTMLResponse)
async def save_scenario(
    request: Request,
    id: str | None = Form(""),
    code: str = Form(...),
    tool: str = Form(...),
    rule: str = Form(...),
    linkedEventId: str = Form(...),
    detected: bool = Form(False),
    notes: str = Form(...)
):
    """Lưu hoặc cập nhật một kịch bản kiểm thử tấn công trong phòng thí nghiệm SOC.

    Args:
        request: FastAPI Request instance.
        id: Mã kịch bản hiện tại nếu chỉnh sửa, rỗng nếu tạo mới.
        code: Mã kỹ thuật tấn công MITRE ATT&CK.
        tool: Công cụ hoặc script kích hoạt tấn công.
        rule: Luật phát hiện tương ứng.
        linkedEventId: Mã sự cố cảnh báo liên kết để tính độ trễ SLA.
        detected: Cờ ghi nhận hệ thống phát hiện thành công hay không.
        notes: Ghi chú phân tích chi tiết của kỹ sư SOC.

    Returns:
        HTMLResponse: Bảng kịch bản mới cập nhật render từ `partials/scenarios_table.html`.
    """
    linked_alert = next((a for a in alerts_store if a["eventId"] == linkedEventId), None)
    delta = linked_alert["testDeltaSec"] if linked_alert else 1.8

    technique_names = {
        "T1046": "Network Service Scanning",
        "T1110": "SSH Credential Brute Force",
        "T1557": "Spanning-Tree BPDU Spoofing",
        "T1498": "SYN Flood Denial of Service"
    }
    name = technique_names.get(code, "Service Scan")

    # Clear highlighted on all
    for s in scenarios_store:
        s["highlighted"] = False

    if id:
        # Edit existing
        existing = next((s for s in scenarios_store if s["id"] == id), None)
        if existing:
            existing.update({
                "code": code,
                "name": name,
                "tool": tool,
                "rule": rule,
                "linkedEventId": linkedEventId,
                "detected": detected,
                "delta": delta,
                "notes": notes,
                "highlighted": True
            })
            msg = f"Updated test {code}"
    else:
        # Create new
        new_id = f"SC-{len(scenarios_store) + 1:02d}"
        now_str = datetime.now().strftime("%d %b, %H:%M")
        scenarios_store.insert(0, {
            "id": new_id,
            "testedTs": now_str,
            "code": code,
            "name": name,
            "tool": tool,
            "rule": rule,
            "linkedEventId": linkedEventId,
            "detected": detected,
            "delta": delta,
            "notes": notes,
            "highlighted": True
        })
        msg = f"Test {code} recorded"

    return templates.TemplateResponse(
        request=request,
        name="partials/scenarios_table.html",
        context={
            "scenarios": scenarios_store
        },
        headers={"HX-Trigger": f'{{"showToast": {{"style": "dark", "message": "{msg}"}}}}'}
    )

@app.get("/api/scenarios/{scenario_id}/edit", response_class=JSONResponse)
async def get_scenario_edit_data(scenario_id: str):
    """Truy xuất dữ liệu chi tiết của một kịch bản kiểm thử để nạp vào biểu mẫu chỉnh sửa.

    Args:
        scenario_id: Mã định danh kịch bản (ví dụ: 'SC-01').

    Returns:
        dict: Dữ liệu kịch bản dạng JSON hoặc mã lỗi 404.
    """
    row = next((s for s in scenarios_store if s["id"] == scenario_id), None)
    if not row:
        return JSONResponse({"error": "Not found"}, status_code=404)
    return row

@app.delete("/api/scenarios/{scenario_id}", response_class=HTMLResponse)
async def delete_scenario(request: Request, scenario_id: str):
    """Xóa một bản ghi kịch bản kiểm thử khỏi kho lưu trữ in-memory.

    Args:
        request: FastAPI Request instance.
        scenario_id: Mã định danh kịch bản cần xóa.

    Returns:
        HTMLResponse: Bảng danh sách kịch bản sau khi xóa.
    """
    global scenarios_store
    scenarios_store = [s for s in scenarios_store if s["id"] != scenario_id]
    return templates.TemplateResponse(
        request=request,
        name="partials/scenarios_table.html",
        context={
            "scenarios": scenarios_store
        },
        headers={"HX-Trigger": '{"showToast": {"style": "light", "message": "Removed test record"}}'}
    )

@app.get("/api/scenarios/calculate-delta", response_class=JSONResponse)
async def calculate_delta(linked_id: str):
    """Tính toán thời gian kiểm thử và độ trễ phát hiện (Detection Delta SLA) từ cảnh báo liên kết.

    Công thức đo lường viễn thông & SLA nghiệm thu VNPT N4.2 theo Rule 3.5:
    Delta = Thời điểm SOC ghi nhận cảnh báo (Alert observed) - Thời điểm bắt đầu kích hoạt tấn công (Test started).
    Ngưỡng SLA cam kết của VNPT N4.2 là <= 5.0 giây.
    Nếu delta <= 5.0s, gán nhãn trạng thái 'Within target', ngược lại đánh dấu 'Exceeded SLA'.

    Args:
        linked_id: Mã định danh sự kiện cảnh báo (ví dụ: 'EVT-2610-099').

    Returns:
        JSONResponse: Đối tượng JSON chứa testStartTs, testObsTs và testDeltaSec.
    """
    item = next((a for a in alerts_store if a["eventId"] == linked_id), alerts_store[3])
    return {
        "testStartTs": item.get("testStartTs", "01:10:46.0"),
        "testObsTs": item.get("testObsTs", "01:10:47.8"),
        "testDeltaSec": item.get("testDeltaSec", 1.8)
    }

@app.get("/api/live-status", response_class=HTMLResponse)
async def live_status_pulse():
    """Tạo fragment trạng thái nhịp tim trực tiếp phục vụ polling trên thanh Topbar.

    Returns:
        HTMLResponse: Thẻ HTML thể hiện chấm xanh trực tiếp và thời gian cập nhật.
    """
    return HTMLResponse(
        '<span id="live-status-dot" class="status-dot dot-live" aria-hidden="true"></span>'
        '<span id="live-status-text">Live · updated <span id="live-sec-counter" class="font-mono">1s</span> ago · GMT+7</span>'
    )

# Authentication routes and session management

@app.get("/api/auth/csrf-token", response_class=JSONResponse)
async def get_csrf_token(response: Response, session_id: str | None = Cookie(None)):
    """Tạo mã CSRF token mới phục vụ bảo vệ biểu mẫu modal hoặc các thao tác xác thực.

    Args:
        response: FastAPI Response instance.
        session_id: ID phiên làm việc hiện tại từ cookie (nếu có).

    Returns:
        dict: Đối tượng JSON chứa giá trị csrf_token hợp lệ.
    """
    sid = session_id if _get_session(session_id) else secrets.token_urlsafe(16)
    token = _generate_csrf_token(sid)
    return {"csrf_token": token}

@app.post("/api/auth/login", response_class=JSONResponse)
async def login(
    response: Response,
    username: str = Form(...),
    password: str = Form(...),
    csrf_token: str | None = Form(None)
):
    """Xác thực tài khoản người dùng theo chuẩn PBKDF2-HMAC-SHA256.

    Hỗ trợ 3 tài khoản demo cho môi trường kiểm thử SOC (admin, tier2, tier1).
    Thiết lập cookie phiên HttpOnly và trả về thông tin vai trò khi thành công.

    Args:
        response: Đối tượng Response của FastAPI để gán HttpOnly cookie.
        username: Tên đăng nhập người dùng gửi từ form modal.
        password: Mật khẩu người dùng nhập.
        csrf_token: Token chống tấn công giả mạo yêu cầu chéo trang (CSRF).

    Returns:
        JSONResponse: Trạng thái thành công kèm username và role, hoặc mã lỗi 401.
    """
    normalized_user = username.strip().lower()
    account = _DEMO_ACCOUNTS.get(normalized_user)

    if not account or not _verify_password(password, account["password"]):
        return JSONResponse({"success": False, "error": "Invalid username or password"}, status_code=401)

    role = account["role"]
    session_id = _create_session(normalized_user, role=role)

    # Set HttpOnly, SameSite=Lax session cookie (8h)
    response.set_cookie(
        key="session_id",
        value=session_id,
        max_age=_SESSION_MAX_AGE,
        httponly=True,
        samesite="lax",
        secure=False  # Set True in production with HTTPS
    )

    return {"success": True, "username": normalized_user, "role": role, "label": account["label"]}

@app.post("/api/auth/logout", response_class=JSONResponse)
async def logout(response: Response, session_id: str | None = Cookie(None)):
    """Invalidate session and clear cookie."""
    if session_id and session_id in _sessions:
        del _sessions[session_id]
    response.delete_cookie("session_id")
    return {"success": True}

@app.get("/api/auth/me", response_class=JSONResponse)
async def get_me(session_id: str | None = Cookie(None)):
    """Check current session status."""
    session = _get_session(session_id)
    if session:
        return {"authenticated": True, "username": session["username"], "role": session["role"]}
    return {"authenticated": False}

# Redesigned public sign-in and UI routes (VNPT SOC N4.2)

from app.ui import mock_feed, topology
from app.ui.routes import router as ui_router

app.include_router(ui_router)


@app.get("/login", response_class=HTMLResponse, name="auth.login")
@app.get("/auth/login", response_class=HTMLResponse)
async def signin_page(request: Request, session_id: str | None = Cookie(None)):
    """Hiển thị toàn bộ trang đăng nhập công khai (VNPT SOC Sign-in Screen).

    Tự động chuyển hướng về trang chủ nếu người dùng đã có phiên đăng nhập hợp lệ.
    Dữ liệu hiển thị (stats, log stream, topology) đều là dữ liệu giả lập từ mock_feed.

    Args:
        request: FastAPI Request instance.
        session_id: Cookie phiên làm việc (nếu có).

    Returns:
        HTMLResponse: Giao diện hoàn chỉnh render từ `auth/sign_in.html`.
    """
    session = _get_session(session_id)
    if session:
        return RedirectResponse(url="/", status_code=303)

    return templates.TemplateResponse(
        request=request,
        name="auth/sign_in.html",
        context={
            "csp_nonce": getattr(request.state, "csp_nonce", ""),
            "stats": mock_feed.stats(),
            "lines": mock_feed.log_lines(time.time(), 5),
            "topology": topology.get_topology_data(),
            "demo_mode": DEMO_MODE,
            "demo_password": _ADMIN_PWD_PLAIN if DEMO_MODE else "",
            "show_build_version": SHOW_BUILD_VERSION,
        },
    )


@app.post("/login", name="auth.login")
@app.post("/auth/login")
async def login_post(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    csrf_token: str | None = Form(None),
    remember: str | None = Form(None),
):
    """Xử lý xác thực người dùng cho cả luồng HTMX lẫn Non-JS (Progressive Enhancement).

    Tuân thủ nguyên tắc an ninh SOC: Mọi nhánh lỗi xác thực đều trả về cùng một thông báo
    chung ('Incorrect username or password.') nhằm ngăn chặn kỹ thuật vét cạn tài khoản.

    Args:
        request: FastAPI Request instance.
        username: Tên đăng nhập gửi từ form.
        password: Mật khẩu người dùng nhập.
        csrf_token: Mã kiểm tra CSRF (nếu có).
        remember: Cờ duy trì phiên đăng nhập 8 tiếng.

    Returns:
        Response: HTMX redirect hoặc fragment lỗi 422; hoặc HTTP 303 Redirect / 422 Full page khi tắt JS.
    """
    normalized_user = username.strip().lower()
    account = _DEMO_ACCOUNTS.get(normalized_user)
    is_htmx = request.headers.get("hx-request") == "true"

    if not account or not _verify_password(password, account["password"]):
        if is_htmx:
            return templates.TemplateResponse(
                request=request,
                name="auth/_feedback.html",
                status_code=422,
            )
        return templates.TemplateResponse(
            request=request,
            name="auth/sign_in.html",
            context={
                "error": True,
                "username_value": username,
                "csp_nonce": getattr(request.state, "csp_nonce", ""),
                "stats": mock_feed.stats(),
                "lines": mock_feed.log_lines(time.time(), 5),
                "topology": topology.get_topology_data(),
                "demo_mode": DEMO_MODE,
                "demo_password": _ADMIN_PWD_PLAIN if DEMO_MODE else "",
                "show_build_version": SHOW_BUILD_VERSION,
            },
            status_code=422,
        )

    role = account["role"]
    session_id = _create_session(normalized_user, role=role)
    cookie_max_age = _SESSION_MAX_AGE if remember else None

    if is_htmx:
        res = Response(status_code=200, headers={"HX-Redirect": "/"})
        res.set_cookie(
            key="session_id",
            value=session_id,
            max_age=cookie_max_age,
            httponly=True,
            samesite="lax",
            secure=False,
        )
        return res

    res = RedirectResponse(url="/", status_code=303)
    res.set_cookie(
        key="session_id",
        value=session_id,
        max_age=cookie_max_age,
        httponly=True,
        samesite="lax",
        secure=False,
    )
    return res


@app.post("/auth/guest", name="auth.guest")
async def guest_post(request: Request):
    """Điều hướng truy cập nhanh vào chế độ Khách (Read-only) không cần mật khẩu.

    Args:
        request: FastAPI Request instance.

    Returns:
        Response hoặc RedirectResponse điều hướng về trang chủ kèm cờ guest=1.
    """
    is_htmx = request.headers.get("hx-request") == "true"
    if is_htmx:
        return Response(status_code=200, headers={"HX-Redirect": "/?guest=1"})
    return RedirectResponse(url="/?guest=1", status_code=303)


@app.get("/auth/forgot", name="auth.forgot")
async def forgot_get(request: Request):
    """Xử lý yêu cầu hỗ trợ quên thông tin đăng nhập trong môi trường kiểm thử SOC.

    Args:
        request: FastAPI Request instance.

    Returns:
        RedirectResponse: Chuyển hướng người dùng về trang /login kèm cờ forgot=1.
    """
    return RedirectResponse(url="/login?forgot=1", status_code=303)

# CSV export handlers

@app.get("/api/export/alerts.csv")
async def export_alerts_csv():
    """Xuất danh sách toàn bộ cảnh báo SOC ra định dạng CSV với cơ chế bảo vệ Formula Injection.

    Phòng vệ CSV Injection (Rule 3.3): Mọi hàng dữ liệu đều được lọc qua hàm csv_safe_row()
    để thêm tiền tố (') trước các ký tự nguy hiểm (=, +, -, @), triệt tiêu rủi ro thực thi lệnh máy tính.

    Returns:
        StreamingResponse: Luồng dữ liệu tệp 'soc_alerts_export.csv'.
    """
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["EventID", "RuleID", "Severity", "Title", "SourceIP", "DestinationIP", "Asset", "Observed", "State"])
    for a in alerts_store:
        writer.writerow(csv_safe_row([
            a["eventId"],
            a["ruleId"],
            a["severity"],
            a["title"],
            a["srcIp"],
            a["dstIp"],
            a["asset"],
            f"{a['observedDate']} {a['observedTime']}",
            a["state"]
        ]))
    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=soc_alerts_export.csv"}
    )

@app.get("/api/export/scenarios.csv")
async def export_scenarios_csv():
    """Xuất kết quả kiểm thử kịch bản tấn công MITRE ATT&CK ra định dạng CSV có bảo vệ an toàn.

    Returns:
        StreamingResponse: Luồng dữ liệu tệp 'soc_attack_scenarios.csv'.
    """
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Tested", "Technique", "Name", "Tool", "Rule", "LinkedAlert", "Detected", "DeltaSeconds", "Notes"])
    for s in scenarios_store:
        writer.writerow(csv_safe_row([
            s["testedTs"],
            s["code"],
            s["name"],
            s["tool"],
            s["rule"],
            s["linkedEventId"],
            s["detected"],
            s["delta"],
            s["notes"]
        ]))
    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=soc_attack_scenarios.csv"}
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)

