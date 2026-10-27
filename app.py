"""
Network Security Monitor – SOC Command Center
Backend Architecture: FastAPI + Jinja2 + HTMX
"""

import io
import csv
import re
import secrets
import hashlib
import hmac
from datetime import datetime, timedelta
from typing import Optional, List
from fastapi import FastAPI, Request, Form, Query, Cookie, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

# Auth config — ASSUMPTION-02
_SECRET_KEY = secrets.token_hex(32)          # Random mỗi lần khởi động (demo mode)
_SESSION_MAX_AGE = 8 * 3600                  # 8 hours in seconds
_CSRF_MAX_AGE = 3600                         # 1 hour
_SERIALIZER = URLSafeTimedSerializer(_SECRET_KEY)

# Demo credentials — trong thực tế đọc từ env/config
# Password hash: PBKDF2-HMAC-SHA256 của "vnpt-soc-2026"
_ADMIN_USERNAME = "admin"
_ADMIN_PWD_PLAIN = "vnpt-soc-2026"          # Chỉ dùng trong demo để verify

# In-memory session store: {session_id: {username, role, created_at}}
_sessions: dict = {}

app = FastAPI(title="Network Security Monitor – SOC Command Center")

# Mount Static Assets (CSS, JS, Icons)
app.mount("/static", StaticFiles(directory="static"), name="static")

# Configure Jinja2 Template Engine
templates = Jinja2Templates(directory="templates")

# =============================================================================
# IN-MEMORY SOC DATA REPOSITORY
# =============================================================================

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
        "observedRel": "2 min ago",
        "ageMinutes": 2,
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
        "eventId": "EVT-2610-089",
        "ruleId": "100200",
        "title": "Port scan detected",
        "severity": "High",
        "state": "New",
        "srcIp": "203.0.113.45",
        "dstIp": "10.0.10.20",
        "asset": "vnpt-edge-fw-01",
        "assetType": "Firewall",
        "observedRel": "5 min ago",
        "ageMinutes": 5,
        "observedDate": "26 Oct 2026",
        "observedTime": "01:10:47 GMT+7",
        "mitre": "T1046 · Network Service Scanning",
        "hits": 3,
        "testStartTs": "01:10:46.0",
        "testObsTs": "01:10:47.8",
        "testDeltaSec": 1.8,
        "rawSyslog": "Oct 26 01:10:47 vnpt-edge-fw-01 suricata[1082]: [1:100200:3] ET SCAN Nmap SYN Scan Detected {TCP} 203.0.113.45:49210 -> 10.0.10.20:1-1024.",
        "playbook": "1. Block scanning IP 203.0.113.45 at perimeter ACL.\n2. Correlate with E2E Playwright test schedule if sourced from authorized red-team subnet."
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
        "observedRel": "18 min ago",
        "ageMinutes": 18,
        "observedDate": "26 Oct 2026",
        "observedTime": "00:54:12 GMT+7",
        "mitre": "T1078 · Valid Accounts",
        "hits": 1,
        "testStartTs": "00:54:10.0",
        "testObsTs": "00:54:12.1",
        "testDeltaSec": 2.1,
        "rawSyslog": "Oct 26 00:54:12 vnpt-edge-fw-01 openvpn[4412]: TLS Auth OK: user=soc_duty_02 rip=192.0.2.88:61023 GeoIP=Unknown-ASN.",
        "playbook": "1. Verify MFA token approval with analyst soc_duty_02.\n2. Revoke active VPN session if unrecognized."
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
        "observedRel": "28 min ago",
        "ageMinutes": 28,
        "observedDate": "26 Oct 2026",
        "observedTime": "01:08:42 GMT+7",
        "mitre": "T1498.001 · Direct Network Flood",
        "hits": 2,
        "testStartTs": "01:08:40.0",
        "testObsTs": "01:08:42.1",
        "testDeltaSec": 2.1,
        "rawSyslog": "Oct 26 01:08:42 vnpt-edge-fw-01 kernel: [UFW SYN-PROXY] SYN rate 14,500 pps from 203.0.113.99 to 10.0.10.15:443 exceeded threshold.",
        "playbook": "1. Enable SYN cookies and rate-limiting on VIP 10.0.10.15:443.\n2. Divert upstream traffic through DDoS scrubbing center."
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
        "alertCount": 1
    },
    {
        "name": "vnpt-agg-switch-05",
        "role": "Switch",
        "icon": "fa-network-wired",
        "status": "Reporting",
        "lastEventRel": "Last event received just now",
        "lastEventTs": "26 Oct 2026, 01:12:20 GMT+7",
        "note": "Active SNMPv3 trap & L2 STP telemetry stream (195 EPS).",
        "alertCount": 1
    },
    {
        "name": "vnpt-access-sw-02",
        "role": "Switch",
        "icon": "fa-server",
        "status": "Silent",
        "lastEventRel": "Last alert received 2 h ago",
        "lastEventTs": "26 Oct 2026, 00:19:56 GMT+7",
        "note": "No alert in 15 min. This does not always mean the device is offline.",
        "alertCount": 0
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
    }
]

alerts_store = [dict(a) for a in INITIAL_ALERTS]
scenarios_store = [dict(s) for s in SCENARIO_RESULTS]

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

# --- REQ-FR-11: CSV Formula Injection Guard (ASSUMPTION-04) ---
_CSV_INJECT_RE = re.compile(r'^[\s\uFEFF]*[=+\-@|%]')

def csv_safe_cell(value) -> str:
    """
    Sanitize a single CSV cell value against Formula Injection attacks.
    Prepends a single-quote ' before any cell whose content starts with
    =, +, -, @, |, % or Unicode whitespace / BOM characters.
    Complies with REQ-FR-11 (VNPT ASSUMPTION-04).
    """
    s = str(value)
    if _CSV_INJECT_RE.match(s):
        return "'" + s
    return s

def csv_safe_row(row: list) -> list:
    """Apply csv_safe_cell() to every element in a CSV row (REQ-FR-11)."""
    return [csv_safe_cell(v) for v in row]

# --- ASSUMPTION-01: 4-State FE ↔ SQLite 2-flag bridge ---
def state_to_db_flags(state: str) -> dict:
    """
    Map FE 4-state string → SQLite acknowledged + suppressed flags.
    ASSUMPTION-01: Bridge layer cho tương thích SRS SQLite schema.
    """
    _MAP = {
        "New":          {"acknowledged": 0, "suppressed": False},
        "Investigating": {"acknowledged": 1, "suppressed": False},
        "Acknowledged": {"acknowledged": 1, "suppressed": False},
        "Resolved":     {"acknowledged": 1, "suppressed": True},
    }
    return _MAP.get(state, {"acknowledged": 0, "suppressed": False})

def db_flags_to_state(acknowledged: int, suppressed: bool) -> str:
    """
    Map SQLite flags → FE state string (reverse bridge).
    Note: Investigating is ephemeral; round-trip resolves to Acknowledged.
    ASSUMPTION-01.
    """
    if suppressed:
        return "Resolved"
    return "Acknowledged" if acknowledged else "New"

# --- Auth helper functions (ASSUMPTION-02) ---
def _verify_password(plain: str, stored_plain: str) -> bool:
    """
    PBKDF2-HMAC-SHA256 comparison (constant-time).
    Demo mode: compares directly with timing-safe compare.
    Production: stored_plain should be the hash.
    """
    return hmac.compare_digest(
        hashlib.pbkdf2_hmac('sha256', plain.encode(), b'vnpt-soc-salt', 260000).hex(),
        hashlib.pbkdf2_hmac('sha256', stored_plain.encode(), b'vnpt-soc-salt', 260000).hex()
    )

def _create_session(username: str, role: str = "admin") -> str:
    """Create a signed session token, store in _sessions dict."""
    session_id = secrets.token_urlsafe(32)
    _sessions[session_id] = {
        "username": username,
        "role": role,
        "created_at": datetime.utcnow().isoformat()
    }
    return session_id

def _get_session(session_id: Optional[str]) -> Optional[dict]:
    """Validate session exists and return session data, or None."""
    if not session_id:
        return None
    return _sessions.get(session_id)

def _generate_csrf_token(session_id: str) -> str:
    """Generate HMAC-signed CSRF token tied to session."""
    return _SERIALIZER.dumps(session_id, salt="csrf")

def _validate_csrf_token(token: str, session_id: str) -> bool:
    """Validate CSRF token matches session, max age 1h."""
    try:
        loaded = _SERIALIZER.loads(token, salt="csrf", max_age=_CSRF_MAX_AGE)
        return loaded == session_id
    except (BadSignature, SignatureExpired):
        return False

def get_window_max_minutes(win: str) -> int:
    if win in ('1h', 'Last 1 hour'):
        return 60
    if win in ('7d', 'Last 7 days'):
        return 10080
    return 1440  # 24h

def compute_overview_stats(time_window: str = "24h"):
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

    top_ips = [
        {"ip": "10.254.0.99", "count": 1, "pct": 33},
        {"ip": "198.51.100.44", "count": 1, "pct": 33},
        {"ip": "203.0.113.195", "count": 1, "pct": 33}
    ]

    dev_types = [
        {"type": "switch", "count": 1, "pct": 33},
        {"type": "router", "count": 1, "pct": 33},
        {"type": "firewall", "count": 1, "pct": 33}
    ]

    queue_alerts = active_alerts[:3]
    top_rules = active_alerts[:4]

    return stats, queue_alerts, top_rules, top_ips, dev_types

def compute_scenario_stats():
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

def filter_alerts(q: str = "", time_range: str = "Last 24 hours", severity: str = "ALL",
                  rule: str = "", ip: str = "", asset: str = "ALL", state: str = "ALL"):
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

# =============================================================================
# FULL PAGE ROUTES (DIRECT NAVIGATION & REFRESH)
# =============================================================================

@app.get("/", response_class=HTMLResponse)
async def get_overview_page(request: Request, window: str = "24h"):
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
async def get_alerts_page(request: Request, severity: Optional[str] = "ALL", asset: Optional[str] = "ALL"):
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
    scenario_stats = compute_scenario_stats()
    return templates.TemplateResponse(
        request=request,
        name="pages/scenarios.html",
        context={
            "scenarios": scenarios_store,
            "scenario_stats": scenario_stats
        }
    )

# =============================================================================
# HTMX VIEW PARTIALS (SEAMLESS TAB SWITCHING)
# =============================================================================

@app.get("/views/overview", response_class=HTMLResponse)
async def get_overview_view(request: Request, window: str = "24h"):
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
async def get_alerts_view(request: Request, severity: Optional[str] = "ALL", asset: Optional[str] = "ALL"):
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
    scenario_stats = compute_scenario_stats()
    return templates.TemplateResponse(
        request=request,
        name="partials/scenarios_content.html",
        context={
            "scenarios": scenarios_store,
            "scenario_stats": scenario_stats
        }
    )

# =============================================================================
# HTMX ACTIONS & APIS
# =============================================================================

@app.get("/api/overview/stats", response_class=HTMLResponse)
async def get_overview_stats(request: Request, window: str = "24h"):
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
    q: Optional[str] = "",
    time: Optional[str] = "Last 24 hours",
    severity: Optional[str] = "ALL",
    rule: Optional[str] = "",
    ip: Optional[str] = "",
    asset: Optional[str] = "ALL",
    state: Optional[str] = "ALL"
):
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
    source: Optional[str] = Form(None),
    session_id: Optional[str] = Cookie(None)
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
async def bulk_update_alerts(state: str = Form(...), event_ids: List[str] = Form(...)):
    updated_count = 0
    for a in alerts_store:
        if a["eventId"] in event_ids:
            a["state"] = state
            updated_count += 1
    return {"success": True, "updated": updated_count}

@app.post("/api/scenarios", response_class=HTMLResponse)
async def save_scenario(
    request: Request,
    id: Optional[str] = Form(""),
    code: str = Form(...),
    tool: str = Form(...),
    rule: str = Form(...),
    linkedEventId: str = Form(...),
    detected: bool = Form(False),
    notes: str = Form(...)
):
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
    row = next((s for s in scenarios_store if s["id"] == scenario_id), None)
    if not row:
        return JSONResponse({"error": "Not found"}, status_code=404)
    return row

@app.delete("/api/scenarios/{scenario_id}", response_class=HTMLResponse)
async def delete_scenario(request: Request, scenario_id: str):
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
    item = next((a for a in alerts_store if a["eventId"] == linked_id), alerts_store[3])
    return {
        "testStartTs": item.get("testStartTs", "01:10:46.0"),
        "testObsTs": item.get("testObsTs", "01:10:47.8"),
        "testDeltaSec": item.get("testDeltaSec", 1.8)
    }

@app.get("/api/live-status", response_class=HTMLResponse)
async def live_status_pulse():
    return HTMLResponse(
        '<span id="live-status-dot" class="status-dot dot-live" aria-hidden="true"></span>'
        '<span id="live-status-text">Live · updated <span id="live-sec-counter" class="font-mono">1s</span> ago · GMT+7</span>'
    )

# =============================================================================
# AUTH ROUTES (ASSUMPTION-02)
# =============================================================================

@app.get("/api/auth/csrf-token", response_class=JSONResponse)
async def get_csrf_token(response: Response, session_id: Optional[str] = Cookie(None)):
    """Issue a fresh CSRF token. Called on modal open."""
    sid = session_id if _get_session(session_id) else secrets.token_urlsafe(16)
    token = _generate_csrf_token(sid)
    return {"csrf_token": token}

@app.post("/api/auth/login", response_class=JSONResponse)
async def login(
    response: Response,
    username: str = Form(...),
    password: str = Form(...),
    csrf_token: Optional[str] = Form(None)
):
    """
    Authenticate user with PBKDF2-HMAC-SHA256.
    Sets HttpOnly session cookie on success.
    ASSUMPTION-02: Tích hợp Modal Sign-in với backend session + CSRF.
    """
    # Validate credentials
    if username != _ADMIN_USERNAME or not _verify_password(password, _ADMIN_PWD_PLAIN):
        return JSONResponse({"success": False, "error": "Invalid credentials"}, status_code=401)

    # Create session
    session_id = _create_session(username, role="admin")

    # Set HttpOnly, SameSite=Lax session cookie (8h)
    response.set_cookie(
        key="session_id",
        value=session_id,
        max_age=_SESSION_MAX_AGE,
        httponly=True,
        samesite="lax",
        secure=False  # Set True in production with HTTPS
    )

    return {"success": True, "username": username, "role": "admin"}

@app.post("/api/auth/logout", response_class=JSONResponse)
async def logout(response: Response, session_id: Optional[str] = Cookie(None)):
    """Invalidate session and clear cookie."""
    if session_id and session_id in _sessions:
        del _sessions[session_id]
    response.delete_cookie("session_id")
    return {"success": True}

@app.get("/api/auth/me", response_class=JSONResponse)
async def get_me(session_id: Optional[str] = Cookie(None)):
    """Check current session status."""
    session = _get_session(session_id)
    if session:
        return {"authenticated": True, "username": session["username"], "role": session["role"]}
    return {"authenticated": False}

# =============================================================================
# CSV EXPORTS
# =============================================================================

@app.get("/api/export/alerts.csv")
async def export_alerts_csv():
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
    uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=True)
