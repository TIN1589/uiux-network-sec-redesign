"""
Convenience launcher for Network Security Monitor SOC Command Center
Stack: FastAPI + Jinja2 + HTMX + Chart.js + Modern Vanilla CSS3 + Vanilla ES6+
"""

import sys
import socket
import uvicorn


def get_lan_ip() -> str:
    """Retrieve the primary local IPv4 address for local network access."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"


if __name__ == "__main__":
    lan_ip = get_lan_ip()
    port = 8000
    print("=" * 70)
    print("  NETWORK SECURITY MONITOR – SOC COMMAND CENTER (VNPT SOC v2.4)")
    print("  Stack: Jinja2 + HTMX + Chart.js + Modern Vanilla CSS3 + Vanilla ES6+")
    print(f"  Localhost (PC):        http://127.0.0.1:{port}/login")
    print(f"  Localhost Dashboard:   http://127.0.0.1:{port}/")
    print(f"  Mobile / LAN (Wi-Fi):  http://{lan_ip}:{port}/login")
    print(f"  Mobile Dashboard:      http://{lan_ip}:{port}/?guest=1")
    print("=" * 70)
    uvicorn.run("app:app", host="0.0.0.0", port=port, reload=True)

