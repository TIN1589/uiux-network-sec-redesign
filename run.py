"""
Convenience launcher for Network Security Monitor SOC Command Center
Stack: FastAPI + Jinja2 + HTMX + Chart.js + Modern Vanilla CSS3 + Vanilla ES6+
"""

import sys
import uvicorn

if __name__ == "__main__":
    print("=" * 70)
    print("  NETWORK SECURITY MONITOR – SOC COMMAND CENTER")
    print("  Stack: Jinja2 + HTMX + Chart.js + Modern Vanilla CSS3 + Vanilla ES6+")
    print("  Server starting on: http://127.0.0.1:8000")
    print("=" * 70)
    uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=True)
