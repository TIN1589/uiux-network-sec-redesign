"""Cấu hình chung cho kiểm thử Pytest."""

import os
import sys

# Tests opt into the otherwise fail-closed demo credential provider explicitly.
os.environ.setdefault("ENV", "test")
os.environ.setdefault("DEMO_MODE", "true")

# Thêm thư mục gốc dự án vào sys.path để pytest định vị chính xác app
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)
