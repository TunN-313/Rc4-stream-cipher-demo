#!/usr/bin/env python3
"""Điểm khởi chạy ứng dụng mô phỏng hệ mã dòng TinyRC4 và RC4."""

from nicegui import ui
from src.ui import dung_khung_giao_dien

# __mp_main__ hỗ trợ khởi tạo tiến trình con trên Windows
if __name__ in {"__main__", "__mp_main__"}:
    dung_khung_giao_dien()

    ui.run(
        title="RC4 Lab — Hệ Mã Dòng TinyRC4 & RC4 NEU",
        favicon="🔐",
        port=8080,
        reload=True,
    )
