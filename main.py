#!/usr/bin/env python3
"""
Điểm Khởi Chạy Ứng Dụng Hệ Mã Dòng RC4 & TinyRC4 (NiceGUI)
==========================================================
Học phần: An toàn và Bảo mật Thông tin (Chương 2)
Khoa Công nghệ Thông tin - Đại học Kinh tế Quốc dân (NEU)

Cách chạy:
    python main.py
Sau đó mở trình duyệt tại: http://localhost:8080
"""

from nicegui import ui
from src.ui import build_nicegui_interface

if __name__ in {"__main__", "__mp_main__"}:
    build_nicegui_interface()
    ui.run(
        title="Hệ Mã Dòng RC4 & TinyRC4 — NEU CNTT",
        port=8080,
        reload=False,
    )
