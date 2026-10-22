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
from src.ui.pwa import setup_pwa_routes

if __name__ in {"__main__", "__mp_main__"}:
    # 1. Đăng ký các endpoints PWA (manifest, sw.js, static)
    setup_pwa_routes()

    # 2. Xây dựng giao diện Workbench
    build_nicegui_interface()

    # 3. Khởi chạy máy chủ NiceGUI
    ui.run(
        title="RC4 Lab — Hệ Mã Dòng TinyRC4 & RC4 NEU",
        favicon="/favicon.ico",
        port=8080,
        reload=True,
    )
