"""
Phân Hệ RC4 Ảnh & Tệp (src/ui/tab_rc4_file.py)
=============================================
Mã hóa & giải mã dữ liệu nhị phân (hình ảnh, tài liệu) theo quy trình 3 bước tách rời.
Tích hợp trực tiếp file pipeline: Nạp -> Mã hóa Streaming -> Giải mã & Đối chiếu toàn vẹn.
"""

from __future__ import annotations
from nicegui import ui

from src.ui.file_pipeline import build_file_pipeline


def build_tab_rc4_file() -> None:
    """Xây dựng giao diện Phân hệ RC4 Ảnh & Tệp (Pipeline 3 bước)."""
    with ui.column().classes("w-full"):
        build_file_pipeline()
