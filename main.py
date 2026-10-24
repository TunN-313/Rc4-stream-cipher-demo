#!/usr/bin/env python3
"""Điểm khởi chạy ứng dụng web mô phỏng hệ mã dòng TinyRC4 và RC4 đầy đủ.

Người dùng trực tiếp khởi thi file này từ dòng lệnh: `python main.py`.
File này gọi hàm build_nicegui_interface() trong src/ui/layout.py để dựng giao diện,
sau đó gọi ui.run() để khởi động máy chủ web cục bộ tại cổng 8080.
"""

from pathlib import Path  # dùng để xử lý đường dẫn tệp tin hệ thống an toàn
from nicegui import ui  # dùng để xây dựng và điều khiển giao diện web tương tác bằng Python
from src.ui import build_nicegui_interface  # file nội bộ của dự án: tạo toàn bộ khung giao diện

if __name__ in {"__main__", "__mp_main__"}:
    # 1. Xây dựng giao diện ứng dụng (gồm 6 tab chức năng và thanh điều hướng)
    build_nicegui_interface()

    # 2. Khởi chạy máy chủ web NiceGUI (ui.run lắng nghe kết nối từ trình duyệt)
    ui.run(
        title="RC4 Lab — Hệ Mã Dòng TinyRC4 & RC4 NEU",  # tiêu đề hiển thị trên tab trình duyệt
        favicon=Path(__file__).parent / "static" / "favicon.ico",  # biểu tượng nhỏ trên tab web
        port=8080,  # mở cổng dịch vụ web tại địa chỉ cục bộ http://localhost:8080
        reload=True,  # tự động nạp lại giao diện khi lập trình viên chỉnh sửa mã nguồn
    )
