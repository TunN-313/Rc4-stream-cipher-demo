from nicegui import ui
from src.ui import dung_khung_giao_dien

if __name__ in {"__main__", "__mp_main__"}:
    dung_khung_giao_dien()

    ui.run(
        title="RC4 Demo — Hệ Mã Dòng TinyRC4 & RC4",
        favicon="🔐",
        port=8080,
        reload=True,
    )
