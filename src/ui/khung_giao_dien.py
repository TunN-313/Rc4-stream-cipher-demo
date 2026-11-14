from __future__ import annotations
from nicegui import ui

from src.ui.tab_rc4_thu_nho import dung_tab_rc4_thu_nho
from src.ui.tab_rc4_van_ban import dung_tab_rc4_van_ban
from src.ui.tab_rc4_tep_tin import dung_tab_rc4_tep_tin
from src.ui.tab_kiem_thu import dung_tab_kiem_thu
from src.ui.tab_tham_ma import dung_tab_tham_ma


def _tich_hop_css() -> None:
    """Cấu hình phông chữ và thanh cuộn."""
    ui.add_head_html(
        """
        <link rel="preconnect" href="https://fonts.googleapis.com">
        <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">

        <style>
            * {
                -webkit-font-smoothing: antialiased;
                -moz-osx-font-smoothing: grayscale;
            }
            html, body {
                height: 100vh !important;
                margin: 0 !important;
                padding: 0 !important;
                overflow: hidden !important;
                background-color: #f8fafc !important;
                color: #0f172a !important;
                font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif !important;
            }
            body, button, input, textarea, select, table, th, td, .q-card, .q-tab, .q-btn, .q-field {
                font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif !important;
            }
            code, pre, .font-mono, .q-table td.font-mono, .q-table th.font-mono {
                font-family: 'JetBrains Mono', 'SF Mono', Menlo, Monaco, Consolas, 'Liberation Mono', 'Courier New', monospace !important;
                font-feature-settings: "liga" 0, "calt" 0;
            }
            ::-webkit-scrollbar {
                width: 6px;
                height: 6px;
            }
            ::-webkit-scrollbar-thumb {
                background: #cbd5e1;
                border-radius: 9999px;
            }
        </style>
        """
    )


def dung_khung_giao_dien() -> None:
    """Khởi tạo bố cục ứng dụng"""
    _tich_hop_css()

    ui.card.default_classes("bg-white border border-slate-200/90 rounded-xl shadow-xs")
    ui.input.default_props("outlined dense")
    ui.textarea.default_props("outlined dense")
    ui.select.default_props("outlined dense")
    ui.button.default_props("unelevated")
    ui.button.default_classes("font-semibold rounded-lg")

    ui.colors(
        primary="#1e3a8a",
        secondary="#0284c7",
        accent="#0d9488",
        positive="#16a34a",
        negative="#dc2626",
        warning="#d97706",
        dark="#0f172a",
    )

    with ui.column().classes("w-screen h-screen m-0 p-0 gap-0 overflow-hidden bg-slate-50"):
        with ui.row().classes(
            "w-full h-14 bg-white border-b border-slate-200 px-5 flex items-center justify-between shrink-0 shadow-xs z-20"
        ):
            with ui.row().classes("items-center gap-3"):
                with ui.avatar(size="md", color="blue-900").classes("text-white font-black text-xs shadow-xs"):
                    ui.label("RC4")
                with ui.column().classes("gap-0"):
                    ui.label("RC4 DEMO — HỆ MÃ DÒNG TINYRC4 & RC4").classes("text-sm font-bold text-slate-900 leading-tight")
                    ui.label("Mô phỏng hệ mã dòng đối xứng").classes("text-2xs text-slate-500 font-medium")

            with ui.tabs().props("dense no-caps inline-label").classes("text-slate-600 font-semibold") as main_tabs:
                tab_tiny = ui.tab("tab_tiny", label="1. TinyRC4 3-bit", icon="calculate")
                tab_text = ui.tab("tab_text", label="2. RC4 Văn Bản", icon="text_fields")
                tab_file = ui.tab("tab_file", label="3. RC4 Tệp Tin & Ảnh", icon="image")
                tab_test = ui.tab("tab_test", label="4. Kiểm Thử Thủ Công", icon="fact_check")
                tab_attack = ui.tab("tab_attack", label="5. Thám Mã Bẻ Khóa", icon="security")

            ui.element("div").classes("w-6")

        with ui.tab_panels(main_tabs, value=tab_tiny).classes("w-full flex-1 m-0 p-6 overflow-y-auto bg-slate-50 select-text"):
            with ui.tab_panel(tab_tiny).classes("p-0"):
                dung_tab_rc4_thu_nho()

            with ui.tab_panel(tab_text).classes("p-0"):
                dung_tab_rc4_van_ban()

            with ui.tab_panel(tab_file).classes("p-0"):
                dung_tab_rc4_tep_tin()

            with ui.tab_panel(tab_test).classes("p-0"):
                dung_tab_kiem_thu()

            with ui.tab_panel(tab_attack).classes("p-0"):
                dung_tab_tham_ma()
