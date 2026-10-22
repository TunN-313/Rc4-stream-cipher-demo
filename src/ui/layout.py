"""
Bố Cục Chính & Khung Điều Hướng NiceGUI (src/ui/layout.py)
=========================================================
Quản lý Header, Bảng màu sắc thương hiệu NEU CNTT, Thanh điều hướng 5 Tab,
phông chữ chuẩn tiếng Việt Inter / JetBrains Mono và tích hợp KaTeX Math an toàn.
"""

from __future__ import annotations
from nicegui import ui

from src.ui.tab_tiny_rc4 import build_tab_tiny_rc4
from src.ui.tab_full_rc4 import build_tab_full_rc4
from src.ui.tab_testing import build_tab_testing
from src.ui.tab_attack_bench import build_tab_attack_bench
from src.ui.tab_theory import build_tab_theory


def _inject_katex_and_fonts() -> None:
    """
    Tích hợp phông chữ tiếng Việt chuẩn (Inter + JetBrains Mono)
    và cấu hình KaTeX Math Engine an toàn (chỉ nhận $$...$$ và $...$).
    """
    ui.add_head_html(
        """
        <!-- 1. Google Fonts: Inter cho giao diện tiếng Việt và JetBrains Mono cho mã nguồn -->
        <link rel="preconnect" href="https://fonts.googleapis.com">
        <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">

        <!-- 2. KaTeX CSS & JS Core -->
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/katex@0.16.11/dist/katex.min.css" crossorigin="anonymous">
        <script defer src="https://cdn.jsdelivr.net/npm/katex@0.16.11/dist/katex.min.js" crossorigin="anonymous"></script>
        <script defer src="https://cdn.jsdelivr.net/npm/katex@0.16.11/dist/contrib/auto-render.min.js" crossorigin="anonymous"></script>

        <style>
            /* Áp dụng phông chữ Inter chuẩn tiếng Việt đẹp mắt, chống lỗi chân chữ */
            body, button, input, textarea, select, .q-tab, .q-header, .q-card {
                font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif !important;
                -webkit-font-smoothing: antialiased;
                -moz-osx-font-smoothing: grayscale;
            }
            code, pre, .font-mono {
                font-family: 'JetBrains Mono', Consolas, Monaco, monospace !important;
            }

            /* Định dạng công thức toán học KaTeX */
            .katex { font-size: 1.05em; line-height: 1.2; }
            .katex-display { margin: 0.8em 0; overflow-x: auto; overflow-y: hidden; padding: 0.25em 0; }

            /* Tối ưu thanh Tabs để không bị tràn màn hình */
            .q-tabs--dense .q-tab {
                min-height: 48px;
                padding: 0 14px;
            }
            .q-tab__label {
                font-size: 0.85rem !important;
                font-weight: 600 !important;
                letter-spacing: 0.01em;
            }

            /* Tinh chỉnh Tabulator: hiện đại, đồng bộ Inter font và màu sắc */
            .tabulator {
                font-family: 'Inter', -apple-system, sans-serif !important;
                border: 1px solid #e2e8f0 !important;
                border-radius: 8px !important;
            }
            .tabulator .tabulator-header {
                background-color: #f8fafc !important;
                border-bottom: 2px solid #cbd5e1 !important;
                color: #1e293b !important;
                font-weight: 700 !important;
            }
            .tabulator-row {
                border-bottom: 1px solid #f1f5f9 !important;
            }
            .tabulator-row:hover {
                background-color: #f8fafc !important;
            }
            .tabulator-group {
                background-color: #f1f5f9 !important;
                border-bottom: 1px solid #cbd5e1 !important;
                color: #0f172a !important;
                font-weight: 700 !important;
                padding: 6px 12px !important;
            }
            .tabulator-header-filter input {
                border: 1px solid #cbd5e1 !important;
                border-radius: 4px !important;
                padding: 2px 6px !important;
                font-size: 0.75rem !important;
            }
        </style>

        <script>
            window._isRenderingMath = false;

            function renderAllMath() {
                if (window._isRenderingMath) return;
                if (typeof renderMathInElement === 'function') {
                    window._isRenderingMath = true;
                    try {
                        if (window._katexObserver) {
                            window._katexObserver.disconnect();
                        }
                        // CHỈ nhận dạng $$...$$ và $...$, không bắt ngoặc đơn (...)
                        renderMathInElement(document.body, {
                            delimiters: [
                                {left: '$$', right: '$$', display: true},
                                {left: '$', right: '$', display: false}
                            ],
                            throwOnError: false,
                            ignoredTags: [
                                "script", "noscript", "style", "textarea",
                                "pre", "code", "option", "svg", "button"
                            ],
                            ignoredClasses: ["mermaid", "q-tab__label", "q-btn"]
                        });
                    } catch (err) {
                        console.warn("KaTeX render notice:", err);
                    } finally {
                        window._isRenderingMath = false;
                        if (window._katexObserver) {
                            window._katexObserver.observe(document.body, { childList: true, subtree: true });
                        }
                    }
                }
            }

            let _mathDebounceTimer = null;
            function triggerMathRender(delay = 120) {
                clearTimeout(_mathDebounceTimer);
                _mathDebounceTimer = setTimeout(renderAllMath, delay);
            }

            document.addEventListener("DOMContentLoaded", () => {
                triggerMathRender(200);
                window._katexObserver = new MutationObserver((mutations) => {
                    let hasRelevantMutation = false;
                    for (const m of mutations) {
                        if (m.addedNodes.length > 0) {
                            hasRelevantMutation = true;
                            break;
                        }
                    }
                    if (hasRelevantMutation && !window._isRenderingMath) {
                        triggerMathRender(150);
                    }
                });
                window._katexObserver.observe(document.body, { childList: true, subtree: true });
            });
        </script>
        """
    )


def build_nicegui_interface() -> None:
    """Khởi tạo toàn bộ giao diện 5 Tab bằng thư viện NiceGUI."""
    # 1. Tích hợp Phông chữ tiếng Việt chuẩn & KaTeX Math an toàn
    _inject_katex_and_fonts()

    # Kích hoạt theme Bootstrap5 cho Tabulator nếu thư viện được cài đặt
    try:
        from nicegui_tabulator import use_theme
        use_theme("bootstrap5")
    except Exception:
        pass

    # 2. Định nghĩa Palette màu sắc
    ui.colors(
        primary="#1e3a8a",
        secondary="#0284c7",
        accent="#0d9488",
        positive="#16a34a",
        negative="#dc2626",
        warning="#d97706",
    )

    # 3. Header chính mang thương hiệu Khoa CNTT - ĐH Kinh tế Quốc dân
    with ui.header().classes("bg-slate-900 text-white shadow-md px-6 py-3 items-center justify-between"):
        with ui.row().classes("items-center gap-3"):
            ui.icon("enhanced_encryption", size="md").classes("text-sky-400")
            with ui.column().classes("gap-0"):
                ui.label("HỆ MÃ DÒNG RC4 & TINYRC4 — BỘ CÔNG CỤ THỰC THI & DEMO").classes(
                    "text-lg font-bold tracking-wide"
                )
                ui.label("Học phần: An toàn và Bảo mật Thông tin • Khoa CNTT – ĐH Kinh tế Quốc dân").classes(
                    "text-xs text-slate-300"
                )
        ui.badge("Python + NiceGUI | Tự cài đặt 100% từ đầu", color="secondary").classes("px-3 py-1 text-xs")

    # 4. Thanh điều hướng 5 Tab (Tên gọn gàng, hiển thị vừa vặn 100% trên mọi kích thước màn hình)
    with ui.tabs().props("dense inline-label align=justify").classes("w-full bg-slate-100 text-slate-800 shadow-sm sticky top-0 z-10") as tabs:
        tab1 = ui.tab("1. TinyRC4 (3-bit)", icon="calculate")
        tab2 = ui.tab("2. RC4 Chuẩn & File", icon="lock")
        tab3 = ui.tab("3. Kiểm Thử (RFC 6229)", icon="verified")
        tab4 = ui.tab("4. Tấn Công & Tốc Độ", icon="security")
        tab5 = ui.tab("5. Lý Thuyết & So Sánh", icon="menu_book")

    # 5. Khung chứa nội dung 5 Tab Panels
    with ui.tab_panels(tabs, value=tab1).classes("w-full max-w-7xl mx-auto p-4"):
        with ui.tab_panel(tab1):
            build_tab_tiny_rc4()

        with ui.tab_panel(tab2):
            build_tab_full_rc4()

        with ui.tab_panel(tab3):
            build_tab_testing()

        with ui.tab_panel(tab4):
            build_tab_attack_bench()

        with ui.tab_panel(tab5):
            build_tab_theory()
