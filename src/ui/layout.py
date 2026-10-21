"""
Bố Cục Chính & Khung Điều Hướng NiceGUI (src/ui/layout.py)
=========================================================
Quản lý Header, Bảng màu sắc thương hiệu NEU CNTT, Thanh điều hướng 5 Tab,
tích hợp thư viện KaTeX để hiển thị công thức toán học LaTeX chuẩn xác.
"""

from __future__ import annotations
from nicegui import ui

from src.ui.tab_tiny_rc4 import build_tab_tiny_rc4
from src.ui.tab_full_rc4 import build_tab_full_rc4
from src.ui.tab_testing import build_tab_testing
from src.ui.tab_attack_bench import build_tab_attack_bench
from src.ui.tab_theory import build_tab_theory


def _inject_katex_math_support() -> None:
    """Tích hợp thư viện KaTeX CDN và script tự động render công thức toán học."""
    ui.add_head_html(
        """
        <!-- KaTeX CSS & Fonts -->
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/katex@0.16.11/dist/katex.min.css" crossorigin="anonymous">
        <!-- KaTeX JS Core -->
        <script defer src="https://cdn.jsdelivr.net/npm/katex@0.16.11/dist/katex.min.js" crossorigin="anonymous"></script>
        <!-- KaTeX Auto-render Extension -->
        <script defer src="https://cdn.jsdelivr.net/npm/katex@0.16.11/dist/contrib/auto-render.min.js" crossorigin="anonymous"></script>

        <style>
            .katex { font-size: 1.08em; line-height: 1.2; }
            .katex-display { margin: 0.75em 0; overflow-x: auto; overflow-y: hidden; padding: 0.25em 0; }
            .math-inline { display: inline-block; }
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
                        renderMathInElement(document.body, {
                            delimiters: [
                                {left: '$$', right: '$$', display: true},
                                {left: '$', right: '$', display: false},
                                {left: '\\(', right: '\\)', display: false},
                                {left: '\\[', right: '\\]', display: true}
                            ],
                            throwOnError: false,
                            ignoredTags: ["script", "noscript", "style", "textarea", "pre", "code", "option"]
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
    # 1. Tích hợp KaTeX Math Engine
    _inject_katex_math_support()

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

    # 4. Thanh điều hướng 5 Tab
    with ui.tabs().classes("w-full bg-slate-100 text-slate-800 shadow-sm sticky top-0 z-10") as tabs:
        tab1 = ui.tab("1. Thực Thi TinyRC4 (3-bit)", icon="calculate")
        tab2 = ui.tab("2. RC4 Chuẩn (256-byte & File/Ảnh)", icon="lock")
        tab3 = ui.tab("3. Kiểm Thử & Đối Chiếu (RFC 6229)", icon="verified")
        tab4 = ui.tab("4. Tấn Công Dòng Khóa & Đo Tốc Độ", icon="security")
        tab5 = ui.tab("5. Tìm Hiểu Hệ Mã (Tóm Tắt)", icon="menu_book")


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
