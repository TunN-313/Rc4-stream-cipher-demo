"""Bố cục giao diện chính của ứng dụng RC4 Lab (src/ui/layout.py).

File này được gọi bởi main.py để khởi tạo cấu trúc màn hình hoàn chỉnh.
File gọi đến các hàm build_tab_* trong thư mục src/ui/ để dựng từng tab chức năng:
mô hình TinyRC4, mã hóa văn bản, xử lý ảnh/tệp, kiểm thử, thám mã và lý thuyết.
Bao gồm thanh điều hướng lướt chuột tự mở rộng, vùng nội dung và bảng tra cứu.
"""

from __future__ import annotations  # dùng để hỗ trợ chú thích kiểu dữ liệu kiểu mới của Python
from nicegui import ui  # dùng để xây dựng và điều khiển các thành phần giao diện người dùng

from src.ui.tab_tiny_rc4 import build_tab_tiny_rc4  # file nội bộ: giao diện mô phỏng thuật toán TinyRC4
from src.ui.tab_rc4_text import build_tab_rc4_text  # file nội bộ: giao diện mã hóa văn bản UTF-8
from src.ui.file_pipeline import build_file_pipeline  # file nội bộ: quy trình 3 bước xử lý tệp và ảnh
from src.ui.tab_testing import build_tab_testing  # file nội bộ: bộ kiểm thử tự động RFC 6229
from src.ui.tab_attack_bench import build_tab_attack_bench  # file nội bộ: thám mã Two-Time Pad & benchmark
from src.ui.tab_theory import build_tab_theory  # file nội bộ: lý thuyết mật mã, sơ đồ Mermaid & A5/1


def _inject_katex_and_fonts() -> None:
    """Tích hợp phông chữ tiếng Việt (Inter, JetBrains Mono) và KaTeX render toán học.

    Tham số: Không có.
    Giá trị trả về: Không có (chèn trực tiếp mã CSS và JS vào thẻ <head> trang web).
    """
    ui.add_head_html(
        """
        <!-- 1. Google Fonts: Inter & JetBrains Mono -->
        <link rel="preconnect" href="https://fonts.googleapis.com">
        <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">

        <!-- 2. KaTeX CSS & JS Core -->
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/katex@0.16.11/dist/katex.min.css" crossorigin="anonymous">
        <script defer src="https://cdn.jsdelivr.net/npm/katex@0.16.11/dist/katex.min.js" crossorigin="anonymous"></script>
        <script defer src="https://cdn.jsdelivr.net/npm/katex@0.16.11/dist/contrib/auto-render.min.js" crossorigin="anonymous"></script>

        <style>
            /* Reset layout Quasar chuẩn Fullscreen Workbench */
            html, body {
                height: 100vh !important;
                margin: 0 !important;
                padding: 0 !important;
                overflow: hidden !important;
                background-color: #0f172a !important;
            }
            .q-layout, .q-page-container {
                height: 100vh !important;
                min-height: 100vh !important;
                padding: 0 !important;
                overflow: hidden !important;
            }
            .nicegui-content {
                width: 100vw !important;
                max-width: 100vw !important;
                height: 100vh !important;
                padding: 0 !important;
                margin: 0 !important;
                overflow: hidden !important;
            }

            /* Áp dụng phông chữ Inter chuẩn tiếng Việt */
            body, button, input, textarea, select, .q-card {
                font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif !important;
                -webkit-font-smoothing: antialiased;
                -moz-osx-font-smoothing: grayscale;
            }
            code, pre, .font-mono {
                font-family: 'JetBrains Mono', Consolas, Monaco, monospace !important;
            }

            /* Định dạng KaTeX */
            .katex { font-size: 1.05em; line-height: 1.2; }
            .katex-display { margin: 0.6em 0; overflow-x: auto; overflow-y: hidden; padding: 0.2em 0; }

            /* Tinh chỉnh thanh cuộn thanh mảnh hiện đại */
            ::-webkit-scrollbar {
                width: 6px;
                height: 6px;
            }
            ::-webkit-scrollbar-track {
                background: transparent;
            }
            ::-webkit-scrollbar-thumb {
                background: #cbd5e1;
                border-radius: 9999px;
            }
            ::-webkit-scrollbar-thumb:hover {
                background: #94a3b8;
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
    """Khởi tạo toàn bộ giao diện theo chuẩn Workbench (6 Tabs trực tiếp).

    Tham số: Không có.
    Giá trị trả về: Không có (dựng các thành phần trực tiếp lên trang web).
    Ví dụ: build_nicegui_interface()
    """
    # 1. Tích hợp phông chữ & KaTeX
    _inject_katex_and_fonts()

    # 2. Thiết lập định dạng mặc định cho các thành phần giao diện
    # ui.card: khung thẻ chữ nhật có viền bóng đổ để nhóm nội dung liên quan lại với nhau
    # các lớp Tailwind CSS chỉnh màu, khoảng cách, cỡ chữ
    ui.card.default_classes("bg-white border border-slate-200/90 rounded-2xl shadow-xs")
    # ui.input: ô nhập văn bản một dòng cho người dùng điền chuỗi
    ui.input.default_props("outlined dense")
    ui.textarea.default_props("outlined dense")
    ui.select.default_props("outlined dense")
    # ui.button: nút bấm để người dùng tương tác khi nhấp chuột
    ui.button.default_props("unelevated")
    ui.button.default_classes("font-semibold rounded-lg transition-all")
    ui.badge.default_classes("rounded-md px-2.5 py-1 font-semibold")
    ui.table.default_props("flat dense")
    ui.table.default_classes("w-full border border-slate-200/80 rounded-xl")

    # Kích hoạt Tabulator theme bootstrap5 nếu có
    try:
        from nicegui_tabulator import use_theme
        use_theme("bootstrap5")
    except Exception:
        pass

    # 3. Palette bảng màu chủ đạo cho toàn bộ ứng dụng
    ui.colors(
        primary="#1d4ed8",    # Blue 700: màu xanh thương hiệu chính
        secondary="#0284c7",  # Sky 600: màu phụ trợ
        accent="#0d9488",     # Teal 600: màu điểm nhấn
        positive="#10b981",   # Emerald 500: màu xanh lá biểu thị thành công/khớp
        negative="#ef4444",   # Rose 500: màu đỏ biểu thị cảnh báo/sai khóa
        warning="#f59e0b",    # Amber 500: màu vàng cảnh báo
        dark="#0f172a",       # Slate 900: màu nền tối
    )

    # =========================================================================
    # KHUNG TOÀN MÀN HÌNH CHUẨN WORKBENCH (FULLSCREEN APP SHELL)
    # =========================================================================
    # ui.column: xếp các phần tử theo chiều dọc từ trên xuống dưới
    with ui.column().classes("w-screen h-screen m-0 p-0 gap-0 overflow-hidden bg-slate-900 select-none"):

        # ---------------------------------------------------------------------
        # TẦNG TRÊN: SIDE MENU (HOVER-TO-EXPAND) + (MAIN CONTENT) + RIGHT SIDEBAR
        # ---------------------------------------------------------------------
        # ui.row: xếp các phần tử nằm ngang cùng một dòng (ví dụ: menu trái, nội dung, bảng phải)
        with ui.row().classes("w-full flex-1 m-0 p-0 gap-0 overflow-hidden items-stretch flex-nowrap"):

            # =================================================================
            # 1. SIDE MENU (LƯỚT CHUỘT TỰ MỞ RỘNG: w-16 -> w-64, CHỐNG WRAP)
            # Cơ chế: bình thường chỉ rộng 16 đơn vị (w-16, chỉ hiện icon). Khi rê chuột
            # vào vùng group (group-hover), menu tự trượt mở rộng ra 64 đơn vị (hover:w-64)
            # để hiện đầy đủ tiêu đề và mô tả của từng mục điều hướng.
            # =================================================================
            with ui.column().classes(
                "group w-16 hover:w-64 bg-slate-950 border-r border-slate-800 "
                "transition-all duration-300 ease-in-out overflow-hidden "
                "flex flex-col justify-between py-3.5 px-0 z-30 shrink-0 h-full select-none shadow-xl"
            ):
                # Khối Trên: Brand / Logo + 6 Mục Menu Điều Hướng (Tab 1 -> Tab 5)
                with ui.column().classes("w-full gap-2 px-0"):
                    # Logo Header (flex-nowrap, click chuyển về Tab 1)
                    with ui.row().classes(
                        "w-full flex items-center flex-nowrap h-11 px-3 gap-3 mb-2 overflow-hidden cursor-pointer"
                    ) as brand_logo_row:
                        with ui.row().classes(
                            "shrink-0 w-10 h-10 rounded-xl bg-gradient-to-tr from-blue-600 to-indigo-600 "
                            "text-white flex items-center justify-center shadow-md m-0 p-0"
                        ):
                            ui.icon("shield", size="sm")
                        with ui.column().classes(
                            "flex-1 min-w-0 gap-0 whitespace-nowrap overflow-hidden transition-all duration-300 "
                            "opacity-0 group-hover:opacity-100 max-w-0 group-hover:max-w-[180px]"
                        ):
                            ui.label("RC4 LAB").classes("text-xs font-black tracking-widest text-white leading-tight truncate")
                            ui.label("NEU Security Lab 2026").classes("text-3xs text-slate-400 font-mono truncate")

                    ui.separator().classes("w-full bg-slate-800/80 mb-2")

                    # Cấu trúc menu điều hướng (Tab 1, Nhóm RC4 Chuẩn & File, Tab 3 -> Tab 5)
                    menu_config_before = [
                        {
                            "id": "tab1",
                            "title": "TinyRC4 (3-bit)",
                            "subtitle": "Mô hình 3-bit Modulo 8",
                            "icon": "calculate",
                        },
                    ]
                    group_rc4_config = {
                        "id": "group_rc4",
                        "title": "RC4 Chuẩn & File",
                        "subtitle": "Văn bản & Ảnh/Tệp",
                        "icon": "lock",
                        "children": [
                            {
                                "id": "tab2_text",
                                "title": "Văn bản (UTF-8)",
                                "icon": "text_fields",
                            },
                            {
                                "id": "tab2_file",
                                "title": "Ảnh & Tệp",
                                "icon": "image",
                            },
                        ],
                    }
                    menu_config_after = [
                        {
                            "id": "tab3",
                            "title": "Kiểm Thử (RFC 6229)",
                            "subtitle": "8/8 ca kiểm thử PASS",
                            "icon": "verified",
                        },
                        {
                            "id": "tab4",
                            "title": "Tấn Công & Tốc Độ",
                            "subtitle": "Two-Time Pad & Benchmark",
                            "icon": "security",
                        },
                        {
                            "id": "tab5",
                            "title": "Lý Thuyết & So Sánh",
                            "subtitle": "Sơ đồ Mermaid & A5/1",
                            "icon": "menu_book",
                        },
                    ]

                    nav_rows: dict[str, ui.row] = {}
                    child_rows: dict[str, ui.row] = {}

                    # Hàm render mục menu thường (h-12)
                    def render_nav_row(item: dict[str, str]) -> ui.row:
                        """Vẽ một dòng mục chọn trên menu điều hướng bên trái.

                        Tham số:
                            item: Từ điển chứa thông tin mục menu ('id', 'title', 'subtitle', 'icon').
                        Giá trị trả về:
                            Đối tượng ui.row chứa biểu tượng và nhãn văn bản của mục menu.
                        """
                        is_initial_active = (item["id"] == "tab1")
                        # các lớp Tailwind CSS chỉnh màu, khoảng cách, cỡ chữ
                        init_classes = (
                            "w-full flex items-center flex-nowrap h-12 px-3 gap-3 cursor-pointer transition-all duration-200 border-l-4 overflow-hidden "
                            + (
                                "bg-blue-600 text-white font-bold border-l-sky-300 shadow-md"
                                if is_initial_active
                                else "text-slate-400 hover:text-white hover:bg-slate-900 border-l-transparent"
                            )
                        )
                        with ui.row().classes(init_classes) as row_elem:
                            with ui.row().classes("shrink-0 w-10 h-10 flex items-center justify-center m-0 p-0"):
                                ui.icon(item["icon"], size="sm")

                            with ui.column().classes(
                                "flex-1 min-w-0 gap-0 whitespace-nowrap overflow-hidden transition-all duration-300 "
                                "opacity-0 group-hover:opacity-100 max-w-0 group-hover:max-w-[180px]"
                            ):
                                ui.label(item["title"]).classes("text-sm font-semibold leading-tight truncate text-current")
                                ui.label(item["subtitle"]).classes("text-3xs text-slate-400 font-mono truncate")
                        return row_elem

                    # 1. Render Tab 1 (TinyRC4)
                    for item in menu_config_before:
                        nav_rows[item["id"]] = render_nav_row(item)

                    # 2. Render Header Nhóm "RC4 Chuẩn & File" có icon chevron
                    group_header_classes = (
                        "w-full flex items-center flex-nowrap h-12 px-3 gap-3 cursor-pointer transition-all duration-200 border-l-4 overflow-hidden "
                        "text-slate-400 hover:text-white hover:bg-slate-900 border-l-transparent"
                    )
                    with ui.row().classes(group_header_classes) as group_header_row:
                        with ui.row().classes("shrink-0 w-10 h-10 flex items-center justify-center m-0 p-0"):
                            ui.icon(group_rc4_config["icon"], size="sm")

                        with ui.column().classes(
                            "flex-1 min-w-0 gap-0 whitespace-nowrap overflow-hidden transition-all duration-300 "
                            "opacity-0 group-hover:opacity-100 max-w-0 group-hover:max-w-[180px]"
                        ):
                            ui.label(group_rc4_config["title"]).classes("text-sm font-semibold leading-tight truncate text-current")
                            ui.label(group_rc4_config["subtitle"]).classes("text-3xs text-slate-400 font-mono truncate")

                        with ui.row().classes("shrink-0 w-5 h-5 flex items-center justify-center transition-all duration-300 opacity-0 group-hover:opacity-100 mr-1"):
                            chevron_icon = ui.icon("expand_more", size="xs").classes("text-slate-400")

                    # 3. Render Khối Con (Sub menu) chứa tab2_text và tab2_file
                    with ui.column().classes("w-full gap-0.5 px-0 overflow-hidden transition-all duration-200") as sub_menu_col:
                        for child in group_rc4_config["children"]:
                            child_init_classes = (
                                "w-full flex items-center flex-nowrap h-10 px-3 group-hover:pl-6 gap-3 cursor-pointer transition-all duration-200 border-l-4 overflow-hidden "
                                "text-slate-400 hover:text-white hover:bg-slate-900 border-l-transparent"
                            )
                            with ui.row().classes(child_init_classes) as c_row:
                                with ui.row().classes("shrink-0 w-10 h-8 flex items-center justify-center m-0 p-0"):
                                    ui.icon(child["icon"], size="xs")

                                with ui.column().classes(
                                    "flex-1 min-w-0 gap-0 whitespace-nowrap overflow-hidden transition-all duration-300 "
                                    "opacity-0 group-hover:opacity-100 max-w-0 group-hover:max-w-[180px]"
                                ):
                                    ui.label(child["title"]).classes("text-xs font-semibold leading-tight truncate text-current")

                            child_rows[child["id"]] = c_row

                    # Khối con mặc định đóng
                    is_sub_menu_open = False
                    sub_menu_col.set_visibility(False)

                    def set_sub_menu_state(open_state: bool) -> None:
                        """Đóng hoặc mở danh sách các mục con của nhóm RC4 Chuẩn & File.

                        Tham số:
                            open_state: True để mở rộng danh sách con, False để thu gọn lại.
                        Giá trị trả về: Không có.
                        """
                        nonlocal is_sub_menu_open
                        is_sub_menu_open = open_state
                        sub_menu_col.set_visibility(open_state)
                        chevron_icon.name = "expand_less" if open_state else "expand_more"

                    def toggle_sub_menu() -> None:
                        """Đảo ngược trạng thái đóng/mở hiện tại của menu con nhóm RC4 Chuẩn & File.

                        Tham số: Không có.
                        Giá trị trả về: Không có.
                        """
                        set_sub_menu_state(not is_sub_menu_open)

                    group_header_row.on("click", lambda _e: toggle_sub_menu())

                    # 4. Render các Tab còn lại (Tab 3 -> Tab 5)
                    for item in menu_config_after:
                        nav_rows[item["id"]] = render_nav_row(item)

                # Khối Dưới: Thông tin NEU & Avatar (flex-nowrap, không bị co kéo)
                with ui.column().classes("w-full px-0 gap-1.5"):
                    ui.separator().classes("w-full bg-slate-800/80 my-0.5")
                    with ui.row().classes("w-full flex items-center flex-nowrap h-10 px-3 gap-3 overflow-hidden"):
                        with ui.avatar(size="sm", color="blue-800").classes(
                            "shrink-0 w-8 h-8 text-white font-bold text-xs cursor-pointer shadow-inner flex items-center justify-center"
                        ):
                            ui.label("NEU")
                        with ui.column().classes(
                            "flex-1 min-w-0 gap-0 whitespace-nowrap overflow-hidden transition-all duration-300 "
                            "opacity-0 group-hover:opacity-100 max-w-0 group-hover:max-w-[180px]"
                        ):
                            ui.label("Khoa CNTT - NEU").classes("text-xs font-semibold text-slate-300 leading-tight truncate")
                            ui.label("An Toàn & BMTT").classes("text-3xs text-slate-500 truncate")

            # =================================================================
            # 2. TRUNG TÂM: MAIN CONTENT (Flex-1, min-w-0, đẩy sát mép trên)
            # =================================================================
            with ui.column().classes("flex-1 min-w-0 h-full m-0 p-0 gap-0 overflow-hidden bg-slate-100"):

                # ẨN HOÀN TOÀN THANH TABS NGANG Ở TRÊN ĐẦU
                with ui.tabs().props("dense no-caps").classes("hidden") as main_tabs:
                    tab1 = ui.tab("tab1")
                    tab2_text = ui.tab("tab2_text")
                    tab2_file = ui.tab("tab2_file")
                    tab3 = ui.tab("tab3")
                    tab4 = ui.tab("tab4")
                    tab5 = ui.tab("tab5")

                tab_map = {
                    "tab1": tab1,
                    "tab2_text": tab2_text,
                    "tab2_file": tab2_file,
                    "tab3": tab3,
                    "tab4": tab4,
                    "tab5": tab5,
                }

                # MAIN CONTENT CONTAINER (Mặc định hiển thị tab1: TinyRC4)
                with ui.tab_panels(main_tabs, value=tab1).classes(
                    "w-full flex-1 m-0 p-6 overflow-y-auto bg-slate-100/90 select-text"
                ):
                    with ui.tab_panel(tab1).classes("p-0 space-y-5"):
                        build_tab_tiny_rc4()

                    with ui.tab_panel(tab2_text).classes("p-0 space-y-5"):
                        build_tab_rc4_text()

                    with ui.tab_panel(tab2_file).classes("p-0 space-y-5"):
                        build_file_pipeline()

                    with ui.tab_panel(tab3).classes("p-0 space-y-5"):
                        build_tab_testing()

                    with ui.tab_panel(tab4).classes("p-0 space-y-5"):
                        build_tab_attack_bench()

                    with ui.tab_panel(tab5).classes("p-0 space-y-5"):
                        build_tab_theory()

            # =================================================================
            # 3. RIGHT SIDE BAR (Bảng tra cứu S-Box / Cheatsheet - Width 72)
            # =================================================================
            with ui.column().classes(
                "w-72 bg-white border-l border-slate-200/90 p-4 shrink-0 overflow-y-auto hidden xl:flex flex-col gap-4 text-slate-800"
            ):
                with ui.row().classes("items-center justify-between w-full pb-2 border-b border-slate-200 flex-nowrap"):
                    with ui.row().classes("items-center gap-2 flex-nowrap"):
                        ui.icon("menu_book", size="xs").classes("text-blue-600")
                        ui.label("BẢNG TRA CỨU & QUY TẮC").classes("text-xs font-bold text-slate-900 tracking-tight")
                    ui.badge("3-Bit / 8-Bit", color="slate-100").classes("text-slate-600 text-2xs font-semibold")

                # Widget 1: Bảng quy đổi 3-bit thu nhỏ
                with ui.card().classes("w-full p-3 bg-slate-50 border border-slate-200/80 rounded-xl gap-1"):
                    ui.label("Bảng chữ cái 3-bit:").classes("text-2xs font-bold text-slate-700 uppercase tracking-wider")
                    with ui.grid(columns=4).classes("w-full gap-1 font-mono text-2xs mt-1"):
                        ui.label("A: 000 (0)").classes("bg-white p-1 rounded border text-center text-slate-700")
                        ui.label("B: 001 (1)").classes("bg-white p-1 rounded border text-center font-bold text-blue-700")
                        ui.label("C: 010 (2)").classes("bg-white p-1 rounded border text-center text-slate-700")
                        ui.label("D: 011 (3)").classes("bg-white p-1 rounded border text-center text-slate-700")
                        ui.label("E: 100 (4)").classes("bg-white p-1 rounded border text-center font-bold text-emerald-700")
                        ui.label("F: 101 (5)").classes("bg-white p-1 rounded border text-center text-slate-700")
                        ui.label("G: 110 (6)").classes("bg-white p-1 rounded border text-center text-slate-700")
                        ui.label("H: 111 (7)").classes("bg-white p-1 rounded border text-center text-slate-700")

                # Widget 2: Công thức Toán học KaTeX chuẩn
                with ui.card().classes("w-full p-3 bg-blue-50/50 border border-blue-200/70 rounded-xl gap-1"):
                    ui.label("Công thức toán học RC4:").classes("text-2xs font-bold text-blue-900 uppercase tracking-wider")
                    ui.markdown("**KSA Step:** $j = (j + S[i] + T[i]) \\bmod N$").classes("text-2xs text-slate-700 my-0.5")
                    ui.markdown("**PRGA Step:** $t = (S[i] + S[j]) \\bmod N$").classes("text-2xs text-slate-700 my-0.5")
                    ui.markdown("**Keystream:** $k = S[t]$").classes("text-2xs text-slate-700 my-0.5")
                    ui.markdown("**Phép XOR:** $c = p \\oplus k \\iff p = c \\oplus k$").classes("text-2xs text-slate-700 my-0.5")

                # Widget 3: Cảnh báo Bảo mật Lỗ hổng
                with ui.card().classes("w-full p-3 bg-amber-50/60 border border-amber-200/80 rounded-xl gap-1"):
                    with ui.row().classes("items-center gap-1.5 flex-nowrap"):
                        ui.icon("warning", size="xs").classes("text-amber-600")
                        ui.label("Lỗ hổng KSA Key Bias").classes("text-2xs font-bold text-amber-900")
                    ui.label(
                        "Các byte đầu tiên của dòng khóa RC4 có tương quan cao với khóa K (lỗ hổng WEP/WPA). Chuẩn bảo mật khuyến cáo bỏ qua (drop) 3072 byte đầu tiên."
                    ).classes("text-3xs text-amber-900/80 leading-relaxed")

                # Widget 4: Trạng thái Verification Test Suite
                with ui.card().classes("w-full p-3 bg-emerald-50/60 border border-emerald-200/80 rounded-xl gap-1.5"):
                    with ui.row().classes("items-center justify-between w-full flex-nowrap"):
                        with ui.row().classes("items-center gap-1.5 flex-nowrap"):
                            ui.icon("check_circle", size="xs").classes("text-emerald-600")
                            ui.label("Trạng Thái Kiểm Thử").classes("text-2xs font-bold text-emerald-900")
                        ui.badge("8/8 PASS", color="emerald-700").classes("text-3xs text-white px-1.5 py-0.5")
                    ui.label("• RFC 6229: 4 ca kiểm thử 40..256 bit đạt chuẩn 100%").classes("text-3xs text-emerald-800")
                    ui.label("• Ví dụ mẫu: Khớp tuyệt đối P='BAG' -> C='EBA'").classes("text-3xs text-emerald-800")
                    ui.label("• File nhị phân: Khôi phục ảnh PNG 100% toàn vẹn").classes("text-3xs text-emerald-800")

        # ---------------------------------------------------------------------
        # TẦNG DƯỚI: BOTTOM BAR (Status Bar cố định chân trang - Height 7 / 28px)
        # ---------------------------------------------------------------------
        with ui.row().classes(
            "w-full h-7 bg-slate-950 text-slate-400 border-t border-slate-800/90 px-4 flex items-center flex-nowrap justify-between text-2xs font-mono shrink-0 select-none overflow-hidden"
        ):
            with ui.row().classes("items-center gap-3 flex-nowrap"):
                with ui.row().classes("items-center gap-1.5 text-emerald-400 font-semibold flex-nowrap"):
                    ui.icon("circle", size="8px").classes("text-emerald-400 animate-pulse")
                    ui.label("HỆ THỐNG SẴN SÀNG")
                ui.label("|").classes("text-slate-700")
                ui.label("Core: Python Thuần 100% (Không Thư Viện Ngoài)")
                ui.label("|").classes("text-slate-700")
                ui.label("Modulo: 8 (TinyRC4) & 256 (Full RC4)")

            with ui.row().classes("items-center gap-3 flex-nowrap"):
                ui.label("Port: 8080")
                ui.label("|").classes("text-slate-700")
                ui.label("Khoa CNTT — Đại học Kinh tế Quốc dân (NEU)")

    # =========================================================================
    # HÀM XỬ LÝ CHUYỂN TAB & CẬP NHẬT TRẠNG THÁI ACTIVE CỦA SIDE MENU
    # Cơ chế chuyển tab:
    # 1. Toàn bộ nội dung 6 tab được chứa trong ui.tab_panels, thanh tab ngang bị ẩn.
    # 2. Khi người dùng bấm vào một mục menu hoặc logo, switch_tab(target_id) được gọi.
    # 3. Hàm kích hoạt main_tabs.set_value(target_tab) để đổi màn hình hiển thị.
    # 4. Sau đó hàm cập nhật class CSS viền sáng và màu nền xanh (active_class) cho mục
    #    vừa chọn, đồng thời đưa các mục còn lại về màu tối (inactive_class).
    # 5. Nếu tab được chọn là tab con (tab2_text, tab2_file), menu nhóm cha tự mở rộng.
    # =========================================================================
    # các lớp Tailwind CSS chỉnh màu, khoảng cách, cỡ chữ
    active_class = "w-full flex items-center flex-nowrap h-12 px-3 gap-3 cursor-pointer transition-all duration-200 border-l-4 overflow-hidden bg-blue-600 text-white font-bold border-l-sky-300 shadow-md"
    inactive_class = "w-full flex items-center flex-nowrap h-12 px-3 gap-3 cursor-pointer transition-all duration-200 border-l-4 overflow-hidden text-slate-400 hover:text-white hover:bg-slate-900 border-l-transparent"

    group_header_inactive = inactive_class
    group_header_child_active = "w-full flex items-center flex-nowrap h-12 px-3 gap-3 cursor-pointer transition-all duration-200 border-l-4 overflow-hidden text-white font-semibold border-l-sky-300 bg-slate-900/60 hover:bg-slate-900"

    child_active_class = "w-full flex items-center flex-nowrap h-10 px-3 group-hover:pl-6 gap-3 cursor-pointer transition-all duration-200 border-l-4 overflow-hidden bg-blue-600 text-white font-bold border-l-sky-300 shadow-md"
    child_inactive_class = "w-full flex items-center flex-nowrap h-10 px-3 group-hover:pl-6 gap-3 cursor-pointer transition-all duration-200 border-l-4 overflow-hidden text-slate-400 hover:text-white hover:bg-slate-900 border-l-transparent"

    child_tab_ids = {"tab2_text", "tab2_file"}

    def switch_tab(target_id: str) -> None:
        """Chuyển đổi tab nội dung hiển thị ở giữa màn hình và đổi màu mục menu tương ứng.

        Tham số:
            target_id: Chuỗi mã định danh của tab cần chuyển tới ('tab1', 'tab2_text',...).
        Giá trị trả về: Không có.
        """
        if target_id not in tab_map:
            return
        target_tab = tab_map[target_id]
        main_tabs.set_value(target_tab)

        # 1. Cập nhật style cho các mục menu thường
        for item_id, row_obj in nav_rows.items():
            if item_id == target_id:
                row_obj.classes(replace=active_class)
            else:
                row_obj.classes(replace=inactive_class)

        # 2. Cập nhật style cho các mục con trong nhóm
        for child_id, child_row in child_rows.items():
            if child_id == target_id:
                child_row.classes(replace=child_active_class)
            else:
                child_row.classes(replace=child_inactive_class)

        # 3. Cập nhật trạng thái header nhóm & tự động mở submenu khi tab con được chọn
        if target_id in child_tab_ids:
            group_header_row.classes(replace=group_header_child_active)
            set_sub_menu_state(True)
        else:
            group_header_row.classes(replace=group_header_inactive)

    # Gắn sự kiện click cho từng mục thường trong Side Menu
    for item_id, row_obj in nav_rows.items():
        row_obj.on("click", lambda _e, i_id=item_id: switch_tab(i_id))

    # Gắn sự kiện click cho các mục con trong nhóm
    for child_id, child_row in child_rows.items():
        child_row.on("click", lambda _e, c_id=child_id: switch_tab(c_id))

    # Click logo chuyển về Tab 1 (không làm hỏng trạng thái nhóm)
    brand_logo_row.on("click", lambda: switch_tab("tab1"))
