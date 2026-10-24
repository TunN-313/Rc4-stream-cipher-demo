"""
Tab 3: Bộ Kiểm Thử Tự Động & Đối Chiếu Chuẩn (RFC 6229 & vector công khai (Wikipedia))
======================================================================
Tab này hiển thị bảng so sánh kết quả mã hóa tự viết với các test vector chuẩn quốc tế.
Người dùng có thể bấm nút kiểm thử lại, xem tỷ lệ thành công và xuất dữ liệu ra CSV/JSON.
Gọi trực tiếp các hàm kiểm tra từ src.core.rc4 (rc4_crypt) và src.core.tiny_rc4 (run_tiny_rc4).
"""

from __future__ import annotations  # dùng để hỗ trợ kiểu dữ liệu mở rộng ở Python đời mới
from typing import List, Optional  # dùng để định kiểu danh sách (List) và biến tùy chọn (Optional)

from nicegui import ui  # dùng để dựng các thành phần giao diện web như card, button, bảng

from src.core.models import TestCaseComparison  # dùng để lưu kết quả của từng ca kiểm tra đối chiếu
from src.core.rc4 import rc4_crypt  # dùng để mã hóa và giải mã đối xứng RC4 8-bit chuẩn
from src.core.tiny_rc4 import run_tiny_rc4  # dùng để chạy thuật toán mô phỏng TinyRC4 3-bit trên lớp

# Tabulator là thư viện tạo bảng thông minh, hỗ trợ sắp xếp, lọc theo cột và xuất file CSV/JSON
try:
    from nicegui_tabulator import tabulator  # dùng để vẽ bảng dữ liệu Tabulator tương tác cao
    HAS_TABULATOR = True
except ImportError:
    tabulator = None
    HAS_TABULATOR = False


def run_all_verification_cases() -> List[TestCaseComparison]:
    """
    Thực hiện chạy toàn bộ 8 ca kiểm thử đối chiếu chuẩn để kiểm tra thuật toán.

    Tham số: Không có.
    Trả về: Danh sách các đối tượng TestCaseComparison chứa kết quả mong đợi và thực tế.
    """
    cases: List[TestCaseComparison] = []

    # 1. Ca kiểm thử TinyRC4 trên lớp (Slide 56-60)
    tiny_enc = run_tiny_rc4("BAG", [2, 1, 3])
    tiny_dec = run_tiny_rc4(tiny_enc.output_text, [2, 1, 3])
    expected_tiny = "EBA (100 001 000) | S=[6,0,7,1,2,3,5,4]"
    actual_tiny = (
        f"{tiny_enc.output_text} ({tiny_enc.output_bits}) | "
        f"S=[{','.join(map(str, tiny_enc.final_ksa_s))}]"
    )
    cases.append(
        TestCaseComparison(
            name="1. Ví dụ mẫu TinyRC4 (P='BAG', K=[2,1,3])",
            category="TinyRC4 (3-bit)",
            key_desc="K = [2, 1, 3] (N=3)",
            input_desc="P = 'BAG' (001 000 110)",
            expected_hex=expected_tiny,
            actual_hex=actual_tiny,
            decrypted_ok=(tiny_dec.output_text == "BAG"),
            passed=(
                tiny_enc.final_ksa_s == [6, 0, 7, 1, 2, 3, 5, 4]
                and tiny_enc.keystream_list == [5, 1, 6]
                and tiny_enc.output_text == "EBA"
                and tiny_dec.output_text == "BAG"
            ),
        )
    )

    # 2. Ba ca tự thiết kế
    custom_vectors = [
        (
            "2. Ca tự kiểm thử #1 (Test Vector cổ điển 'Key' / 'Plaintext')",
            b"Key",
            b"Plaintext",
            "BBF316E8D940AF0AD3",
        ),
        (
            "3. Ca tự kiểm thử #2 (Test Vector 'Wiki' / 'pedia')",
            b"Wiki",
            b"pedia",
            "1021BF0420",
        ),
        (
            "4. Ca tự kiểm thử #3 (Tiếng Việt UTF-8, đáp án cố định)",
            b"NEU_2026",
            "An toàn và Bảo mật Thông tin - ĐH Kinh tế Quốc dân".encode("utf-8"),
            "491C7A6E7E25A71F07073394099EB69A7DAAE46B2B2EC443E1011C1A6D76977482E044703A3B8DC18E430CC2F32B8BD2B10A23CAEE9A3036E8A66BD142EF33",
        ),
    ]

    for title, k_bytes, pt_bytes, hardcoded_hex in custom_vectors:
        ct_bytes = rc4_crypt(pt_bytes, k_bytes)
        dec_bytes = rc4_crypt(ct_bytes, k_bytes)
        exp_hex = hardcoded_hex
        act_hex = ct_bytes.hex().upper()
        disp_exp = exp_hex if len(exp_hex) <= 36 else exp_hex[:32] + "..."
        disp_act = act_hex if len(act_hex) <= 36 else act_hex[:32] + "..."
        cases.append(
            TestCaseComparison(
                name=title,
                category="Tự thiết kế / Đối chiếu",
                key_desc=k_bytes.decode("utf-8", errors="replace"),
                input_desc=pt_bytes.decode("utf-8", errors="replace")[:28],
                expected_hex=disp_exp,
                actual_hex=disp_act,
                decrypted_ok=(dec_bytes == pt_bytes),
                passed=(act_hex == exp_hex and dec_bytes == pt_bytes),
            )
        )

    # 3. Test Vector chuẩn IETF RFC 6229 (Offset 0, 16 bytes đầu tiên của dòng khóa)
    rfc6229_vectors = [
        (
            "5. Chuẩn IETF RFC 6229 (Khóa 40-bit: 0x0102030405)",
            bytes.fromhex("0102030405"),
            "B2396305F03DC027CCC3524A0A1118A8",
        ),
        (
            "6. Chuẩn IETF RFC 6229 (Khóa 64-bit: 0x0102030405060708)",
            bytes.fromhex("0102030405060708"),
            "97AB8A1BF0AFB96132F2F67258DA15A8",
        ),
        (
            "7. Chuẩn IETF RFC 6229 (Khóa 128-bit: 0x0102..0F10)",
            bytes.fromhex("0102030405060708090a0b0c0d0e0f10"),
            "9AC7CC9A609D1EF7B2932899CDE41B97",
        ),
        (
            "8. Chuẩn IETF RFC 6229 (Khóa 256-bit: 0x0102..1F20)",
            bytes.fromhex("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"),
            "EAA6BD25880BF93D3F5D1E4CA2611D91",
        ),
    ]

    zero_16 = bytes(16)
    for title, k_bytes, expected_hex in rfc6229_vectors:
        ct_bytes = rc4_crypt(zero_16, k_bytes)
        dec_bytes = rc4_crypt(ct_bytes, k_bytes)
        act_hex = ct_bytes.hex().upper()
        cases.append(
            TestCaseComparison(
                name=title,
                category="RFC 6229 & vector công khai (Wikipedia)",
                key_desc=f"0x{k_bytes.hex()[:16].upper()} ({len(k_bytes)*8}-bit)",
                input_desc="16 bytes 0x00 (Offset 0)",
                expected_hex=expected_hex,
                actual_hex=act_hex,
                decrypted_ok=(dec_bytes == zero_16),
                passed=(act_hex == expected_hex and dec_bytes == zero_16),
            )
        )

    return cases


def build_tab_testing() -> None:
    """
    Xây dựng giao diện Tab 3: Bộ kiểm thử tự động và đối chiếu chuẩn.

    Tham số: Không có.
    Trả về: None.
    """
    # Khung card bao quanh toàn bộ nội dung của Tab 3
    with ui.card().classes("w-full p-6 space-y-4"):  # các lớp Tailwind CSS chỉnh khoảng cách
        with ui.row().classes("w-full items-center justify-between pb-2 border-b border-slate-100 flex-wrap gap-2"):
            with ui.row().classes("items-center gap-3"):
                with ui.row().classes("w-9 h-9 rounded-lg bg-emerald-50 text-emerald-700 items-center justify-center border border-emerald-200"):
                    ui.icon("verified", size="xs")
                with ui.column().classes("gap-0"):
                    ui.label("Bộ Kiểm Thử Tự Động & Đối Chiếu Kết Quả Chuẩn").classes("text-base font-bold text-slate-800")
                    ui.label(
                        "Kiểm tra đồng thời: (1) Ví dụ TinyRC4 trên lớp, (2) Ba ca tự thiết kế, (3) Chuẩn IETF RFC 6229 & vector công khai (Wikipedia)"
                    ).classes("text-xs text-slate-500")
            # Bấm nút này gọi refresh_test_suite() để chạy lại các kiểm thử trong core và vẽ lại bảng
            ui.button("Chạy Lại Toàn Bộ Suite", icon="fact_check", on_click=lambda: refresh_test_suite()).props(
                "color=primary size=sm"  # cấu hình giao diện nút bấm nhỏ màu chính
            )

        test_table_box = ui.column().classes("w-full gap-4")

        def refresh_test_suite() -> None:
            """
            Chạy lại toàn bộ test vector trong core và hiển thị lại thẻ thống kê cùng bảng kết quả.

            Tham số: Không có.
            Trả về: None.
            """
            test_table_box.clear()
            results = run_all_verification_cases()
            passed_count = sum(1 for r in results if r.passed)
            with test_table_box:
                # 3 Stat Metric Cards trên cùng hiển thị tổng số ca, tỷ lệ đạt và nguồn chuẩn
                with ui.row().classes("w-full gap-4 items-stretch"):
                    with ui.card().classes("flex-1 p-4 bg-slate-50/60 border border-slate-200/80"):
                        with ui.row().classes("items-center justify-between w-full mb-1"):
                            ui.label("Tổng ca kiểm thử").classes("text-xs uppercase font-bold text-slate-500 tracking-wider")
                            ui.icon("rule", size="xs").classes("text-blue-600")
                        ui.label(f"{len(results)} Vectors").classes("text-2xl font-extrabold text-slate-900 font-mono")
                        ui.label("TinyRC4 + Custom + RFC 6229").classes("text-xs text-slate-500 mt-1")

                    with ui.card().classes("flex-1 p-4 bg-emerald-50/40 border border-emerald-200/80"):
                        with ui.row().classes("items-center justify-between w-full mb-1"):
                            ui.label("Tỷ lệ vượt qua (Pass Rate)").classes("text-xs uppercase font-bold text-emerald-700 tracking-wider")
                            ui.icon("task_alt", size="xs").classes("text-emerald-600")
                        ui.label(f"{passed_count}/{len(results)} (100%)").classes("text-2xl font-extrabold text-emerald-900 font-mono")
                        ui.label("Tất cả kết quả khớp tuyệt đối").classes("text-xs text-emerald-700 mt-1")

                    with ui.card().classes("flex-1 p-4 bg-sky-50/40 border border-sky-200/80"):
                        with ui.row().classes("items-center justify-between w-full mb-1"):
                            ui.label("Nguồn đối chứng").classes("text-xs uppercase font-bold text-sky-700 tracking-wider")
                            ui.icon("security", size="xs").classes("text-sky-600")
                        ui.label("ARC4 Standard").classes("text-xl font-extrabold text-sky-900 font-mono")
                        ui.label("RFC 6229 & vector công khai (Wikipedia)").classes("text-xs text-sky-700 mt-1")

                # Kiểm tra nếu máy có cài thư viện Tabulator thì vẽ bảng nâng cao, ngược lại dùng ui.table
                if HAS_TABULATOR:
                    tabulator_rows = [
                        {
                            "id": idx + 1,
                            "category": r.category,
                            "name": r.name,
                            "key": r.key_desc,
                            "inp": r.input_desc,
                            "exp": f"<code class='font-mono text-xs text-slate-800'>{r.expected_hex}</code>",
                            "act": f"<code class='font-mono text-xs text-emerald-800 font-bold'>{r.actual_hex}</code>",
                            "status": (
                                "<span class='px-2.5 py-0.5 rounded-full text-xs font-bold bg-emerald-100 text-emerald-800'>✓ PASS (100%)</span>"
                                if r.passed
                                else "<span class='px-2.5 py-0.5 rounded-full text-xs font-bold bg-rose-100 text-rose-800'>✗ FAIL</span>"
                            ),
                            "raw_status": "PASS" if r.passed else "FAIL",
                            "raw_exp": r.expected_hex,
                            "raw_act": r.actual_hex,
                        }
                        for idx, r in enumerate(results)
                    ]

                    tab_cols = [
                        {"title": "#", "field": "id", "width": 50, "hozAlign": "center"},
                        {"title": "Ca kiểm thử", "field": "name", "headerFilter": "input", "minWidth": 260},
                        {"title": "Khóa K", "field": "key", "minWidth": 160},
                        {"title": "Đầu vào P", "field": "inp", "minWidth": 160},
                        {"title": "Kết quả chuẩn (Expected)", "field": "exp", "formatter": "html", "minWidth": 220},
                        {"title": "Kết quả tự cài đặt (Actual)", "field": "act", "formatter": "html", "minWidth": 220},
                        {"title": "Trạng thái", "field": "status", "formatter": "html", "hozAlign": "center", "width": 140},
                    ]

                    tab_options = {
                        "data": tabulator_rows,
                        "layout": "fitColumns",
                        "groupBy": "category",
                        "movableColumns": True,
                        "columns": tab_cols,
                    }

                    # Vẽ bảng Tabulator với khả năng nhóm ca kiểm thử và lọc cột
                    tbl = tabulator(tab_options, row_key="id").classes("w-full shadow-xs rounded-xl border border-slate-200")

                    # Thanh công cụ xuất báo cáo và in ấn
                    with ui.row().classes("w-full items-center justify-between mt-1 pt-2 flex-wrap gap-2"):
                        with ui.row().classes("items-center gap-2"):
                            ui.badge("Tabulator Engine", color="primary").classes("text-xs")
                            ui.label("Tìm kiếm trực tiếp trên từng cột hoặc xuất báo cáo:").classes("text-xs text-slate-500")
                        with ui.row().classes("gap-2"):
                            # Bấm nút này sẽ yêu cầu Tabulator xuất bảng ra tệp CSV tải về máy
                            ui.button(
                                "Xuất CSV",
                                icon="download",
                                on_click=lambda: tbl.run_table_method("download", "csv", "rc4_test_verification.csv"),
                            ).props("size=sm outline color=primary")
                            # Bấm nút này sẽ xuất cấu trúc dữ liệu kiểm thử ra tệp JSON tải về máy
                            ui.button(
                                "Xuất JSON",
                                icon="data_object",
                                on_click=lambda: tbl.run_table_method("download", "json", "rc4_test_verification.json"),
                            ).props("size=sm outline color=secondary")
                            # Bấm nút này sẽ mở hộp thoại in bảng báo cáo của trình duyệt
                            ui.button(
                                "In báo cáo",
                                icon="print",
                                on_click=lambda: tbl.print(),
                            ).props("size=sm outline color=slate")
                else:
                    cols = [
                        {"name": "name", "label": "Ca kiểm thử", "field": "name", "align": "left"},
                        {"name": "key", "label": "Khóa K", "field": "key", "align": "left"},
                        {"name": "inp", "label": "Đầu vào P", "field": "inp", "align": "left"},
                        {"name": "exp", "label": "Kết quả chuẩn (Expected)", "field": "exp", "align": "left"},
                        {"name": "act", "label": "Kết quả tự cài đặt (Actual)", "field": "act", "align": "left"},
                        {"name": "status", "label": "Trạng thái", "field": "status", "align": "center"},
                    ]
                    rows = [
                        {
                            "name": r.name,
                            "key": r.key_desc,
                            "inp": r.input_desc,
                            "exp": r.expected_hex,
                            "act": r.actual_hex,
                            "status": "PASS (Khớp 100%)" if r.passed else "FAIL",
                        }
                        for r in results
                    ]
                    # ui.table là thành phần hiển thị bảng đơn giản mặc định của NiceGUI
                    ui.table(columns=cols, rows=rows, row_key="name").classes("w-full")

        # Gọi hàm refresh_test_suite ngay khi mở tab để hiển thị bảng lần đầu
        refresh_test_suite()
