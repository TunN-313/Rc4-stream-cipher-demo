"""
Tab 1: Thực Thi & Trực Quan Hóa Từng Bước TinyRC4 (3-bit)
==========================================================
Bám sát Slide 53-60 bài giảng ATBMTT (Khoa CNTT - ĐH Kinh tế Quốc dân)
Mô hình thu nhỏ: Đơn vị 3-bit, mảng S & T gồm 8 phần tử (0..7), modulo 8.
Giao diện sắc nét, bảng biểu trực quan và chip quy đổi ký tự chuẩn.
"""

from __future__ import annotations
from nicegui import ui

from src.core.models import TinyRC4Result
from src.core.tiny_rc4 import run_tiny_rc4


def build_tab_tiny_rc4() -> None:
    """Xây dựng giao diện Tab 1: TinyRC4 Step-by-Step."""
    with ui.card().classes("w-full p-5 mb-4 border-l-4 border-blue-700 shadow-sm"):
        ui.label("Mô hình thu nhỏ TinyRC4 (Đơn vị mã hóa 3-bit, mảng S và T gồm 8 phần tử 0..7)").classes(
            "text-lg font-bold text-slate-800 mb-2"
        )

        # 8 Chips quy đổi ký tự 3-bit đẹp mắt, dễ đọc
        with ui.row().classes("w-full items-center gap-2 mb-4 bg-slate-50 p-2.5 rounded border flex-wrap"):
            ui.label("Bảng quy đổi 3-bit (Slide 40):").classes("text-xs font-bold text-slate-700 mr-1")
            alphabet_mapping = [
                ("A", "000 (0)"),
                ("B", "001 (1)"),
                ("C", "010 (2)"),
                ("D", "011 (3)"),
                ("E", "100 (4)"),
                ("F", "101 (5)"),
                ("G", "110 (6)"),
                ("H", "111 (7)"),
            ]
            for letter, val in alphabet_mapping:
                with ui.row().classes("items-center gap-1 bg-white px-2 py-0.5 rounded border border-slate-200 shadow-2xs font-mono text-xs"):
                    ui.label(letter).classes("font-bold text-blue-700")
                    ui.label(f": {val}").classes("text-slate-600")

        with ui.row().classes("w-full gap-4 items-end"):
            tiny_in = ui.input(
                label="Bản rõ P hoặc Bản mã C (chữ A..H hoặc nhị phân 3-bit)",
                value="BAG",
            ).classes("flex-1")
            tiny_key = ui.input(
                label="Khóa K (1..8 số từ 0 đến 7, cách nhau dấu phẩy)",
                value="2, 1, 3",
            ).classes("flex-1")

        ksa_container = ui.column().classes("w-full mt-4")

        def render_tiny_result(res: TinyRC4Result, mode_label: str) -> None:
            ksa_container.clear()
            with ksa_container:
                # Tóm tắt kết quả nổi bật
                with ui.row().classes("w-full gap-4"):
                    with ui.card().classes("flex-1 bg-blue-50 border border-blue-200 p-4"):
                        ui.label(f"Đầu vào ({mode_label})").classes("text-xs uppercase text-blue-700 font-bold")
                        ui.label(f"Chữ cái: {res.input_text}").classes("text-xl font-bold text-slate-900")
                        ui.label(f"Nhị phân: {res.input_bits}").classes("font-mono text-sm text-slate-700")

                    with ui.card().classes("flex-1 bg-amber-50 border border-amber-200 p-4"):
                        ui.label("Dòng khóa sinh ra (Keystream S)").classes(
                            "text-xs uppercase text-amber-800 font-bold"
                        )
                        ui.label(f"Thập phân: {res.keystream_list}").classes("text-xl font-bold text-slate-900")
                        ui.label(f"Nhị phân: {res.keystream_bits}").classes("font-mono text-sm text-slate-700")

                    with ui.card().classes("flex-1 bg-emerald-50 border border-emerald-200 p-4"):
                        ui.label("Kết quả đầu ra (Sau phép XOR)").classes(
                            "text-xs uppercase text-emerald-800 font-bold"
                        )
                        ui.label(f"Chữ cái: {res.output_text}").classes("text-xl font-bold text-emerald-900")
                        ui.label(f"Nhị phân: {res.output_bits}").classes("font-mono text-sm text-slate-700")

                # Bước 1: Khởi tạo và Hoán vị S (KSA)
                ui.label("Giai đoạn 1: Khởi tạo & Hoán vị mảng S (KSA — 8 vòng từ i = 0 đến 7)").classes(
                    "text-base font-bold text-slate-800 mt-4"
                )
                with ui.row().classes("w-full items-center gap-2 text-sm font-mono text-slate-700 mt-1 mb-2"):
                    ui.label(f"Khởi tạo ban đầu: S = {res.initial_s} | T = {res.initial_t}")
                    ui.icon("arrow_forward", size="xs").classes("text-blue-600")
                    ui.badge(f"Mảng S sau KSA (i=7): {res.final_ksa_s}", color="primary").classes("px-2 py-0.5 text-xs font-mono")

                ksa_cols = [
                    {"name": "step_i", "label": "Vòng i", "field": "step_i", "align": "center"},
                    {"name": "j_before", "label": "j trước", "field": "j_before", "align": "center"},
                    {"name": "s_i_before", "label": "S[i]", "field": "s_i_before", "align": "center"},
                    {"name": "t_i", "label": "T[i]", "field": "t_i", "align": "center"},
                    {"name": "j_after", "label": "j = (j+S[i]+T[i]) mod 8", "field": "j_after", "align": "center"},
                    {"name": "swapped_pair", "label": "Thao tác hoán vị", "field": "swapped_pair", "align": "left"},
                    {"name": "s_array", "label": "Mảng S sau bước i", "field": "s_array", "align": "left"},
                ]
                ksa_rows = [
                    {
                        "step_i": f"i = {st.step_i}",
                        "j_before": st.j_before,
                        "s_i_before": st.s_i_before,
                        "t_i": st.t_i,
                        "j_after": st.j_after,
                        "swapped_pair": st.swapped_pair,
                        "s_array": str(st.s_array),
                    }
                    for st in res.ksa_steps
                ]
                ui.table(columns=ksa_cols, rows=ksa_rows, row_key="step_i").classes("w-full")

                # Bước 2: Sinh dòng khóa (PRGA) và XOR
                ui.label("Giai đoạn 2: Sinh số (PRGA) & Mã hóa/Giải mã từng đơn vị 3-bit").classes(
                    "text-base font-bold text-slate-800 mt-4"
                )
                prga_cols = [
                    {"name": "step", "label": "Bước", "field": "step", "align": "center"},
                    {"name": "ij", "label": "(i, j)", "field": "ij", "align": "center"},
                    {"name": "s_arr", "label": "Mảng S sau Swap(S[i], S[j])", "field": "s_arr", "align": "left"},
                    {"name": "t_idx", "label": "t = (S[i]+S[j]) mod 8", "field": "t_idx", "align": "center"},
                    {"name": "ks", "label": "Số sinh s = S[t]", "field": "ks", "align": "center"},
                    {"name": "xor_op", "label": "Phép tính XOR: p ⊕ k = c", "field": "xor_op", "align": "left"},
                ]
                prga_rows = [
                    {
                        "step": f"Bước {st.step_idx}",
                        "ij": f"i={st.i_val}, j={st.j_val}",
                        "s_arr": str(st.s_array),
                        "t_idx": f"t = {st.t_val}",
                        "ks": f"{st.keystream_val} ({st.keystream_bin})",
                        "xor_op": (
                            f"{st.char_in} ({st.input_bin}) ⊕ {st.keystream_bin} "
                            f"= {st.output_bin} ({st.char_out})"
                        ),
                    }
                    for st in res.prga_steps
                ]
                ui.table(columns=prga_cols, rows=prga_rows, row_key="step").classes("w-full")

        def handle_tiny_run(mode_label: str = "Mã hóa / Giải mã") -> None:
            try:
                res = run_tiny_rc4(tiny_in.value, tiny_key.value)
                render_tiny_result(res, mode_label)
            except Exception as exc:
                ui.notify(str(exc), type="negative")

        def load_classroom_example() -> None:
            tiny_in.value = "BAG"
            tiny_key.value = "2, 1, 3"
            handle_tiny_run("Ví dụ chuẩn Slide 56 (BAG -> EBA)")

        def swap_to_decrypt() -> None:
            try:
                res = run_tiny_rc4(tiny_in.value, tiny_key.value)
                tiny_in.value = res.output_text
                handle_tiny_run("Giải mã ngược lại bản rõ")
            except Exception as exc:
                ui.notify(str(exc), type="negative")

        with ui.row().classes("gap-3 mt-3"):
            ui.button("Thực thi TinyRC4", icon="play_arrow", on_click=lambda: handle_tiny_run()).props(
                "color=primary"
            )
            ui.button(
                "Nạp ví dụ chuẩn trên lớp (P='BAG', K=[2,1,3])",
                icon="school",
                on_click=load_classroom_example,
            ).props("color=secondary outline")
            ui.button(
                "Đảo kết quả đầu ra vào ô nhập để Giải mã",
                icon="swap_horiz",
                on_click=swap_to_decrypt,
            ).props("color=accent outline")

        # Hiển thị mặc định ví dụ trên lớp ngay khi mở trang
        load_classroom_example()
