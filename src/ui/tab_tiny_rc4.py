"""Tab 1: Thực thi và trực quan hóa từng bước thuật toán TinyRC4 (3-bit).

Người dùng nhập bản rõ/bản mã (A..H hoặc 3-bit nhị phân) và khóa bí mật (0..7),
hoặc bấm nút nạp ví dụ mẫu bài giảng NEU, thực thi mã hóa và giải mã đối xứng.
Giao diện gọi hàm run_tiny_rc4() trong src/core/tiny_rc4.py và hiển thị bảng chi tiết KSA, PRGA.
Mọi phép toán tuân thủ đúng chuẩn giáo trình An toàn & Bảo mật Thông tin NEU.
"""

from __future__ import annotations  # dùng để hỗ trợ chú thích kiểu dữ liệu kiểu mới của Python
from nicegui import ui  # dùng để xây dựng các thành phần giao diện web bằng Python

from src.core.models import TinyRC4Result  # file nội bộ: cấu trúc dữ liệu kết quả thực thi TinyRC4
from src.core.tiny_rc4 import run_tiny_rc4  # file nội bộ: hàm thuật toán cốt lõi TinyRC4


def build_tab_tiny_rc4() -> None:
    """Xây dựng giao diện Tab 1: Trực quan hóa từng bước TinyRC4 (Slide 53-60 NEU).

    Tham số: Không có.
    Giá trị trả về: Không có (dựng các thành phần trực tiếp lên giao diện NiceGUI).
    Ví dụ: build_tab_tiny_rc4()
    """
    # các lớp Tailwind CSS chỉnh màu, khoảng cách, cỡ chữ
    # Khung điều khiển & Nhập liệu chính (Flat Control Card)
    with ui.card().classes("w-full p-6 bg-white border border-slate-200/90 rounded-2xl shadow-xs"):
        with ui.row().classes("w-full items-center justify-between mb-4 flex-wrap gap-3"):
            with ui.row().classes("items-center gap-3"):
                with ui.row().classes(
                    "w-11 h-11 rounded-xl bg-gradient-to-br from-blue-600 to-indigo-700 text-white items-center justify-center shadow-sm"
                ):
                    ui.icon("calculate", size="sm")
                with ui.column().classes("gap-0.5"):
                    ui.label("Mô Hình Thu Nhỏ TinyRC4 (Đơn Vị Mã Hóa 3-Bit)").classes(
                        "text-lg font-bold text-slate-900 tracking-tight"
                    )
                    ui.label(
                        "Mảng trạng thái S & T gồm 8 phần tử (0..7) • Phép cộng modulo 8 • Bám sát chuẩn bài giảng NEU"
                    ).classes("text-xs text-slate-500 font-medium")
            with ui.row().classes("items-center gap-2"):
                ui.badge("Đơn vị 3-bit", color="primary").classes("text-xs px-2.5 py-1 font-semibold")
                ui.badge("N = 8", color="secondary").classes("text-xs px-2.5 py-1 font-semibold")

        # Bảng quy đổi ký tự 3-bit chuẩn hóa dạng Interactive Keypad Chips
        with ui.column().classes("w-full mb-5 bg-slate-50/90 p-4 rounded-xl border border-slate-200/80"):
            with ui.row().classes("items-center justify-between w-full mb-2"):
                ui.label("Bảng quy đổi ký tự sang số 3-bit (Click chữ cái để nhập nhanh):").classes(
                    "text-xs font-bold text-slate-700 uppercase tracking-wider"
                )
                ui.label("8 ký tự A..H tương ứng 0..7").classes("text-2xs text-slate-400 font-mono")

            with ui.row().classes("w-full items-center gap-2 flex-wrap"):
                alphabet_mapping = [
                    ("A", 0, "000"),
                    ("B", 1, "001"),
                    ("C", 2, "010"),
                    ("D", 3, "011"),
                    ("E", 4, "100"),
                    ("F", 5, "101"),
                    ("G", 6, "110"),
                    ("H", 7, "111"),
                ]
                for letter, num, bit_str in alphabet_mapping:
                    # Bấm nút chữ cái này để tự động điền vào ô bản rõ
                    with ui.button(
                        on_click=lambda l=letter: append_letter_to_input(l)
                    ).props("flat dense").classes(
                        "bg-white hover:bg-blue-50/80 px-3 py-1.5 rounded-lg border border-slate-200/90 hover:border-blue-300 shadow-2xs cursor-pointer transition-all gap-1.5 items-center normal-case"
                    ):
                        ui.label(letter).classes("font-black text-sm text-blue-700")
                        ui.label(f"= {bit_str}").classes("font-mono text-xs text-slate-600 font-medium")
                        ui.badge(str(num), color="slate-200").classes("text-2xs text-slate-700 px-1.5 py-0.5 rounded")

        # Form nhập liệu
        with ui.row().classes("w-full gap-4 items-center"):
            # Ô nhập bản rõ P hoặc bản mã C cần xử lý
            tiny_in = ui.input(
                label="Bản rõ P hoặc Bản mã C (chữ cái A..H hoặc chuỗi 3-bit)",
                value="BAG",
                placeholder="Ví dụ: BAG hoặc 001 000 110",
            ).props("outlined clearable").classes("flex-1 text-sm font-medium")

            # Ô nhập khóa bí mật K gồm các số nguyên từ 0 đến 7
            tiny_key = ui.input(
                label="Khóa bí mật K (1..8 số từ 0 đến 7, cách nhau dấu phẩy)",
                value="2, 1, 3",
                placeholder="Ví dụ: 2, 1, 3",
            ).props("outlined clearable").classes("flex-1 text-sm font-medium")

        # Thanh nút thao tác cao cấp (Gradient Primary & Action Buttons)
        # hàm callback: hàm được tự động gọi khi người dùng bấm nút trên giao diện
        with ui.row().classes("gap-3 mt-4 items-center flex-wrap"):
            # Bấm nút này gọi run_tiny_rc4() trong core và hiển thị bảng KSA, PRGA ở ksa_container
            ui.button(
                "Thực thi TinyRC4",
                icon="play_arrow",
                on_click=lambda: handle_tiny_run(),
            ).classes(
                "bg-blue-700 hover:bg-blue-800 text-white font-bold px-5 py-2.5 rounded-xl shadow-xs hover:shadow-md transition-all"
            )
            # Bấm nút này điền P='BAG', K=[2,1,3] và gọi handle_tiny_run() hiển thị kết quả khớp slide NEU
            ui.button(
                "Nạp ví dụ mẫu P='BAG', K=[2,1,3]",
                icon="school",
                on_click=lambda: load_classroom_example(),
            ).props("outline color=primary").classes("px-4 py-2 rounded-xl font-semibold")
            # Bấm nút này lấy output làm input, gọi run_tiny_rc4() để khôi phục bản rõ ban đầu
            ui.button(
                "Đảo kết quả để giải mã đối xứng",
                icon="swap_horiz",
                on_click=lambda: swap_to_decrypt(),
            ).props("outline color=teal-8").classes("px-4 py-2 rounded-xl font-semibold")

    # Khung chứa kết quả động
    ksa_container = ui.column().classes("w-full gap-4 mt-3")

    def append_letter_to_input(letter: str) -> None:
        """Nối ký tự hoặc mã nhị phân tương ứng vào ô nhập liệu bản rõ P.

        Tham số:
            letter: Ký tự chữ cái A..H cần bổ sung.
        Giá trị trả về: Không có.
        """
        current = tiny_in.value or ""
        # Nếu đang là chuỗi nhị phân thì thêm dạng nhị phân, ngược lại thêm chữ cái
        if current.replace(" ", "").isdigit():
            val_map = {"A": "000", "B": "001", "C": "010", "D": "011", "E": "100", "F": "101", "G": "110", "H": "111"}
            tiny_in.value = (current + " " + val_map[letter]).strip()
        else:
            tiny_in.value = current + letter

    def render_tiny_result(res: TinyRC4Result, mode_label: str) -> None:
        """Hiển thị kết quả thực thi TinyRC4 gồm 3 thẻ tóm tắt và 2 bảng chi tiết KSA, PRGA.

        Tham số:
            res: Đối tượng TinyRC4Result chứa toàn bộ lịch sử các bước KSA, PRGA từ core.
            mode_label: Nhãn hiển thị chế độ (ví dụ 'Giải mã ngược lại').
        Giá trị trả về: Không có.
        """
        ksa_container.clear()
        with ksa_container:
            # 1. Thẻ tóm tắt chỉ số Dashboard (3 Metric Cards - High-contrast & Modern Crypto Style)
            with ui.row().classes("w-full gap-4 items-stretch flex-wrap md:flex-nowrap"):
                # Card 1: Bản rõ / Đầu vào
                with ui.card().classes(
                    "flex-1 min-w-[280px] p-5 bg-gradient-to-br from-blue-50/70 to-indigo-50/30 border border-blue-200/80 border-l-4 border-l-blue-600 rounded-2xl shadow-xs"
                ):
                    with ui.row().classes("items-center justify-between w-full mb-1.5"):
                        header_title = f"ĐẦU VÀO — {mode_label}" if mode_label else "ĐẦU VÀO"
                        ui.label(header_title).classes(
                            "text-2xs font-extrabold text-blue-800 tracking-wider uppercase"
                        )
                        ui.icon("input", size="xs").classes("text-blue-600")
                    ui.label(res.input_text).classes(
                        "text-3xl font-black text-slate-900 font-mono tracking-tight my-0.5"
                    )
                    with ui.row().classes("items-center gap-2 mt-2"):
                        ui.badge("3-Bit Bin", color="blue-100").classes("text-2xs text-blue-900 font-semibold")
                        ui.label(res.input_bits).classes("font-mono text-xs font-semibold text-blue-800")

                # Card 2: Dòng khóa PRGA
                with ui.card().classes(
                    "flex-1 min-w-[280px] p-5 bg-gradient-to-br from-amber-50/70 to-yellow-50/30 border border-amber-200/80 border-l-4 border-l-amber-500 rounded-2xl shadow-xs"
                ):
                    with ui.row().classes("items-center justify-between w-full mb-1.5"):
                        ui.label("DÒNG KHÓA PRGA").classes(
                            "text-2xs font-extrabold text-amber-800 tracking-wider uppercase"
                        )
                        ui.icon("vpn_key", size="xs").classes("text-amber-600")
                    ui.label(str(res.keystream_list)).classes(
                        "text-3xl font-black text-amber-950 font-mono tracking-tight my-0.5"
                    )
                    with ui.row().classes("items-center gap-2 mt-2"):
                        ui.badge("3-Bit Bin", color="amber-100").classes("text-2xs text-amber-900 font-semibold")
                        ui.label(res.keystream_bits).classes("font-mono text-xs font-semibold text-amber-900")

                # Card 3: Kết quả đầu ra (Ciphertext)
                with ui.card().classes(
                    "flex-1 min-w-[280px] p-5 bg-gradient-to-br from-emerald-50/70 to-teal-50/30 border border-emerald-200/80 border-l-4 border-l-emerald-600 rounded-2xl shadow-xs"
                ):
                    with ui.row().classes("items-center justify-between w-full mb-1.5"):
                        ui.label("KẾT QUẢ ĐẦU RA").classes(
                            "text-2xs font-extrabold text-emerald-800 tracking-wider uppercase"
                        )
                        ui.icon("output", size="xs").classes("text-emerald-600")
                    ui.label(res.output_text).classes(
                        "text-3xl font-black text-emerald-950 font-mono tracking-tight my-0.5"
                    )
                    with ui.row().classes("items-center gap-2 mt-2"):
                        ui.badge("3-Bit Bin", color="emerald-100").classes("text-2xs text-emerald-900 font-semibold")
                        ui.label(res.output_bits).classes("font-mono text-xs font-semibold text-emerald-900")

            # 2. Thẻ giai đoạn KSA
            with ui.card().classes("w-full p-6 bg-white border border-slate-200/90 rounded-2xl shadow-xs"):
                with ui.row().classes("w-full items-center justify-between mb-4 flex-wrap gap-2"):
                    with ui.row().classes("items-center gap-3"):
                        with ui.row().classes(
                            "w-8 h-8 rounded-lg bg-blue-600 text-white items-center justify-center font-bold text-sm shadow-2xs"
                        ):
                            ui.label("1")
                        with ui.column().classes("gap-0"):
                            ui.label("Giai Đoạn 1: Khởi Tạo & Hoán Vị Mảng S (KSA — 8 Vòng)").classes(
                                "text-base font-bold text-slate-900"
                            )
                            ui.label("Công thức: j = (j + S[i] + T[i]) mod 8, sau đó hoán vị S[i] và S[j]").classes(
                                "text-xs text-slate-500"
                            )
                    with ui.row().classes("items-center gap-2 text-xs font-mono"):
                        ui.label(f"S ban đầu: {res.initial_s} | T = {res.initial_t}").classes("text-slate-600")
                        ui.badge(f"S sau KSA (i=7): {res.final_ksa_s}", color="primary").classes(
                            "text-xs font-mono px-2.5 py-1"
                        )

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
                # ui.table: bảng hiển thị dữ liệu dạng lưới gồm nhiều hàng và cột (bảng KSA)
                ui.table(columns=ksa_cols, rows=ksa_rows, row_key="step_i").classes(
                    "w-full border border-slate-200/80 rounded-xl overflow-hidden font-mono text-xs"
                )

            # 3. Thẻ giai đoạn PRGA & XOR
            with ui.card().classes("w-full p-6 bg-white border border-slate-200/90 rounded-2xl shadow-xs"):
                with ui.row().classes("w-full items-center justify-between mb-4 flex-wrap gap-2"):
                    with ui.row().classes("items-center gap-3"):
                        with ui.row().classes(
                            "w-8 h-8 rounded-lg bg-emerald-600 text-white items-center justify-center font-bold text-sm shadow-2xs"
                        ):
                            ui.label("2")
                        with ui.column().classes("gap-0"):
                            ui.label("Giai Đoạn 2: Sinh Dòng Khóa (PRGA) & Mã Hóa/Giải Mã XOR").classes(
                                "text-base font-bold text-slate-900"
                            )
                            ui.label("Công thức: i = (i + 1) mod 8, j = (j + S[i]) mod 8, swap, t = (S[i] + S[j]) mod 8, k = S[t], c = p ⊕ k").classes(
                                "text-xs text-slate-500"
                            )

                prga_cols = [
                    {"name": "step", "label": "Bước", "field": "step", "align": "center"},
                    {"name": "ij", "label": "(i, j)", "field": "ij", "align": "center"},
                    {"name": "s_arr", "label": "Mảng S sau Swap(S[i], S[j])", "field": "s_arr", "align": "left"},
                    {"name": "t_idx", "label": "t = (S[i]+S[j]) mod 8", "field": "t_idx", "align": "center"},
                    {"name": "ks", "label": "Số sinh k = S[t]", "field": "ks", "align": "center"},
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
                # ui.table: bảng hiển thị dữ liệu dạng lưới gồm nhiều hàng và cột (bảng PRGA)
                ui.table(columns=prga_cols, rows=prga_rows, row_key="step").classes(
                    "w-full border border-slate-200/80 rounded-xl overflow-hidden font-mono text-xs"
                )

    def handle_tiny_run(mode_label: str = "") -> None:
        """Xử lý gọi hàm run_tiny_rc4 từ src/core và hiển thị kết quả lên giao diện.

        Tham số:
            mode_label: Nhãn bổ sung cho tiêu đề kết quả (mặc định rỗng).
        Giá trị trả về: Không có.
        """
        try:
            res = run_tiny_rc4(tiny_in.value, tiny_key.value)
            render_tiny_result(res, mode_label)
        except Exception as exc:
            ui.notify(str(exc), type="negative")

    def load_classroom_example() -> None:
        """Điền dữ liệu ví dụ chuẩn Slide 56-60 NEU (P='BAG', K=[2,1,3]) và chạy mô phỏng.

        Tham số: Không có.
        Giá trị trả về: Không có.
        """
        tiny_in.value = "BAG"
        tiny_key.value = "2, 1, 3"
        handle_tiny_run("")

    def swap_to_decrypt() -> None:
        """Đưa bản mã đầu ra làm đầu vào để minh họa tính đối xứng giải mã của RC4.

        Tham số: Không có.
        Giá trị trả về: Không có.
        """
        try:
            res = run_tiny_rc4(tiny_in.value, tiny_key.value)
            tiny_in.value = res.output_text
            handle_tiny_run("Giải mã ngược lại")
        except Exception as exc:
            ui.notify(str(exc), type="negative")

    # Hiển thị mặc định ví dụ trên lớp ngay khi mở trang
    load_classroom_example()
