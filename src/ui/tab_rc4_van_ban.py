"""Tab 2 (Văn bản): Mã hóa và giải mã chuỗi văn bản UTF-8 bằng RC4 256-byte chuẩn.

Người dùng nhập văn bản tiếng Việt và khóa bí mật (dạng chuỗi hoặc Hex),
bấm nút 'Mã hóa & Kiểm tra Giải mã' để thực thi thuật toán đối xứng.
Giao diện gọi rc4_crypt_with_details() và rc4_crypt() trong src/core/rc4_chuan.py,
hiển thị bản mã Hex, Base64, kết quả giải mã và ma trận trạng thái S (16x16).
"""

from __future__ import annotations  # dùng để hỗ trợ chú thích kiểu dữ liệu kiểu mới của Python
from nicegui import ui  # dùng để xây dựng các thành phần giao diện web bằng Python

from src.core.quan_ly_khoa import khoa_tu_chuoi, khoa_tu_hex, sinh_khoa_rc4  # file nội bộ: sinh và phân tích khóa
from src.core.chuyen_doi_du_lieu import (  # file nội bộ: chuyển đổi bytes, hex và phân tích UTF-8
    bytes_sang_hex,
    hex_sang_bytes,
    kiem_tra_giai_ma_utf8_ban_ma,
    phan_tich_ky_tu_utf8,
    trace_rc4_utf8_xor,
)
from src.core.rc4_chuan import rc4_crypt, rc4_crypt_with_details  # file nội bộ: thuật toán RC4 256-byte


def dung_tab_rc4_van_ban() -> None:
    """Xây dựng giao diện Phân hệ RC4 Văn Bản (Mảng S 256 byte).

    Tham số: Không có.
    Giá trị trả về: Không có (dựng các thành phần trực tiếp lên giao diện NiceGUI).
    Ví dụ: dung_tab_rc4_van_ban()
    """
    # các lớp Tailwind CSS chỉnh màu, khoảng cách, cỡ chữ
    with ui.card().classes("w-full p-6 space-y-4"):
        with ui.row().classes("w-full items-center justify-between pb-2 border-b border-slate-100"):
            with ui.row().classes("items-center gap-3"):
                with ui.row().classes("w-9 h-9 rounded-lg bg-sky-50 text-sky-700 items-center justify-center border border-sky-200"):
                    ui.icon("article", size="xs")
                with ui.column().classes("gap-0"):
                    ui.label("1. Mã Hóa & Giải Mã Văn Bản (UTF-8)").classes("text-base font-bold text-slate-800")
                    ui.label("RC4 256-byte chuẩn • Modulo 256 • Xử lý chuỗi ký tự Unicode").classes("text-xs text-slate-500")
            ui.badge("Mảng S 256 bytes", color="primary").classes("text-xs")

        # Ghi chú học thuật: Vị trí của UTF-8 trong quy trình RC4
        with ui.row().classes("w-full items-start gap-2.5 p-3.5 bg-sky-50/70 border border-sky-200/80 rounded-xl text-xs text-sky-950"):
            ui.icon("info", size="xs").classes("text-sky-600 mt-0.5 shrink-0")
            with ui.column().classes("gap-1"):
                ui.label("Vị trí của UTF-8 trong quy trình RC4:").classes("font-bold text-sky-900")
                ui.label(
                    "UTF-8 là bước tiền xử lý chuyển đổi văn bản M thành dãy m byte nhị phân P = UTF8Encode(M) trước khi vào lõi RC4. "
                    "Lõi RC4 (KSA, PRGA, XOR) chỉ xử lý dãy byte nhị phân thuần túy (0..255). "
                    "Bản mã C sau phép XOR không còn là chuỗi UTF-8 hợp lệ nên không thể decode UTF-8 trực tiếp, "
                    "mà cần được lưu nhị phân hoặc biểu diễn an toàn qua định dạng Hex hoặc Base64."
                ).classes("leading-relaxed text-sky-900/90")

        # Ô nhập bản rõ văn bản UTF-8
        full_pt = ui.textarea(
            label="Bản rõ (Plaintext UTF-8)",
            value="An toàn và Bảo mật Thông tin - Hệ mã dòng RC4 (Mảng S 256 byte)",
        ).classes("w-full")

        with ui.row().classes("w-full items-center gap-2"):
            # Ô nhập khóa bí mật (dạng chuỗi UTF-8 hoặc chuỗi Hex)
            full_key = ui.input(
                label="Khóa bí mật K (1..256 byte)",
                value="NEU-CNTT-SecretKey-2026",
            ).classes("flex-1")
            # ui.toggle: nút bấm gạt nhiều trạng thái lựa chọn (như công tắc chuyển đổi UTF-8 và Hex)
            text_key_toggle = ui.toggle(["UTF-8", "Hex"], value="UTF-8").props("dense no-caps")
            # Bấm nút này gọi sinh_khoa_rc4(16) và chuyển chế độ sang Hex
            btn_rand_key = ui.button("Khóa ngẫu nhiên", icon="casino").props("outline size=sm color=primary")

        text_key_len_label = ui.label("").classes("text-xs text-slate-500 font-mono -mt-2")

        def update_text_key_len() -> None:
            """Cập nhật độ dài byte thực tế của khóa trên nhãn hiển thị.

            Tham số: Không có.
            Giá trị trả về: Không có.
            """
            try:
                if text_key_toggle.value == "Hex":
                    k_b = khoa_tu_hex(full_key.value or "")
                else:
                    k_b = khoa_tu_chuoi(full_key.value or "")
                text_key_len_label.text = f"Độ dài khóa: {len(k_b)} byte"
            except ValueError:
                text_key_len_label.text = "Khóa không hợp lệ"

        def on_random_key() -> None:
            """Sinh khóa ngẫu nhiên 16 byte (128 bit) và điền vào ô nhập dưới dạng Hex.

            Tham số: Không có.
            Giá trị trả về: Không có.
            """
            rand_bytes = sinh_khoa_rc4(16)
            text_key_toggle.value = "Hex"
            full_key.value = bytes_sang_hex(rand_bytes)
            update_text_key_len()

        btn_rand_key.on_click(on_random_key)
        full_key.on_value_change(update_text_key_len)
        full_key.on("input", update_text_key_len)
        text_key_toggle.on_value_change(update_text_key_len)
        update_text_key_len()

        # Chip tóm tắt chỉ số thực thi (Execution Stats Bar)
        full_meta_row = ui.row().classes("w-full items-center gap-2 p-2.5 bg-slate-50 rounded-lg border border-slate-200/60 text-xs font-mono text-slate-700 flex-wrap")

        full_hex_out = ui.textarea(label="Bản mã (Hexadecimal)").classes("w-full font-mono text-xs")
        full_b64_out = ui.input(label="Bản mã (Base64)").classes("w-full font-mono text-xs")
        full_dec_out = ui.input(label="Kết quả Giải mã ngược lại (Khôi phục bản rõ)").classes(
            "w-full font-bold text-emerald-800"
        )

        # Khu vực xem ma trận trạng thái S (16x16)
        with ui.expansion("Xem trạng thái Ma trận hoán vị S (256 byte — Lưới 16x16)", icon="grid_view").classes(
            "w-full bg-slate-50/70 border border-slate-200/80 rounded-lg"
        ):
            sbox_grid_label = ui.label("").classes("font-mono text-xs p-3 whitespace-pre leading-relaxed text-slate-700")

        def run_full_text_demo() -> None:
            """Thực thi mã hóa bản rõ và kiểm tra giải mã ngược lại bằng rc4_crypt.

            Hàm gọi rc4_crypt_with_details() để lấy bản mã, thời gian đo và trạng thái ma trận S,
            sau đó gọi rc4_crypt() giải mã ngược lại để chứng minh tính đối xứng hoàn hảo.

            Tham số: Không có.
            Giá trị trả về: Không có.
            """
            try:
                pt_bytes = full_pt.value.encode("utf-8")
                if text_key_toggle.value == "Hex":
                    k_bytes = khoa_tu_hex(full_key.value or "")
                else:
                    k_bytes = khoa_tu_chuoi(full_key.value or "")
            except ValueError as exc:
                ui.notify(str(exc), type="negative")
                return

            try:
                enc_res = rc4_crypt_with_details(pt_bytes, k_bytes)
                dec_bytes = rc4_crypt(enc_res.output_bytes, k_bytes)

                full_hex_out.value = enc_res.output_hex
                full_b64_out.value = enc_res.output_base64
                full_dec_out.value = dec_bytes.decode("utf-8", errors="replace")

                full_meta_row.clear()
                with full_meta_row:
                    ui.badge(f"Kích thước: {len(pt_bytes)} bytes", color="secondary").classes("text-xs")
                    ui.badge(f"Thời gian: {enc_res.elapsed_ms:.3f} ms", color="accent").classes("text-xs")
                    ui.label(f"8 byte dòng khóa đầu: {enc_res.keystream_preview[:8]}").classes("text-slate-600 text-xs")

                # Định dạng hiển thị ma trận 16x16
                sbox_rows = []
                for row_idx in range(16):
                    row_vals = enc_res.final_ksa_s[row_idx * 16 : (row_idx + 1) * 16]
                    row_str = " ".join(f"{val:02X}" for val in row_vals)
                    sbox_rows.append(f"Row {row_idx:02X}: {row_str}")
                sbox_grid_label.text = "\n".join(sbox_rows)

            except Exception as exc:
                ui.notify(str(exc), type="negative")

        # Bấm nút này gọi rc4_crypt_with_details() trong core, hiện Hex, Base64 và ma trận S
        ui.button("Mã hóa & Kiểm tra Giải mã", icon="lock", on_click=run_full_text_demo).props(
            "color=primary"
        )
        run_full_text_demo()

    # =========================================================================
    # CARD 2: MINH HỌA BIỂU DIỄN UTF-8 TRONG RC4
    # =========================================================================
    with ui.card().classes("w-full p-6 space-y-4 mt-4"):
        with ui.row().classes("w-full items-center justify-between pb-2 border-b border-slate-100"):
            with ui.row().classes("items-center gap-3"):
                with ui.row().classes("w-9 h-9 rounded-lg bg-emerald-50 text-emerald-700 items-center justify-center border border-emerald-200"):
                    ui.icon("science", size="xs")
                with ui.column().classes("gap-0"):
                    ui.label("Minh Họa Biểu Diễn UTF-8 Trong RC4").classes("text-base font-bold text-slate-800")
                    ui.label("Phân rã mã điểm Unicode • Diễn giải phép XOR 8-bit từng byte").classes("text-xs text-slate-500")
            ui.badge("Unicode UTF-8", color="positive").classes("text-xs")

        # Khung nhập liệu thử nghiệm
        with ui.row().classes("w-full items-center gap-3 flex-wrap"):
            utf8_input_text = ui.input(
                label="Văn bản thử nghiệm M (Unicode UTF-8)",
                value="Haha",
            ).classes("flex-1 min-w-[200px]")
            utf8_input_key = ui.input(
                label="Khóa bí mật K (Hex)",
                value="01 02 03 04 05",
            ).classes("w-64 font-mono")
            btn_run_utf8_lab = ui.button("MÔ PHỎNG UTF-8", icon="play_arrow").props("color=primary")

        # Container chứa kết quả bảng 1, bảng 2 và giải thích ngắn gọn
        utf8_results_container = ui.column().classes("w-full gap-5 mt-2")

        def render_utf8_lab() -> None:
            """Kết xuất kết quả phân tích UTF-8 và bảng diễn giải 8-bit XOR."""
            utf8_results_container.clear()
            text_val = utf8_input_text.value or ""
            key_raw = utf8_input_key.value or ""

            try:
                k_bytes = hex_sang_bytes(key_raw)
            except ValueError as exc:
                with utf8_results_container:
                    ui.label(f"Lỗi khóa: {exc}").classes("text-rose-600 text-xs font-semibold")
                return

            if not text_val:
                with utf8_results_container:
                    ui.label("Vui lòng nhập ít nhất 1 ký tự để phân tích.").classes("text-slate-500 text-xs italic")
                return

            if not k_bytes:
                with utf8_results_container:
                    ui.label("Vui lòng nhập khóa bí mật.").classes("text-slate-500 text-xs italic")
                return

            char_breakdown = phan_tich_ky_tu_utf8(text_val)
            xor_steps = trace_rc4_utf8_xor(text_val, k_bytes)
            cipher_bytes = bytes([s.c_val for s in xor_steps])

            total_chars = len(text_val)
            total_bytes = len(text_val.encode("utf-8"))

            with utf8_results_container:
                # -------------------------------------------------------------
                # BẢNG 1: PHÂN RÃ CẤU TRÚC KÝ TỰ SANG UTF-8
                # -------------------------------------------------------------
                with ui.column().classes("w-full gap-2"):
                    with ui.row().classes("w-full items-center justify-between"):
                        with ui.row().classes("items-center gap-2"):
                            ui.label("Bảng 1: Phân Rã Cấu Trúc Biểu Diễn Ký Tự Sang UTF-8").classes("text-xs font-bold text-slate-800")
                            ui.badge(f"{total_chars} ký tự → {total_bytes} bytes", color="primary").classes("text-xs")
                        if total_bytes != total_chars:
                            ui.label(
                                f"💡 Chuỗi có {total_chars} ký tự nhưng nở thành {total_bytes} byte. PRGA sẽ lặp đúng m = {total_bytes} vòng!"
                            ).classes("text-xs text-sky-700 font-medium")

                    table_1_rows = []
                    for c in char_breakdown:
                        dec_repr = ", ".join(str(d) for d in c.byte_dec_list)
                        table_1_rows.append(
                            f"<tr class='border-b border-slate-100 hover:bg-slate-50/80 transition-colors'>"
                            f"<td class='p-2 font-bold text-slate-900'>{c.char}</td>"
                            f"<td class='p-2 font-mono text-indigo-700'>{c.codepoint} ({c.codepoint_dec})</td>"
                            f"<td class='p-2 text-center'><span class='px-2 py-0.5 rounded-full text-[11px] font-semibold bg-emerald-100 text-emerald-800'>{c.byte_count} byte</span></td>"
                            f"<td class='p-2 font-mono text-slate-600'>{c.pattern}</td>"
                            f"<td class='p-2 font-mono text-purple-700'>{c.data_bits}</td>"
                            f"<td class='p-2 font-mono text-sky-800 font-semibold'>{c.bin_str}</td>"
                            f"<td class='p-2 font-mono text-amber-800 font-semibold'>{c.hex_str}</td>"
                            f"<td class='p-2 font-mono text-slate-800 font-bold'>[{dec_repr}]</td>"
                            f"</tr>"
                        )
                    table_1_html = (
                        "<div class='overflow-x-auto w-full border border-slate-200 rounded-lg'>"
                        "<table class='w-full text-xs text-left border-collapse'>"
                        "<thead class='bg-slate-100/90 text-slate-700 font-semibold border-b border-slate-200'>"
                        "<tr>"
                        "<th class='p-2'>Ký tự</th>"
                        "<th class='p-2'>Mã điểm Unicode</th>"
                        "<th class='p-2 text-center'>Số byte</th>"
                        "<th class='p-2'>Mẫu bit UTF-8</th>"
                        "<th class='p-2'>Bit dữ liệu</th>"
                        "<th class='p-2'>Dạng nhị phân 8-bit</th>"
                        "<th class='p-2'>Dạng Hex</th>"
                        "<th class='p-2'>Byte bản rõ P_r (Dec)</th>"
                        "</tr>"
                        "</thead>"
                        f"<tbody>{''.join(table_1_rows)}</tbody>"
                        "</table>"
                        "</div>"
                    )
                    ui.html(table_1_html).classes("w-full")

                # -------------------------------------------------------------
                # BẢNG 2: DIỄN GIẢI TỪNG BYTE QUA LÕI RC4 (8-BIT XOR)
                # -------------------------------------------------------------
                with ui.column().classes("w-full gap-2"):
                    with ui.row().classes("w-full items-center justify-between"):
                        with ui.row().classes("items-center gap-2"):
                            ui.label("Bảng 2: Diễn Giải Từng Byte Qua Lõi RC4 (8-bit XOR)").classes("text-xs font-bold text-slate-800")
                            ui.badge(f"m = {len(xor_steps)} bước XOR", color="secondary").classes("text-xs")
                        cipher_hex = cipher_bytes.hex().upper()
                        cipher_dec_list = [s.c_val for s in xor_steps]
                        ui.label(f"Bản mã C = {cipher_dec_list} (Hex: {cipher_hex})").classes("text-xs font-mono font-bold text-emerald-800")

                    table_2_rows = []
                    for s in xor_steps:
                        table_2_rows.append(
                            f"<tr class='border-b border-slate-100 hover:bg-slate-50/80 transition-colors'>"
                            f"<td class='p-2 font-mono font-bold text-slate-700 text-center'>{s.r}</td>"
                            f"<td class='p-2 font-bold text-slate-900'>{s.char_ref}</td>"
                            f"<td class='p-2 font-mono text-sky-800'>{s.p_val} (0x{s.p_hex})</td>"
                            f"<td class='p-2 font-mono text-indigo-700'>{s.z_val} (0x{s.z_hex})</td>"
                            f"<td class='p-2 font-mono text-slate-800 font-semibold bg-slate-50/50'>{s.xor_expr}</td>"
                            f"<td class='p-2 font-mono font-bold text-emerald-800'>{s.c_val}</td>"
                            f"<td class='p-2 font-mono font-bold text-emerald-700'>0x{s.c_hex}</td>"
                            f"</tr>"
                        )
                    table_2_html = (
                        "<div class='overflow-x-auto w-full border border-slate-200 rounded-lg'>"
                        "<table class='w-full text-xs text-left border-collapse'>"
                        "<thead class='bg-slate-100/90 text-slate-700 font-semibold border-b border-slate-200'>"
                        "<tr>"
                        "<th class='p-2 text-center'>r</th>"
                        "<th class='p-2'>Ký tự</th>"
                        "<th class='p-2'>Byte bản rõ P_r</th>"
                        "<th class='p-2'>Byte dòng khóa Z_r</th>"
                        "<th class='p-2'>Phép XOR trên 8 bit (P_r ⊕ Z_r)</th>"
                        "<th class='p-2'>Bản mã C_r (Dec)</th>"
                        "<th class='p-2'>Bản mã C_r (Hex)</th>"
                        "</tr>"
                        "</thead>"
                        f"<tbody>{''.join(table_2_rows)}</tbody>"
                        "</table>"
                        "</div>"
                    )
                    ui.html(table_2_html).classes("w-full")

                # -------------------------------------------------------------
                # GIẢI THÍCH NGẮN GỌN: TẠI SAO UTF-8 KHÔNG GIẢI MÃ TRỰC TIẾP TRÊN BẢN MÃ
                # -------------------------------------------------------------
                with ui.row().classes("w-full items-start gap-2.5 p-3.5 bg-rose-50/70 border border-rose-200/80 rounded-xl text-xs text-rose-950"):
                    ui.icon("info", size="xs").classes("text-rose-600 mt-0.5 shrink-0")
                    with ui.column().classes("gap-1"):
                        ui.label("Tại sao không thể giải mã UTF-8 trực tiếp trên bản mã?").classes("font-bold text-rose-900")
                        ui.label(
                            "Phép XOR giữa byte bản rõ và dòng khóa (C_r = P_r ⊕ Z_r) tạo ra các byte có giá trị ngẫu nhiên (0..255). "
                            "Các byte ngẫu nhiên này thường xuyên vi phạm cấu trúc tiền tố chuẩn của UTF-8 (ví dụ: byte mở đầu báo hiệu ký tự đa byte nhưng byte tiếp theo không có dạng '10xxxxxx', hoặc xuất hiện byte không hợp lệ), "
                            "dẫn đến lỗi UnicodeDecodeError khi giải mã. Do đó, bản mã bắt buộc phải được lưu trữ dưới dạng nhị phân hoặc biểu diễn an toàn qua chuỗi Hex hoặc Base64."
                        ).classes("leading-relaxed text-rose-900/90")

        btn_run_utf8_lab.on_click(render_utf8_lab)
        utf8_input_text.on("change", render_utf8_lab)
        utf8_input_key.on("change", render_utf8_lab)

        # Chạy hiển thị ban đầu
        render_utf8_lab()




