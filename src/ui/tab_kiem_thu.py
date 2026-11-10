"""
Giao diện Kiểm Thử Thủ Công (src/ui/tab_kiem_thu.py)
Nhiệm vụ: Cung cấp màn hình kiểm thử thủ công (Manual Testing) trực tiếp.
Người dùng hoặc giảng viên tự do nhập dữ liệu bất kỳ để đối chiếu tính đối xứng
của thuật toán RC4 chuẩn (8-bit) hoặc TinyRC4 (3-bit).
"""

from __future__ import annotations
from nicegui import ui
from src.core import (
    van_ban_sang_bytes,
    bytes_sang_van_ban,
    bytes_sang_hex,
    rc4_crypt,
    rc4_crypt_with_details,
    tiny_chuoi_sang_so,
    tiny_so_sang_chuoi,
    run_tiny_rc4,
)


def dung_tab_kiem_thu() -> None:
    """Dựng giao diện kiểm thử thủ công."""
    with ui.column().classes("w-full max-w-5xl mx-auto gap-5 pb-10 text-slate-800"):

        # 1. TIÊU ĐỀ TAB
        with ui.card().classes("w-full p-5 bg-white border border-slate-200 shadow-sm rounded-xl"):
            with ui.row().classes("items-center justify-between w-full flex-wrap gap-2"):
                with ui.row().classes("items-center gap-3"):
                    with ui.avatar(size="md", color="blue-900").classes("text-white shadow"):
                        ui.icon("fact_check", size="sm")
                    with ui.column().classes("gap-0"):
                        ui.label("KIỂM THỬ THỦ CÔNG").classes("text-base font-bold text-slate-900")
                        ui.label(
                            "Nhập dữ liệu tùy ý để kiểm chứng trực tiếp tính bảo toàn và đối xứng của thuật toán"
                        ).classes("text-xs text-slate-500")

        # 2. KHUNG NHẬP LIỆU KIỂM THỬ
        with ui.card().classes("w-full p-5 bg-white border border-slate-200 shadow-sm rounded-xl gap-4"):
            ui.label("1. THIẾT LẬP DỮ LIỆU KIỂM THỬ").classes("text-xs font-bold text-slate-900 tracking-wider uppercase border-b pb-2")

            # Chọn chế độ: RC4 Chuẩn 8-bit hoặc TinyRC4 3-bit
            with ui.row().classes("items-center gap-4"):
                ui.label("Hệ mã cần kiểm thử:").classes("text-sm font-semibold text-slate-700")
                mode_selector = ui.radio(
                    options={
                        "rc4_chuan": "RC4 Chuẩn 8-bit (Văn bản / Unicode tiếng Việt)",
                        "tiny_rc4": "TinyRC4 3-bit (Chữ cái A-H hoặc số 0-7)",
                    },
                    value="rc4_chuan",
                ).props("inline").classes("text-sm")

            # Ô nhập Bản rõ và Khóa
            with ui.grid(columns=2).classes("w-full gap-4"):
                inp_ban_ro = ui.input(
                    label="Bản rõ cần mã hóa:",
                    placeholder="Nhập chuỗi văn bản bất kỳ để kiểm thử...",
                    value="Đại Học Kinh Tế Quốc Dân - TMĐT",
                ).classes("w-full")

                inp_khoa = ui.input(
                    label="Khóa bí mật:",
                    placeholder="Nhập khóa kiểm thử...",
                    value="BaoMat2026",
                ).classes("w-full")

            hint_label = ui.label(
                "• Gợi ý: RC4 chuẩn hỗ trợ mọi chuỗi Unicode tiếng Việt và ký tự đặc biệt."
            ).classes("text-xs text-slate-500 italic")

            # Khi đổi chế độ thì cập nhật gợi ý và dữ liệu mẫu
            def on_mode_change(e):
                if mode_selector.value == "tiny_rc4":
                    inp_ban_ro.value = "BAG"
                    inp_khoa.value = "2, 1, 3"
                    hint_label.text = "• Gợi ý TinyRC4: Bản rõ gồm các chữ cái từ A đến H; Khóa gồm các số từ 0 đến 7 cách nhau bởi dấu phẩy."
                else:
                    inp_ban_ro.value = "Đại Học Kinh Tế Quốc Dân - TMĐT"
                    inp_khoa.value = "BaoMat2026"
                    hint_label.text = "• Gợi ý: RC4 chuẩn hỗ trợ mọi chuỗi Unicode tiếng Việt và ký tự đặc biệt."

            mode_selector.on_value_change(on_mode_change)

            # Các nút thao tác
            with ui.row().classes("items-center gap-3 pt-2"):
                btn_chay = ui.button(
                    "▶ Chạy Kiểm Thử Đối Xứng",
                    color="blue-900",
                ).classes("text-white font-semibold px-5 py-2 rounded-lg")

                btn_xoa = ui.button(
                    "Xóa Trắng",
                    color="slate-200",
                ).classes("text-slate-700 font-semibold px-4 py-2 rounded-lg")

        # 3. KHUNG KẾT QUẢ KIỂM THỬ ĐỐI XỨNG
        with ui.card().classes("w-full p-5 bg-white border border-slate-200 shadow-sm rounded-xl gap-4") as card_ket_qua:
            card_ket_qua.set_visibility(False)  # Mặc định ẩn đến khi bấm chạy

            with ui.row().classes("items-center justify-between w-full border-b pb-2"):
                ui.label("2. KẾT QUẢ ĐỐI CHIẾU KIỂM THỬ THỦ CÔNG").classes("text-xs font-bold text-slate-900 tracking-wider uppercase")
                badge_ket_luan = ui.badge("", color="emerald-700").classes("text-xs text-white px-2.5 py-1 font-bold")

            # 3 Khối kết quả theo từng bước
            with ui.grid(columns=3).classes("w-full gap-4 text-xs"):
                # Bước A: Dòng khóa
                with ui.card().classes("p-3 bg-slate-50 border border-slate-200 rounded-lg gap-1.5"):
                    ui.label("BƯỚC 1: DÒNG KHÓA").classes("font-bold text-blue-900")
                    lbl_dong_khoa = ui.label("").classes("font-mono break-all text-slate-800")

                # Bước B: Bản mã
                with ui.card().classes("p-3 bg-slate-50 border border-slate-200 rounded-lg gap-1.5"):
                    ui.label("BƯỚC 2: BẢN MÃ").classes("font-bold text-indigo-900")
                    lbl_ban_ma = ui.label("").classes("font-mono break-all text-slate-800")

                # Bước C: Giải mã đối xứng
                with ui.card().classes("p-3 bg-slate-50 border border-slate-200 rounded-lg gap-1.5"):
                    ui.label("BƯỚC 3: GIẢI MÃ").classes("font-bold text-emerald-900")
                    lbl_giai_ma = ui.label("").classes("font-mono break-all font-bold text-emerald-700")

            # Bảng so sánh kiểm chứng
            with ui.card().classes("w-full p-3 bg-emerald-50/70 border border-emerald-200 rounded-lg gap-1"):
                ui.label("KẾT LUẬN KIỂM CHỨNG:").classes("text-xs font-bold text-emerald-900")
                lbl_thong_diep_ket_luan = ui.label("").classes("text-xs text-emerald-800 leading-relaxed")

        # 4. KHUNG THỬ NGHIỆM GIẢI MÃ VỚI KHÓA SAI (NEGATIVE TESTING)
        with ui.card().classes("w-full p-5 bg-white border border-slate-200 shadow-sm rounded-xl gap-3") as card_sai_khoa:
            card_sai_khoa.set_visibility(False)

            ui.label("3. THỬ NGHIỆM TIÊU CỰC: GIẢI MÃ BẰNG KHÓA SAI").classes("text-xs font-bold text-slate-900 tracking-wider uppercase border-b pb-2")
            ui.label(
                "Mục đích: Chứng minh cho người nghe thấy khi kẻ gian không có đúng khóa bí mật thì hoàn toàn không thể khôi phục được nội dung."
            ).classes("text-xs text-slate-500")

            with ui.row().classes("w-full items-center gap-3"):
                inp_khoa_sai = ui.input(
                    label="Khóa thử nghiệm sai lệch:",
                    placeholder="Gõ khóa sai vào đây...",
                    value="KhoaSaiBatKy_999",
                ).classes("flex-1")

                btn_thu_sai = ui.button(
                    "Thử Giải Mã Khóa Sai",
                    color="rose-800",
                ).classes("text-white font-semibold px-4 py-2 rounded-lg")

            with ui.card().classes("w-full p-3 bg-rose-50 border border-rose-200 rounded-lg gap-1") as card_ket_qua_sai:
                card_ket_qua_sai.set_visibility(False)
                ui.label("KẾT QUẢ KHI GIẢI MÃ VỚI KHÓA SAI:").classes("text-xs font-bold text-rose-900")
                lbl_noi_dung_sai = ui.label("").classes("font-mono break-all text-xs text-rose-800")
                ui.label(
                    "⇒ KẾT LUẬN: Bản rõ giải mã hoàn toàn bị sai lệch / biến thành ký tự vô nghĩa. Dữ liệu được bảo vệ an toàn."
                ).classes("text-xs text-rose-900 font-semibold mt-1")

        def xoa_trang():
            inp_ban_ro.value = ""
            inp_khoa.value = ""
            card_ket_qua.set_visibility(False)
            card_sai_khoa.set_visibility(False)

        btn_xoa.on("click", xoa_trang)

        # XỬ LÝ SỰ KIỆN NÚT "CHẠY KIỂM THỬ"
        current_cipher_bytes = b""
        current_cipher_tiny = []

        def thuc_hien_kiem_thu():
            nonlocal current_cipher_bytes, current_cipher_tiny
            ban_ro_str = inp_ban_ro.value or ""
            khoa_str = inp_khoa.value or ""

            if not ban_ro_str:
                ui.notify("Vui lòng nhập bản rõ cần kiểm thử!", type="warning")
                return
            if not khoa_str:
                ui.notify("Vui lòng nhập khóa bí mật!", type="warning")
                return

            if mode_selector.value == "rc4_chuan":
                # Kiểm thử RC4 Chuẩn 8-bit
                data_b = van_ban_sang_bytes(ban_ro_str)
                key_b = van_ban_sang_bytes(khoa_str)

                # Mã hóa
                kq = rc4_crypt_with_details(data_b, key_b)
                current_cipher_bytes = kq.output_bytes

                # Giải mã đối xứng
                dec_b = rc4_crypt(current_cipher_bytes, key_b)
                dec_str = bytes_sang_van_ban(dec_b)

                # Hiển thị
                dong_khoa_hex = " ".join(f"{b:02X}" for b in kq.keystream_preview[:16])
                if len(kq.keystream_preview) > 16:
                    dong_khoa_hex += " ..."
                lbl_dong_khoa.text = f"Hex: {dong_khoa_hex}"
                lbl_ban_ma.text = f"Hex ({len(current_cipher_bytes)} bytes):\n{kq.output_hex[:60]}" + (
                    "..." if len(kq.output_hex) > 60 else ""
                )
                lbl_giai_ma.text = dec_str

                is_match = (dec_str == ban_ro_str)
                if is_match:
                    badge_ket_luan.text = "✓ ĐẠT (PASS 100%)"
                    badge_ket_luan.props("color=emerald-700")
                    lbl_thong_diep_ket_luan.text = (
                        f"Bản rõ sau khi giải mã trùng khớp 100% với bản rõ ban đầu ('{ban_ro_str}'). "
                        "Thuật toán RC4 chuẩn 8-bit bảo toàn trọn vẹn dữ liệu qua cơ chế mã hóa đối xứng XOR."
                    )
                else:
                    badge_ket_luan.text = "✗ KHÔNG KHỚP"
                    badge_ket_luan.props("color=rose-700")
                    lbl_thong_diep_ket_luan.text = "Phát hiện sai lệch giữa dữ liệu giải mã và bản rõ gốc."

            else:
                # Kiểm thử TinyRC4 3-bit
                raw_k = [x.strip() for x in khoa_str.replace(";", ",").split(",") if x.strip()]
                key_nums = []
                for item in raw_k:
                    if item.isdigit():
                        key_nums.append(int(item) % 8)
                    else:
                        key_nums.extend(tiny_chuoi_sang_so(item))

                if not ban_ro_str:
                    ui.notify("Vui lòng nhập bản rõ TinyRC4!", type="warning")
                    return
                if not key_nums:
                    ui.notify("Khóa TinyRC4 phải chứa các số từ 0 đến 7!", type="warning")
                    return

                kq_tiny = run_tiny_rc4(ban_ro_str, key_nums)
                current_cipher_tiny = kq_tiny.output_text

                # Giải mã đối xứng: Mã hóa lại bản mã với cùng khóa
                kq_dec_tiny = run_tiny_rc4(current_cipher_tiny, key_nums)
                dec_tiny_str = kq_dec_tiny.output_text

                lbl_dong_khoa.text = f"Số: {kq_tiny.keystream_list}"
                lbl_ban_ma.text = f"Chữ: '{kq_tiny.output_text}' (Số: {kq_tiny.output_list})"
                lbl_giai_ma.text = f"'{dec_tiny_str}' (Số: {kq_dec_tiny.output_list})"

                is_match = (kq_dec_tiny.output_text == kq_tiny.input_text)
                if is_match:
                    badge_ket_luan.text = "✓ ĐẠT (PASS 100%)"
                    badge_ket_luan.props("color=emerald-700")
                    lbl_thong_diep_ket_luan.text = (
                        f"Bản rõ 3-bit giải mã '{dec_tiny_str}' trùng khớp 100% với bản rõ ban đầu. "
                        "Hệ mã dòng TinyRC4 hoạt động chính xác theo quy chuẩn Modulo 8."
                    )
                else:
                    badge_ket_luan.text = "✗ KHÔNG KHỚP"
                    badge_ket_luan.props("color=rose-700")
                    lbl_thong_diep_ket_luan.text = "Không khớp kết quả giải mã TinyRC4."

            card_ket_qua.set_visibility(True)
            card_sai_khoa.set_visibility(True)
            card_ket_qua_sai.set_visibility(False)

        btn_chay.on("click", thuc_hien_kiem_thu)

        # XỬ LÝ SỰ KIỆN NÚT "THỬ GIẢI MÃ VỚI KHÓA SAI"
        def thuc_hien_thu_khoa_sai():
            khoa_sai_str = inp_khoa_sai.value or ""
            if not khoa_sai_str:
                ui.notify("Vui lòng nhập khóa sai để thử nghiệm!", type="warning")
                return

            if mode_selector.value == "rc4_chuan":
                if not current_cipher_bytes:
                    return
                key_sai_b = van_ban_sang_bytes(khoa_sai_str)
                dec_sai_b = rc4_crypt(current_cipher_bytes, key_sai_b)
                dec_sai_str = bytes_sang_van_ban(dec_sai_b)
                lbl_noi_dung_sai.text = (
                    f"Dữ liệu giải mã với khóa sai '{khoa_sai_str}':\n"
                    f"• Dạng Hex: {bytes_sang_hex(dec_sai_b)[:40]}...\n"
                    f"• Ký tự: \"{dec_sai_str}\" (xuất hiện ký tự rác/thay thế do sai khóa)"
                )
            else:
                if not current_cipher_tiny:
                    return
                raw_k = [x.strip() for x in khoa_sai_str.replace(";", ",").split(",") if x.strip()]
                key_sai_nums = []
                for item in raw_k:
                    if item.isdigit():
                        key_sai_nums.append(int(item) % 8)
                    else:
                        key_sai_nums.extend(tiny_chuoi_sang_so(item))
                if not key_sai_nums:
                    key_sai_nums = [7, 7, 7]

                kq_sai_tiny = run_tiny_rc4(current_cipher_tiny, key_sai_nums)
                lbl_noi_dung_sai.text = f"Kết quả giải mã với khóa sai {key_sai_nums}:\nChữ: '{kq_sai_tiny.output_text}' (Số: {kq_sai_tiny.output_list})"

            card_ket_qua_sai.set_visibility(True)

        btn_thu_sai.on("click", thuc_hien_thu_khoa_sai)
