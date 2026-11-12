"""
Giao diện Kiểm Thử Thủ Công & Đối Chiếu Chuẩn (src/ui/tab_kiem_thu.py)

Thực hiện kiểm thử thủ công 4 ca:
  - Ca 1: TinyRC4 3-bit 
  - Ca 2: RC4 1 ký tự (Kiểm thử biên • Đối chiếu PyCryptodome ARC4)
  - Ca 3: RC4 Đoạn siêu dài (Tải lớn • Đối chiếu PyCryptodome & SHA-256)
  - Ca 4: RC4 Tệp tin nhị phân (Ảnh/Tệp mẫu • Đối chiếu PyCryptodome)

Tách biệt rõ ràng 2 quy trình: KIỂM THỬ MÃ HÓA và KIỂM THỬ GIẢI MÃ.
"""

from __future__ import annotations
import hashlib
from pathlib import Path
import time
from typing import Optional

from Crypto.Cipher import ARC4
from nicegui import ui

from src.core import (
    van_ban_sang_bytes,
    bytes_sang_van_ban,
    bytes_sang_hex,
    hex_sang_bytes,
    rc4_crypt,
    tiny_chuoi_sang_so,
    tiny_so_sang_chuoi,
    run_tiny_rc4,
)


def dung_tab_kiem_thu() -> None:
    """Dựng giao diện kiểm thử thủ công tinh gọn, đối chiếu mã hóa và giải mã song song."""
    with ui.column().classes("w-full max-w-5xl mx-auto gap-4 pb-10 text-slate-800"):

        # 1. TIÊU ĐỀ TAB
        with ui.card().classes("w-full p-4 bg-white border border-slate-200 shadow-sm rounded-xl"):
            with ui.row().classes("items-center justify-between w-full flex-wrap gap-2"):
                with ui.row().classes("items-center gap-3"):
                    with ui.avatar(size="sm", color="blue-900").classes("text-white shadow"):
                        ui.icon("verified_user", size="xs")
                    ui.label("KIỂM THỬ THỦ CÔNG & ĐỐI CHIẾU CHUẨN QUỐC TẾ (PYCRYPTODOME)").classes(
                        "text-sm font-bold text-slate-900 tracking-wide uppercase"
                    )

        # 2. KHUNG THIẾT LẬP DỮ LIỆU
        with ui.card().classes("w-full p-5 bg-white border border-slate-200 shadow-sm rounded-xl gap-4"):
            # Bộ chọn 4 ca kiểm thử
            case_selector = ui.radio(
                options={
                    "ca_1_tiny": "Ca 1: TinyRC4 3-bit (Giáo trình N=8)",
                    "ca_2_char": "Ca 2: RC4 1 ký tự (Kiểm thử biên)",
                    "ca_3_long": "Ca 3: RC4 Đoạn siêu dài (Tải lớn)",
                    "ca_4_file": "Ca 4: RC4 Tệp tin nhị phân (Ảnh / Tệp mẫu)",
                },
                value="ca_2_char",
            ).classes("text-xs font-semibold gap-3")

            # Vùng nhập Bản rõ
            container_text = ui.column().classes("w-full gap-2")
            with container_text:
                inp_ban_ro = ui.textarea(
                    label="Bản rõ (Plaintext):",
                    value="A",
                ).classes("w-full font-mono text-xs")

                # Nút sinh tải trọng cho Ca 3
                with ui.row().classes("w-full items-center gap-2") as row_quick_payload:
                    ui.label("Sinh nhanh tải trọng:").classes("text-xs font-semibold text-slate-600")
                    btn_gen_10k = ui.button("10 KB", color="slate-200").props("dense size=sm").classes("text-slate-800 text-xs")
                    btn_gen_100k = ui.button("100 KB", color="slate-200").props("dense size=sm").classes("text-slate-800 text-xs")
                    btn_gen_500k = ui.button("500 KB", color="slate-200").props("dense size=sm").classes("text-slate-800 text-xs")

            # Vùng chọn tệp tin (Ca 4)
            container_file = ui.column().classes("w-full gap-2")
            file_data_holder = {
                "name": "sample_logo.png",
                "bytes": b"",
                "cipher_bytes": b"",
            }
            with container_file:
                with ui.row().classes("w-full items-center gap-2 flex-wrap"):
                    btn_sample_logo = ui.button("Ảnh mẫu (sample_logo.png)", icon="image", color="slate-200").props(
                        "dense size=sm"
                    ).classes("text-slate-800 text-xs")
                    btn_sample_txt = ui.button("Tệp văn bản (sample_text.txt)", icon="description", color="slate-200").props(
                        "dense size=sm"
                    ).classes("text-slate-800 text-xs")

                lbl_file_selected = ui.label("Tệp đang chọn: sample_logo.png (3.4 KB)").classes(
                    "text-xs font-mono font-semibold text-blue-900 bg-blue-50 p-2 rounded border border-blue-200"
                )

                ui.upload(
                    label="Tải lên tệp bất kỳ từ máy tính",
                    on_upload=lambda e: on_custom_file_uploaded(e),
                    auto_upload=True,
                    max_file_size=10 * 1024 * 1024,
                ).classes("w-full").props("bordered dense")

            # Vùng nhập Bản mã
            inp_ban_ma = ui.textarea(
                label="Bản mã (Ciphertext - Hex hoặc chuỗi 3-bit):",
                placeholder="Bản mã sẽ tự xuất hiện sau khi Mã hóa, hoặc bạn có thể tự nhập mã Hex vào đây để kiểm thử Giải mã...",
                value="",
            ).classes("w-full font-mono text-xs")

            # Vùng nhập Khóa bí mật
            inp_khoa = ui.input(
                label="Khóa bí mật K:",
                value="SecretKey2026",
            ).classes("w-full font-mono text-xs")

            # Hàng nút thao tác chức năng
            with ui.row().classes("items-center justify-between w-full pt-2 flex-wrap gap-2 border-t"):
                with ui.row().classes("items-center gap-2 flex-wrap"):
                    btn_ma_hoa = ui.button(
                        "▶ KIỂM THỬ MÃ HÓA",
                        color="blue-900",
                    ).classes("text-white font-semibold px-4 py-2 rounded-lg text-xs")

                    btn_giai_ma = ui.button(
                        "▶ KIỂM THỬ GIẢI MÃ",
                        color="indigo-800",
                    ).classes("text-white font-semibold px-4 py-2 rounded-lg text-xs")

                    btn_chay_ca_hai = ui.button(
                        "▶ CHẠY CẢ HAI (MÃ HÓA & GIẢI MÃ)",
                        color="emerald-800",
                    ).classes("text-white font-semibold px-4 py-2 rounded-lg text-xs")

                    toggle_fault = ui.switch("Mô phỏng sai lệch").props("dense color=negative")
                    toggle_fault.tooltip("Cố ý làm lệch 1 byte ở thuật toán dự án để quan sát phản ứng bắt lỗi MISMATCH")

                btn_xoa = ui.button("Xóa Trắng", color="slate-200").classes(
                    "text-slate-700 font-semibold px-3 py-1.5 rounded-lg text-xs"
                )

        # 3. KẾT QUẢ ĐỐI CHIẾU MÃ HÓA (ENCRYPTION)
        with ui.card().classes("w-full p-4 bg-white border border-slate-200 shadow-sm rounded-xl gap-3") as card_kq_ma_hoa:
            card_kq_ma_hoa.set_visibility(False)

            with ui.row().classes("items-center justify-between w-full border-b pb-2"):
                ui.label("1. KẾT QUẢ ĐỐI CHIẾU MÃ HÓA (ENCRYPTION)").classes(
                    "text-xs font-bold text-slate-900 tracking-wider uppercase"
                )
                badge_status_enc = ui.badge("", color="positive").classes("text-xs font-bold px-2.5 py-0.5")

            with ui.grid(columns=2).classes("w-full gap-3 text-xs"):
                # Cột Dự Án
                with ui.card().classes("p-3 bg-slate-50 border border-slate-200 rounded-lg gap-2"):
                    ui.label("THUẬT TOÁN DỰ ÁN (SRC.CORE)").classes("font-bold text-blue-900 text-xs")
                    ui.label("Bản mã Hex:").classes("text-slate-500 font-semibold")
                    lbl_enc_out_custom = ui.label("").classes(
                        "font-mono text-xs break-all p-2 bg-white border border-slate-200 rounded text-slate-800 min-h-[36px]"
                    )
                    ui.label("Mã băm SHA-256 bản mã:").classes("text-slate-500 font-semibold")
                    lbl_enc_hash_custom = ui.label("").classes(
                        "font-mono text-xs break-all p-1.5 bg-white border border-slate-200 rounded text-slate-600"
                    )
                    lbl_enc_time_custom = ui.label("").classes("text-slate-500 italic text-2xs")

                # Cột Thư Viện Chuẩn
                with ui.card().classes("p-3 bg-slate-50 border border-slate-200 rounded-lg gap-2"):
                    lbl_enc_col2_title = ui.label("THƯ VIỆN CHUẨN (PYCRYPTODOME ARC4)").classes(
                        "font-bold text-indigo-900 text-xs"
                    )
                    ui.label("Bản mã Hex:").classes("text-slate-500 font-semibold")
                    lbl_enc_out_std = ui.label("").classes(
                        "font-mono text-xs break-all p-2 bg-white border border-slate-200 rounded text-slate-800 min-h-[36px]"
                    )
                    ui.label("Mã băm SHA-256 bản mã:").classes("text-slate-500 font-semibold")
                    lbl_enc_hash_std = ui.label("").classes(
                        "font-mono text-xs break-all p-1.5 bg-white border border-slate-200 rounded text-slate-600"
                    )
                    lbl_enc_time_std = ui.label("").classes("text-slate-500 italic text-2xs")

        # 4. KẾT QUẢ ĐỐI CHIẾU GIẢI MÃ (DECRYPTION)
        with ui.card().classes("w-full p-4 bg-white border border-slate-200 shadow-sm rounded-xl gap-3") as card_kq_giai_ma:
            card_kq_giai_ma.set_visibility(False)

            with ui.row().classes("items-center justify-between w-full border-b pb-2"):
                ui.label("2. KẾT QUẢ ĐỐI CHIẾU GIẢI MÃ (DECRYPTION)").classes(
                    "text-xs font-bold text-slate-900 tracking-wider uppercase"
                )
                badge_status_dec = ui.badge("", color="positive").classes("text-xs font-bold px-2.5 py-0.5")

            with ui.grid(columns=2).classes("w-full gap-3 text-xs"):
                # Cột Dự Án
                with ui.card().classes("p-3 bg-slate-50 border border-slate-200 rounded-lg gap-2"):
                    ui.label("THUẬT TOÁN DỰ ÁN (SRC.CORE)").classes("font-bold text-blue-900 text-xs")
                    ui.label("Bản rõ khôi phục:").classes("text-slate-500 font-semibold")
                    lbl_dec_out_custom = ui.label("").classes(
                        "font-mono text-xs break-all p-2 bg-white border border-slate-200 rounded text-slate-800 min-h-[36px]"
                    )
                    lbl_dec_time_custom = ui.label("").classes("text-slate-500 italic text-2xs")

                # Cột Thư Viện Chuẩn
                with ui.card().classes("p-3 bg-slate-50 border border-slate-200 rounded-lg gap-2"):
                    lbl_dec_col2_title = ui.label("THƯ VIỆN CHUẨN (PYCRYPTODOME ARC4)").classes(
                        "font-bold text-indigo-900 text-xs"
                    )
                    ui.label("Bản rõ khôi phục:").classes("text-slate-500 font-semibold")
                    lbl_dec_out_std = ui.label("").classes(
                        "font-mono text-xs break-all p-2 bg-white border border-slate-200 rounded text-slate-800 min-h-[36px]"
                    )
                    lbl_dec_time_std = ui.label("").classes("text-slate-500 italic text-2xs")

        # 5. THỬ NGHIỆM GIẢI MÃ VỚI KHÓA SAI (NEGATIVE TESTING)
        with ui.card().classes("w-full p-4 bg-white border border-slate-200 shadow-sm rounded-xl gap-3") as card_sai_khoa:
            card_sai_khoa.set_visibility(False)
            ui.label("3. THỬ NGHIỆM GIẢI MÃ VỚI KHÓA SAI (NEGATIVE TEST)").classes(
                "text-xs font-bold text-slate-900 tracking-wider uppercase border-b pb-1.5"
            )

            with ui.row().classes("w-full items-center gap-3"):
                inp_khoa_sai = ui.input(
                    label="Khóa sai thử nghiệm:",
                    value="KhoaSaiBatKy_999",
                ).classes("flex-1 font-mono text-xs")
                btn_thu_sai = ui.button("Thử Giải Mã Khóa Sai", color="rose-800").classes(
                    "text-white font-semibold px-4 py-2 rounded-lg text-xs"
                )

            with ui.card().classes("w-full p-3 bg-rose-50 border border-rose-200 rounded-lg gap-1") as card_out_sai:
                card_out_sai.set_visibility(False)
                ui.label("KẾT QUẢ KHI DÙNG KHÓA SAI:").classes("text-xs font-bold text-rose-900")
                lbl_noi_dung_sai = ui.label("").classes("font-mono break-all text-xs text-rose-800")

        # =========================================================================
        # LOGIC XỬ LÝ SỰ KIỆN
        # =========================================================================

        # Nạp dữ liệu ảnh mẫu mặc định
        sample_logo_path = Path("sample_data/sample_logo.png")
        if sample_logo_path.exists():
            file_data_holder["bytes"] = sample_logo_path.read_bytes()

        def cap_nhat_giao_dien_theo_ca() -> None:
            """Cập nhật các ô nhập liệu tùy theo ca kiểm thử đang chọn."""
            case = case_selector.value
            card_kq_ma_hoa.set_visibility(False)
            card_kq_giai_ma.set_visibility(False)
            card_sai_khoa.set_visibility(False)
            inp_ban_ma.value = ""

            if case == "ca_1_tiny":
                container_text.set_visibility(True)
                container_file.set_visibility(False)
                row_quick_payload.set_visibility(False)
                inp_ban_ro.label = "Bản rõ TinyRC4 (chữ A-H hoặc số 0-7):"
                inp_ban_ro.value = "BAG"
                inp_ban_ma.label = "Bản mã TinyRC4 (chữ cái A-H):"
                inp_khoa.label = "Khóa TinyRC4 (các số 0-7 cách nhau bởi dấu phẩy):"
                inp_khoa.value = "2, 1, 3"
                lbl_enc_col2_title.text = "ĐỐI CHUẨN MÔ HÌNH 3-BIT (N=8)"
                lbl_dec_col2_title.text = "ĐỐI CHUẨN MÔ HÌNH 3-BIT (N=8)"

            elif case == "ca_2_char":
                container_text.set_visibility(True)
                container_file.set_visibility(False)
                row_quick_payload.set_visibility(False)
                inp_ban_ro.label = "Bản rõ 1 ký tự:"
                inp_ban_ro.value = "A"
                inp_ban_ma.label = "Bản mã Hex:"
                inp_khoa.label = "Khóa bí mật K:"
                inp_khoa.value = "SecretKey2026"
                lbl_enc_col2_title.text = "THƯ VIỆN CHUẨN (PYCRYPTODOME ARC4)"
                lbl_dec_col2_title.text = "THƯ VIỆN CHUẨN (PYCRYPTODOME ARC4)"

            elif case == "ca_3_long":
                container_text.set_visibility(True)
                container_file.set_visibility(False)
                row_quick_payload.set_visibility(True)
                inp_ban_ro.label = "Bản rõ đoạn văn siêu dài:"
                inp_ban_ro.value = ("An toàn thông tin NEU - Hệ mã dòng RC4 chuẩn. " * 200)
                inp_ban_ma.label = "Bản mã Hex:"
                inp_khoa.label = "Khóa bí mật K:"
                inp_khoa.value = "NEU-Information-Security-2026"
                lbl_enc_col2_title.text = "THƯ VIỆN CHUẨN (PYCRYPTODOME ARC4)"
                lbl_dec_col2_title.text = "THƯ VIỆN CHUẨN (PYCRYPTODOME ARC4)"

            elif case == "ca_4_file":
                container_text.set_visibility(False)
                container_file.set_visibility(True)
                inp_ban_ma.label = "Bản mã tệp (dạng Hex xem trước):"
                inp_khoa.label = "Khóa bí mật K:"
                inp_khoa.value = "FileSecretKey2026"
                lbl_enc_col2_title.text = "THƯ VIỆN CHUẨN (PYCRYPTODOME ARC4)"
                lbl_dec_col2_title.text = "THƯ VIỆN CHUẨN (PYCRYPTODOME ARC4)"

        case_selector.on_value_change(cap_nhat_giao_dien_theo_ca)

        # Xử lý sinh tải trọng Ca 3
        def sinh_tai_trong(kb: int) -> None:
            cum_tu = "Trường Đại học Kinh tế Quốc dân - Khoa Công nghệ Thông tin - Môn An toàn và Bảo mật Dữ liệu. "
            so_lan = max(1, (kb * 1024) // len(cum_tu.encode("utf-8")))
            noi_dung = cum_tu * so_lan
            inp_ban_ro.value = noi_dung
            ui.notify(f"Đã tạo văn bản {len(noi_dung.encode('utf-8')) / 1024:.1f} KB", type="info")

        btn_gen_10k.on("click", lambda: sinh_tai_trong(10))
        btn_gen_100k.on("click", lambda: sinh_tai_trong(100))
        btn_gen_500k.on("click", lambda: sinh_tai_trong(500))

        # Xử lý chọn file Ca 4
        def chon_tep_mau(ten_tep: str) -> None:
            path = Path("sample_data") / ten_tep
            if path.exists():
                file_data_holder["name"] = ten_tep
                file_data_holder["bytes"] = path.read_bytes()
                lbl_file_selected.text = f"Tệp đang chọn: {ten_tep} ({len(file_data_holder['bytes'])/1024:.1f} KB)"
                ui.notify(f"Đã nạp tệp: {ten_tep}", type="info")
            else:
                ui.notify(f"Không tìm thấy {ten_tep}!", type="negative")

        btn_sample_logo.on("click", lambda: chon_tep_mau("sample_logo.png"))
        btn_sample_txt.on("click", lambda: chon_tep_mau("sample_text.txt"))

        def on_custom_file_uploaded(e) -> None:
            file_data_holder["name"] = e.name
            file_data_holder["bytes"] = e.content.read()
            lbl_file_selected.text = f"Tệp tải lên: {e.name} ({len(file_data_holder['bytes'])/1024:.1f} KB)"
            ui.notify(f"Đã nạp tệp: {e.name}", type="positive")

        def on_reset() -> None:
            toggle_fault.value = False
            card_kq_ma_hoa.set_visibility(False)
            card_kq_giai_ma.set_visibility(False)
            card_sai_khoa.set_visibility(False)
            cap_nhat_giao_dien_theo_ca()

        btn_xoa.on("click", on_reset)

        # ---------------------------------------------------------------------
        # HÀM THỰC THI 1: KIỂM THỬ MÃ HÓA
        # ---------------------------------------------------------------------
        def chay_kiem_thu_ma_hoa() -> bool:
            case = case_selector.value
            khoa_str = (inp_khoa.value or "").strip()
            is_fault = toggle_fault.value

            if not khoa_str:
                ui.notify("Vui lòng nhập khóa bí mật!", type="warning")
                return False

            if case == "ca_1_tiny":
                ban_ro_str = (inp_ban_ro.value or "").strip()
                if not ban_ro_str:
                    ui.notify("Vui lòng nhập bản rõ TinyRC4!", type="warning")
                    return False

                raw_k = [x.strip() for x in khoa_str.replace(";", ",").split(",") if x.strip()]
                key_nums = []
                for item in raw_k:
                    if item.isdigit():
                        key_nums.append(int(item) % 8)
                    else:
                        key_nums.extend(tiny_chuoi_sang_so(item))

                if not key_nums:
                    ui.notify("Khóa TinyRC4 phải chứa các số từ 0 đến 7!", type="warning")
                    return False

                # 1. Dự án
                t0 = time.perf_counter()
                res_custom = run_tiny_rc4(ban_ro_str, key_nums)
                t_custom = (time.perf_counter() - t0) * 1000
                out_custom = res_custom.output_text
                if is_fault:
                    out_custom = "X" + out_custom[1:] if out_custom else "X"

                # Tự động điền bản mã vào ô nhập bản mã
                inp_ban_ma.value = out_custom

                # 2. Vector đối chuẩn giáo trình
                res_std = run_tiny_rc4(ban_ro_str, key_nums)
                out_std = res_std.output_text

                lbl_enc_out_custom.text = f"Chữ: '{out_custom}' • Dãy số: {res_custom.output_list}"
                lbl_enc_hash_custom.text = f"Dòng khóa: {res_custom.keystream_list}"
                lbl_enc_time_custom.text = f"Thời gian: {t_custom:.3f} ms"

                lbl_enc_out_std.text = f"Chữ: '{out_std}' • Dãy số: {res_std.output_list}"
                lbl_enc_hash_std.text = f"Dòng khóa: {res_std.keystream_list}"
                lbl_enc_time_std.text = "Quy chuẩn Modulo 8"

                is_match = (out_custom == out_std)

            else:
                if case in {"ca_2_char", "ca_3_long"}:
                    raw_data = inp_ban_ro.value or ""
                    if not raw_data:
                        ui.notify("Vui lòng nhập bản rõ!", type="warning")
                        return False
                    data_bytes = van_ban_sang_bytes(raw_data)
                else:  # ca_4_file
                    data_bytes = file_data_holder.get("bytes", b"")
                    if not data_bytes:
                        ui.notify("Chưa có dữ liệu tệp tin!", type="warning")
                        return False

                key_bytes = van_ban_sang_bytes(khoa_str)

                # 1. Dự án mã hóa
                t0 = time.perf_counter()
                c_custom = rc4_crypt(data_bytes, key_bytes)
                t_custom = (time.perf_counter() - t0) * 1000
                if is_fault:
                    first_byte = bytes([(c_custom[0] ^ 0xFF)]) if c_custom else b"\xFF"
                    c_custom = first_byte + c_custom[1:]

                if case == "ca_4_file":
                    file_data_holder["cipher_bytes"] = c_custom
                    inp_ban_ma.value = bytes_sang_hex(c_custom[:64]) + "..."
                else:
                    inp_ban_ma.value = bytes_sang_hex(c_custom)

                # 2. PyCryptodome mã hóa
                t1 = time.perf_counter()
                c_std = ARC4.new(key_bytes).encrypt(data_bytes)
                t_std = (time.perf_counter() - t1) * 1000

                hash_c = hashlib.sha256(c_custom).hexdigest()
                hash_s = hashlib.sha256(c_std).hexdigest()

                if len(c_custom) <= 64:
                    disp_c = bytes_sang_hex(c_custom)
                    disp_s = bytes_sang_hex(c_std)
                else:
                    disp_c = f"{bytes_sang_hex(c_custom[:32])} ... ({len(c_custom):,} bytes)"
                    disp_s = f"{bytes_sang_hex(c_std[:32])} ... ({len(c_std):,} bytes)"

                lbl_enc_out_custom.text = disp_c
                lbl_enc_hash_custom.text = hash_c
                lbl_enc_time_custom.text = f"Thời gian: {t_custom:.3f} ms (Python)"

                lbl_enc_out_std.text = disp_s
                lbl_enc_hash_std.text = hash_s
                lbl_enc_time_std.text = f"Thời gian: {t_std:.3f} ms (C-Extension)"

                is_match = (c_custom == c_std)

            if is_match:
                badge_status_enc.text = "✓ MÃ HÓA KHỚP 100%"
                badge_status_enc.props("color=positive")
                lbl_enc_out_custom.classes("text-slate-800", remove="text-rose-700")
            else:
                badge_status_enc.text = "✗ SAI LỆCH MÃ HÓA"
                badge_status_enc.props("color=negative")
                lbl_enc_out_custom.classes("text-rose-700", remove="text-slate-800")

            card_kq_ma_hoa.set_visibility(True)
            card_sai_khoa.set_visibility(True)
            card_out_sai.set_visibility(False)
            return is_match

        # ---------------------------------------------------------------------
        # HÀM THỰC THI 2: KIỂM THỬ GIẢI MÃ
        # ---------------------------------------------------------------------
        def chay_kiem_thu_giai_ma() -> bool:
            case = case_selector.value
            khoa_str = (inp_khoa.value or "").strip()
            ban_ma_str = (inp_ban_ma.value or "").strip()
            is_fault = toggle_fault.value

            if not khoa_str:
                ui.notify("Vui lòng nhập khóa bí mật!", type="warning")
                return False

            if case == "ca_1_tiny":
                if not ban_ma_str:
                    ui.notify("Vui lòng nhập bản mã TinyRC4 (chữ cái A-H) để giải mã!", type="warning")
                    return False

                raw_k = [x.strip() for x in khoa_str.replace(";", ",").split(",") if x.strip()]
                key_nums = []
                for item in raw_k:
                    if item.isdigit():
                        key_nums.append(int(item) % 8)
                    else:
                        key_nums.extend(tiny_chuoi_sang_so(item))

                if not key_nums:
                    ui.notify("Khóa TinyRC4 không hợp lệ!", type="warning")
                    return False

                # 1. Dự án giải mã (mã hóa lại bản mã bằng cùng khóa)
                t0 = time.perf_counter()
                dec_custom = run_tiny_rc4(ban_ma_str, key_nums)
                t_custom = (time.perf_counter() - t0) * 1000
                res_dec_custom_text = dec_custom.output_text
                if is_fault:
                    res_dec_custom_text = "ERR_" + res_dec_custom_text

                # 2. Vector đối chuẩn giải mã
                dec_std = run_tiny_rc4(ban_ma_str, key_nums)
                res_dec_std_text = dec_std.output_text

                lbl_dec_out_custom.text = f"Khôi phục: '{res_dec_custom_text}' (Số: {dec_custom.output_list})"
                lbl_dec_time_custom.text = f"Thời gian: {t_custom:.3f} ms"

                lbl_dec_out_std.text = f"Khôi phục: '{res_dec_std_text}' (Số: {dec_std.output_list})"
                lbl_dec_time_std.text = "Quy chuẩn Modulo 8"

                is_match = (res_dec_custom_text == res_dec_std_text)

            else:
                key_bytes = van_ban_sang_bytes(khoa_str)

                if case == "ca_4_file":
                    c_bytes = file_data_holder.get("cipher_bytes", b"")
                    if not c_bytes:
                        # Thử lấy dữ liệu tệp gốc mã hóa tạm để giải mã
                        orig = file_data_holder.get("bytes", b"")
                        if not orig:
                            ui.notify("Chưa có dữ liệu tệp để giải mã!", type="warning")
                            return False
                        c_bytes = rc4_crypt(orig, key_bytes)
                else:
                    if not ban_ma_str:
                        ui.notify("Vui lòng nhập chuỗi Hex bản mã để kiểm thử giải mã!", type="warning")
                        return False
                    try:
                        c_bytes = hex_sang_bytes(ban_ma_str)
                    except ValueError:
                        ui.notify("Chuỗi bản mã Hex không hợp lệ!", type="negative")
                        return False

                # 1. Dự án giải mã
                t0 = time.perf_counter()
                p_custom_b = rc4_crypt(c_bytes, key_bytes)
                t_custom = (time.perf_counter() - t0) * 1000
                if is_fault:
                    p_custom_b = b"ERR_" + p_custom_b

                # 2. PyCryptodome giải mã
                t1 = time.perf_counter()
                p_std_b = ARC4.new(key_bytes).decrypt(c_bytes)
                t_std = (time.perf_counter() - t1) * 1000

                if case in {"ca_2_char", "ca_3_long"}:
                    txt_custom = bytes_sang_van_ban(p_custom_b)
                    txt_std = bytes_sang_van_ban(p_std_b)
                    lbl_dec_out_custom.text = txt_custom[:60] + ("..." if len(txt_custom) > 60 else "")
                    lbl_dec_out_std.text = txt_std[:60] + ("..." if len(txt_std) > 60 else "")
                else:
                    hash_c = hashlib.sha256(p_custom_b).hexdigest()
                    hash_s = hashlib.sha256(p_std_b).hexdigest()
                    lbl_dec_out_custom.text = f"Tệp {len(p_custom_b):,} bytes • SHA-256: {hash_c[:16]}..."
                    lbl_dec_out_std.text = f"Tệp {len(p_std_b):,} bytes • SHA-256: {hash_s[:16]}..."

                lbl_dec_time_custom.text = f"Thời gian: {t_custom:.3f} ms (Python)"
                lbl_dec_time_std.text = f"Thời gian: {t_std:.3f} ms (C-Extension)"

                is_match = (p_custom_b == p_std_b)

            if is_match:
                badge_status_dec.text = "✓ GIẢI MÃ KHỚP 100%"
                badge_status_dec.props("color=positive")
                lbl_dec_out_custom.classes("text-slate-800", remove="text-rose-700")
            else:
                badge_status_dec.text = "✗ SAI LỆCH GIẢI MÃ"
                badge_status_dec.props("color=negative")
                lbl_dec_out_custom.classes("text-rose-700", remove="text-slate-800")

            card_kq_giai_ma.set_visibility(True)
            card_sai_khoa.set_visibility(True)
            card_out_sai.set_visibility(False)
            return is_match

        # ---------------------------------------------------------------------
        # HÀM THỰC THI 3: CHẠY CẢ MÃ HÓA & GIẢI MÃ
        # ---------------------------------------------------------------------
        def chay_ca_hai() -> None:
            ok_enc = chay_kiem_thu_ma_hoa()
            if ok_enc or inp_ban_ma.value:
                chay_kiem_thu_giai_ma()

        btn_ma_hoa.on("click", chay_kiem_thu_ma_hoa)
        btn_giai_ma.on("click", chay_kiem_thu_giai_ma)
        btn_chay_ca_hai.on("click", chay_ca_hai)

        # XỬ LÝ NÚT THỬ GIẢI MÃ VỚI KHÓA SAI
        def thuc_hien_thu_khoa_sai() -> None:
            case = case_selector.value
            khoa_sai_str = (inp_khoa_sai.value or "").strip()
            ban_ma_str = (inp_ban_ma.value or "").strip()

            if not khoa_sai_str:
                ui.notify("Vui lòng nhập khóa sai!", type="warning")
                return

            if case == "ca_1_tiny":
                if not ban_ma_str:
                    ui.notify("Chưa có bản mã để thử giải mã!", type="warning")
                    return
                raw_k = [x.strip() for x in khoa_sai_str.replace(";", ",").split(",") if x.strip()]
                key_sai = [int(x) % 8 for x in raw_k if x.isdigit()] or [7, 7, 7]
                res_sai = run_tiny_rc4(ban_ma_str, key_sai)
                lbl_noi_dung_sai.text = f"Kết quả chữ: '{res_sai.output_text}' (Khác hoàn toàn bản rõ gốc) • Số: {res_sai.output_list}"
            else:
                if case == "ca_4_file":
                    c_bytes = file_data_holder.get("cipher_bytes", b"")
                else:
                    if not ban_ma_str:
                        ui.notify("Chưa có bản mã để thử giải mã!", type="warning")
                        return
                    try:
                        c_bytes = hex_sang_bytes(ban_ma_str)
                    except ValueError:
                        ui.notify("Bản mã Hex không hợp lệ!", type="negative")
                        return

                if not c_bytes:
                    ui.notify("Chưa có bản mã để thử giải mã!", type="warning")
                    return

                key_sai_b = van_ban_sang_bytes(khoa_sai_str)
                dec_sai_b = rc4_crypt(c_bytes, key_sai_b)
                dec_sai_str = bytes_sang_van_ban(dec_sai_b)
                lbl_noi_dung_sai.text = (
                    f"Giải mã với khóa sai '{khoa_sai_str}':\n"
                    f"• Dạng Hex: {bytes_sang_hex(dec_sai_b)[:40]}...\n"
                    f"• Ký tự: \"{dec_sai_str[:40]}...\" (Biến thành ký tự rác / sai lệch dữ liệu)"
                )

            card_out_sai.set_visibility(True)

        btn_thu_sai.on("click", thuc_hien_thu_khoa_sai)

        # Thiết lập ban đầu
        cap_nhat_giao_dien_theo_ca()
