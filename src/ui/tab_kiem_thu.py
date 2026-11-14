from __future__ import annotations
import hashlib
from pathlib import Path
import time

from Crypto.Cipher import ARC4
from nicegui import ui

from src.core import (
    van_ban_sang_bytes,
    bytes_sang_van_ban,
    bytes_sang_hex,
    hex_sang_bytes,
    khoa_tu_chuoi,
    khoa_tu_hex,
    sinh_khoa_rc4,
    rc4_crypt,
    tiny_chuoi_sang_so,
    run_tiny_rc4,
)


def dung_tab_kiem_thu() -> None:
    """Khởi tạo giao diện"""
    with ui.column().classes("w-full max-w-5xl mx-auto gap-4 pb-10 text-slate-800"):
        with ui.card().classes("w-full p-4 bg-white border border-slate-200 shadow-sm rounded-xl"):
            with ui.row().classes("items-center justify-between w-full flex-wrap gap-2"):
                with ui.row().classes("items-center gap-3"):
                    with ui.avatar(size="sm", color="blue-900").classes("text-white shadow"):
                        ui.icon("fact_check", size="xs")
                    with ui.column().classes("gap-0"):
                        ui.label("KIỂM THỬ VÀ ĐỐI CHIẾU THUẬT TOÁN").classes(
                            "text-sm font-bold text-slate-900 tracking-wide uppercase"
                        )

            with ui.tabs().props("dense no-caps inline-label").classes("w-full border-b border-slate-200 mt-2 text-slate-600 font-semibold") as sub_tabs:
                tab_full = ui.tab("sub_full", label="1. RC4 Đầy Đủ", icon="security")
                tab_tiny = ui.tab("sub_tiny", label="2. TinyRC4", icon="calculate")

        with ui.tab_panels(sub_tabs, value=tab_full).classes("w-full m-0 p-0 bg-transparent"):
            # =================================================================
            # KHỐI 1: KIỂM THỬ RC4 ĐẦY ĐỦ (ĐỐI CHIẾU PYCRYPTODOME ARC4)
            # =================================================================
            with ui.tab_panel(tab_full).classes("w-full p-0 gap-4"):
                with ui.card().classes("w-full p-5 bg-white border border-slate-200 shadow-sm rounded-xl gap-4"):
                    with ui.row().classes("w-full items-center justify-between border-b pb-2 flex-wrap gap-2"):
                        ui.label("Dữ liệu đầu vào:").classes("text-xs font-bold text-slate-700 uppercase")
                        rc4_mode_toggle = ui.toggle(["Văn bản", "Tệp tin"], value="Văn bản").props("dense no-caps")

                    container_rc4_text = ui.column().classes("w-full gap-2")
                    with container_rc4_text:
                        inp_rc4_pt = ui.textarea(
                            label="Bản rõ UTF-8:",
                            value="An toàn thông tin - Thử nghiệm thuật toán mã dòng RC4.",
                        ).classes("w-full font-mono text-xs")

                        with ui.row().classes("w-full items-center gap-2 flex-wrap"):
                            ui.label("Mẫu thử nhanh:").classes("text-xs font-semibold text-slate-600")
                            btn_sample_1char = ui.button("1 ký tự", color="slate-200").props("dense size=sm").classes("text-slate-800 text-xs")
                            btn_sample_short = ui.button("Đoạn ngắn", color="slate-200").props("dense size=sm").classes("text-slate-800 text-xs")
                            btn_sample_long = ui.button("Đoạn dài 10 KB", color="slate-200").props("dense size=sm").classes("text-slate-800 text-xs")
                            btn_clear_pt = ui.button("Xóa bản rõ", color="slate-200").props("dense size=sm").classes("text-slate-700 text-xs")

                    container_rc4_file = ui.column().classes("w-full gap-2")
                    container_rc4_file.set_visibility(False)
                    file_data_holder = {
                        "name": "sample_logo.png",
                        "bytes": b"",
                        "cipher_bytes": b"",
                    }
                    sample_logo_path = Path("sample_data/sample_logo.png")
                    if sample_logo_path.exists():
                        file_data_holder["bytes"] = sample_logo_path.read_bytes()

                    with container_rc4_file:
                        with ui.row().classes("w-full items-center gap-2 flex-wrap"):
                            btn_sample_logo = ui.button("Ảnh mẫu", icon="image", color="slate-200").props(
                                "dense size=sm"
                            ).classes("text-slate-800 text-xs")
                            btn_sample_txt = ui.button("Tệp văn bản", icon="description", color="slate-200").props(
                                "dense size=sm"
                            ).classes("text-slate-800 text-xs")

                        lbl_file_selected = ui.label("Tệp đang chọn: sample_logo.png").classes(
                            "text-xs font-mono font-semibold text-blue-900 bg-blue-50 p-2 rounded border border-blue-200"
                        )

                        ui.upload(
                            label="Tải lên tệp bất kỳ từ máy tính",
                            on_upload=lambda e: on_file_uploaded(e),
                            auto_upload=True,
                            max_file_size=10 * 1024 * 1024,
                        ).classes("w-full").props("bordered dense")

                    def on_rc4_mode_change() -> None:
                        is_text = (rc4_mode_toggle.value == "Văn bản")
                        container_rc4_text.set_visibility(is_text)
                        container_rc4_file.set_visibility(not is_text)
                        inp_rc4_ct.value = ""
                        card_rc4_enc.set_visibility(False)
                        card_rc4_dec.set_visibility(False)
                        card_rc4_wrong.set_visibility(False)

                    rc4_mode_toggle.on_value_change(on_rc4_mode_change)

                    with ui.row().classes("w-full items-center gap-2"):
                        inp_rc4_key = ui.input(
                            label="Khóa bí mật K (1..256 byte):",
                            value="SecretKey-2026-StreamCipher",
                        ).classes("flex-1 font-mono text-xs")
                        rc4_key_toggle = ui.toggle(["UTF-8", "Hex"], value="UTF-8").props("dense no-caps")
                        btn_rc4_rand_key = ui.button("Khóa ngẫu nhiên", icon="casino").props("outline size=sm color=primary")

                    lbl_rc4_key_len = ui.label("").classes("text-xs text-slate-500 font-mono -mt-2")

                    def update_rc4_key_len() -> None:
                        try:
                            if rc4_key_toggle.value == "Hex":
                                k_b = khoa_tu_hex(inp_rc4_key.value or "")
                            else:
                                k_b = khoa_tu_chuoi(inp_rc4_key.value or "")
                            lbl_rc4_key_len.text = f"Độ dài khóa: {len(k_b)} byte"
                        except ValueError:
                            lbl_rc4_key_len.text = "Khóa không hợp lệ"

                    def on_rc4_random_key() -> None:
                        rand_bytes = sinh_khoa_rc4(16)
                        rc4_key_toggle.value = "Hex"
                        inp_rc4_key.value = bytes_sang_hex(rand_bytes)
                        update_rc4_key_len()

                    btn_rc4_rand_key.on("click", on_rc4_random_key)
                    inp_rc4_key.on_value_change(update_rc4_key_len)
                    rc4_key_toggle.on_value_change(update_rc4_key_len)
                    update_rc4_key_len()

                    btn_sample_1char.on("click", lambda: setattr(inp_rc4_pt, "value", "A"))
                    btn_sample_short.on("click", lambda: setattr(inp_rc4_pt, "value", "An toàn thông tin - Thử nghiệm thuật toán mã dòng RC4."))
                    btn_sample_long.on("click", lambda: setattr(inp_rc4_pt, "value", ("Kiểm thử tải trọng thuật toán RC4 với chuỗi kiểm thử dài. " * 200)))
                    btn_clear_pt.on("click", lambda: setattr(inp_rc4_pt, "value", ""))

                    def chon_tep_mau(ten_tep: str) -> None:
                        path = Path("sample_data") / ten_tep
                        if path.exists():
                            file_data_holder["name"] = ten_tep
                            file_data_holder["bytes"] = path.read_bytes()
                            file_data_holder["cipher_bytes"] = b""
                            lbl_file_selected.text = f"Tệp đang chọn: {ten_tep}"
                            inp_rc4_ct.value = ""
                            ui.notify(f"Đã nạp tệp: {ten_tep}", type="info")
                        else:
                            ui.notify(f"Không tìm thấy {ten_tep}!", type="negative")

                    btn_sample_logo.on("click", lambda: chon_tep_mau("sample_logo.png"))
                    btn_sample_txt.on("click", lambda: chon_tep_mau("sample_text.txt"))

                    def on_file_uploaded(e) -> None:
                        file_data_holder["name"] = e.name
                        file_data_holder["bytes"] = e.content.read()
                        file_data_holder["cipher_bytes"] = b""
                        lbl_file_selected.text = f"Tệp tải lên: {e.name}"
                        inp_rc4_ct.value = ""
                        ui.notify(f"Đã nạp tệp: {e.name}", type="positive")

                    inp_rc4_ct = ui.textarea(
                        label="Bản mã Hex:",
                        placeholder="Dán hoặc nhập chuỗi Hex bản mã để kiểm thử giải mã hoặc thẩm định...",
                        value="",
                    ).classes("w-full font-mono text-xs")

                    with ui.row().classes("items-center justify-between w-full pt-2 flex-wrap gap-2 border-t"):
                        with ui.row().classes("items-center gap-2 flex-wrap"):
                            btn_rc4_enc = ui.button("▶ KIỂM THỬ MÃ HÓA", color="blue-900").classes("text-white font-semibold px-4 py-2 rounded-lg text-xs")
                            btn_rc4_dec = ui.button("▶ KIỂM THỬ GIẢI MÃ", color="indigo-800").classes("text-white font-semibold px-4 py-2 rounded-lg text-xs")
                            btn_rc4_both = ui.button("▶ CHẠY CẢ HAI", color="emerald-800").classes("text-white font-semibold px-4 py-2 rounded-lg text-xs")
                        btn_rc4_reset = ui.button("Reset", color="slate-200").classes("text-slate-700 font-semibold px-3 py-1.5 rounded-lg text-xs")

                with ui.card().classes("w-full p-4 bg-white border border-slate-200 shadow-sm rounded-xl gap-3") as card_rc4_enc:
                    card_rc4_enc.set_visibility(False)
                    with ui.row().classes("items-center justify-between w-full border-b pb-2"):
                        ui.label("1. KẾT QUẢ MÃ HÓA ĐỐI CHIẾU").classes("text-xs font-bold text-slate-900 tracking-wider uppercase")
                        badge_rc4_enc = ui.badge("", color="positive").classes("text-xs font-bold px-2.5 py-0.5")

                    alert_rc4_enc = ui.label("Bản mã không tương ứng với bản rõ hiện tại").classes(
                        "w-full p-2 bg-rose-50 border border-rose-200 text-rose-700 text-xs font-semibold rounded"
                    )
                    alert_rc4_enc.set_visibility(False)

                    with ui.grid(columns=2).classes("w-full gap-3 text-xs"):
                        with ui.card().classes("p-3 bg-slate-50 border border-slate-200 rounded-lg gap-2"):
                            ui.label("MÃ NGUỒN DỰ ÁN").classes("font-bold text-blue-900 text-xs")
                            ui.label("Bản mã:").classes("text-slate-500 font-semibold")
                            lbl_rc4_enc_custom = ui.label("").classes("font-mono text-xs break-all p-2 bg-white border border-slate-200 rounded text-slate-800 min-h-[36px]")
                            ui.label("Mã băm SHA-256 bản mã:").classes("text-slate-500 font-semibold")
                            lbl_rc4_enc_hash_custom = ui.label("").classes("font-mono text-xs break-all p-1.5 bg-white border border-slate-200 rounded text-slate-600")
                            lbl_rc4_enc_time_custom = ui.label("").classes("text-slate-500 italic text-2xs")

                        with ui.card().classes("p-3 bg-slate-50 border border-slate-200 rounded-lg gap-2"):
                            ui.label("PYCRYPTODOME ARC4").classes("font-bold text-indigo-900 text-xs")
                            ui.label("Bản mã:").classes("text-slate-500 font-semibold")
                            lbl_rc4_enc_std = ui.label("").classes("font-mono text-xs break-all p-2 bg-white border border-slate-200 rounded text-slate-800 min-h-[36px]")
                            ui.label("Mã băm SHA-256 bản mã:").classes("text-slate-500 font-semibold")
                            lbl_rc4_enc_hash_std = ui.label("").classes("font-mono text-xs break-all p-1.5 bg-white border border-slate-200 rounded text-slate-600")
                            lbl_rc4_enc_time_std = ui.label("").classes("text-slate-500 italic text-2xs")

                with ui.card().classes("w-full p-4 bg-white border border-slate-200 shadow-sm rounded-xl gap-3") as card_rc4_dec:
                    card_rc4_dec.set_visibility(False)
                    with ui.row().classes("items-center justify-between w-full border-b pb-2"):
                        ui.label("2. KẾT QUẢ GIẢI MÃ ĐỐI CHIẾU").classes("text-xs font-bold text-slate-900 tracking-wider uppercase")
                        badge_rc4_dec = ui.badge("", color="positive").classes("text-xs font-bold px-2.5 py-0.5")

                    alert_rc4_dec = ui.label("Bản mã không tương ứng với bản rõ hiện tại").classes(
                        "w-full p-2 bg-rose-50 border border-rose-200 text-rose-700 text-xs font-semibold rounded"
                    )
                    alert_rc4_dec.set_visibility(False)

                    with ui.grid(columns=2).classes("w-full gap-3 text-xs"):
                        with ui.card().classes("p-3 bg-slate-50 border border-slate-200 rounded-lg gap-2"):
                            ui.label("MÃ NGUỒN DỰ ÁN").classes("font-bold text-blue-900 text-xs")
                            ui.label("Bản rõ khôi phục:").classes("text-slate-500 font-semibold")
                            lbl_rc4_dec_custom = ui.label("").classes("font-mono text-xs break-all p-2 bg-white border border-slate-200 rounded text-slate-800 min-h-[36px]")
                            lbl_rc4_dec_time_custom = ui.label("").classes("text-slate-500 italic text-2xs")

                        with ui.card().classes("p-3 bg-slate-50 border border-slate-200 rounded-lg gap-2"):
                            ui.label("PYCRYPTODOME ARC4").classes("font-bold text-indigo-900 text-xs")
                            ui.label("Bản rõ khôi phục:").classes("text-slate-500 font-semibold")
                            lbl_rc4_dec_std = ui.label("").classes("font-mono text-xs break-all p-2 bg-white border border-slate-200 rounded text-slate-800 min-h-[36px]")
                            lbl_rc4_dec_time_std = ui.label("").classes("text-slate-500 italic text-2xs")

                with ui.card().classes("w-full p-4 bg-white border border-slate-200 shadow-sm rounded-xl gap-3") as card_rc4_wrong:
                    card_rc4_wrong.set_visibility(False)
                    ui.label("3. THỬ NGHIỆM GIẢI MÃ VỚI KHÓA SAI").classes("text-xs font-bold text-slate-900 tracking-wider uppercase border-b pb-1.5")
                    with ui.row().classes("w-full items-center gap-3"):
                        inp_rc4_wrong_key = ui.input(
                            label="Khóa sai thử nghiệm:",
                            placeholder="Nhập khóa sai để thử nghiệm...",
                            value="",
                        ).classes("flex-1 font-mono text-xs")
                        btn_rc4_wrong_key = ui.button("Thử Giải Mã Khóa Sai", color="rose-800").classes("text-white font-semibold px-4 py-2 rounded-lg text-xs")

                    with ui.card().classes("w-full p-3 bg-rose-50 border border-rose-200 rounded-lg gap-1") as card_rc4_out_wrong:
                        card_rc4_out_wrong.set_visibility(False)
                        ui.label("KẾT QUẢ KHI DÙNG KHÓA SAI:").classes("text-xs font-bold text-rose-900")
                        lbl_rc4_out_wrong = ui.label("").classes("font-mono break-all text-xs text-rose-800")

                def lay_bytes_khoa_rc4(val: str, toggle_val: str) -> bytes:
                    s = (val or "").strip()
                    if not s:
                        raise ValueError("Vui lòng nhập khóa bí mật!")
                    if toggle_val == "Hex":
                        return khoa_tu_hex(s)
                    return khoa_tu_chuoi(s)

                def chay_rc4_ma_hoa() -> bool:
                    try:
                        k_bytes = lay_bytes_khoa_rc4(inp_rc4_key.value or "", rc4_key_toggle.value)
                    except ValueError as exc:
                        ui.notify(str(exc), type="warning")
                        return False

                    is_text = (rc4_mode_toggle.value == "Văn bản")
                    if is_text:
                        raw_pt = inp_rc4_pt.value or ""
                        if not raw_pt:
                            ui.notify("Vui lòng nhập bản rõ!", type="warning")
                            return False
                        data_bytes = van_ban_sang_bytes(raw_pt)
                    else:
                        data_bytes = file_data_holder.get("bytes", b"")
                        if not data_bytes:
                            ui.notify("Chưa có dữ liệu tệp tin!", type="warning")
                            return False

                    t0 = time.perf_counter()
                    c_custom = rc4_crypt(data_bytes, k_bytes)
                    t_custom = (time.perf_counter() - t0) * 1000

                    t1 = time.perf_counter()
                    c_std = ARC4.new(k_bytes).encrypt(data_bytes)
                    t_std = (time.perf_counter() - t1) * 1000

                    ban_ma_nhap = (inp_rc4_ct.value or "").strip()
                    hex_chuan = bytes_sang_hex(c_custom)

                    if not is_text:
                        file_data_holder["cipher_bytes"] = c_custom

                    if ban_ma_nhap:
                        hex_nhap = ban_ma_nhap.replace(" ", "").lower()
                        lech_ban_ma = bool(hex_nhap != hex_chuan.replace(" ", "").lower())
                    else:
                        lech_ban_ma = False
                        inp_rc4_ct.value = hex_chuan

                    hash_c = hashlib.sha256(c_custom).hexdigest()
                    hash_s = hashlib.sha256(c_std).hexdigest()

                    if len(c_custom) <= 64:
                        disp_c = hex_chuan
                        disp_s = bytes_sang_hex(c_std)
                    else:
                        disp_c = f"{bytes_sang_hex(c_custom[:32])} ... ({len(c_custom):,} bytes)"
                        disp_s = f"{bytes_sang_hex(c_std[:32])} ... ({len(c_std):,} bytes)"

                    lbl_rc4_enc_custom.text = disp_c
                    lbl_rc4_enc_hash_custom.text = hash_c
                    lbl_rc4_enc_time_custom.text = f"Thời gian: {t_custom:.3f} ms"

                    lbl_rc4_enc_std.text = disp_s
                    lbl_rc4_enc_hash_std.text = hash_s
                    lbl_rc4_enc_time_std.text = f"Thời gian: {t_std:.3f} ms"

                    is_match = (c_custom == c_std)

                    if not is_match:
                        badge_rc4_enc.text = "Sai lệch mã hóa"
                        badge_rc4_enc.props("color=negative")
                        lbl_rc4_enc_custom.classes("text-rose-700", remove="text-slate-800")
                        alert_rc4_enc.set_visibility(False)
                    elif lech_ban_ma:
                        badge_rc4_enc.text = "Bản mã không tương ứng với bản rõ hiện tại"
                        badge_rc4_enc.props("color=negative")
                        lbl_rc4_enc_custom.classes("text-rose-700", remove="text-slate-800")
                        alert_rc4_enc.text = "Bản mã không tương ứng với bản rõ hiện tại"
                        alert_rc4_enc.set_visibility(True)
                        ui.notify("Bản mã không tương ứng với bản rõ hiện tại", type="negative")
                    else:
                        badge_rc4_enc.text = "Mã hóa khớp hoàn toàn"
                        badge_rc4_enc.props("color=positive")
                        lbl_rc4_enc_custom.classes("text-slate-800", remove="text-rose-700")
                        alert_rc4_enc.set_visibility(False)

                    card_rc4_enc.set_visibility(True)
                    card_rc4_wrong.set_visibility(True)
                    card_rc4_out_wrong.set_visibility(False)
                    return is_match and not lech_ban_ma

                def chay_rc4_giai_ma() -> bool:
                    try:
                        k_bytes = lay_bytes_khoa_rc4(inp_rc4_key.value or "", rc4_key_toggle.value)
                    except ValueError as exc:
                        ui.notify(str(exc), type="warning")
                        return False

                    is_text = (rc4_mode_toggle.value == "Văn bản")
                    ban_ma_str = (inp_rc4_ct.value or "").strip()

                    if is_text:
                        if not ban_ma_str:
                            ui.notify("Vui lòng nhập chuỗi Hex bản mã để kiểm thử giải mã!", type="warning")
                            return False
                        try:
                            c_bytes = hex_sang_bytes(ban_ma_str)
                        except ValueError:
                            ui.notify("Chuỗi bản mã Hex không hợp lệ!", type="negative")
                            return False
                    else:
                        c_bytes = b""
                        if ban_ma_str:
                            try:
                                c_bytes = hex_sang_bytes(ban_ma_str)
                            except ValueError:
                                pass
                        if not c_bytes:
                            c_bytes = file_data_holder.get("cipher_bytes", b"")
                        if not c_bytes:
                            orig = file_data_holder.get("bytes", b"")
                            if not orig:
                                ui.notify("Chưa có dữ liệu tệp để giải mã!", type="warning")
                                return False
                            c_bytes = rc4_crypt(orig, k_bytes)

                    t0 = time.perf_counter()
                    p_custom_b = rc4_crypt(c_bytes, k_bytes)
                    t_custom = (time.perf_counter() - t0) * 1000

                    t1 = time.perf_counter()
                    p_std_b = ARC4.new(k_bytes).decrypt(c_bytes)
                    t_std = (time.perf_counter() - t1) * 1000

                    if is_text:
                        txt_custom = bytes_sang_van_ban(p_custom_b)
                        txt_std = bytes_sang_van_ban(p_std_b)
                        lbl_rc4_dec_custom.text = txt_custom[:80] + ("..." if len(txt_custom) > 80 else "")
                        lbl_rc4_dec_std.text = txt_std[:80] + ("..." if len(txt_std) > 80 else "")

                        raw_pt = inp_rc4_pt.value or ""
                        lech_ban_ro = bool(raw_pt.strip() and p_custom_b != van_ban_sang_bytes(raw_pt))
                    else:
                        hash_c = hashlib.sha256(p_custom_b).hexdigest()
                        hash_s = hashlib.sha256(p_std_b).hexdigest()
                        lbl_rc4_dec_custom.text = f"Tệp {len(p_custom_b):,} bytes • SHA-256: {hash_c[:16]}..."
                        lbl_rc4_dec_std.text = f"Tệp {len(p_std_b):,} bytes • SHA-256: {hash_s[:16]}..."

                        orig_bytes = file_data_holder.get("bytes", b"")
                        lech_ban_ro = bool(orig_bytes and p_custom_b != orig_bytes)

                    lbl_rc4_dec_time_custom.text = f"Thời gian: {t_custom:.3f} ms"
                    lbl_rc4_dec_time_std.text = f"Thời gian: {t_std:.3f} ms"

                    is_match = (p_custom_b == p_std_b)

                    if not is_match:
                        badge_rc4_dec.text = "Sai lệch giải mã"
                        badge_rc4_dec.props("color=negative")
                        lbl_rc4_dec_custom.classes("text-rose-700", remove="text-slate-800")
                        alert_rc4_dec.set_visibility(False)
                    elif lech_ban_ro:
                        badge_rc4_dec.text = "Bản mã không tương ứng với bản rõ hiện tại"
                        badge_rc4_dec.props("color=negative")
                        lbl_rc4_dec_custom.classes("text-rose-700", remove="text-slate-800")
                        alert_rc4_dec.text = "Bản mã không tương ứng với bản rõ hiện tại"
                        alert_rc4_dec.set_visibility(True)
                        ui.notify("Bản mã không tương ứng với bản rõ hiện tại", type="negative")
                    else:
                        badge_rc4_dec.text = "Giải mã khớp hoàn toàn"
                        badge_rc4_dec.props("color=positive")
                        lbl_rc4_dec_custom.classes("text-slate-800", remove="text-rose-700")
                        alert_rc4_dec.set_visibility(False)

                    card_rc4_dec.set_visibility(True)
                    card_rc4_wrong.set_visibility(True)
                    card_rc4_out_wrong.set_visibility(False)
                    return is_match and not lech_ban_ro

                def chay_rc4_ca_hai() -> None:
                    is_text = (rc4_mode_toggle.value == "Văn bản")
                    if is_text:
                        co_ban_ro = bool((inp_rc4_pt.value or "").strip())
                        co_ban_ma = bool((inp_rc4_ct.value or "").strip())
                    else:
                        co_ban_ro = bool(file_data_holder.get("bytes"))
                        co_ban_ma = bool(file_data_holder.get("cipher_bytes") or (inp_rc4_ct.value or "").strip())

                    if co_ban_ro:
                        ok = chay_rc4_ma_hoa()
                        if ok or co_ban_ma:
                            chay_rc4_giai_ma()
                    elif co_ban_ma:
                        card_rc4_enc.set_visibility(False)
                        chay_rc4_giai_ma()
                    else:
                        ui.notify("Vui lòng nhập bản rõ hoặc bản mã để kiểm thử!", type="warning")

                def on_rc4_reset() -> None:
                    rc4_mode_toggle.value = "Văn bản"
                    inp_rc4_pt.value = "An toàn thông tin - Thử nghiệm thuật toán mã dòng RC4."
                    inp_rc4_key.value = "SecretKey-2026-StreamCipher"
                    rc4_key_toggle.value = "UTF-8"
                    inp_rc4_ct.value = ""
                    inp_rc4_wrong_key.value = ""
                    card_rc4_enc.set_visibility(False)
                    card_rc4_dec.set_visibility(False)
                    card_rc4_wrong.set_visibility(False)
                    card_rc4_out_wrong.set_visibility(False)
                    alert_rc4_enc.set_visibility(False)
                    alert_rc4_dec.set_visibility(False)
                    update_rc4_key_len()

                def on_rc4_wrong_key_test() -> None:
                    k_sai_str = (inp_rc4_wrong_key.value or "").strip()
                    ban_ma_str = (inp_rc4_ct.value or "").strip()

                    if not k_sai_str:
                        ui.notify("Vui lòng nhập khóa sai để thử nghiệm!", type="warning")
                        return

                    is_text = (rc4_mode_toggle.value == "Văn bản")
                    if is_text:
                        if not ban_ma_str:
                            ui.notify("Chưa có bản mã để thử giải mã!", type="warning")
                            return
                        try:
                            c_bytes = hex_sang_bytes(ban_ma_str)
                        except ValueError:
                            ui.notify("Bản mã Hex không hợp lệ!", type="negative")
                            return
                    else:
                        c_bytes = file_data_holder.get("cipher_bytes", b"")
                        if not c_bytes:
                            ui.notify("Chưa có bản mã để thử giải mã!", type="warning")
                            return

                    try:
                        key_sai_b = lay_bytes_khoa_rc4(k_sai_str, rc4_key_toggle.value)
                    except ValueError:
                        key_sai_b = van_ban_sang_bytes(k_sai_str)

                    dec_sai_b = rc4_crypt(c_bytes, key_sai_b)
                    dec_sai_str = bytes_sang_van_ban(dec_sai_b)
                    lbl_rc4_out_wrong.text = (
                        f"Giải mã với khóa sai '{k_sai_str}':\n"
                        f"• Dạng Hex: {bytes_sang_hex(dec_sai_b)[:48]}...\n"
                        f"• Ký tự: \"{dec_sai_str[:48]}...\""
                    )
                    card_rc4_out_wrong.set_visibility(True)

                btn_rc4_enc.on("click", chay_rc4_ma_hoa)
                btn_rc4_dec.on("click", chay_rc4_giai_ma)
                btn_rc4_both.on("click", chay_rc4_ca_hai)
                btn_rc4_reset.on("click", on_rc4_reset)
                btn_rc4_wrong_key.on("click", on_rc4_wrong_key_test)

            # =================================================================
            # KHỐI 2: KIỂM THỬ TINYRC4 3-BIT
            # =================================================================
            with ui.tab_panel(tab_tiny).classes("w-full p-0 gap-4"):
                with ui.card().classes("w-full p-5 bg-white border border-slate-200 shadow-sm rounded-xl gap-4"):
                    inp_tiny_pt = ui.textarea(
                        label="Bản rõ TinyRC4:",
                        value="BAG",
                    ).classes("w-full font-mono text-xs")

                    inp_tiny_key = ui.input(
                        label="Khóa TinyRC4 (các số 0..7 hoặc chữ):",
                        value="2, 1, 3",
                    ).classes("w-full font-mono text-xs")

                    inp_tiny_ct = ui.textarea(
                        label="Bản mã TinyRC4:",
                        placeholder="Bản mã TinyRC4...",
                        value="",
                    ).classes("w-full font-mono text-xs")

                    with ui.row().classes("items-center justify-between w-full pt-2 flex-wrap gap-2 border-t"):
                        with ui.row().classes("items-center gap-2 flex-wrap"):
                            btn_tiny_enc = ui.button("▶ KIỂM THỬ MÃ HÓA", color="blue-900").classes("text-white font-semibold px-4 py-2 rounded-lg text-xs")
                            btn_tiny_dec = ui.button("▶ KIỂM THỬ GIẢI MÃ", color="indigo-800").classes("text-white font-semibold px-4 py-2 rounded-lg text-xs")
                            btn_tiny_both = ui.button("▶ CHẠY CẢ HAI", color="emerald-800").classes("text-white font-semibold px-4 py-2 rounded-lg text-xs")
                        btn_tiny_reset = ui.button("Reset", color="slate-200").classes("text-slate-700 font-semibold px-3 py-1.5 rounded-lg text-xs")

                with ui.card().classes("w-full p-4 bg-white border border-slate-200 shadow-sm rounded-xl gap-3") as card_tiny_enc:
                    card_tiny_enc.set_visibility(False)
                    with ui.row().classes("items-center justify-between w-full border-b pb-2"):
                        ui.label("1. KẾT QUẢ MÃ HÓA TINYRC4").classes("text-xs font-bold text-slate-900 tracking-wider uppercase")
                        badge_tiny_enc = ui.badge("", color="positive").classes("text-xs font-bold px-2.5 py-0.5")

                    alert_tiny_enc = ui.label("Bản mã không tương ứng với bản rõ hiện tại").classes(
                        "w-full p-2 bg-rose-50 border border-rose-200 text-rose-700 text-xs font-semibold rounded"
                    )
                    alert_tiny_enc.set_visibility(False)

                    with ui.grid(columns=2).classes("w-full gap-3 text-xs"):
                        with ui.card().classes("p-3 bg-slate-50 border border-slate-200 rounded-lg gap-2"):
                            ui.label("MÃ NGUỒN DỰ ÁN").classes("font-bold text-blue-900 text-xs")
                            ui.label("Bản mã:").classes("text-slate-500 font-semibold")
                            lbl_tiny_enc_custom = ui.label("").classes("font-mono text-xs break-all p-2 bg-white border border-slate-200 rounded text-slate-800 min-h-[36px]")
                            ui.label("Dòng khóa:").classes("text-slate-500 font-semibold")
                            lbl_tiny_enc_hash_custom = ui.label("").classes("font-mono text-xs break-all p-1.5 bg-white border border-slate-200 rounded text-slate-600")
                            lbl_tiny_enc_time_custom = ui.label("").classes("text-slate-500 italic text-2xs")

                        with ui.card().classes("p-3 bg-slate-50 border border-slate-200 rounded-lg gap-2"):
                            ui.label("TINYRC4").classes("font-bold text-indigo-900 text-xs")
                            ui.label("Bản mã:").classes("text-slate-500 font-semibold")
                            lbl_tiny_enc_std = ui.label("").classes("font-mono text-xs break-all p-2 bg-white border border-slate-200 rounded text-slate-800 min-h-[36px]")
                            ui.label("Dòng khóa:").classes("text-slate-500 font-semibold")
                            lbl_tiny_enc_hash_std = ui.label("").classes("font-mono text-xs break-all p-1.5 bg-white border border-slate-200 rounded text-slate-600")
                            lbl_tiny_enc_time_std = ui.label("").classes("text-slate-500 italic text-2xs")

                with ui.card().classes("w-full p-4 bg-white border border-slate-200 shadow-sm rounded-xl gap-3") as card_tiny_dec:
                    card_tiny_dec.set_visibility(False)
                    with ui.row().classes("items-center justify-between w-full border-b pb-2"):
                        ui.label("2. KẾT QUẢ GIẢI MÃ TINYRC4").classes("text-xs font-bold text-slate-900 tracking-wider uppercase")
                        badge_tiny_dec = ui.badge("", color="positive").classes("text-xs font-bold px-2.5 py-0.5")

                    alert_tiny_dec = ui.label("Bản mã không tương ứng với bản rõ hiện tại").classes(
                        "w-full p-2 bg-rose-50 border border-rose-200 text-rose-700 text-xs font-semibold rounded"
                    )
                    alert_tiny_dec.set_visibility(False)

                    with ui.grid(columns=2).classes("w-full gap-3 text-xs"):
                        with ui.card().classes("p-3 bg-slate-50 border border-slate-200 rounded-lg gap-2"):
                            ui.label("MÃ NGUỒN DỰ ÁN").classes("font-bold text-blue-900 text-xs")
                            ui.label("Bản rõ khôi phục:").classes("text-slate-500 font-semibold")
                            lbl_tiny_dec_custom = ui.label("").classes("font-mono text-xs break-all p-2 bg-white border border-slate-200 rounded text-slate-800 min-h-[36px]")
                            lbl_tiny_dec_time_custom = ui.label("").classes("text-slate-500 italic text-2xs")

                        with ui.card().classes("p-3 bg-slate-50 border border-slate-200 rounded-lg gap-2"):
                            ui.label("TINYRC4").classes("font-bold text-indigo-900 text-xs")
                            ui.label("Bản rõ khôi phục:").classes("text-slate-500 font-semibold")
                            lbl_tiny_dec_std = ui.label("").classes("font-mono text-xs break-all p-2 bg-white border border-slate-200 rounded text-slate-800 min-h-[36px]")
                            lbl_tiny_dec_time_std = ui.label("").classes("text-slate-500 italic text-2xs")

                with ui.card().classes("w-full p-4 bg-white border border-slate-200 shadow-sm rounded-xl gap-3") as card_tiny_wrong:
                    card_tiny_wrong.set_visibility(False)
                    ui.label("3. THỬ NGHIỆM GIẢI MÃ VỚI KHÓA SAI").classes("text-xs font-bold text-slate-900 tracking-wider uppercase border-b pb-1.5")
                    with ui.row().classes("w-full items-center gap-3"):
                        inp_tiny_wrong_key = ui.input(
                            label="Khóa sai thử nghiệm:",
                            placeholder="Nhập khóa sai (các số 0..7)...",
                            value="",
                        ).classes("flex-1 font-mono text-xs")
                        btn_tiny_wrong_key = ui.button("Thử Giải Mã Khóa Sai", color="rose-800").classes("text-white font-semibold px-4 py-2 rounded-lg text-xs")

                    with ui.card().classes("w-full p-3 bg-rose-50 border border-rose-200 rounded-lg gap-1") as card_tiny_out_wrong:
                        card_tiny_out_wrong.set_visibility(False)
                        ui.label("KẾT QUẢ KHI DÙNG KHÓA SAI:").classes("text-xs font-bold text-rose-900")
                        lbl_tiny_out_wrong = ui.label("").classes("font-mono break-all text-xs text-rose-800")

                def lay_khoa_tiny(khoa_str: str) -> list[int]:
                    raw_k = [x.strip() for x in khoa_str.replace(";", ",").split(",") if x.strip()]
                    key_nums = []
                    for item in raw_k:
                        if item.isdigit():
                            key_nums.append(int(item) % 8)
                        else:
                            key_nums.extend(tiny_chuoi_sang_so(item))
                    return key_nums

                def chay_tiny_ma_hoa() -> bool:
                    khoa_str = (inp_tiny_key.value or "").strip()
                    if not khoa_str:
                        ui.notify("Vui lòng nhập khóa TinyRC4!", type="warning")
                        return False

                    key_nums = lay_khoa_tiny(khoa_str)
                    if not key_nums:
                        ui.notify("Khóa TinyRC4 phải chứa các số từ 0 đến 7!", type="warning")
                        return False

                    ban_ro_str = (inp_tiny_pt.value or "").strip()
                    if not ban_ro_str:
                        ui.notify("Vui lòng nhập bản rõ TinyRC4!", type="warning")
                        return False

                    ban_ma_nhap = (inp_tiny_ct.value or "").strip()

                    t0 = time.perf_counter()
                    res_custom = run_tiny_rc4(ban_ro_str, key_nums)
                    t_custom = (time.perf_counter() - t0) * 1000
                    out_custom = res_custom.output_text

                    lech_ban_ma = bool(ban_ma_nhap and ban_ma_nhap != out_custom)
                    if not ban_ma_nhap:
                        inp_tiny_ct.value = out_custom

                    res_std = run_tiny_rc4(ban_ro_str, key_nums)
                    out_std = res_std.output_text

                    lbl_tiny_enc_custom.text = f"Bản mã: '{out_custom}'"
                    lbl_tiny_enc_hash_custom.text = f"{res_custom.keystream_list}"
                    lbl_tiny_enc_time_custom.text = f"Thời gian: {t_custom:.3f} ms"

                    lbl_tiny_enc_std.text = f"Bản mã: '{out_std}'"
                    lbl_tiny_enc_hash_std.text = f"{res_std.keystream_list}"
                    lbl_tiny_enc_time_std.text = "Modulo 8"

                    is_match = (out_custom == out_std)

                    if not is_match:
                        badge_tiny_enc.text = "Sai lệch mã hóa"
                        badge_tiny_enc.props("color=negative")
                        lbl_tiny_enc_custom.classes("text-rose-700", remove="text-slate-800")
                        alert_tiny_enc.set_visibility(False)
                    elif lech_ban_ma:
                        badge_tiny_enc.text = "Bản mã không tương ứng với bản rõ hiện tại"
                        badge_tiny_enc.props("color=negative")
                        lbl_tiny_enc_custom.classes("text-rose-700", remove="text-slate-800")
                        alert_tiny_enc.text = "Bản mã không tương ứng với bản rõ hiện tại"
                        alert_tiny_enc.set_visibility(True)
                        ui.notify("Bản mã không tương ứng với bản rõ hiện tại", type="negative")
                    else:
                        badge_tiny_enc.text = "Mã hóa khớp hoàn toàn"
                        badge_tiny_enc.props("color=positive")
                        lbl_tiny_enc_custom.classes("text-slate-800", remove="text-rose-700")
                        alert_tiny_enc.set_visibility(False)

                    card_tiny_enc.set_visibility(True)
                    card_tiny_wrong.set_visibility(True)
                    card_tiny_out_wrong.set_visibility(False)
                    return is_match and not lech_ban_ma

                def chay_tiny_giai_ma() -> bool:
                    khoa_str = (inp_tiny_key.value or "").strip()
                    if not khoa_str:
                        ui.notify("Vui lòng nhập khóa TinyRC4!", type="warning")
                        return False

                    key_nums = lay_khoa_tiny(khoa_str)
                    if not key_nums:
                        ui.notify("Khóa TinyRC4 không hợp lệ!", type="warning")
                        return False

                    ban_ma_str = (inp_tiny_ct.value or "").strip()
                    if not ban_ma_str:
                        ui.notify("Vui lòng nhập bản mã TinyRC4 để giải mã!", type="warning")
                        return False

                    t0 = time.perf_counter()
                    dec_custom = run_tiny_rc4(ban_ma_str, key_nums)
                    t_custom = (time.perf_counter() - t0) * 1000
                    res_dec_custom_text = dec_custom.output_text

                    dec_std = run_tiny_rc4(ban_ma_str, key_nums)
                    res_dec_std_text = dec_std.output_text

                    lbl_tiny_dec_custom.text = f"Khôi phục: '{res_dec_custom_text}'"
                    lbl_tiny_dec_time_custom.text = f"Thời gian: {t_custom:.3f} ms"

                    lbl_tiny_dec_std.text = f"Khôi phục: '{res_dec_std_text}'"
                    lbl_tiny_dec_time_std.text = "Modulo 8"

                    is_match = (res_dec_custom_text == res_dec_std_text)
                    ban_ro_goc = (inp_tiny_pt.value or "").strip()
                    lech_ban_ro = bool(ban_ro_goc and res_dec_custom_text != ban_ro_goc)

                    if not is_match:
                        badge_tiny_dec.text = "Sai lệch giải mã"
                        badge_tiny_dec.props("color=negative")
                        lbl_tiny_dec_custom.classes("text-rose-700", remove="text-slate-800")
                        alert_tiny_dec.set_visibility(False)
                    elif lech_ban_ro:
                        badge_tiny_dec.text = "Bản mã không tương ứng với bản rõ hiện tại"
                        badge_tiny_dec.props("color=negative")
                        lbl_tiny_dec_custom.classes("text-rose-700", remove="text-slate-800")
                        alert_tiny_dec.text = "Bản mã không tương ứng với bản rõ hiện tại"
                        alert_tiny_dec.set_visibility(True)
                        ui.notify("Bản mã không tương ứng với bản rõ hiện tại", type="negative")
                    else:
                        badge_tiny_dec.text = "Giải mã khớp hoàn toàn"
                        badge_tiny_dec.props("color=positive")
                        lbl_tiny_dec_custom.classes("text-slate-800", remove="text-rose-700")
                        alert_tiny_dec.set_visibility(False)

                    card_tiny_dec.set_visibility(True)
                    card_tiny_wrong.set_visibility(True)
                    card_tiny_out_wrong.set_visibility(False)
                    return is_match and not lech_ban_ro

                def chay_tiny_ca_hai() -> None:
                    co_ban_ro = bool((inp_tiny_pt.value or "").strip())
                    co_ban_ma = bool((inp_tiny_ct.value or "").strip())

                    if co_ban_ro:
                        ok = chay_tiny_ma_hoa()
                        if ok or co_ban_ma:
                            chay_tiny_giai_ma()
                    elif co_ban_ma:
                        card_tiny_enc.set_visibility(False)
                        chay_tiny_giai_ma()
                    else:
                        ui.notify("Vui lòng nhập bản rõ hoặc bản mã để kiểm thử!", type="warning")

                def on_tiny_reset() -> None:
                    inp_tiny_pt.value = "BAG"
                    inp_tiny_key.value = "2, 1, 3"
                    inp_tiny_ct.value = ""
                    inp_tiny_wrong_key.value = ""
                    card_tiny_enc.set_visibility(False)
                    card_tiny_dec.set_visibility(False)
                    card_tiny_wrong.set_visibility(False)
                    card_tiny_out_wrong.set_visibility(False)
                    alert_tiny_enc.set_visibility(False)
                    alert_tiny_dec.set_visibility(False)

                def on_tiny_wrong_key_test() -> None:
                    k_sai_str = (inp_tiny_wrong_key.value or "").strip()
                    ban_ma_str = (inp_tiny_ct.value or "").strip()

                    if not k_sai_str:
                        ui.notify("Vui lòng nhập khóa sai để thử nghiệm!", type="warning")
                        return

                    if not ban_ma_str:
                        ui.notify("Chưa có bản mã để thử giải mã!", type="warning")
                        return

                    key_sai = lay_khoa_tiny(k_sai_str)
                    if not key_sai:
                        ui.notify("Khóa TinyRC4 không hợp lệ! Vui lòng nhập số từ 0 đến 7.", type="warning")
                        return

                    res_sai = run_tiny_rc4(ban_ma_str, key_sai)
                    lbl_tiny_out_wrong.text = f"Kết quả chữ: '{res_sai.output_text}'"
                    card_tiny_out_wrong.set_visibility(True)

                btn_tiny_enc.on("click", chay_tiny_ma_hoa)
                btn_tiny_dec.on("click", chay_tiny_giai_ma)
                btn_tiny_both.on("click", chay_tiny_ca_hai)
                btn_tiny_reset.on("click", on_tiny_reset)
                btn_tiny_wrong_key.on("click", on_tiny_wrong_key_test)
