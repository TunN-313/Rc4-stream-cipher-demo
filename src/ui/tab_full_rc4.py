"""
Tab 2: Thực Thi RC4 Chuẩn (256-byte, Văn Bản UTF-8 & File/Ảnh Thật)
===================================================================
Hỗ trợ mã hóa/giải mã toàn vẹn tệp văn bản và ảnh nhị phân (.png, .jpg).
Tự động đối chiếu tính toàn vẹn 100% giữa dữ liệu gốc và dữ liệu sau giải mã.
"""

from __future__ import annotations
import base64
from pathlib import Path
from typing import Dict, Union

from nicegui import events, ui

from src.core.rc4 import rc4_crypt, rc4_crypt_with_details


def _get_default_sample_bytes() -> bytes:
    """Lấy dữ liệu ảnh mẫu từ thư mục sample_data hoặc fallback."""
    sample_path = Path("sample_data") / "sample_logo.png"
    if sample_path.exists():
        return sample_path.read_bytes()
    # Fallback 1x1 png hợp lệ
    return base64.b64decode(
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="
    )


def build_tab_full_rc4() -> None:
    """Xây dựng giao diện Tab 2: RC4 256-byte & File/Ảnh thật theo chuẩn Flat Cards Dashboard."""
    with ui.row().classes("w-full gap-6 items-start"):

        # ======================================================================
        # CỘT TRÁI: MÃ HÓA & GIẢI MÃ VĂN BẢN (FLAT CARD 1)
        # ======================================================================
        with ui.card().classes("flex-1 p-6 space-y-4"):
            with ui.row().classes("w-full items-center justify-between pb-2 border-b border-slate-100"):
                with ui.row().classes("items-center gap-3"):
                    with ui.row().classes("w-9 h-9 rounded-lg bg-sky-50 text-sky-700 items-center justify-center border border-sky-200"):
                        ui.icon("article", size="xs")
                    with ui.column().classes("gap-0"):
                        ui.label("1. Mã Hóa & Giải Mã Văn Bản (UTF-8)").classes("text-base font-bold text-slate-800")
                        ui.label("RC4 256-byte chuẩn • Modulo 256 • Xử lý chuỗi ký tự Unicode").classes("text-xs text-slate-500")
                ui.badge("Mảng S 256 bytes", color="primary").classes("text-xs")

            full_pt = ui.textarea(
                label="Bản rõ (Plaintext UTF-8)",
                value="An toàn và Bảo mật Thông tin - Hệ mã dòng RC4 (Mảng S 256 byte)",
            ).classes("w-full")

            full_key = ui.input(
                label="Khóa bí mật K (1..256 byte)",
                value="NEU-CNTT-SecretKey-2026",
            ).classes("w-full")

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
                try:
                    pt_bytes = full_pt.value.encode("utf-8")
                    k_bytes = full_key.value.encode("utf-8")
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

            ui.button("Mã hóa & Kiểm tra Giải mã", icon="lock", on_click=run_full_text_demo).props(
                "color=primary"
            )
            run_full_text_demo()

        # ======================================================================
        # CỘT PHẢI: MÃ HÓA & GIẢI MÃ DỮ LIỆU THẬT (FILE / ẢNH) (FLAT CARD 2)
        # ======================================================================
        with ui.card().classes("flex-1 p-6 space-y-4"):
            with ui.row().classes("w-full items-center justify-between pb-2 border-b border-slate-100"):
                with ui.row().classes("items-center gap-3"):
                    with ui.row().classes("w-9 h-9 rounded-lg bg-teal-50 text-teal-700 items-center justify-center border border-teal-200"):
                        ui.icon("folder_zip", size="xs")
                    with ui.column().classes("gap-0"):
                        ui.label("2. Demo Dữ Liệu Thật (File Văn Bản & Ảnh Nhị Phân)").classes("text-base font-bold text-slate-800")
                        ui.label("Mã hóa tệp bất kỳ rồi giải mã lại đúng 100% tệp gốc • Kiểm tra toàn vẹn").classes("text-xs text-slate-500")
                ui.badge("Tệp & Ảnh thật", color="accent").classes("text-xs")

            file_key_input = ui.input(
                label="Khóa mã hóa File/Ảnh",
                value="RC4-File-Encryption-Key-2026",
            ).classes("w-full")

            file_state: Dict[str, Union[bytes, str]] = {
                "name": "sample_logo.png",
                "raw": _get_default_sample_bytes(),
                "encrypted": b"",
                "decrypted": b"",
            }

            # Thanh trạng thái toàn vẹn dữ liệu
            file_status_box = ui.row().classes("w-full items-center justify-between p-2.5 bg-slate-50 rounded-lg border border-slate-200/60 text-xs font-mono")
            preview_box = ui.row().classes("w-full gap-3 items-center justify-between")

            def process_current_file() -> None:
                raw_bytes = file_state["raw"]
                assert isinstance(raw_bytes, bytes)
                k_bytes = file_key_input.value.encode("utf-8")
                enc_res = rc4_crypt_with_details(raw_bytes, k_bytes)
                dec_res = rc4_crypt_with_details(enc_res.output_bytes, k_bytes)
                file_state["encrypted"] = enc_res.output_bytes
                file_state["decrypted"] = dec_res.output_bytes

                integrity_ok = dec_res.output_bytes == raw_bytes

                file_status_box.clear()
                with file_status_box:
                    with ui.row().classes("items-center gap-2"):
                        ui.icon("check_circle" if integrity_ok else "cancel", size="xs").classes(
                            "text-emerald-600" if integrity_ok else "text-rose-600"
                        )
                        ui.label(f"{file_state['name']} ({len(raw_bytes):,} bytes • {enc_res.elapsed_ms:.2f} ms)").classes("text-slate-700")
                    ui.badge("✓ 100% KHỚP TỆP GỐC" if integrity_ok else "✗ LỖI TOÀN VẸN", color="positive" if integrity_ok else "negative").classes("text-xs")

                preview_box.clear()
                with preview_box:
                    if str(file_state["name"]).lower().endswith((".png", ".jpg", ".jpeg", ".gif")):
                        b64_orig = base64.b64encode(raw_bytes).decode("ascii")
                        b64_dec = base64.b64encode(dec_res.output_bytes).decode("ascii")
                        with ui.column().classes("flex-1 items-center p-2 rounded-lg border border-slate-200 bg-slate-50/50"):
                            ui.label("Ảnh gốc ban đầu").classes("text-xs font-bold text-slate-700 mb-1")
                            ui.image(f"data:image/png;base64,{b64_orig}").classes("w-full h-32 object-contain rounded")
                        with ui.column().classes("flex-1 items-center p-2 rounded-lg border border-slate-200 bg-slate-900 text-amber-300"):
                            ui.label("Bản mã (.rc4)").classes("text-xs font-bold text-amber-400 mb-1")
                            ui.label(enc_res.output_hex[:96] + "...").classes("w-full h-32 p-1 font-mono text-[10px] break-all overflow-hidden")
                        with ui.column().classes("flex-1 items-center p-2 rounded-lg border border-slate-200 bg-emerald-50/40"):
                            ui.label("Ảnh sau giải mã").classes("text-xs font-bold text-emerald-800 mb-1")
                            ui.image(f"data:image/png;base64,{b64_dec}").classes("w-full h-32 object-contain rounded")
                    else:
                        txt_orig = raw_bytes[:200].decode("utf-8", errors="replace")
                        txt_dec = dec_res.output_bytes[:200].decode("utf-8", errors="replace")
                        ui.textarea("Nội dung tệp gốc (trích đoạn)", value=txt_orig).classes("flex-1")
                        ui.textarea("Nội dung sau giải mã", value=txt_dec).classes("flex-1")

            def handle_upload(e: events.UploadEventArguments) -> None:
                content = e.content.read()
                file_state["name"] = e.name
                file_state["raw"] = content
                process_current_file()
                ui.notify(f"Đã tải lên và mã hóa tệp {e.name} ({len(content):,} bytes)", type="positive")

            def load_sample_file(choice: str) -> None:
                if choice == "logo":
                    file_state["name"] = "sample_logo.png"
                    file_state["raw"] = _get_default_sample_bytes()
                else:
                    txt_path = Path("sample_data") / "sample_text.txt"
                    file_state["name"] = "sample_text.txt"
                    file_state["raw"] = txt_path.read_bytes() if txt_path.exists() else b"Sample text"
                process_current_file()
                ui.notify(f"Đã nạp file mẫu: {file_state['name']}", type="info")

            ui.upload(
                label="Kéo thả hoặc chọn tệp (.txt, .png, .jpg) để mã hóa",
                on_upload=handle_upload,
                auto_upload=True,
            ).props("flat bordered").classes("w-full")

            with ui.row().classes("w-full gap-2 items-center justify-between flex-wrap"):
                with ui.row().classes("gap-2"):
                    ui.button("Ảnh mẫu Logo NEU", icon="image", on_click=lambda: load_sample_file("logo")).props(
                        "color=primary outline size=sm"
                    )
                    ui.button("Text mẫu Tiếng Việt", icon="description", on_click=lambda: load_sample_file("txt")).props(
                        "color=secondary outline size=sm"
                    )
                with ui.row().classes("gap-2"):
                    ui.button(
                        "Tải Bản mã (.rc4)",
                        icon="download",
                        on_click=lambda: ui.download(
                            file_state["encrypted"],  # type: ignore
                            f"{file_state['name']}.rc4",
                        ),
                    ).props("color=primary size=sm")
                    ui.button(
                        "Tải Tệp Giải mã",
                        icon="verified",
                        on_click=lambda: ui.download(
                            file_state["decrypted"],  # type: ignore
                            f"decrypted_{file_state['name']}",
                        ),
                    ).props("color=positive size=sm")

            process_current_file()
