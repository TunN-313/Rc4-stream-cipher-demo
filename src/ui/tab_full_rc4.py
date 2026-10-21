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
    """Xây dựng giao diện Tab 2: RC4 256-byte & File/Ảnh thật."""
    with ui.row().classes("w-full gap-6 items-start"):

        # ======================================================================
        # CỘT TRÁI: MÃ HÓA & GIẢI MÃ VĂN BẢN
        # ======================================================================
        with ui.card().classes("flex-1 p-5 border-t-4 border-sky-600 shadow-sm"):
            ui.label("1. Mã hóa & Giải mã Văn bản (RC4 256-byte chuẩn)").classes(
                "text-lg font-bold text-slate-800"
            )
            full_pt = ui.textarea(
                label="Bản rõ (Plaintext UTF-8)",
                value="An toàn và Bảo mật Thông tin - Hệ mã dòng RC4 (Mảng S 256 byte)",
            ).classes("w-full")
            full_key = ui.input(
                label="Khóa bí mật K (1..256 byte)",
                value="NEU-CNTT-SecretKey-2026",
            ).classes("w-full")

            full_hex_out = ui.textarea(label="Bản mã (Hexadecimal)").classes("w-full font-mono text-xs")
            full_b64_out = ui.input(label="Bản mã (Base64)").classes("w-full font-mono text-xs")
            full_dec_out = ui.input(label="Kết quả Giải mã ngược lại (Khôi phục bản rõ)").classes(
                "w-full font-bold text-emerald-800"
            )
            full_meta_label = ui.label("").classes("text-xs text-slate-600 font-mono")

            # Khu vực xem ma trận trạng thái S (16x16)
            with ui.expansion("Xem trạng thái Ma trận hoán vị S (256 byte — Lưới 16x16)", icon="grid_view").classes(
                "w-full bg-slate-50 border rounded mt-2"
            ):
                sbox_grid_label = ui.label("").classes("font-mono text-xs p-2 whitespace-pre leading-relaxed")

            def run_full_text_demo() -> None:
                try:
                    pt_bytes = full_pt.value.encode("utf-8")
                    k_bytes = full_key.value.encode("utf-8")
                    enc_res = rc4_crypt_with_details(pt_bytes, k_bytes)
                    dec_bytes = rc4_crypt(enc_res.output_bytes, k_bytes)

                    full_hex_out.value = enc_res.output_hex
                    full_b64_out.value = enc_res.output_base64
                    full_dec_out.value = dec_bytes.decode("utf-8", errors="replace")
                    full_meta_label.text = (
                        f"Kích thước: {len(pt_bytes)} bytes | Thời gian: {enc_res.elapsed_ms:.3f} ms | "
                        f"8 byte dòng khóa đầu: {enc_res.keystream_preview[:8]}"
                    )

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
        # CỘT PHẢI: MÃ HÓA & GIẢI MÃ DỮ LIỆU THẬT (FILE / ẢNH)
        # ======================================================================
        with ui.card().classes("flex-1 p-5 border-t-4 border-teal-600 shadow-sm"):
            ui.label("2. Demo trên Dữ liệu thật (Tệp Văn bản & Tệp Ảnh nhỏ)").classes(
                "text-lg font-bold text-slate-800"
            )
            ui.label(
                "Đáp ứng yêu cầu đề bài: Mã hóa một tệp văn bản hoặc tệp ảnh rồi giải mã lại đúng 100% tệp gốc."
            ).classes("text-xs text-slate-600 mb-2")

            file_key_input = ui.input(
                label="Khóa mã hóa File/Ảnh",
                value="RC4-File-Encryption-Key-2026",
            ).classes("w-full mb-2")

            file_state: Dict[str, Union[bytes, str]] = {
                "name": "sample_logo.png",
                "raw": _get_default_sample_bytes(),
                "encrypted": b"",
                "decrypted": b"",
            }

            file_status = ui.label("").classes("text-sm font-mono text-slate-700 my-2")
            preview_box = ui.row().classes("w-full gap-4 items-center")

            def process_current_file() -> None:
                raw_bytes = file_state["raw"]
                assert isinstance(raw_bytes, bytes)
                k_bytes = file_key_input.value.encode("utf-8")
                enc_res = rc4_crypt_with_details(raw_bytes, k_bytes)
                dec_res = rc4_crypt_with_details(enc_res.output_bytes, k_bytes)
                file_state["encrypted"] = enc_res.output_bytes
                file_state["decrypted"] = dec_res.output_bytes

                integrity_ok = dec_res.output_bytes == raw_bytes
                file_status.text = (
                    f"Tệp: {file_state['name']} ({len(raw_bytes):,} bytes) | "
                    f"Mã hóa: {enc_res.elapsed_ms:.2f} ms | "
                    f"Toàn vẹn dữ liệu: {'✓ 100% KHỚP' if integrity_ok else '✗ LỖI'}"
                )

                preview_box.clear()
                with preview_box:
                    if str(file_state["name"]).lower().endswith((".png", ".jpg", ".jpeg", ".gif")):
                        b64_orig = base64.b64encode(raw_bytes).decode("ascii")
                        b64_dec = base64.b64encode(dec_res.output_bytes).decode("ascii")
                        with ui.column().classes("items-center"):
                            ui.label("Ảnh gốc ban đầu").classes("text-xs font-bold")
                            ui.image(f"data:image/png;base64,{b64_orig}").classes("w-44 border rounded shadow-sm")
                        with ui.column().classes("items-center"):
                            ui.label("Dữ liệu Bản mã (.rc4)").classes("text-xs font-bold text-amber-800")
                            ui.label(enc_res.output_hex[:96] + "...").classes(
                                "w-44 h-24 p-2 bg-slate-900 text-amber-300 font-mono text-[10px] break-all rounded"
                            )
                        with ui.column().classes("items-center"):
                            ui.label("Ảnh sau Giải mã RC4").classes("text-xs font-bold text-emerald-700")
                            ui.image(f"data:image/png;base64,{b64_dec}").classes("w-44 border rounded shadow-sm")
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
                label="Tải tệp thật (.txt, .png, .jpg) lên để Mã hóa & Giải mã",
                on_upload=handle_upload,
                auto_upload=True,
            ).classes("w-full mb-3")

            with ui.row().classes("gap-3 flex-wrap"):
                ui.button("Nạp Ảnh mẫu Logo", icon="image", on_click=lambda: load_sample_file("logo")).props(
                    "color=secondary outline"
                )
                ui.button("Nạp Text mẫu Tiếng Việt", icon="description", on_click=lambda: load_sample_file("txt")).props(
                    "color=secondary outline"
                )
                ui.button(
                    "Tải xuống Bản mã (.rc4)",
                    icon="download",
                    on_click=lambda: ui.download(
                        file_state["encrypted"],  # type: ignore
                        f"{file_state['name']}.rc4",
                    ),
                ).props("color=primary")
                ui.button(
                    "Tải xuống Tệp đã Giải mã",
                    icon="verified_user",
                    on_click=lambda: ui.download(
                        file_state["decrypted"],  # type: ignore
                        f"decrypted_{file_state['name']}",
                    ),
                ).props("color=positive")

            process_current_file()
