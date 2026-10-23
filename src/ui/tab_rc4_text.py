"""
Phân Hệ RC4 Văn Bản (UTF-8 & Mảng S 256 byte) — src/ui/tab_rc4_text.py
======================================================================
Mã hóa & giải mã chuỗi văn bản UTF-8 bằng hệ mã RC4 256-byte chuẩn.
Hiển thị bản mã Hex, Base64, kết quả giải mã và ma trận trạng thái S (16x16).
"""

from __future__ import annotations
from nicegui import ui

from src.core.rc4 import rc4_crypt, rc4_crypt_with_details


def build_tab_rc4_text() -> None:
    """Xây dựng giao diện Phân hệ RC4 Văn Bản (Mảng S 256 byte)."""
    with ui.card().classes("w-full p-6 space-y-4"):
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
