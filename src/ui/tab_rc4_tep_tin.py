"""Tab 3: Xử lý tệp tin và hình ảnh với RC4 theo 3 bước."""

from __future__ import annotations
import asyncio
import base64
import hashlib
import inspect
import io
import math
from pathlib import Path
import time
from typing import Any, Dict, Optional, Tuple

from nicegui import ui
from PIL import Image

from src.core import (
    khoa_tu_chuoi,
    khoa_tu_hex,
    sinh_khoa_rc4,
    bytes_sang_hex,
    rc4_crypt_chunks,
)

# Giới hạn 8MB để tránh tràn bộ nhớ trình duyệt khi render ảnh preview và Base64 trên frontend
MAX_BYTES: int = 8 * 1024 * 1024
IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp"}
# PNG 1x1 pixel dự phòng khi không có tệp mẫu trên đĩa
FALLBACK_1X1_PNG = (
    b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
    b"\x08\x06\x00\x00\x00\x1f\x15c4\x00\x00\x00\rIDATx\x9cc`\x00\x00\x00"
    b"\x02\x00\x01H\xaf\xa4q\x00\x00\x00\x00IEND\xaeB`\x82"
)


def get_image_mime(data: bytes) -> str:
    """Xác định MIME type qua magic bytes mở đầu của tệp nhị phân."""
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if data.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if data.startswith(b"GIF87a") or data.startswith(b"GIF89a"):
        return "image/gif"
    if len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "image/webp"
    return "application/octet-stream"


def validate_image(data: bytes) -> Tuple[bool, str]:
    """Kiểm tra cấu trúc tệp ảnh hợp lệ qua Pillow để ngăn nạp dữ liệu hỏng vào thẻ <img>."""
    if not data:
        return False, ""
    try:
        with Image.open(io.BytesIO(data)) as img:
            img.load()
            mime = get_image_mime(data)
            if mime == "application/octet-stream":
                fmt = (img.format or "").lower()
                fmt_map = {
                    "png": "image/png",
                    "jpeg": "image/jpeg",
                    "jpg": "image/jpeg",
                    "gif": "image/gif",
                    "webp": "image/webp",
                }
                mime = fmt_map.get(fmt, "image/png")
            return True, mime
    except Exception:
        return False, get_image_mime(data)


def create_noise_image_b64(data: bytes) -> str:
    """Trích xuất tối đa 128KB dữ liệu để tạo ảnh mức xám thể hiện độ ngẫu nhiên của bản mã."""
    if not data:
        return ""
    # Giới hạn 128KB để giữ tốc độ dựng ảnh tức thì mà vẫn đủ diện tích hiển thị tính phân tán ngẫu nhiên
    sample = data[:131072]
    n = len(sample)
    if n < 16:
        sample = sample.ljust(16, b"\x00")
        n = 16
    width = max(16, int(math.isqrt(n)))
    height = max(1, n // width)
    pixel_data = sample[: width * height]
    try:
        img = Image.frombytes("L", (width, height), pixel_data)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        return base64.b64encode(buf.getvalue()).decode("ascii")
    except Exception:
        return ""


def get_default_sample_bytes() -> bytes:
    """Nạp tệp ảnh mẫu logo từ đĩa hoặc trả về ảnh PNG dự phòng."""
    sample_path = Path("sample_data") / "sample_logo.png"
    if sample_path.exists():
        try:
            return sample_path.read_bytes()
        except Exception:
            pass
    return FALLBACK_1X1_PNG


def get_default_text_bytes() -> bytes:
    """Nạp tệp văn bản mẫu từ đĩa hoặc trả về chuỗi UTF-8 mặc định."""
    txt_path = Path("sample_data") / "sample_text.txt"
    if txt_path.exists():
        try:
            return txt_path.read_bytes()
        except Exception:
            pass
    return "Hệ mã dòng RC4 - An toàn và Bảo mật Thông tin".encode("utf-8")


def dung_tab_rc4_tep_tin() -> None:
    """Khởi tạo giao diện xử lý tệp 3 bước: Nạp, mã hóa, giải mã."""
    # State quản lý vòng đời tệp tin giữa 3 bước độc lập trong pipeline
    file_state: Dict[str, Any] = {
        "name": "sample_logo.png",
        "original": None,
        "encrypted": None,
        "decrypted": None,
        "is_enc_loaded": False,
    }

    # Mutex cờ tránh re-entrancy khi đang chạy tác vụ mã hóa/giải mã async
    is_busy: bool = False

    with ui.column().classes("w-full space-y-4"):
        with ui.card().classes("w-full p-4 border border-slate-200/80 shadow-sm"):
            with ui.row().classes("w-full items-center justify-between pb-1 flex-wrap gap-3"):
                with ui.row().classes("items-center gap-3"):
                    with ui.row().classes(
                        "w-10 h-10 rounded-xl bg-teal-50 text-teal-700 items-center justify-center border border-teal-200 shadow-sm"
                    ):
                        ui.icon("folder_zip", size="sm")
                    with ui.column().classes("gap-0"):
                        ui.label("Quy Trình Xử Lý Tệp").classes("text-base font-bold text-slate-800")
                        ui.label("Luồng 3 bước: Nạp → Mã hóa từng phần → Giải mã & Đối chiếu toàn vẹn").classes(
                            "text-xs text-slate-500"
                        )
                with ui.row().classes("items-center gap-3"):
                    slow_switch = ui.switch("Trình diễn chậm", value=True).props("dense").classes("text-xs")

        with ui.element("div").classes("grid grid-cols-1 xl:grid-cols-3 gap-4 w-full items-start"):
            # -----------------------------------------------------------------
            # Bước 1: Nạp tệp dữ liệu
            # -----------------------------------------------------------------
            with ui.card().classes("w-full p-5 rounded-xl border border-slate-200/80 shadow-sm space-y-3"):
                with ui.row().classes("w-full items-center gap-2"):
                    ui.badge("1", color="primary").classes("rounded-full w-6 h-6 text-xs flex items-center justify-center")
                    ui.label("Bước 1 – Nạp tệp").classes("text-sm font-bold text-slate-800")

                ui_upload_element = ui.upload(
                    label="Kéo thả hoặc bấm để nạp tệp (tối đa 8 MB)",
                    auto_upload=True,
                    max_file_size=MAX_BYTES,
                ).props("flat bordered").classes("w-full")

                with ui.row().classes("w-full items-center justify-between flex-wrap gap-2"):
                    with ui.row().classes("items-center gap-2"):
                        btn_sample_img = ui.button("Ảnh mẫu", icon="image").props("outline size=sm color=primary")
                        btn_sample_txt = ui.button("Văn bản mẫu", icon="description").props("outline size=sm color=secondary")
                    ui.label("Hỗ trợ: .png, .jpg, .txt, .enc (chỉ có bản mã)...").classes("text-xs text-slate-400")

                step1_info_box = ui.column().classes("w-full gap-2")

            # -----------------------------------------------------------------
            # Bước 2: Mã hóa RC4 streaming
            # -----------------------------------------------------------------
            with ui.card().classes("w-full p-5 rounded-xl border border-slate-200/80 shadow-sm space-y-3"):
                with ui.row().classes("w-full items-center justify-between flex-wrap gap-1"):
                    with ui.row().classes("items-center gap-2"):
                        ui.badge("2", color="primary").classes("rounded-full w-6 h-6 text-xs flex items-center justify-center")
                        ui.label("Bước 2 – Mã hóa").classes("text-sm font-bold text-slate-800")
                    enc_status_label = ui.label("").classes("text-xs font-mono text-slate-600")

                with ui.row().classes("w-full items-center gap-2"):
                    enc_key_input = ui.input(
                        label="Khóa mã hóa (UTF-8, 1–256 byte)",
                        value="RC4-File-Encryption-Key-2026",
                    ).classes("flex-1")
                    key_mode_toggle = ui.toggle(["UTF-8", "Hex"], value="UTF-8").props("dense no-caps")
                    btn_rand_key = ui.button("Khóa ngẫu nhiên", icon="casino").props("outline size=sm color=primary")

                enc_key_len_label = ui.label("").classes("text-xs text-slate-500 font-mono -mt-2")

                with ui.row().classes("w-full items-center gap-3"):
                    btn_encrypt = ui.button("Mã hóa", icon="lock").props("color=primary size=sm")

                enc_progress = ui.linear_progress(value=0.0, show_value=False).props("instant-feedback stripe rounded").classes("w-full h-2")
                step2_result_box = ui.column().classes("w-full gap-2")

                with ui.row().classes("w-full items-center justify-end gap-2 pt-2 border-t border-slate-200/60"):
                    btn_download_rc4 = ui.button("Tải bản mã (.enc)", icon="download").props("color=primary size=sm")

            # -----------------------------------------------------------------
            # Bước 3: Giải mã & đối chiếu toàn vẹn
            # -----------------------------------------------------------------
            with ui.card().classes("w-full p-5 rounded-xl border border-slate-200/80 shadow-sm space-y-3"):
                with ui.row().classes("w-full items-center justify-between flex-wrap gap-1"):
                    with ui.row().classes("items-center gap-2"):
                        ui.badge("3", color="positive").classes("rounded-full w-6 h-6 text-xs flex items-center justify-center")
                        ui.label("Bước 3 – Giải mã và kiểm tra").classes("text-sm font-bold text-slate-800")
                    dec_status_label = ui.label("").classes("text-xs font-mono text-slate-600")

                with ui.row().classes("w-full items-center gap-2"):
                    dec_key_input = ui.input(
                        label="Khóa giải mã",
                        value="RC4-File-Encryption-Key-2026",
                    ).classes("flex-1")
                    btn_fill_wrong_key = ui.button("Điền khóa sai", icon="shuffle").props("outline size=sm color=amber-9")

                dec_key_len_label = ui.label("").classes("text-xs text-slate-500 font-mono -mt-2")

                with ui.row().classes("w-full items-center gap-3"):
                    btn_decrypt = ui.button("Giải mã", icon="lock_open").props("color=positive size=sm")

                dec_progress = ui.linear_progress(value=0.0, show_value=False).props(
                    "instant-feedback stripe rounded color=positive"
                ).classes("w-full h-2")

                step3_result_box = ui.column().classes("w-full gap-2")

                with ui.row().classes("w-full items-center justify-end gap-2 pt-2 border-t border-slate-200/60"):
                    btn_download_dec = ui.button("Tải tệp giải mã", icon="verified").props("color=positive size=sm")

        def update_enc_key_len() -> None:
            try:
                if key_mode_toggle.value == "Hex":
                    k_b = khoa_tu_hex(enc_key_input.value or "")
                else:
                    k_b = khoa_tu_chuoi(enc_key_input.value or "")
                enc_key_len_label.text = f"Độ dài khóa: {len(k_b)} byte"
            except ValueError:
                enc_key_len_label.text = "Khóa không hợp lệ"

        def update_dec_key_len() -> None:
            try:
                if key_mode_toggle.value == "Hex":
                    k_b = khoa_tu_hex(dec_key_input.value or "")
                else:
                    k_b = khoa_tu_chuoi(dec_key_input.value or "")
                dec_key_len_label.text = f"Độ dài khóa: {len(k_b)} byte"
            except ValueError:
                dec_key_len_label.text = "Khóa không hợp lệ"

        def on_random_key() -> None:
            rand_bytes = sinh_khoa_rc4(16)
            rand_hex = bytes_sang_hex(rand_bytes)
            key_mode_toggle.value = "Hex"
            enc_key_input.value = rand_hex
            dec_key_input.value = rand_hex
            update_enc_key_len()
            update_dec_key_len()

        btn_rand_key.on_click(on_random_key)
        enc_key_input.on_value_change(update_enc_key_len)
        enc_key_input.on("input", update_enc_key_len)
        dec_key_input.on_value_change(update_dec_key_len)
        dec_key_input.on("input", update_dec_key_len)
        key_mode_toggle.on_value_change(lambda: (update_enc_key_len(), update_dec_key_len()))
        update_enc_key_len()
        update_dec_key_len()

        def clear_step3() -> None:
            dec_progress.value = 0.0
            dec_status_label.text = ""
            step3_result_box.clear()
            file_state["decrypted"] = None

        def clear_step2_and_step3() -> None:
            enc_progress.value = 0.0
            enc_status_label.text = ""
            step2_result_box.clear()
            clear_step3()

        def render_step1_preview() -> None:
            step1_info_box.clear()
            filename = file_state["name"]
            is_enc = file_state.get("is_enc_loaded", False) or file_state.get("is_rc4_loaded", False)
            data = file_state["encrypted"] if is_enc else file_state["original"]

            if data is None:
                return

            data_len = len(data)
            sha16 = hashlib.sha256(data).hexdigest()[:16]

            with step1_info_box:
                with ui.row().classes(
                    "w-full items-center justify-between p-2.5 bg-white rounded-lg border border-slate-200 text-xs font-mono flex-wrap gap-2"
                ):
                    with ui.row().classes("items-center gap-2 flex-wrap"):
                        ui.icon("insert_drive_file", size="xs").classes("text-slate-600")
                        ui.label(f"{filename}").classes("font-bold text-slate-800 break-all")
                        ui.label(f"({data_len:,} bytes)").classes("text-slate-500")
                    with ui.row().classes("items-center gap-2 flex-wrap"):
                        ui.label(f"SHA-256: {sha16}...").classes("text-slate-600")
                        if is_enc:
                            ui.badge("chỉ có bản mã", color="warning").classes("text-xs")
                        else:
                            ui.badge("Bản gốc", color="primary").classes("text-xs")

                if is_enc:
                    with ui.column().classes("w-full p-3 rounded-lg border border-amber-200 bg-amber-50/50"):
                        ui.label("Tệp nạp vào là bản mã (.enc). Chuyển sang Bước 3 để giải mã.").classes(
                            "text-xs text-amber-800 font-semibold"
                        )
                else:
                    is_img, mime = validate_image(data)
                    if is_img:
                        b64_img = base64.b64encode(data).decode("ascii")
                        with ui.column().classes("w-full items-center p-2 rounded-lg border border-slate-200 bg-white"):
                            ui.label("Bản xem trước ảnh gốc:").classes("text-xs font-bold text-slate-600 mb-1 self-start")
                            ui.image(f"data:{mime};base64,{b64_img}").classes(
                                "w-full h-64 object-contain bg-slate-50 rounded border"
                            )
                    else:
                        txt_preview = data[:2000].decode("utf-8", errors="replace")
                        ui.textarea(label="Bản xem trước văn bản (trích đoạn)", value=txt_preview).props("readonly").classes(
                            "w-full font-mono text-xs"
                        )

        def render_step2_preview() -> None:
            step2_result_box.clear()
            ciphertext = file_state.get("encrypted")
            if not ciphertext:
                return

            original = file_state.get("original")
            c_len = len(ciphertext)
            c_sha = hashlib.sha256(ciphertext).hexdigest()
            c_hex48 = ciphertext[:48].hex().upper()
            noise_b64 = create_noise_image_b64(ciphertext)

            diff_str = ""
            if original is not None and len(original) > 0:
                diff_count = sum(1 for a, b in zip(original, ciphertext) if a != b)
                diff_pct = (diff_count / len(original)) * 100.0
                diff_str = f"{diff_pct:.2f}% byte khác bản gốc"

            with step2_result_box:
                with ui.column().classes("w-full items-center p-2 rounded-lg border border-slate-200 bg-white"):
                    ui.label("Ảnh nhiễu bản mã (128 KB)").classes("text-[11px] font-semibold text-slate-600 mb-1 self-start")
                    if noise_b64:
                        ui.image(f"data:image/png;base64,{noise_b64}").style("image-rendering: pixelated;").classes(
                            "w-full h-64 object-contain bg-slate-900 rounded border border-slate-700"
                        )
                    else:
                        ui.label("Không tạo được ảnh nhiễu").classes("text-xs text-slate-500 py-10")

                with ui.column().classes("w-full gap-2 p-2.5 rounded-lg border border-slate-200 bg-white"):
                    with ui.row().classes("w-full items-center justify-between"):
                        ui.label("48 byte Hex đầu:").classes("text-xs font-bold text-slate-700")
                        if diff_str:
                            ui.badge(diff_str, color="secondary").classes("text-xs")
                    ui.label(c_hex48).classes(
                        "w-full p-2 bg-slate-900 text-amber-300 font-mono text-[11px] rounded break-all select-all"
                    )
                    ui.label(f"SHA-256 bản mã: {c_sha}").classes("font-mono text-xs text-slate-600 break-all")

        def render_step3_preview() -> None:
            step3_result_box.clear()
            decrypted = file_state.get("decrypted")
            if decrypted is None:
                return

            original = file_state.get("original")
            filename = file_state["name"]
            is_image_name = any(filename.lower().endswith(ext) for ext in IMAGE_EXTENSIONS)
            is_valid_img, mime = validate_image(decrypted)

            with step3_result_box:
                with ui.row().classes("w-full items-center gap-2"):
                    if original is not None:
                        orig_sha = hashlib.sha256(original).hexdigest()
                        dec_sha = hashlib.sha256(decrypted).hexdigest()
                        if orig_sha == dec_sha:
                            ui.badge("Khớp bản gốc (SHA-256 trùng)", color="positive").classes(
                                "text-xs font-bold px-3 py-1.5"
                            )
                        else:
                            ui.badge("Không khớp bản gốc (có thể sai khóa)", color="negative").classes(
                                "text-xs font-bold px-3 py-1.5"
                            )
                    else:
                        ui.badge("Không có bản gốc để đối chiếu", color="warning").classes(
                            "text-xs font-bold px-3 py-1.5"
                        )

                if is_valid_img:
                    b64_img = base64.b64encode(decrypted).decode("ascii")
                    with ui.column().classes("w-full items-center p-2 rounded-lg border border-emerald-200 bg-emerald-50/30"):
                        ui.label("Ảnh sau khi giải mã:").classes("text-xs font-bold text-emerald-800 mb-1 self-start")
                        ui.image(f"data:{mime};base64,{b64_img}").classes(
                            "w-full h-64 object-contain bg-slate-50 rounded border"
                        )
                elif is_image_name:
                    noise_b64 = create_noise_image_b64(decrypted)
                    with ui.column().classes("w-full p-3 rounded-lg border border-rose-300 bg-rose-50/50 items-center gap-2"):
                        ui.label("Dữ liệu không tạo được ảnh hợp lệ").classes(
                            "text-rose-700 font-bold text-xs"
                        )
                        if noise_b64:
                            ui.image(f"data:image/png;base64,{noise_b64}").style("image-rendering: pixelated;").classes(
                                "w-full h-64 object-contain bg-slate-900 rounded border border-rose-200"
                            )
                else:
                    txt_dec = decrypted[:5000].decode("utf-8", errors="replace")
                    ui.textarea(label="Nội dung giải mã (trích đoạn)", value=txt_dec).props("readonly").classes(
                        "w-full font-mono text-xs"
                    )

        async def process_loaded_content(name: str, content: bytes) -> None:
            if len(content) > MAX_BYTES:
                ui.notify(f"Kích thước tệp quá lớn ({len(content):,} bytes > 8 MB)!", type="warning")
                return

            if len(content) == 0:
                ui.notify("Cảnh báo: Tệp tải lên rỗng (0 bytes)!", type="warning")
                return

            clear_step2_and_step3()

            is_enc = name.lower().endswith(".enc") or name.lower().endswith(".rc4")
            if is_enc:
                file_state["name"] = name[:-4] if (name.lower().endswith(".enc") or name.lower().endswith(".rc4")) else name
                file_state["original"] = None
                file_state["encrypted"] = content
                file_state["is_enc_loaded"] = True
                render_step1_preview()
                render_step2_preview()
                ui.notify(f"Đã nạp tệp bản mã: {name} ({len(content):,} bytes)", type="info")
            else:
                file_state["name"] = name
                file_state["original"] = content
                file_state["encrypted"] = None
                file_state["is_enc_loaded"] = False
                render_step1_preview()
                ui.notify(f"Đã nạp tệp: {name} ({len(content):,} bytes)", type="positive")

        async def handle_upload(e: Any) -> None:
            try:
                name = "uploaded_file"
                if hasattr(e, "name") and e.name:
                    name = str(e.name)
                elif hasattr(e, "file") and hasattr(e.file, "name") and e.file.name:
                    name = str(e.file.name)
                elif hasattr(e, "file") and hasattr(e.file, "filename") and e.file.filename:
                    name = str(e.file.filename)

                content_raw = None
                if hasattr(e, "content"):
                    if hasattr(e.content, "read"):
                        res = e.content.read()
                        content_raw = await res if inspect.isawaitable(res) else res
                    elif isinstance(e.content, (bytes, bytearray)):
                        content_raw = bytes(e.content)

                if content_raw is None and hasattr(e, "file"):
                    if hasattr(e.file, "read"):
                        res = e.file.read()
                        content_raw = await res if inspect.isawaitable(res) else res
                    elif isinstance(e.file, (bytes, bytearray)):
                        content_raw = bytes(e.file)

                if content_raw is None:
                    raise ValueError("Không thể đọc nội dung tệp tải lên.")

                if isinstance(content_raw, str):
                    content_raw = content_raw.encode("utf-8")

                await process_loaded_content(name, bytes(content_raw))
            except Exception as exc:
                ui.notify(f"Lỗi khi nạp tệp: {exc}", type="negative")

        async def load_sample_file(kind: str) -> None:
            if kind == "logo":
                await process_loaded_content("sample_logo.png", get_default_sample_bytes())
            else:
                await process_loaded_content("sample_text.txt", get_default_text_bytes())

        btn_sample_img.on_click(lambda: load_sample_file("logo"))
        btn_sample_txt.on_click(lambda: load_sample_file("txt"))
        ui_upload_element.on_upload(handle_upload)

        # ---------------------------------------------------------------------
        # Thực thi mã hóa streaming
        # ---------------------------------------------------------------------
        async def run_encryption() -> None:
            nonlocal is_busy
            if is_busy:
                return

            original = file_state.get("original")
            if original is None:
                if file_state.get("is_enc_loaded") or file_state.get("is_rc4_loaded"):
                    ui.notify("Tệp hiện tại chỉ có bản mã (.enc). Vui lòng chuyển sang Bước 3 để giải mã.", type="info")
                else:
                    ui.notify("Chưa có dữ liệu bản gốc để mã hóa. Vui lòng nạp tệp ở Bước 1.", type="warning")
                return

            try:
                if key_mode_toggle.value == "Hex":
                    key_bytes = khoa_tu_hex(enc_key_input.value or "")
                else:
                    key_bytes = khoa_tu_chuoi(enc_key_input.value or "")
            except ValueError as e:
                ui.notify(str(e), type="negative")
                return

            is_busy = True
            btn_encrypt.disable()
            btn_decrypt.disable()
            clear_step3()

            total = len(original)
            # Tự động chia khoảng ~50 chunk để progress bar chuyển động mượt, cận biên [256B, 64KB] để tối ưu I/O
            chunk_size = max(256, min(65536, (total // 50) or 256))
            enc_progress.value = 0.0

            chunks: list[bytes] = []
            processed = 0
            cpu_time = 0.0

            try:
                it = iter(rc4_crypt_chunks(original, key_bytes, chunk_size=chunk_size))
                while True:
                    t0 = time.perf_counter()
                    try:
                        chunk = next(it)
                    except StopIteration:
                        break
                    cpu_time += time.perf_counter() - t0
                    chunks.append(chunk)
                    processed += len(chunk)
                    enc_progress.value = processed / total if total > 0 else 1.0

                    # Nhường quyền điều khiển event loop để NiceGUI/Vue cập nhật UI và tránh treo tab trình duyệt
                    if slow_switch.value:
                        await asyncio.sleep(0.03)
                    else:
                        await asyncio.sleep(0)

                ciphertext = b"".join(chunks)
                file_state["encrypted"] = ciphertext

                cpu_ms = cpu_time * 1000.0
                mb_s = ((total / (1024 * 1024)) / cpu_time) if cpu_time > 1e-6 else 0.0
                enc_status_label.text = f"Mã hóa xong: {total:,} byte • CPU {cpu_ms:.2f} ms • {mb_s:.2f} MB/s"

                render_step2_preview()
                ui.notify(f"Mã hóa thành công ({total:,} bytes)!", type="positive")

            except Exception as exc:
                ui.notify(f"Lỗi mã hóa: {exc}", type="negative")
            finally:
                is_busy = False
                btn_encrypt.enable()
                btn_decrypt.enable()

        btn_encrypt.on_click(run_encryption)

        # ---------------------------------------------------------------------
        # Thực thi giải mã & kiểm định
        # ---------------------------------------------------------------------
        def fill_wrong_key() -> None:
            """Điền sai lệch 1 ký tự vào khóa giải mã để kiểm chứng cơ chế phát hiện lỗi."""
            if key_mode_toggle.value == "Hex":
                dec_key_input.value = (dec_key_input.value or "") + "00"
                ui.notify("Đã điền khóa sai (thêm '00')", type="warning")
            else:
                dec_key_input.value = (dec_key_input.value or "") + "x"
                ui.notify("Đã điền khóa sai (thêm 'x')", type="warning")
            update_dec_key_len()

        btn_fill_wrong_key.on_click(fill_wrong_key)

        async def run_decryption() -> None:
            nonlocal is_busy
            if is_busy:
                return

            ciphertext = file_state.get("encrypted")
            if ciphertext is None:
                ui.notify("Chưa có bản mã để giải mã. Hãy mã hóa ở Bước 2 hoặc nạp tệp .enc ở Bước 1.", type="warning")
                return

            try:
                if key_mode_toggle.value == "Hex":
                    key_bytes = khoa_tu_hex(dec_key_input.value or "")
                else:
                    key_bytes = khoa_tu_chuoi(dec_key_input.value or "")
            except ValueError as e:
                ui.notify(str(e), type="negative")
                return

            is_busy = True
            btn_encrypt.disable()
            btn_decrypt.disable()

            total = len(ciphertext)
            chunk_size = max(256, min(65536, (total // 50) or 256))
            dec_progress.value = 0.0

            chunks: list[bytes] = []
            processed = 0
            cpu_time = 0.0

            try:
                it = iter(rc4_crypt_chunks(ciphertext, key_bytes, chunk_size=chunk_size))
                while True:
                    t0 = time.perf_counter()
                    try:
                        chunk = next(it)
                    except StopIteration:
                        break
                    cpu_time += time.perf_counter() - t0
                    chunks.append(chunk)
                    processed += len(chunk)
                    dec_progress.value = processed / total if total > 0 else 1.0

                    if slow_switch.value:
                        await asyncio.sleep(0.03)
                    else:
                        await asyncio.sleep(0)

                decrypted = b"".join(chunks)
                file_state["decrypted"] = decrypted

                cpu_ms = cpu_time * 1000.0
                mb_s = ((total / (1024 * 1024)) / cpu_time) if cpu_time > 1e-6 else 0.0
                dec_status_label.text = f"Giải mã xong: {total:,} byte • CPU {cpu_ms:.2f} ms • {mb_s:.2f} MB/s"

                render_step3_preview()
                ui.notify("Giải mã hoàn tất!", type="info")

            except Exception as exc:
                ui.notify(f"Lỗi giải mã: {exc}", type="negative")
            finally:
                is_busy = False
                btn_encrypt.enable()
                btn_decrypt.enable()

        btn_decrypt.on_click(run_decryption)

        def download_ciphertext() -> None:
            c = file_state.get("encrypted")
            if not c:
                ui.notify("Chưa có dữ liệu bản mã để tải về.", type="warning")
                return
            download_name = f"{file_state['name']}.enc"
            ui.download(c, download_name)

        def download_decrypted() -> None:
            d = file_state.get("decrypted")
            if not d:
                ui.notify("Chưa có dữ liệu tệp giải mã để tải về.", type="warning")
                return
            download_name = f"decrypted_{file_state['name']}"
            ui.download(d, download_name)

        btn_download_rc4.on_click(download_ciphertext)
        btn_download_dec.on_click(download_decrypted)

        init_sample = get_default_sample_bytes()
        file_state["name"] = "sample_logo.png"
        file_state["original"] = init_sample
        file_state["encrypted"] = None
        file_state["decrypted"] = None
        file_state["is_rc4_loaded"] = False
        render_step1_preview()
