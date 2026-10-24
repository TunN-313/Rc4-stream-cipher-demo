"""Quy trình xử lý tệp tin và hình ảnh với hệ mã dòng RC4 (src/ui/file_pipeline.py).

File này được gọi bởi tab_rc4_file hoặc layout.py để dựng tab 'Ảnh & Tệp'.
File gọi đến module src/core/rc4.py (hàm rc4_crypt_chunks) để mã hóa/giải mã theo khối,
gọi src/core/keys.py để sinh và kiểm tra khóa, và dùng thư viện PIL để thẩm định ảnh.
Chia quy trình thành 3 bước độc lập: Nạp tệp -> Mã hóa Streaming -> Giải mã & Đối chiếu.
"""

from __future__ import annotations  # dùng để hỗ trợ chú thích kiểu dữ liệu kiểu mới của Python
import asyncio  # dùng để chạy tác vụ bất đồng bộ và tạo khoảng nghỉ cập nhật giao diện
import base64  # dùng để mã hóa dữ liệu nhị phân sang chuỗi Base64 nhúng vào thẻ ảnh HTML
import hashlib  # dùng để tính mã băm SHA-256 (dấu vân tay duy nhất của dữ liệu)
import inspect  # dùng để kiểm tra tính chất của đối tượng (ví dụ: hàm coroutine bất đồng bộ)
import io  # dùng để tạo luồng dữ liệu byte trong bộ nhớ (BytesIO)
import math  # dùng để tính toán kích thước ảnh lưới vuông (isqrt)
from pathlib import Path  # dùng để đọc tệp tin mẫu từ hệ thống tệp
import time  # dùng để đo thời gian thực thi mã hóa chính xác (perf_counter)
from typing import Any, Dict, Optional, Tuple  # dùng để khai báo gợi ý kiểu dữ liệu

from nicegui import ui  # dùng để xây dựng các thành phần giao diện web bằng Python
from PIL import Image  # dùng để đọc, kiểm định định dạng ảnh và tạo ảnh nhiễu nhị phân

from src.core.keys import khoa_tu_chuoi, khoa_tu_hex, sinh_khoa_rc4  # file nội bộ: sinh và phân tích khóa
from src.core.encoding import bytes_sang_hex  # file nội bộ: chuyển đổi mảng byte sang chuỗi Hex
from src.core.rc4 import rc4_crypt_chunks  # file nội bộ: generator mã hóa RC4 theo từng khối nhỏ

MAX_BYTES: int = 8 * 1024 * 1024  # Giới hạn kích thước tệp tối đa cho phép tải lên là 8 MiB
IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp"}  # Tập các đuôi tệp ảnh
FALLBACK_1X1_PNG = (  # Ảnh mẫu PNG 1x1 pixel dự phòng khi không tìm thấy tệp ảnh trên đĩa
    b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
    b"\x08\x06\x00\x00\x00\x1f\x15c4\x00\x00\x00\rIDATx\x9cc`\x00\x00\x00"
    b"\x02\x00\x01H\xaf\xa4q\x00\x00\x00\x00IEND\xaeB`\x82"
)


def get_image_mime(data: bytes) -> str:
    """Xác định kiểu MIME (định dạng ảnh) dựa trên các byte mở đầu (magic bytes).

    Tham số:
        data: Dữ liệu nhị phân của tệp cần kiểm tra định dạng.
    Giá trị trả về:
        Chuỗi MIME type chuẩn (ví dụ: 'image/png', 'image/jpeg', hoặc 'application/octet-stream').
    Ví dụ:
        get_image_mime(b"\\x89PNG\\r\\n\\x1a\\n...") -> "image/png"
    """
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
    """Kiểm tra tệp tin có phải là ảnh hợp lệ hay không bằng thư viện PIL (Image.open + load).

    PIL.Image: thư viện chuyên xử lý và đọc thông tin cấu trúc, kích thước, định dạng tệp ảnh.

    Tham số:
        data: Dữ liệu nhị phân cần thẩm định tính hợp lệ.
    Giá trị trả về:
        Bộ (is_valid, mime_type) gồm cờ True/False và chuỗi MIME type tương ứng.
    Ví dụ:
        validate_image(sample_png_bytes) -> (True, "image/png")
    """
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
    """Tạo ảnh nhiễu mức xám (grayscale) từ dữ liệu byte và chuyển thành chuỗi Base64.

    Tham số:
        data: Mảng byte bản mã hoặc dữ liệu bất kỳ cần trực quan hóa thành ảnh nhiễu.
    Giá trị trả về:
        Chuỗi ảnh PNG mã hóa Base64 dùng để nhúng trực tiếp vào thẻ img giao diện web.
    Ví dụ:
        create_noise_image_b64(b"...") -> "iVBORw0KGgoAAAANSUhEUgAA..."
    """
    if not data:
        return ""
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
    """Đọc tệp ảnh mẫu logo từ thư mục sample_data hoặc trả về ảnh PNG 1x1 thay thế.

    Tham số: Không có.
    Giá trị trả về:
        Mảng bytes chứa nội dung tệp ảnh mẫu.
    Ví dụ:
        len(get_default_sample_bytes()) > 0
    """
    sample_path = Path("sample_data") / "sample_logo.png"
    if sample_path.exists():
        try:
            return sample_path.read_bytes()
        except Exception:
            pass
    return FALLBACK_1X1_PNG


def get_default_text_bytes() -> bytes:
    """Đọc tệp văn bản mẫu từ thư mục sample_data hoặc trả về chuỗi UTF-8 mặc định.

    Tham số: Không có.
    Giá trị trả về:
        Mảng bytes chứa văn bản tiếng Việt mẫu.
    Ví dụ:
        get_default_text_bytes().startswith(b"H\\xe1\\xbb\\x87")
    """
    txt_path = Path("sample_data") / "sample_text.txt"
    if txt_path.exists():
        try:
            return txt_path.read_bytes()
        except Exception:
            pass
    return "Hệ mã dòng RC4 - An toàn và Bảo mật Thông tin".encode("utf-8")


def build_file_pipeline() -> None:
    """Xây dựng giao diện Quy trình Xử lý Tệp (File Pipeline) 3 bước tách rời.

    Tham số: Không có.
    Giá trị trả về: Không có (dựng các thành phần trực tiếp lên giao diện NiceGUI).
    Ví dụ: build_file_pipeline()
    """
    # Biến trạng thái state: lưu trữ toàn bộ dữ liệu tạm thời của phiên làm việc gồm:
    # tên tệp (name), byte bản rõ gốc (original), byte bản mã (encrypted), byte sau giải mã (decrypted),
    # và cờ is_rc4_loaded (xác định tệp nạp vào là bản mã .rc4 có sẵn hay tệp gốc).
    file_state: Dict[str, Any] = {
        "name": "sample_logo.png",
        "original": None,
        "encrypted": None,
        "decrypted": None,
        "is_rc4_loaded": False,
    }

    # Cờ busy: cờ kiểm soát ngăn người dùng bấm thao tác khi tiến trình đang xử lý
    is_busy: bool = False

    # các lớp Tailwind CSS chỉnh màu, khoảng cách, cỡ chữ
    with ui.column().classes("w-full space-y-4"):
        # Header trên cùng (tên quy trình, badge, switch "Trình diễn chậm")
        with ui.card().classes("w-full p-4 border border-slate-200/80 shadow-sm"):
            with ui.row().classes("w-full items-center justify-between pb-1 flex-wrap gap-3"):
                with ui.row().classes("items-center gap-3"):
                    with ui.row().classes(
                        "w-10 h-10 rounded-xl bg-teal-50 text-teal-700 items-center justify-center border border-teal-200 shadow-sm"
                    ):
                        ui.icon("folder_zip", size="sm")
                    with ui.column().classes("gap-0"):
                        ui.label("2. Quy Trình Xử Lý Tệp (File Pipeline)").classes("text-base font-bold text-slate-800")
                        ui.label("Luồng 3 bước: Nạp → Mã hóa Streaming → Giải mã & Đối chiếu toàn vẹn").classes(
                            "text-xs text-slate-500"
                        )
                with ui.row().classes("items-center gap-3"):
                    slow_switch = ui.switch("Trình diễn chậm", value=True).props("dense").classes("text-xs")
                    ui.badge("RC4 Chunked • 3 Bước Tách Rời", color="accent").classes("text-xs font-semibold px-2 py-1")

        # Div grid chứa 3 ui.card, mỗi card một bước độc lập
        with ui.element("div").classes("grid grid-cols-1 xl:grid-cols-3 gap-4 w-full items-start"):
            # ==================================================================
            # BƯỚC 1 – NẠP TỆP (LOAD)
            # Nhận: Tệp tin người dùng tải lên từ máy tính hoặc dữ liệu mẫu có sẵn.
            # Trả về: Dữ liệu bytes lưu vào file_state, cùng thông số kích thước, SHA-256 và ảnh xem trước.
            # ==================================================================
            with ui.card().classes("w-full p-5 rounded-xl border border-slate-200/80 shadow-sm space-y-3"):
                with ui.row().classes("w-full items-center gap-2"):
                    ui.badge("1", color="primary").classes("rounded-full w-6 h-6 text-xs flex items-center justify-center")
                    ui.label("Bước 1 – Nạp Tệp Dữ Liệu").classes("text-sm font-bold text-slate-800")

                # ui.upload: thành phần giao diện cho phép kéo thả hoặc chọn tệp tin từ máy tính
                ui_upload_element = ui.upload(
                    label="Kéo thả hoặc bấm để nạp tệp (tối đa 8 MiB)",
                    auto_upload=True,
                    max_file_size=MAX_BYTES,
                ).props("flat bordered").classes("w-full")

                with ui.row().classes("w-full items-center justify-between flex-wrap gap-2"):
                    with ui.row().classes("items-center gap-2"):
                        btn_sample_img = ui.button("Ảnh mẫu", icon="image").props("outline size=sm color=primary")
                        btn_sample_txt = ui.button("Text mẫu", icon="description").props("outline size=sm color=secondary")
                    ui.label("Hỗ trợ: .png, .jpg, .txt, .rc4 (chỉ có bản mã)...").classes("text-xs text-slate-400")

                # Khung thông tin metadata & Preview Bước 1
                step1_info_box = ui.column().classes("w-full gap-2")

            # ==================================================================
            # BƯỚC 2 – MÃ HÓA RC4 (ENCRYPT)
            # Nhận: Byte bản rõ gốc từ file_state['original'] và chuỗi khóa mã hóa từ người dùng.
            # Trả về: Byte bản mã lưu vào file_state['encrypted'], ảnh nhiễu trực quan và chuỗi hex 48 byte đầu.
            # Vì sao chia khối (chunk): mã hóa từng khối nhỏ để cập nhật % tiến trình và tránh đơ giao diện web.
            # ==================================================================
            with ui.card().classes("w-full p-5 rounded-xl border border-slate-200/80 shadow-sm space-y-3"):
                with ui.row().classes("w-full items-center justify-between flex-wrap gap-1"):
                    with ui.row().classes("items-center gap-2"):
                        ui.badge("2", color="primary").classes("rounded-full w-6 h-6 text-xs flex items-center justify-center")
                        ui.label("Bước 2 – Mã Hóa RC4 (Chunked Streaming)").classes("text-sm font-bold text-slate-800")
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

                # ui.linear_progress: thanh tiến trình ngang hiển thị tỷ lệ % công việc đã hoàn thành
                enc_progress = ui.linear_progress(value=0.0, show_value=False).props("instant-feedback stripe rounded").classes("w-full h-2")

                # Khung hiển thị kết quả bản mã
                step2_result_box = ui.column().classes("w-full gap-2")

                # Nút tải bản mã
                with ui.row().classes("w-full items-center justify-end gap-2 pt-2 border-t border-slate-200/60"):
                    btn_download_rc4 = ui.button("Tải bản mã (.rc4)", icon="download").props("color=primary size=sm")

            # ==================================================================
            # BƯỚC 3 – GIẢI MÃ & ĐỐI CHIẾU (DECRYPT & INTEGRITY)
            # Nhận: Byte bản mã từ file_state['encrypted'] và khóa giải mã từ người dùng.
            # Trả về: Byte giải mã lưu vào file_state['decrypted'], kết quả so khớp SHA-256 và ảnh khôi phục.
            # ==================================================================
            with ui.card().classes("w-full p-5 rounded-xl border border-slate-200/80 shadow-sm space-y-3"):
                with ui.row().classes("w-full items-center justify-between flex-wrap gap-1"):
                    with ui.row().classes("items-center gap-2"):
                        ui.badge("3", color="positive").classes("rounded-full w-6 h-6 text-xs flex items-center justify-center")
                        ui.label("Bước 3 – Giải Mã & Đối Chiếu Toàn Vẹn").classes("text-sm font-bold text-slate-800")
                    dec_status_label = ui.label("").classes("text-xs font-mono text-slate-600")

                with ui.row().classes("w-full items-center gap-2"):
                    dec_key_input = ui.input(
                        label="Khóa giải mã (UTF-8)",
                        value="RC4-File-Encryption-Key-2026",
                    ).classes("flex-1")
                    btn_fill_wrong_key = ui.button("Điền khóa sai", icon="shuffle").props("outline size=sm color=amber-9")

                dec_key_len_label = ui.label("").classes("text-xs text-slate-500 font-mono -mt-2")

                with ui.row().classes("w-full items-center gap-3"):
                    btn_decrypt = ui.button("Giải mã", icon="lock_open").props("color=positive size=sm")

                dec_progress = ui.linear_progress(value=0.0, show_value=False).props(
                    "instant-feedback stripe rounded color=positive"
                ).classes("w-full h-2")

                # Khung hiển thị kết quả giải mã và đối chiếu SHA-256
                step3_result_box = ui.column().classes("w-full gap-2")

                # Nút tải tệp giải mã
                with ui.row().classes("w-full items-center justify-end gap-2 pt-2 border-t border-slate-200/60"):
                    btn_download_dec = ui.button("Tải tệp giải mã", icon="verified").props("color=positive size=sm")

        # ----------------------------------------------------------------------
        # CẬP NHẬT ĐỘ DÀI KHÓA VÀ SINH KHÓA NGẪU NHIÊN
        # ----------------------------------------------------------------------
        def update_enc_key_len() -> None:
            """Cập nhật nhãn hiển thị số lượng byte của khóa mã hóa.

            Tham số: Không có.
            Giá trị trả về: Không có.
            """
            try:
                if key_mode_toggle.value == "Hex":
                    k_b = khoa_tu_hex(enc_key_input.value or "")
                else:
                    k_b = khoa_tu_chuoi(enc_key_input.value or "")
                enc_key_len_label.text = f"Độ dài khóa: {len(k_b)} byte"
            except ValueError:
                enc_key_len_label.text = "Khóa không hợp lệ"

        def update_dec_key_len() -> None:
            """Cập nhật nhãn hiển thị số lượng byte của khóa giải mã.

            Tham số: Không có.
            Giá trị trả về: Không có.
            """
            try:
                if key_mode_toggle.value == "Hex":
                    k_b = khoa_tu_hex(dec_key_input.value or "")
                else:
                    k_b = khoa_tu_chuoi(dec_key_input.value or "")
                dec_key_len_label.text = f"Độ dài khóa: {len(k_b)} byte"
            except ValueError:
                dec_key_len_label.text = "Khóa không hợp lệ"

        def on_random_key() -> None:
            """Sinh ngẫu nhiên khóa 16 byte (128-bit) bằng CSPRNG và điền vào 2 ô nhập.

            Tham số: Không có.
            Giá trị trả về: Không có.
            """
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

        # ----------------------------------------------------------------------
        # CÁC HÀM XỬ LÝ GIAO DIỆN & LOGIC
        # ----------------------------------------------------------------------

        def clear_step2_and_step3() -> None:
            """Xóa kết quả downstream của Bước 2 và Bước 3 khi nạp tệp mới.

            Tham số: Không có.
            Giá trị trả về: Không có.
            """
            enc_progress.value = 0.0
            enc_status_label.text = ""
            step2_result_box.clear()
            clear_step3()

        def clear_step3() -> None:
            """Xóa kết quả downstream của Bước 3 khi mã hóa lại.

            Tham số: Không có.
            Giá trị trả về: Không có.
            """
            dec_progress.value = 0.0
            dec_status_label.text = ""
            step3_result_box.clear()
            file_state["decrypted"] = None

        def render_step1_preview() -> None:
            """Hiển thị tên, kích thước, SHA-256 và bản xem trước Bước 1.

            Tham số: Không có.
            Giá trị trả về: Không có.
            """
            step1_info_box.clear()
            filename = file_state["name"]
            is_rc4 = file_state["is_rc4_loaded"]
            data = file_state["encrypted"] if is_rc4 else file_state["original"]

            if data is None:
                return

            data_len = len(data)
            # hashlib.sha256: dấu vân tay của dữ liệu (chuỗi băm cố định 64 ký tự hex)
            sha16 = hashlib.sha256(data).hexdigest()[:16]

            with step1_info_box:
                # Metadata bar
                with ui.row().classes(
                    "w-full items-center justify-between p-2.5 bg-white rounded-lg border border-slate-200 text-xs font-mono flex-wrap gap-2"
                ):
                    with ui.row().classes("items-center gap-2 flex-wrap"):
                        ui.icon("insert_drive_file", size="xs").classes("text-slate-600")
                        ui.label(f"{filename}").classes("font-bold text-slate-800 break-all")
                        ui.label(f"({data_len:,} bytes)").classes("text-slate-500")
                    with ui.row().classes("items-center gap-2 flex-wrap"):
                        ui.label(f"SHA-256: {sha16}...").classes("text-slate-600")
                        if is_rc4:
                            ui.badge("chỉ có bản mã", color="warning").classes("text-xs")
                        else:
                            ui.badge("Bản gốc", color="primary").classes("text-xs")

                # Preview container
                if is_rc4:
                    with ui.column().classes("w-full p-3 rounded-lg border border-amber-200 bg-amber-50/50"):
                        ui.label("Tệp nạp vào là bản mã RC4 (.rc4). Chuyển sang Bước 3 để giải mã.").classes(
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
            """Hiển thị kết quả mã hóa: ảnh nhiễu, 48 byte hex đầu, SHA-256, % byte khác.

            Tham số: Không có.
            Giá trị trả về: Không có.
            """
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
                # Cột ảnh nhiễu
                with ui.column().classes("w-full items-center p-2 rounded-lg border border-slate-200 bg-white"):
                    ui.label("Ảnh nhiễu bản mã (128 KB)").classes("text-[11px] font-semibold text-slate-600 mb-1 self-start")
                    if noise_b64:
                        ui.image(f"data:image/png;base64,{noise_b64}").style("image-rendering: pixelated;").classes(
                            "w-full h-64 object-contain bg-slate-900 rounded border border-slate-700"
                        )
                    else:
                        ui.label("Không tạo được ảnh nhiễu").classes("text-xs text-slate-500 py-10")

                # Cột thông số bản mã
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
            """Hiển thị kết quả giải mã, đối chiếu toàn vẹn và kiểm định ảnh.

            Tham số: Không có.
            Giá trị trả về: Không có.
            """
            step3_result_box.clear()
            decrypted = file_state.get("decrypted")
            if decrypted is None:
                return

            original = file_state.get("original")
            filename = file_state["name"]
            is_image_name = any(filename.lower().endswith(ext) for ext in IMAGE_EXTENSIONS)
            is_valid_img, mime = validate_image(decrypted)

            with step3_result_box:
                # 1. Badge đối chiếu tính toàn vẹn
                with ui.row().classes("w-full items-center gap-2"):
                    if original is not None:
                        orig_sha = hashlib.sha256(original).hexdigest()
                        dec_sha = hashlib.sha256(decrypted).hexdigest()
                        if orig_sha == dec_sha:
                            ui.badge("✓ KHỚP 100% BẢN GỐC (SHA-256 trùng)", color="positive").classes(
                                "text-xs font-bold px-3 py-1.5"
                            )
                        else:
                            ui.badge("✗ KHÔNG KHỚP BẢN GỐC (sai khóa?)", color="negative").classes(
                                "text-xs font-bold px-3 py-1.5"
                            )
                    else:
                        ui.badge("Không có bản gốc để đối chiếu, hãy kiểm tra bằng mắt", color="warning").classes(
                            "text-xs font-bold px-3 py-1.5"
                        )

                # 2. Nội dung hiển thị dữ liệu sau giải mã
                if is_valid_img:
                    b64_img = base64.b64encode(decrypted).decode("ascii")
                    with ui.column().classes("w-full items-center p-2 rounded-lg border border-emerald-200 bg-emerald-50/30"):
                        ui.label("Ảnh sau khi giải mã thành công:").classes("text-xs font-bold text-emerald-800 mb-1 self-start")
                        ui.image(f"data:{mime};base64,{b64_img}").classes(
                            "w-full h-64 object-contain bg-slate-50 rounded border"
                        )
                elif is_image_name:
                    noise_b64 = create_noise_image_b64(decrypted)
                    with ui.column().classes("w-full p-3 rounded-lg border border-rose-300 bg-rose-50/50 items-center gap-2"):
                        ui.label("KHÔNG phải ảnh hợp lệ (Dữ liệu bị hỏng hoặc giải mã sai khóa)").classes(
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
            """Xử lý nạp dữ liệu tệp vào pipeline và cập nhật giao diện xem trước.

            Tham số:
                name: Tên tệp tin được nạp (ví dụ 'sample_logo.png' hoặc 'secret.rc4').
                content: Mảng byte nhị phân của tệp tin.
            Giá trị trả về: Không có.
            """
            if len(content) > MAX_BYTES:
                # ui.notify: thông báo nhỏ dạng pop-up hiện lên ở góc màn hình rồi tự biến mất
                ui.notify(f"Kích thước tệp quá lớn ({len(content):,} bytes > 8 MiB)!", type="warning")
                return

            if len(content) == 0:
                ui.notify("Cảnh báo: Tệp tải lên rỗng (0 bytes)!", type="warning")
                return

            clear_step2_and_step3()

            is_rc4 = name.lower().endswith(".rc4")
            if is_rc4:
                file_state["name"] = name[:-4] if name.lower().endswith(".rc4") else name
                file_state["original"] = None
                file_state["encrypted"] = content
                file_state["is_rc4_loaded"] = True
                render_step1_preview()
                render_step2_preview()
                ui.notify(f"Đã nạp tệp bản mã: {name} ({len(content):,} bytes)", type="info")
            else:
                file_state["name"] = name
                file_state["original"] = content
                file_state["encrypted"] = None
                file_state["is_rc4_loaded"] = False
                render_step1_preview()
                ui.notify(f"Đã nạp tệp: {name} ({len(content):,} bytes)", type="positive")

        async def handle_upload(e: Any) -> None:
            """Hàm xử lý sự kiện khi người dùng kéo thả hoặc tải tệp lên giao diện.

            Tham số:
                e: Đối tượng sự kiện upload của NiceGUI chứa dữ liệu tệp tin.
            Giá trị trả về: Không có.
            """
            try:
                # 1. Trích xuất tên tệp
                name = "uploaded_file"
                if hasattr(e, "name") and e.name:
                    name = str(e.name)
                elif hasattr(e, "file") and hasattr(e.file, "name") and e.file.name:
                    name = str(e.file.name)
                elif hasattr(e, "file") and hasattr(e.file, "filename") and e.file.filename:
                    name = str(e.file.filename)

                # 2. Trích xuất nội dung bytes
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
            """Nạp tệp mẫu có sẵn của dự án (ảnh logo trường hoặc văn bản UTF-8).

            Tham số:
                kind: Chuỗi định danh loại tệp mẫu ('logo' hoặc 'txt').
            Giá trị trả về: Không có.
            """
            if kind == "logo":
                await process_loaded_content("sample_logo.png", get_default_sample_bytes())
            else:
                await process_loaded_content("sample_text.txt", get_default_text_bytes())

        btn_sample_img.on_click(lambda: load_sample_file("logo"))
        btn_sample_txt.on_click(lambda: load_sample_file("txt"))

        # Gán handler upload
        ui_upload_element.on_upload(handle_upload)

        # ----------------------------------------------------------------------
        # BƯỚC 2: MÃ HÓA
        # ----------------------------------------------------------------------
        async def run_encryption() -> None:
            """Thực hiện luồng mã hóa RC4 theo khối streaming và cập nhật tiến trình.

            Hàm chia dữ liệu thành nhiều khối nhỏ (chunk) bằng generator rc4_crypt_chunks,
            sau mỗi khối sẽ nhường quyền CPU (asyncio.sleep) để giao diện kịp cập nhật
            thanh tiến trình và tránh làm treo trình duyệt.

            Tham số: Không có.
            Giá trị trả về: Không có.
            """
            nonlocal is_busy
            if is_busy:
                return

            original = file_state.get("original")
            if original is None:
                if file_state.get("is_rc4_loaded"):
                    ui.notify("Tệp hiện tại chỉ có bản mã (.rc4). Vui lòng chuyển sang Bước 3 để giải mã.", type="info")
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

                    # asyncio.sleep: tạm dừng trong nền để trình duyệt kịp cập nhật giao diện
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

        # ----------------------------------------------------------------------
        # BƯỚC 3: GIẢI MÃ
        # ----------------------------------------------------------------------
        def fill_wrong_key() -> None:
            """Tự động điền sai khóa giải mã để người dùng kiểm chứng cảnh báo lỗi.

            Tham số: Không có.
            Giá trị trả về: Không có.
            """
            if key_mode_toggle.value == "Hex":
                dec_key_input.value = (dec_key_input.value or "") + "00"
                ui.notify("Đã điền khóa sai (thêm '00')", type="warning")
            else:
                dec_key_input.value = (dec_key_input.value or "") + "x"
                ui.notify("Đã điền khóa sai (thêm 'x')", type="warning")
            update_dec_key_len()

        btn_fill_wrong_key.on_click(fill_wrong_key)

        async def run_decryption() -> None:
            """Thực hiện giải mã RC4 theo khối, đối chiếu SHA-256 và kiểm định ảnh.

            Hàm giải mã dòng khóa đối xứng, sau đó so sánh mã băm SHA-256 với tệp gốc ban đầu
            và gọi PIL.Image để thẩm định xem dữ liệu giải mã có tái tạo được ảnh chuẩn không.

            Tham số: Không có.
            Giá trị trả về: Không có.
            """
            nonlocal is_busy
            if is_busy:
                return

            ciphertext = file_state.get("encrypted")
            if ciphertext is None:
                ui.notify("Chưa có bản mã để giải mã. Hãy mã hóa ở Bước 2 hoặc nạp tệp .rc4 ở Bước 1.", type="warning")
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

                    # asyncio.sleep: nhường luồng xử lý để trình duyệt render giao diện
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

        # Download handlers
        def download_ciphertext() -> None:
            """Kích hoạt tải tệp bản mã (.rc4) về máy tính người dùng.

            Tham số: Không có.
            Giá trị trả về: Không có.
            """
            c = file_state.get("encrypted")
            if not c:
                ui.notify("Chưa có dữ liệu bản mã để tải về.", type="warning")
                return
            download_name = f"{file_state['name']}.rc4"
            # ui.download: kích hoạt trình duyệt tự động tải tệp tin về máy tính người dùng
            ui.download(c, download_name)

        def download_decrypted() -> None:
            """Kích hoạt tải tệp tin đã giải mã về máy tính người dùng.

            Tham số: Không có.
            Giá trị trả về: Không có.
            """
            d = file_state.get("decrypted")
            if not d:
                ui.notify("Chưa có dữ liệu tệp giải mã để tải về.", type="warning")
                return
            download_name = f"decrypted_{file_state['name']}"
            # ui.download: kích hoạt trình duyệt tự động tải tệp tin về máy tính người dùng
            ui.download(d, download_name)

        btn_download_rc4.on_click(download_ciphertext)
        btn_download_dec.on_click(download_decrypted)

        # ----------------------------------------------------------------------
        # TRẠNG THÁI KHỞI ĐẦU: Đã nạp sẵn ảnh mẫu, CHƯA mã hóa
        # ----------------------------------------------------------------------
        init_sample = get_default_sample_bytes()
        file_state["name"] = "sample_logo.png"
        file_state["original"] = init_sample
        file_state["encrypted"] = None
        file_state["decrypted"] = None
        file_state["is_rc4_loaded"] = False
        render_step1_preview()
