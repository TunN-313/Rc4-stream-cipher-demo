"""
Bộ Kiểm Thử Giao Diện Quy Trình Xử Lý Tệp (tests/test_file_pipeline_ui.py)
========================================================================
Kiểm thử tự động luồng Nạp -> Mã hóa -> Giải mã với NiceGUI Testing User:
1. Luồng chuẩn: Mã hóa -> Giải mã -> Khớp 100% bản gốc SHA-256.
2. Luồng sai khóa: Mã hóa -> Điền khóa sai -> Giải mã -> Báo lỗi & ảnh không hợp lệ.
3. Luồng tải tệp tùy chỉnh: Upload anh_cua_toi.png -> Mã hóa -> Giải mã thành công.
4. Luồng tệp bản mã: Upload logo.png.rc4 -> Báo 'chỉ có bản mã' -> Giải mã thành công.
5. Luồng tệp quá lớn: Upload > 8 MiB -> Báo 'quá lớn'.
"""

from __future__ import annotations
import inspect
import io
import pytest
from starlette.datastructures import Headers, UploadFile

from nicegui import ui
from nicegui.elements.upload_files import create_file_upload
from nicegui.testing import User

from src.core.rc4 import rc4_crypt
import src.ui.file_pipeline as file_pipeline
from src.ui.file_pipeline import build_file_pipeline

pytest_plugins = ["nicegui.testing.user_plugin"]

# Thiết lập alias _sample_bytes nếu cần
_sample_bytes = getattr(file_pipeline, "_sample_bytes", file_pipeline.get_default_sample_bytes)
if not hasattr(file_pipeline, "_sample_bytes"):
    file_pipeline._sample_bytes = file_pipeline.get_default_sample_bytes  # type: ignore


def _page() -> None:
    """Hàm đăng ký @ui.page('/') gọi build_file_pipeline()."""
    @ui.page("/")
    def index() -> None:
        build_file_pipeline()


@pytest.fixture(autouse=True)
def setup_page() -> None:
    """Đăng ký trang trước mỗi ca kiểm thử."""
    _page()


async def _upload_helper(
    user: User,
    filename: str,
    content: bytes,
    content_type: str = "application/octet-stream",
) -> None:
    """Helper nạp tệp qua starlette UploadFile và create_file_upload."""
    upload_file = UploadFile(
        file=io.BytesIO(content),
        filename=filename,
        headers=Headers({"content-type": content_type}),
    )
    res = create_file_upload(upload_file)
    fu = await res if inspect.isawaitable(res) else res
    upload_elem = user.find(kind=ui.upload).elements.pop()
    handle_res = upload_elem.handle_uploads([fu])
    if inspect.isawaitable(handle_res):
        await handle_res


@pytest.mark.asyncio
async def test_encrypt_then_decrypt_success(user: User) -> None:
    """Test 1: Bấm 'Mã hóa' rồi 'Giải mã' thấy 'Mã hóa xong' và 'KHỚP 100% BẢN GỐC'."""
    _page()
    await user.open("/")

    # Tắt 'Trình diễn chậm' trước khi mã hóa
    user.find(kind=ui.switch).elements.pop().set_value(False)

    # Bấm 'Mã hóa'
    user.find(kind=ui.button, content="Mã hóa").click()
    await user.should_see("Mã hóa xong")

    # Bấm 'Giải mã'
    user.find(kind=ui.button, content="Giải mã").click()
    await user.should_see("KHỚP 100% BẢN GỐC")


@pytest.mark.asyncio
async def test_wrong_key_decryption(user: User) -> None:
    """Test 2: Bấm 'Mã hóa', 'Điền khóa sai', 'Giải mã' thấy 'KHÔNG KHỚP BẢN GỐC' và 'KHÔNG phải ảnh hợp lệ'."""
    _page()
    await user.open("/")

    # Tắt 'Trình diễn chậm' trước khi mã hóa
    user.find(kind=ui.switch).elements.pop().set_value(False)

    # Bấm 'Mã hóa'
    user.find(kind=ui.button, content="Mã hóa").click()
    await user.should_see("Mã hóa xong")

    # Bấm 'Điền khóa sai'
    user.find(kind=ui.button, content="Điền khóa sai").click()

    # Bấm 'Giải mã'
    user.find(kind=ui.button, content="Giải mã").click()
    await user.should_see("KHÔNG KHỚP BẢN GỐC")
    await user.should_see("KHÔNG phải ảnh hợp lệ")


@pytest.mark.asyncio
async def test_upload_custom_image(user: User) -> None:
    """Test 3: Upload anh_cua_toi.png (dùng _sample_bytes() từ file_pipeline) rồi mã hóa -> giải mã thấy 'KHỚP 100% BẢN GỐC'."""
    _page()
    await user.open("/")

    # Upload anh_cua_toi.png
    sample_data = _sample_bytes()
    await _upload_helper(user, "anh_cua_toi.png", sample_data, content_type="image/png")
    await user.should_see("anh_cua_toi.png")

    # Tắt 'Trình diễn chậm' trước khi mã hóa
    user.find(kind=ui.switch).elements.pop().set_value(False)

    # Bấm 'Mã hóa'
    user.find(kind=ui.button, content="Mã hóa").click()
    await user.should_see("Mã hóa xong")

    # Bấm 'Giải mã'
    user.find(kind=ui.button, content="Giải mã").click()
    await user.should_see("KHỚP 100% BẢN GỐC")


@pytest.mark.asyncio
async def test_upload_rc4_file_decryption(user: User) -> None:
    """Test 4: Upload 'logo.png.rc4' (mã hóa bằng rc4_crypt với khóa 'RC4-File-Encryption-Key-2026')

    thấy 'chỉ có bản mã', bấm 'Giải mã' thấy 'Giải mã xong' và 'Không có bản gốc để đối chiếu'.
    """
    _page()
    await user.open("/")

    # Tạo dữ liệu bản mã từ ảnh mẫu
    raw_sample = _sample_bytes()
    rc4_key = b"RC4-File-Encryption-Key-2026"
    encrypted_bytes = rc4_crypt(raw_sample, rc4_key)

    # Upload tệp logo.png.rc4
    await _upload_helper(user, "logo.png.rc4", encrypted_bytes, content_type="application/octet-stream")
    await user.should_see("chỉ có bản mã")

    # Tắt 'Trình diễn chậm' trước khi giải mã
    user.find(kind=ui.switch).elements.pop().set_value(False)

    # Bấm 'Giải mã'
    user.find(kind=ui.button, content="Giải mã").click()
    await user.should_see("Giải mã xong")
    await user.should_see("Không có bản gốc để đối chiếu")


@pytest.mark.asyncio
async def test_upload_oversized_file(user: User) -> None:
    """Test 5: Upload 8 MiB + 1 byte thấy 'quá lớn'."""
    _page()
    await user.open("/")

    # Tạo tệp vượt quá 8 MiB đúng 1 byte
    oversized_data = b"0" * (8 * 1024 * 1024 + 1)
    await _upload_helper(user, "oversized_test.bin", oversized_data)
    await user.should_see("quá lớn")
