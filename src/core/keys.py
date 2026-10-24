"""
Module Quản lý và Khởi tạo Khóa Bí Mật (src/core/keys.py)
Sinh ngẫu nhiên an toàn và chuẩn hóa khóa từ văn bản hoặc chuỗi Hex cho RC4 và TinyRC4.
Được gọi bởi: phân hệ giao diện (tab_rc4_text, file_pipeline, tab_tiny_rc4) và test suite.
Gọi đến: thư viện chuẩn Python secrets để tạo byte ngẫu nhiên an toàn mật mã (CSPRNG).
Thuật ngữ: CSPRNG (Cryptographically Secure Pseudo-Random Number Generator) là bộ sinh
số ngẫu nhiên an toàn chuẩn mã hóa, kẻ tấn công không thể đoán trước giá trị kế tiếp.
"""

from __future__ import annotations  # dùng để kích hoạt tính năng kiểm tra kiểu dữ liệu tĩnh
import secrets  # dùng để tạo số ngẫu nhiên bảo mật cao (CSPRNG) không thể dự đoán
from typing import List  # dùng để khai báo kiểu dữ liệu danh sách

KHOA_TOI_DA_RC4: int = 256  # Độ dài khóa tối đa của RC4 chuẩn là 256 byte
KHOA_TOI_DA_TINY: int = 8  # Độ dài khóa tối đa của TinyRC4 là 8 phần tử 3-bit


def sinh_khoa_rc4(do_dai: int = 16) -> bytes:
    """
    Sinh khóa ngẫu nhiên an toàn mật mã cho RC4 có độ dài từ 1 đến 256 byte.

    Tham số:
        do_dai (int): Số lượng byte của khóa cần sinh (mặc định 16 byte = 128 bit).

    Trả về:
        bytes: Chuỗi byte khóa ngẫu nhiên tạo bởi hàm secrets.token_bytes.

    Ví dụ:
        len(sinh_khoa_rc4(16)) -> 16
    """
    if not (1 <= do_dai <= KHOA_TOI_DA_RC4):
        raise ValueError(
            f"Độ dài khóa RC4 ({do_dai}) phải nằm trong khoảng từ 1 đến {KHOA_TOI_DA_RC4} byte."
        )
    return secrets.token_bytes(do_dai)


def khoa_tu_chuoi(text: str) -> bytes:
    """
    Chuyển đổi chuỗi ký tự mật khẩu người dùng nhập thành chuỗi byte UTF-8 cho RC4.

    Tham số:
        text (str): Chuỗi mật khẩu dạng văn bản (độ dài khi đổi sang UTF-8 từ 1..256 byte).

    Trả về:
        bytes: Mảng byte của khóa sẵn sàng đưa vào thuật toán KSA.

    Ví dụ:
        khoa_tu_chuoi("SecretKey") -> b'SecretKey'
    """
    k_bytes = text.encode("utf-8")
    byte_len = len(k_bytes)
    if not (1 <= byte_len <= KHOA_TOI_DA_RC4):
        raise ValueError(
            f"Độ dài khóa ({byte_len} byte) không hợp lệ (phải từ 1 đến {KHOA_TOI_DA_RC4} byte)."
        )
    return k_bytes


def khoa_tu_hex(text: str) -> bytes:
    """
    Chuyển đổi chuỗi mã thập lục phân (Hexadecimal) thành chuỗi byte khóa chuẩn.
    Tự động loại bỏ khoảng trắng, kiểm tra tính chẵn và ký tự hợp lệ [0-9, A-F].

    Tham số:
        text (str): Chuỗi hex người dùng nhập (ví dụ: "01 02 03 04" hoặc "01020304").

    Trả về:
        bytes: Dãy byte nhị phân tương ứng với chuỗi hex.

    Ví dụ:
        khoa_tu_hex("4B6579") -> b'Key'
    """
    cleaned = text.replace(" ", "")
    if len(cleaned) % 2 != 0:
        raise ValueError("Khoá hex chỉ gồm ký tự 0-9, A-F và số ký tự phải chẵn")
    try:
        k_bytes = bytes.fromhex(cleaned)
    except ValueError:
        raise ValueError("Khoá hex chỉ gồm ký tự 0-9, A-F và số ký tự phải chẵn")

    if not (1 <= len(k_bytes) <= KHOA_TOI_DA_RC4):
        raise ValueError(
            f"Độ dài khóa ({len(k_bytes)} byte) phải nằm trong khoảng từ 1 đến {KHOA_TOI_DA_RC4} byte."
        )
    return k_bytes


def sinh_khoa_tiny(do_dai: int = 3, n: int = 3) -> List[int]:
    """
    Sinh ngẫu nhiên khóa cho TinyRC4 gồm `do_dai` số nguyên 3-bit (mỗi số từ 0 đến 7).

    Tham số:
        do_dai (int): Số lượng phần tử khóa N (từ 1 đến 8 số, mặc định 3 số như trên lớp).
        n (int): Số bit của mỗi phần tử (mặc định n=3, tức giá trị từ 0 đến 2^3 - 1 = 7).

    Trả về:
        List[int]: Danh sách các số nguyên biểu diễn khóa TinyRC4.

    Ví dụ:
        sinh_khoa_tiny(3) -> [2, 1, 3] (ngẫu nhiên trong khoảng 0..7)
    """
    if not (1 <= do_dai <= KHOA_TOI_DA_TINY):
        raise ValueError(
            f"Độ dài khóa TinyRC4 ({do_dai}) phải nằm trong khoảng từ 1 đến {KHOA_TOI_DA_TINY}."
        )
    max_val = 1 << n
    return [secrets.randbelow(max_val) for _ in range(do_dai)]

