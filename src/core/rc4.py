"""
Thuật toán RC4 Đầy Đủ (8-bit, Modulo 256) — Backend Core
=========================================================
Quy chuẩn: Hệ mã dòng RC4 chuẩn hoạt động trên kiểu bytes (văn bản UTF-8 và file nhị phân).
Ràng buộc: TUYỆT ĐỐI KHÔNG dùng thư viện mật mã có sẵn bên trong module này.
"""

from __future__ import annotations
import time
from typing import List

from src.core.models import FullRC4Result


def rc4_ksa(key_bytes: bytes) -> List[int]:
    """
    Giai đoạn Khởi tạo KSA cho hệ mã RC4 đầy đủ (256 byte - Slide 61-62).
    """
    if not key_bytes:
        raise ValueError("Khóa RC4 không được rỗng (độ dài từ 1 đến 256 byte).")
    if len(key_bytes) > 256:
        raise ValueError("Khóa RC4 vượt quá 256 byte.")

    n_len = len(key_bytes)
    s_arr = list(range(256))
    t_arr = [key_bytes[i % n_len] for i in range(256)]

    j = 0
    for i in range(256):
        j = (j + s_arr[i] + t_arr[i]) % 256
        s_arr[i], s_arr[j] = s_arr[j], s_arr[i]
    return s_arr


def rc4_crypt_with_details(data: bytes, key_bytes: bytes, preview_len: int = 16) -> FullRC4Result:
    """
    Thực thi mã hóa / giải mã RC4 256-byte trên dữ liệu nhị phân bất kỳ (văn bản, file, ảnh).
    """
    t0 = time.perf_counter()
    s_arr = rc4_ksa(key_bytes)
    final_ksa_s = list(s_arr)

    out_bytearray = bytearray(len(data))
    keystream_preview: List[int] = []

    i = 0
    j = 0
    for idx, byte_in in enumerate(data):
        i = (i + 1) % 256
        j = (j + s_arr[i]) % 256
        s_arr[i], s_arr[j] = s_arr[j], s_arr[i]
        t = (s_arr[i] + s_arr[j]) % 256
        k = s_arr[t]
        if idx < preview_len:
            keystream_preview.append(k)
        out_bytearray[idx] = byte_in ^ k

    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    return FullRC4Result(
        input_bytes=data,
        key_bytes=key_bytes,
        output_bytes=bytes(out_bytearray),
        keystream_preview=keystream_preview,
        final_ksa_s=final_ksa_s,
        elapsed_ms=elapsed_ms,
    )


def rc4_crypt(data: bytes, key_bytes: bytes) -> bytes:
    """Hàm rút gọn trả về trực tiếp bytes bản mã / bản rõ."""
    return rc4_crypt_with_details(data, key_bytes, preview_len=0).output_bytes
