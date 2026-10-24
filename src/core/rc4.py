"""
Thuật toán mã hóa dòng RC4 chuẩn 8-bit (src/core/rc4.py)
Cài đặt thuần Python cho thuật toán KSA (xáo mảng S) và PRGA (sinh dòng khóa XOR dữ liệu).
Được gọi bởi: phân hệ mã hóa văn bản (tab_rc4_text), mã hóa tệp (file_pipeline) và test suite.
Gọi đến: src.core.models (chứa FullRC4Result).
Thuật ngữ: KSA (Key-Scheduling Algorithm) là bước trộn 256 phần tử của S-box bằng khóa K;
PRGA (Pseudo-Random Generation Algorithm) là bộ sinh dòng byte ngẫu nhiên (keystream);
XOR (phép cộng nhị phân không nhớ: b ^ k) dùng để biến đổi bản rõ thành bản mã và ngược lại.
"""

from __future__ import annotations  # dùng để kích hoạt tính năng kiểm tra kiểu dữ liệu tĩnh
import time  # dùng để bấm giờ hiệu năng mã hóa chính xác từng mili-giây
from typing import Iterator, List  # dùng để khai báo kiểu dữ liệu danh sách và hàm sinh khối (generator)

from src.core.models import FullRC4Result  # file nội bộ của dự án: cấu trúc lưu kết quả mã hóa RC4


def rc4_ksa(key_bytes: bytes) -> List[int]:
    """
    Giai đoạn Khởi tạo KSA (Key-Scheduling Algorithm) xáo trộn mảng S gồm 256 byte (Slide 61-62).
    Thuật toán dùng mảng T lặp lại từ khóa K để xáo trộn vị trí của mảng hoán vị S ban đầu.

    Tham số:
        key_bytes (bytes): Khóa bí mật dạng nhị phân, độ dài từ 1 đến 256 byte.

    Trả về:
        List[int]: Mảng hoán vị S gồm 256 số nguyên (0..255) sau khi đã được xáo trộn hoàn chỉnh.

    Ví dụ:
        rc4_ksa(b"Key") -> mảng 256 số bắt đầu bằng [187, 243, 22, ...]
    """
    if not key_bytes:
        raise ValueError("Khóa RC4 không được rỗng (độ dài từ 1 đến 256 byte).")
    if len(key_bytes) > 256:
        raise ValueError("Khóa RC4 vượt quá 256 byte.")

    n_len = len(key_bytes)
    # Mảng S ban đầu là dãy số tăng dần từ 0 đến 255: S = [0, 1, 2, ..., 255]
    s_arr = list(range(256))
    # Mảng T sao chép lặp lại các byte khóa cho đủ 256 phần tử: T[i] = K[i % len(K)]
    t_arr = [key_bytes[i % n_len] for i in range(256)]

    j = 0
    # Lặp qua từng vị trí i từ 0 đến 255 để xáo trộn ngẫu nhiên mảng S
    for i in range(256):
        # Cộng dồn chỉ số j: j = (j + S[i] + T[i]) mod 256 (ví dụ: (0 + 0 + 75) % 256 = 75)
        j = (j + s_arr[i] + t_arr[i]) % 256
        # Hoán vị hai phần tử S[i] và S[j] để xáo vị trí (ví dụ: đổi chỗ phần tử tại i và j)
        s_arr[i], s_arr[j] = s_arr[j], s_arr[i]
    return s_arr


def rc4_crypt_chunks(
    data: bytes,
    key_bytes: bytes,
    chunk_size: int = 65536,
) -> Iterator[bytes]:
    """
    Mã hóa hoặc giải mã RC4 theo từng khối (chunked streaming generator) cho dữ liệu lớn.
    Chạy giai đoạn PRGA (Pseudo-Random Generation Algorithm) sinh byte dòng khóa để XOR.
    Modulo 256 giúp chỉ số xoay vòng liên tục trong phạm vi mảng S từ 0 đến 255.

    Tham số:
        data (bytes): Dữ liệu nhị phân cần xử lý (văn bản UTF-8 hoặc tệp tin).
        key_bytes (bytes): Khóa bí mật (từ 1 đến 256 byte).
        chunk_size (int): Kích thước mỗi khối cắt nhỏ để xử lý (mặc định 65536 byte = 64 KB).

    Trả về:
        Iterator[bytes]: Trình sinh (generator) nhả ra từng khối byte đã được mã hóa/giải mã.

    Ví dụ:
        b"".join(rc4_crypt_chunks(b"Wiki", b"pedia")) -> b'\\x10!\\xbf\\x04'
    """
    if chunk_size < 1:
        raise ValueError("chunk_size phải lớn hơn hoặc bằng 1.")

    s_arr = rc4_ksa(key_bytes)
    total_len = len(data)
    if total_len == 0:
        return

    i = 0
    j = 0
    # Cắt dữ liệu thành từng khối (chunk) có độ dài chunk_size để tiết kiệm bộ nhớ RAM
    for offset in range(0, total_len, chunk_size):
        chunk = data[offset : offset + chunk_size]
        chunk_len = len(chunk)
        out_chunk = bytearray(chunk_len)
        for idx in range(chunk_len):
            # 1. Tăng i (modulo 256): con trỏ i bước sang vị trí tiếp theo (ví dụ: i=(0+1)%256=1)
            i = (i + 1) % 256
            # 2. Cộng j với S[i] (modulo 256): con trỏ j nhảy ngẫu nhiên (ví dụ: j=(0+S[1])%256)
            j = (j + s_arr[i]) % 256
            # 3. Hoán vị S[i] và S[j]: đảo vị trí hai phần tử để thay đổi trạng thái S-box
            s_arr[i], s_arr[j] = s_arr[j], s_arr[i]
            # 4. Lấy byte dòng khóa k = S[(S[i] + S[j]) % 256] (ví dụ: t=(S[i]+S[j])%256, k=S[t])
            t = (s_arr[i] + s_arr[j]) % 256
            k = s_arr[t]
            # 5. Phép XOR giữa byte đầu vào và byte dòng khóa: c = p ^ k (ngược lại p = c ^ k)
            out_chunk[idx] = chunk[idx] ^ k
        yield bytes(out_chunk)


def rc4_crypt(data: bytes, key_bytes: bytes) -> bytes:
    """
    Mã hóa hoặc giải mã nhanh toàn bộ chuỗi byte trong một lần gọi (one-shot).
    Bản chất gọi generator rc4_crypt_chunks với kích thước khối bằng toàn bộ độ dài dữ liệu.

    Tham số:
        data (bytes): Dữ liệu nhị phân đầu vào cần biến đổi.
        key_bytes (bytes): Khóa bí mật (1 đến 256 byte).

    Trả về:
        bytes: Chuỗi byte kết quả (bản mã nếu đầu vào là bản rõ, bản rõ nếu đầu vào là bản mã).

    Ví dụ:
        rc4_crypt(b"Plaintext", b"Key").hex().upper() -> 'BBF316E8D940AF0AD3'
    """
    return b"".join(rc4_crypt_chunks(data, key_bytes, max(len(data), 1)))


def rc4_crypt_with_details(data: bytes, key_bytes: bytes, preview_len: int = 16) -> FullRC4Result:
    """
    Thực thi mã hóa/giải mã và đóng gói chi tiết phục vụ hiển thị giáo trình trực quan.
    Ghi nhận lại mảng S sau KSA, 16 byte dòng khóa đầu tiên và thời gian thực thi (mili-giây).

    Tham số:
        data (bytes): Chuỗi byte đầu vào (văn bản UTF-8 hoặc dữ liệu tệp tin).
        key_bytes (bytes): Khóa bí mật dạng byte.
        preview_len (int): Số lượng byte keystream mẫu cần trích xuất (mặc định 16).

    Trả về:
        FullRC4Result: Đối tượng chứa dữ liệu ra, mảng S, keystream mẫu và thời gian chạy.

    Ví dụ:
        res = rc4_crypt_with_details(b"Hello", b"Secret"); print(res.output_hex)
    """
    t0 = time.perf_counter()
    output_bytes = rc4_crypt(data, key_bytes)
    elapsed_ms = (time.perf_counter() - t0) * 1000.0

    final_ksa_s = rc4_ksa(key_bytes)
    keystream_preview = list(rc4_crypt(bytes(preview_len), key_bytes))

    return FullRC4Result(
        input_bytes=data,
        key_bytes=key_bytes,
        output_bytes=output_bytes,
        keystream_preview=keystream_preview,
        final_ksa_s=final_ksa_s,
        elapsed_ms=elapsed_ms,
    )

