"""
Module Chuyển Đổi Định Dạng Dữ Liệu (src/core/encoding.py)
Cung cấp các hàm biến đổi qua lại giữa nhị phân (bytes), số nguyên n-bit và chuỗi Hex.
Được gọi bởi: phân hệ mã hóa văn bản (tab_rc4_text), mã hóa tệp (file_pipeline) và test suite.
Gọi đến: không gọi file nội bộ nào khác, chỉ dùng thư viện chuẩn Python.
Thuật ngữ: Hex (hệ thập lục phân) biểu diễn mỗi byte bằng 2 ký tự (0-9, A-F, ví dụ b'A' -> '41');
n-bit là số lượng bit trong một đơn vị dữ liệu nhỏ (ví dụ n=3 bit nhận giá trị 0..7).
"""

from __future__ import annotations  # dùng để kích hoạt tính năng kiểm tra kiểu dữ liệu tĩnh
from typing import List, Optional, Sequence  # dùng để định nghĩa kiểu danh sách và chuỗi tuần tự


def bytes_sang_so(data: bytes, n: int = 3) -> List[int]:
    """
    Tách mảng bytes thành danh sách các số nguyên n-bit (ví dụ n=3 bit phục vụ TinyRC4).
    Tự động đệm thêm các bit 0 vào cuối nếu số bit tổng cộng không chia hết cho n.

    Tham số:
        data (bytes): Dữ liệu nhị phân đầu vào.
        n (int): Số bit của mỗi đơn vị đầu ra (mặc định n=3, dải giá trị 0..7).

    Trả về:
        List[int]: Danh sách các số nguyên n-bit.

    Ví dụ:
        bytes_sang_so(b"A", n=3) -> [2, 0, 2] (vì 'A'=0b01000001 -> tách [010, 000, 010])
    """
    if not data:
        return []

    bit_str = "".join(f"{b:08b}" for b in data)
    rem = len(bit_str) % n
    if rem != 0:
        bit_str += "0" * (n - rem)

    return [int(bit_str[i : i + n], 2) for i in range(0, len(bit_str), n)]


def so_sang_bytes(
    nums: Sequence[int], n: int = 3, do_dai_goc: Optional[int] = None
) -> bytes:
    """
    Gom danh sách các số nguyên n-bit trở lại thành chuỗi bytes chuẩn (8-bit mỗi byte).
    Loại bỏ các bit đệm ở cuối nếu biết trước độ dài byte gốc (do_dai_goc).

    Tham số:
        nums (Sequence[int]): Danh sách số nguyên n-bit cần ghép lại.
        n (int): Số lượng bit của mỗi phần tử (mặc định n=3).
        do_dai_goc (Optional[int]): Số lượng byte thực tế trước khi tách (tùy chọn).

    Trả về:
        bytes: Mảng byte hoàn chỉnh sau khi ghép lại.

    Ví dụ:
        so_sang_bytes([2, 0, 2], n=3, do_dai_goc=1) -> b'A'
    """
    if not nums:
        return b""

    bit_str = "".join(f"{num:0{n}b}" for num in nums)
    byte_list = bytearray()
    for i in range(0, len(bit_str), 8):
        chunk = bit_str[i : i + 8]
        if len(chunk) == 8:
            byte_list.append(int(chunk, 2))

    res = bytes(byte_list)
    if do_dai_goc is not None:
        return res[:do_dai_goc]
    return res


def bytes_sang_hex(data: bytes) -> str:
    """
    Chuyển đổi dữ liệu nhị phân (bytes) thành chuỗi ký tự thập lục phân (Hex) viết hoa.

    Tham số:
        data (bytes): Chuỗi byte đầu vào cần chuyển đổi.

    Trả về:
        str: Chuỗi hex viết hoa tương ứng (mỗi byte thành 2 ký tự hex, ví dụ: 0x0A -> '0A').

    Ví dụ:
        bytes_sang_hex(b"Wiki") -> '57696B69'
    """
    return data.hex().upper()


def hex_sang_bytes(text: str) -> bytes:
    """
    Chuyển đổi chuỗi Hex thành dữ liệu nhị phân (bytes), tự động xóa bỏ dấu cách thừa.

    Tham số:
        text (str): Chuỗi hex đầu vào (ví dụ: "57 69 6B 69" hoặc "57696B69").

    Trả về:
        bytes: Dãy byte nhị phân được khôi phục từ chuỗi hex.

    Ví dụ:
        hex_sang_bytes("57696B69") -> b'Wiki'
    """
    cleaned = text.replace(" ", "")
    if len(cleaned) % 2 != 0:
        raise ValueError("Chuỗi hex không hợp lệ (số ký tự phải chẵn).")
    try:
        return bytes.fromhex(cleaned)
    except ValueError as e:
        raise ValueError(f"Chuỗi hex không hợp lệ: {e}") from e

