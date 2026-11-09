"""
Module Chuyển Đổi Định Dạng Dữ Liệu (src/core/chuyen_doi_du_lieu.py)
Cung cấp các hàm biến đổi qua lại giữa nhị phân (bytes), số nguyên n-bit và chuỗi Hex.
Được gọi bởi: phân hệ mã hóa văn bản (tab_rc4_van_ban), mã hóa tệp (tab_rc4_tep_tin) và test suite.
Gọi đến: src.core.mo_hinh_du_lieu và src.core.rc4_chuan.
Thuật ngữ: Hex (hệ thập lục phân) biểu diễn mỗi byte bằng 2 ký tự (0-9, A-F, ví dụ b'A' -> '41');
n-bit là số lượng bit trong một đơn vị dữ liệu nhỏ (ví dụ n=3 bit nhận giá trị 0..7).
"""

from __future__ import annotations  # dùng để kích hoạt tính năng kiểm tra kiểu dữ liệu tĩnh
from typing import List, Optional, Sequence, Tuple  # dùng để định nghĩa kiểu danh sách và chuỗi tuần tự

from src.core.mo_hinh_du_lieu import (  # file nội bộ: cấu trúc dữ liệu UTF-8 và RC4
    Utf8CharBreakdown,
    Utf8DecodeFailure,
    Utf8Rc4Step,
)


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


def phan_tich_ky_tu_utf8(text: str) -> List[Utf8CharBreakdown]:
    """
    Phân tích cấu trúc biểu diễn mã điểm Unicode bằng UTF-8 theo Mục 2.1.4 (Bảng 2.2, 2.3, 2.4).

    Duyệt từng ký tự trong chuỗi văn bản, trích xuất điểm mã Unicode, số byte, mẫu bit phân bố
    (template), các bit dữ liệu và dãy byte UTF-8 tương ứng.

    Tham số:
        text (str): Chuỗi ký tự Unicode đầu vào (ví dụ: "Aà").

    Trả về:
        List[Utf8CharBreakdown]: Danh sách phân tích chi tiết từng ký tự.

    Ví dụ:
        phan_tich_ky_tu_utf8("Aà") -> phân tích ký tự 'A' (1 byte: 65, 0x41) và 'à' (2 byte: 195, 160).
    """
    res: List[Utf8CharBreakdown] = []
    for ch in text:
        cp = ord(ch)
        cp_hex = f"U+{cp:04X}"
        b_data = ch.encode("utf-8")
        dec_list = list(b_data)
        b_count = len(b_data)
        hex_str = " ".join(f"{b:02X}" for b in b_data)
        bin_str = " ".join(f"{b:08b}" for b in b_data)

        if cp <= 0x007F:
            pattern = "0xxxxxxx"
            data_bits = f"{cp:07b}"
        elif cp <= 0x07FF:
            pattern = "110xxxxx 10xxxxxx"
            cp_bin11 = f"{cp:011b}"
            data_bits = f"{cp_bin11[:5]} {cp_bin11[5:]}"
        elif cp <= 0xFFFF:
            pattern = "1110xxxx 10xxxxxx 10xxxxxx"
            cp_bin16 = f"{cp:016b}"
            data_bits = f"{cp_bin16[:4]} {cp_bin16[4:10]} {cp_bin16[10:]}"
        else:
            pattern = "11110xxx 10xxxxxx 10xxxxxx 10xxxxxx"
            cp_bin21 = f"{cp:021b}"
            data_bits = f"{cp_bin21[:3]} {cp_bin21[3:9]} {cp_bin21[9:15]} {cp_bin21[15:]}"

        res.append(
            Utf8CharBreakdown(
                char=ch,
                codepoint=cp_hex,
                codepoint_dec=cp,
                byte_count=b_count,
                utf8_bytes=b_data,
                hex_str=hex_str,
                bin_str=bin_str,
                pattern=pattern,
                data_bits=data_bits,
                byte_dec_list=dec_list,
            )
        )
    return res


def trace_rc4_utf8_xor(text: str, key_bytes: bytes) -> List[Utf8Rc4Step]:
    """
    Theo dõi chi tiết từng bước 8-bit XOR giữa byte bản rõ UTF-8 và byte dòng khóa RC4 (Mục 2.1.4, Bảng 2.5).

    Mỗi byte bản rõ P_r được XOR với 1 byte dòng khóa Z_r: C_r = P_r XOR Z_r.
    Chuỗi 'Aà' với khóa K=[1, 2, 3, 4, 5] cho dòng khóa đầu Z=[178, 57, 99],
    bản mã C=[243, 250, 195] (F3 FA C3).

    Tham số:
        text (str): Chuỗi bản rõ văn bản UTF-8.
        key_bytes (bytes): Khóa RC4 dạng mảng byte.

    Trả về:
        List[Utf8Rc4Step]: Danh sách thông tin chi tiết từng byte mã hóa.
    """
    from src.core.rc4_chuan import rc4_crypt

    pt_bytes = text.encode("utf-8")
    if not pt_bytes or not key_bytes:
        return []

    # Ánh xạ từng byte nhị phân về ký tự nguồn tương ứng trong text
    byte_to_char_map: List[str] = []
    for ch in text:
        ch_bytes_len = len(ch.encode("utf-8"))
        for _ in range(ch_bytes_len):
            byte_to_char_map.append(ch)

    cipher_bytes = rc4_crypt(pt_bytes, key_bytes)
    keystream = [p ^ c for p, c in zip(pt_bytes, cipher_bytes)]

    steps: List[Utf8Rc4Step] = []
    for idx in range(len(pt_bytes)):
        r = idx + 1
        p_val = pt_bytes[idx]
        z_val = keystream[idx]
        c_val = cipher_bytes[idx]

        p_bin = f"{p_val:08b}"
        z_bin = f"{z_val:08b}"
        c_bin = f"{c_val:08b}"

        steps.append(
            Utf8Rc4Step(
                r=r,
                char_ref=byte_to_char_map[idx] if idx < len(byte_to_char_map) else "?",
                p_val=p_val,
                p_bin=p_bin,
                p_hex=f"{p_val:02X}",
                z_val=z_val,
                z_bin=z_bin,
                z_hex=f"{z_val:02X}",
                c_val=c_val,
                c_bin=c_bin,
                c_hex=f"{c_val:02X}",
                xor_expr=f"{p_bin} ⊕ {z_bin} = {c_bin}",
            )
        )
    return steps


def kiem_tra_giai_ma_utf8_ban_ma(
    cipher_bytes: bytes,
) -> Tuple[bool, str, Optional[Utf8DecodeFailure]]:
    """
    Kiểm tra khả năng giải mã UTF-8 trực tiếp trên bản mã C và phân tích lỗi vi phạm tiền tố (Mục 2.1.4).

    Giải thích vì sao phép XOR biến bản rõ thành các byte ngẫu nhiên thường vi phạm quy tắc tiền tố
    UTF-8 (RFC 3629), dẫn đến lỗi UnicodeDecodeError và khẳng định bản mã bắt buộc phải được lưu nhị phân
    hoặc mã hóa qua Hex / Base64.

    Tham số:
        cipher_bytes (bytes): Dãy byte bản mã C.

    Trả về:
        Tuple[bool, str, Optional[Utf8DecodeFailure]]:
            - bool: True nếu giải mã UTF-8 thành công, False nếu thất bại.
            - str: Thông điệp phân tích sư phạm chi tiết.
            - Optional[Utf8DecodeFailure]: Dữ liệu lỗi cấu trúc nếu giải mã thất bại.
    """
    if not cipher_bytes:
        return True, "Bản mã rỗng, giải mã hợp lệ thành chuỗi rỗng.", None

    try:
        decoded_text = cipher_bytes.decode("utf-8")
        return (
            True,
            f"Bản mã ngẫu nhiên trùng hợp tạo thành chuỗi UTF-8 hợp lệ: '{decoded_text}'. "
            "Tuy nhiên đây chỉ là sự trùng hợp ngẫu nhiên và rất hiếm gặp với dữ liệu dài.",
            None,
        )
    except UnicodeDecodeError as exc:
        err_idx = exc.start
        err_byte = cipher_bytes[err_idx]
        err_bin = f"{err_byte:08b}"
        err_hex = f"{err_byte:02X}"

        next_val: Optional[int] = (
            cipher_bytes[err_idx + 1] if err_idx + 1 < len(cipher_bytes) else None
        )
        next_bin = f"{next_val:08b}" if next_val is not None else None
        next_hex = f"{next_val:02X}" if next_val is not None else None

        if err_bin.startswith("11110"):
            prefix_info = "tiền tố 11110 (báo hiệu ký tự 4-byte theo RFC 3629, đòi hỏi 3 byte tiếp theo bắt đầu bằng 10xxxxxx)"
        elif err_bin.startswith("1110"):
            prefix_info = "tiền tố 1110 (báo hiệu ký tự 3-byte theo RFC 3629, đòi hỏi 2 byte tiếp theo bắt đầu bằng 10xxxxxx)"
        elif err_bin.startswith("110"):
            prefix_info = "tiền tố 110 (báo hiệu ký tự 2-byte theo RFC 3629, đòi hỏi byte tiếp theo bắt đầu bằng 10xxxxxx)"
        elif err_bin.startswith("10"):
            prefix_info = "tiền tố 10xxxxxx (byte tiếp diễn / continuation byte, không được phép đứng độc lập ở đầu chuỗi ký tự)"
        else:
            prefix_info = "dạng byte không hợp lệ trong cấu trúc chuẩn của UTF-8"

        if next_val is not None:
            if not next_bin.startswith("10"):
                reason = (
                    f"Byte thứ {err_idx + 1} (giá trị {err_byte}, Hex 0x{err_hex}, nhị phân {err_bin}) có {prefix_info}. "
                    f"Tuy nhiên byte tiếp theo tại vị trí {err_idx + 2} (giá trị {next_val}, Hex 0x{next_hex}, nhị phân {next_bin}) "
                    f"bắt đầu bằng '{next_bin[:6]}' thay vì tiền tố '10xxxxxx' chuẩn. "
                    "Vì vậy trình giải mã UTF-8 từ chối và phát sinh ngoại lệ UnicodeDecodeError."
                )
            else:
                reason = (
                    f"Byte thứ {err_idx + 1} (giá trị {err_byte}, Hex 0x{err_hex}, nhị phân {err_bin}) có {prefix_info}, "
                    f"nhưng dãy byte kế tiếp không hoàn tất đủ số byte tiếp diễn hợp lệ."
                )
        else:
            reason = (
                f"Byte thứ {err_idx + 1} (giá trị {err_byte}, Hex 0x{err_hex}, nhị phân {err_bin}) có {prefix_info}, "
                "nhưng chuỗi bản mã kết thúc đột ngột thiếu các byte tiếp diễn."
            )

        failure_obj = Utf8DecodeFailure(
            err_index=err_idx,
            err_byte_val=err_byte,
            err_byte_bin=err_bin,
            err_byte_hex=err_hex,
            next_byte_val=next_val,
            next_byte_bin=next_bin,
            next_byte_hex=next_hex,
            violation_reason=reason,
            python_err_msg=str(exc),
        )

        pedagogical_msg = (
            f"❌ KHÔNG THỂ GIẢI MÃ UTF-8 TRỰC TIẾP TRÊN BẢN MÃ C:\n"
            f"Lỗi: UnicodeDecodeError: {exc}\n\n"
            f"Phân tích nguyên nhân (Mục 2.1.4):\n"
            f"{reason}\n\n"
            f"👉 KẾT LUẬN: Lõi RC4 XOR tạo ra dãy byte ngẫu nhiên. Bản mã C KHÔNG PHẢI là văn bản UTF-8 hợp lệ. "
            f"Để lưu trữ và truyền tải an toàn, bắt buộc phải lưu dạng nhị phân thuần túy hoặc chuyển đổi sang Hex/Base64."
        )

        return False, pedagogical_msg, failure_obj


