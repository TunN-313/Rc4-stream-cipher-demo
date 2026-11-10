"""
BƯỚC 1: XỬ LÝ ĐẦU VÀO, UTF-8 & QUẢN LÝ KHÓA (src/core/buoc1_xu_ly_dau_vao.py)
Nhiệm vụ:
  - Phân tích cấu trúc byte Unicode / UTF-8 (Bảng 1, Bảng 2.2, 2.3, 2.4).
  - Chuyển đổi linh hoạt giữa nhị phân (bytes), số nguyên n-bit, chuỗi Hex.
  - Quản lý và sinh khóa ngẫu nhiên đạt chuẩn an toàn mật mã CSPRNG.
"""

from __future__ import annotations
import secrets
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

# Bảng quy đổi 8 chữ cái 3-bit cho TinyRC4 
TINY_ALPHABET: Dict[str, int] = {
    "A": 0b000, "B": 0b001, "C": 0b010, "D": 0b011,
    "E": 0b100, "F": 0b101, "G": 0b110, "H": 0b111,
}
INV_TINY_ALPHABET: Dict[int, str] = {v: k for k, v in TINY_ALPHABET.items()}
KHOA_TOI_DA_RC4 = 256
KHOA_TOI_DA_TINY = 8


# ==============================================================================
# CẤU TRÚC DỮ LIỆU UTF-8
# ==============================================================================

@dataclass
class Utf8CharBreakdown:
    """Phân rã cấu trúc UTF-8 của một ký tự Unicode."""
    char: str
    codepoint: str
    codepoint_dec: int
    byte_count: int
    utf8_bytes: bytes
    hex_str: str
    bin_str: str
    pattern: str
    data_bits: str
    byte_dec_list: List[int] = field(default_factory=list)


@dataclass
class Utf8Rc4Step:
    """Chi tiết từng bước 8-bit XOR giữa byte UTF-8 và byte dòng khóa RC4."""
    r: int
    char_ref: str
    p_val: int
    p_bin: str
    p_hex: str
    z_val: int
    z_bin: str
    z_hex: str
    c_val: int
    c_bin: str
    c_hex: str
    xor_expr: str


@dataclass
class Utf8DecodeFailure:
    """Thông tin chẩn đoán lỗi khi giải mã UTF-8 trực tiếp trên bản mã RC4."""
    err_index: int
    err_byte_val: int
    err_byte_bin: str
    err_byte_hex: str
    next_byte_val: Optional[int]
    next_byte_bin: Optional[str]
    next_byte_hex: Optional[str]
    violation_reason: str
    python_err_msg: str


# ==============================================================================
# CHUYỂN ĐỔI ĐỊNH DẠNG DỮ LIỆU
# ==============================================================================

def van_ban_sang_bytes(van_ban: str) -> bytes:
    """Chuyển chuỗi văn bản UTF-8 sang mảng byte nhị phân."""
    return van_ban.encode("utf-8")


def bytes_sang_van_ban(du_lieu: bytes) -> str:
    """Giải mã an toàn mảng byte thành chuỗi UTF-8."""
    return du_lieu.decode("utf-8", errors="replace")


def bytes_sang_hex(data: bytes) -> str:
    """Chuyển đổi dữ liệu nhị phân thành chuỗi Hexadecimal viết hoa."""
    return data.hex().upper()


def hex_sang_bytes(text: str) -> bytes:
    """Chuyển đổi chuỗi Hex thành mảng byte nhị phân."""
    clean = "".join(text.split())
    if len(clean) % 2 != 0:
        clean = "0" + clean
    return bytes.fromhex(clean)


def bytes_sang_so(data: bytes, n: int = 3) -> List[int]:
    """Tách mảng bytes thành danh sách các số nguyên n-bit (0..7 cho TinyRC4)."""
    if not data:
        return []
    bit_str = "".join(f"{b:08b}" for b in data)
    rem = len(bit_str) % n
    if rem != 0:
        bit_str += "0" * (n - rem)
    return [int(bit_str[i : i + n], 2) for i in range(0, len(bit_str), n)]


def so_sang_bytes(nums: Sequence[int], n: int = 3, do_dai_goc: Optional[int] = None) -> bytes:
    """Gom danh sách số nguyên n-bit trở lại thành chuỗi bytes chuẩn 8-bit."""
    if not nums:
        return b""
    bit_str = "".join(f"{num:0{n}b}" for num in nums)
    byte_list = bytearray()
    for i in range(0, len(bit_str), 8):
        chunk = bit_str[i : i + 8]
        if len(chunk) == 8:
            byte_list.append(int(chunk, 2))
    res = bytes(byte_list)
    return res[:do_dai_goc] if do_dai_goc is not None else res


# ==============================================================================
# PHÂN TÍCH UTF-8 & MINH HỌA
# ==============================================================================

def phan_tich_ky_tu_utf8(text: str) -> List[Utf8CharBreakdown]:
    """Phân tích từng ký tự trong chuỗi văn bản ra mã điểm, số byte và mẫu bit UTF-8."""
    result: List[Utf8CharBreakdown] = []
    for ch in text:
        b = ch.encode("utf-8")
        cp = ord(ch)
        cp_hex = f"U+{cp:04X}"
        byte_count = len(b)
        hex_str = " ".join(f"{byte:02X}" for byte in b)
        bin_str = " ".join(f"{byte:08b}" for byte in b)
        byte_decs = list(b)

        if byte_count == 1:
            pattern = "0xxxxxxx"
            data_bits = f"{cp:07b}"
        elif byte_count == 2:
            pattern = "110xxxxx 10xxxxxx"
            b1_data = f"{b[0] & 0x1F:05b}"
            b2_data = f"{b[1] & 0x3F:06b}"
            data_bits = f"{b1_data} {b2_data}"
        elif byte_count == 3:
            pattern = "1110xxxx 10xxxxxx 10xxxxxx"
            b1_data = f"{b[0] & 0x0F:04b}"
            b2_data = f"{b[1] & 0x3F:06b}"
            b3_data = f"{b[2] & 0x3F:06b}"
            data_bits = f"{b1_data} {b2_data} {b3_data}"
        else:
            pattern = "11110xxx 10xxxxxx 10xxxxxx 10xxxxxx"
            b1_data = f"{b[0] & 0x07:03b}"
            b2_data = f"{b[1] & 0x3F:06b}"
            b3_data = f"{b[2] & 0x3F:06b}"
            b4_data = f"{b[3] & 0x3F:06b}"
            data_bits = f"{b1_data} {b2_data} {b3_data} {b4_data}"

        result.append(
            Utf8CharBreakdown(
                char=ch,
                codepoint=cp_hex,
                codepoint_dec=cp,
                byte_count=byte_count,
                utf8_bytes=b,
                hex_str=hex_str,
                bin_str=bin_str,
                pattern=pattern,
                data_bits=data_bits,
                byte_dec_list=byte_decs,
            )
        )
    return result


def trace_rc4_utf8_xor(text: str, keystream_bytes: Sequence[int]) -> List[Utf8Rc4Step]:
    """Tạo bảng diễn giải từng bước 8-bit XOR giữa byte bản rõ UTF-8 và byte dòng khóa RC4."""
    p_bytes = text.encode("utf-8")
    char_map: List[str] = []
    for ch in text:
        cb = ch.encode("utf-8")
        for _ in cb:
            char_map.append(ch)

    steps: List[Utf8Rc4Step] = []
    for r in range(len(p_bytes)):
        p_val = p_bytes[r]
        z_val = keystream_bytes[r] if r < len(keystream_bytes) else 0
        c_val = p_val ^ z_val
        p_bin = f"{p_val:08b}"
        z_bin = f"{z_val:08b}"
        c_bin = f"{c_val:08b}"
        p_hex = f"{p_val:02X}"
        z_hex = f"{z_val:02X}"
        c_hex = f"{c_val:02X}"
        ch_ref = char_map[r] if r < len(char_map) else "?"

        steps.append(
            Utf8Rc4Step(
                r=r + 1,
                char_ref=ch_ref,
                p_val=p_val,
                p_bin=p_bin,
                p_hex=p_hex,
                z_val=z_val,
                z_bin=z_bin,
                z_hex=z_hex,
                c_val=c_val,
                c_bin=c_bin,
                c_hex=c_hex,
                xor_expr=f"{p_bin} ⊕ {z_bin} = {c_bin}",
            )
        )
    return steps


def kiem_tra_giai_ma_utf8_ban_ma(ciphertext: bytes) -> Tuple[bool, Optional[Utf8DecodeFailure]]:
    """Kiểm tra giải mã UTF-8 trực tiếp trên bản mã để phát hiện vi phạm tiền tố RFC 3629."""
    try:
        ciphertext.decode("utf-8")
        return True, None
    except UnicodeDecodeError as exc:
        idx = exc.start
        bad_byte = ciphertext[idx]
        bad_bin = f"{bad_byte:08b}"
        bad_hex = f"{bad_byte:02X}"

        next_b: Optional[int] = None
        next_bin: Optional[str] = None
        next_hex: Optional[str] = None
        if idx + 1 < len(ciphertext):
            next_b = ciphertext[idx + 1]
            next_bin = f"{next_b:08b}"
            next_hex = f"{next_b:02X}"

        reason = "Vi phạm cấu trúc tiền tố byte RFC 3629"
        if 0x80 <= bad_byte <= 0xBF:
            reason = f"Byte 0x{bad_hex} mang tiền tố '10xxxxxx' (byte nối tiếp) nhưng lại đứng ở vị trí bắt đầu ký tự."
        elif bad_byte in (0xC0, 0xC1):
            reason = f"Byte 0x{bad_hex} thuộc dải overlong encoding bị cấm bởi RFC 3629."
        elif 0xC2 <= bad_byte <= 0xDF:
            reason = f"Byte 0x{bad_hex} báo hiệu chuỗi 2-byte, nhưng byte kế tiếp không phải byte nối tiếp hợp lệ ('10xxxxxx')."
        elif 0xE0 <= bad_byte <= 0xEF:
            reason = f"Byte 0x{bad_hex} báo hiệu chuỗi 3-byte, nhưng các byte kế tiếp vi phạm quy tắc tiền tố."
        elif 0xF0 <= bad_byte <= 0xF4:
            reason = f"Byte 0x{bad_hex} báo hiệu chuỗi 4-byte, nhưng dữ liệu không thỏa mãn giới hạn Unicode."
        elif bad_byte >= 0xF5:
            reason = f"Byte 0x{bad_hex} nằm ngoài phạm vi biểu diễn của chuẩn UTF-8 (vượt quá 4 byte)."

        failure = Utf8DecodeFailure(
            err_index=idx,
            err_byte_val=bad_byte,
            err_byte_bin=bad_bin,
            err_byte_hex=bad_hex,
            next_byte_val=next_b,
            next_byte_bin=next_bin,
            next_byte_hex=next_hex,
            violation_reason=reason,
            python_err_msg=str(exc),
        )
        return False, failure


# ==============================================================================
# QUẢN LÝ & SINH KHÓA BẢO MẬT
# ==============================================================================

def sinh_khoa_rc4(so_byte: int = 16) -> bytes:
    """Sinh khóa RC4 ngẫu nhiên """
    if so_byte < 1 or so_byte > KHOA_TOI_DA_RC4:
        raise ValueError(f"Độ dài khóa RC4 phải từ 1 đến {KHOA_TOI_DA_RC4} byte.")
    return secrets.token_bytes(so_byte)


def khoa_tu_chuoi(chuoi_khoa: str) -> bytes:
    """Chuyển chuỗi văn bản thường thành mảng byte làm khóa bí mật."""
    khoa_bytes = chuoi_khoa.encode("utf-8")
    if not khoa_bytes:
        raise ValueError("Khóa bí mật không được rỗng.")
    if len(khoa_bytes) > KHOA_TOI_DA_RC4:
        raise ValueError(f"Khóa vượt quá độ dài tối đa ({KHOA_TOI_DA_RC4} byte).")
    return khoa_bytes


def khoa_tu_hex(chuoi_hex: str) -> bytes:
    """Chuyển chuỗi Hex thành mảng byte làm khóa bí mật."""
    khoa_bytes = hex_sang_bytes(chuoi_hex)
    if not khoa_bytes:
        raise ValueError("Khóa Hex không được rỗng.")
    if len(khoa_bytes) > KHOA_TOI_DA_RC4:
        raise ValueError(f"Khóa vượt quá độ dài tối đa ({KHOA_TOI_DA_RC4} byte).")
    return khoa_bytes


def sinh_khoa_tiny(so_phan_tu: int = 3) -> List[int]:
    """Sinh ngẫu nhiên khóa cho TinyRC4 gồm các số từ 0 đến 7."""
    return [secrets.randbelow(KHOA_TOI_DA_TINY) for _ in range(so_phan_tu)]


def tiny_chuoi_sang_so(van_ban: str) -> List[int]:
    """Chuyển đổi chuỗi chữ cái A-H thành danh sách số 3-bit (0-7)."""
    ket_qua = []
    for c in van_ban.upper():
        if c in TINY_ALPHABET:
            ket_qua.append(TINY_ALPHABET[c])
        elif c.isdigit() and 0 <= int(c) <= 7:
            ket_qua.append(int(c))
    return ket_qua


def tiny_so_sang_chuoi(cac_so: List[int]) -> str:
    """Chuyển đổi danh sách số 3-bit (0-7) thành chữ cái A-H."""
    return "".join(INV_TINY_ALPHABET.get(n % 8, "A") for n in cac_so)
