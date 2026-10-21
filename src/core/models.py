from __future__ import annotations

import base64
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# ==============================================================================
# HỢP ĐỒNG DỮ LIỆU CHUNG GIỮA FRONTEND & BACKEND (src/core/models.py)
# ==============================================================================

# Bảng quy đổi 8 chữ cái 3-bit cố định theo Slide 40 & Slide 56-60 (NEU CNTT)
TINY_ALPHABET: Dict[str, int] = {
    "A": 0b000,
    "B": 0b001,
    "C": 0b010,
    "D": 0b011,
    "E": 0b100,
    "F": 0b101,
    "G": 0b110,
    "H": 0b111,
}
INV_TINY_ALPHABET: Dict[int, str] = {v: k for k, v in TINY_ALPHABET.items()}


@dataclass
class KSAStep:
    """Lưu trạng thái 1 vòng lặp trong giai đoạn Khởi tạo dãy S (KSA)."""
    step_i: int
    j_before: int
    s_i_before: int
    t_i: int
    j_after: int
    swapped_pair: str
    s_array: List[int]


@dataclass
class PRGAStep:
    """Lưu trạng thái 1 bước sinh số giả ngẫu nhiên (PRGA) và phép XOR."""
    step_idx: int
    i_val: int
    j_val: int
    t_val: int
    keystream_val: int
    keystream_bin: str
    input_val: int
    input_bin: str
    output_val: int
    output_bin: str
    s_array: List[int]
    char_in: Optional[str] = None
    char_out: Optional[str] = None


@dataclass
class TinyRC4Result:
    """Kết quả toàn diện của TinyRC4 (3-bit, mảng S và T gồm 8 phần tử 0..7)."""
    input_text: str
    input_bits: str
    key_list: List[int]
    initial_s: List[int]
    initial_t: List[int]
    ksa_steps: List[KSAStep]
    final_ksa_s: List[int]
    prga_steps: List[PRGAStep]
    keystream_list: List[int]
    keystream_bits: str
    output_list: List[int]
    output_bits: str
    output_text: str


@dataclass
class FullRC4Result:
    """Kết quả thực thi RC4 đầy đủ (8-bit, mảng S và T gồm 256 phần tử 0..255)."""
    input_bytes: bytes
    key_bytes: bytes
    output_bytes: bytes
    keystream_preview: List[int]
    final_ksa_s: List[int]
    elapsed_ms: float

    @property
    def output_hex(self) -> str:
        return self.output_bytes.hex().upper()

    @property
    def output_base64(self) -> str:
        return base64.b64encode(self.output_bytes).decode("ascii")


@dataclass
class TestCaseComparison:
    """Kết quả 1 ca kiểm thử và đối chiếu với chuẩn (Slide / RFC 6229 / PyCryptodome)."""
    name: str
    category: str
    key_desc: str
    input_desc: str
    expected_hex: str
    actual_hex: str
    decrypted_ok: bool
    passed: bool


@dataclass
class KeystreamAttackResult:
    """Kết quả mô phỏng tấn công dùng lại dòng khóa (Two-Time Pad / Keystream Reuse)."""
    p1_text: str
    p2_text: str
    key_text: str
    c1_hex: str
    c2_hex: str
    xor_c1_c2_hex: str
    xor_p1_p2_hex: str
    streams_equal: bool
    crib_word: str
    crib_matches: List[Tuple[int, str, str]] = field(default_factory=list)


def get_classroom_mock_tiny_rc4() -> TinyRC4Result:
    """
    Hàm Mock dữ liệu mẫu chuẩn Slide 56-60 (BAG / K=[2,1,3] -> EBA)
    Giúp Frontend kiểm thử hiển thị ngay cả khi Backend chưa cài đặt xong.
    """
    ksa_mock = [
        KSAStep(0, 0, 0, 2, 2, "Swap(S[0], S[2])", [2, 1, 0, 3, 4, 5, 6, 7]),
        KSAStep(1, 2, 1, 1, 4, "Swap(S[1], S[4])", [2, 4, 0, 3, 1, 5, 6, 7]),
        KSAStep(2, 4, 0, 3, 7, "Swap(S[2], S[7])", [2, 4, 7, 3, 1, 5, 6, 0]),
        KSAStep(3, 7, 3, 2, 4, "Swap(S[3], S[4])", [2, 4, 7, 1, 3, 5, 6, 0]),
        KSAStep(4, 4, 3, 1, 0, "Swap(S[4], S[0])", [3, 4, 7, 1, 2, 5, 6, 0]),
        KSAStep(5, 0, 5, 3, 0, "Swap(S[5], S[0])", [5, 4, 7, 1, 2, 3, 6, 0]),
        KSAStep(6, 0, 6, 2, 0, "Swap(S[6], S[0])", [6, 4, 7, 1, 2, 3, 5, 0]),
        KSAStep(7, 0, 0, 1, 1, "Swap(S[7], S[1])", [6, 0, 7, 1, 2, 3, 5, 4]),
    ]
    prga_mock = [
        PRGAStep(0, 1, 0, 6, 5, "101", 1, "001", 4, "100", [6, 0, 7, 1, 2, 3, 5, 4], "B", "E"),
        PRGAStep(1, 2, 7, 3, 1, "001", 0, "000", 1, "001", [6, 4, 7, 1, 2, 3, 5, 0], "A", "B"),
        PRGAStep(2, 3, 0, 0, 6, "110", 6, "110", 0, "000", [1, 4, 7, 6, 2, 3, 5, 0], "G", "A"),
    ]
    return TinyRC4Result(
        input_text="BAG",
        input_bits="001 000 110",
        key_list=[2, 1, 3],
        initial_s=[0, 1, 2, 3, 4, 5, 6, 7],
        initial_t=[2, 1, 3, 2, 1, 3, 2, 1],
        ksa_steps=ksa_mock,
        final_ksa_s=[6, 0, 7, 1, 2, 3, 5, 4],
        prga_steps=prga_mock,
        keystream_list=[5, 1, 6],
        keystream_bits="101 001 110",
        output_list=[4, 1, 0],
        output_bits="100 001 000",
        output_text="EBA",
    )
