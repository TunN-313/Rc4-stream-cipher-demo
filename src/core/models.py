"""
Mô hình dữ liệu lõi của hệ mã RC4 (src/core/models.py)
Định nghĩa các lớp dữ liệu chứa trạng thái từng bước xáo trộn mảng S và sinh dòng khóa.
Được gọi bởi: toàn bộ backend (rc4, tiny_rc4, analysis) và frontend (src/ui/).
Gọi đến: không gọi file nội bộ nào khác, chỉ dùng thư viện chuẩn Python.
"""

from __future__ import annotations  # dùng để hỗ trợ khai báo kiểu dữ liệu hiện đại
import base64  # dùng để mã hóa nhị phân sang chuỗi văn bản Base64 hiển thị an toàn
from dataclasses import dataclass, field  # dùng để tạo các lớp chứa dữ liệu tự động sinh hàm khởi tạo
from typing import Dict, List, Optional, Tuple  # dùng để định nghĩa kiểu dữ liệu danh sách, từ điển

# ==============================================================================
# HỢP ĐỒNG DỮ LIỆU CHUNG GIỮA FRONTEND & BACKEND (src/core/models.py)
# ==============================================================================

# Bảng quy đổi 8 chữ cái 3-bit cố định theo Slide 40 & Slide 56-60 (NEU CNTT)
# Mỗi chữ cái tương ứng một số từ 0 đến 7 (ví dụ: 'A' là 0b000 = 0, 'B' là 0b001 = 1)
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
    """
    Lưu chi tiết 1 vòng lặp trong giai đoạn KSA (Key-Scheduling Algorithm - xáo mảng S bằng khóa).
    Ví dụ: tại bước i=0, hoán vị phần tử S[0] với S[j] dựa vào giá trị khóa bí mật.
    """
    step_i: int
    j_before: int
    s_i_before: int
    t_i: int
    j_after: int
    swapped_pair: str
    s_array: List[int]


@dataclass
class PRGAStep:
    """
    Lưu 1 bước của giai đoạn PRGA (Pseudo-Random Generation Algorithm - thuật toán sinh số ngẫu nhiên).
    Tại mỗi bước, thuật toán hoán vị mảng S, trích xuất 1 byte keystream và XOR với byte bản rõ.
    Ví dụ: bước 0 trích byte dòng khóa k=5 (101) để XOR với ký tự đầu vào P='B' (001) ra C='E' (100).
    """
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
    """
    Kết quả mô phỏng toàn diện TinyRC4 (mô hình học tập 3-bit, mảng S gồm 8 phần tử từ 0 đến 7).
    Chứa lịch sử từng bước KSA và PRGA để hiển thị bảng trực quan trên giao diện lớp học.
    Ví dụ: mã hóa bản rõ 'BAG' với khóa [2, 1, 3] tạo ra bản mã 'EBA'.
    """
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
    """
    Kết quả thực thi thuật toán RC4 chuẩn quốc tế (8-bit, mảng S gồm 256 phần tử từ 0 đến 255).
    Chứa dữ liệu bản mã ra, dòng khóa xem trước (keystream preview) và thời gian thực thi.
    Ví dụ: mã hóa b'Plaintext' với khóa b'Key' ra chuỗi byte hex 'BBF316E8D940AF0AD3'.
    """
    input_bytes: bytes
    key_bytes: bytes
    output_bytes: bytes
    keystream_preview: List[int]
    final_ksa_s: List[int]
    elapsed_ms: float

    @property
    def output_hex(self) -> str:
        """Chuyển đổi dữ liệu bản mã đầu ra thành chuỗi Hex viết hoa (ví dụ: b'\\xab' -> 'AB')."""
        return self.output_bytes.hex().upper()

    @property
    def output_base64(self) -> str:
        """Mã hóa bản mã thành chuỗi Base64 an toàn cho truyền tải web thương mại điện tử."""
        return base64.b64encode(self.output_bytes).decode("ascii")


@dataclass
class TestCaseComparison:
    """
    Kết quả đối chiếu 1 ca kiểm thử thuật toán với đáp án chuẩn lý thuyết (Slide NEU hoặc RFC 6229).
    So sánh giá trị hex tạo ra với giá trị hex kỳ vọng để xác nhận độ chính xác 100%.
    """
    name: str
    category: str
    key_desc: str
    input_desc: str
    expected_hex: str
    actual_hex: str
    decrypted_ok: bool
    passed: bool


@dataclass
class CribCandidate:
    """
    Một ứng viên giải mã khi thực hiện thám mã đoán từ (crib-dragging) trên hai bản mã trùng khóa.
    Chứa vị trí pos trượt từ, từ đoán trước, chuỗi giải mã thu được và điểm khả thi đọc được.
    """
    pos: int
    crib: str
    recovered: str
    score: float
    matches_real: bool


@dataclass
class KeystreamAttackResult:
    """
    Kết quả phân tích tấn công Two-Time Pad (dùng lại dòng khóa cho hai bản rõ P1 và P2 khác nhau).
    Khai thác tính chất C1 ^ C2 = P1 ^ P2 để triệt tiêu hoàn toàn khóa bí mật K.
    """
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
    crib_candidates: List[CribCandidate] = field(default_factory=list)
    crib_in: str = "p1"
    len_p1: int = 0
    len_p2: int = 0


