"""
Gói lõi thuật toán mật mã (src/core/__init__.py)
Tập hợp và công bố toàn bộ các hàm toán học, mô hình dữ liệu và công cụ phân tích RC4.
Được gọi bởi: tầng giao diện người dùng (src/ui/) và bộ kiểm thử tự động (tests/).
Gọi đến: các file nội bộ models, tiny_rc4, rc4, analysis, keys, encoding.
"""

from src.core.models import (  # file nội bộ của dự án: cấu trúc dữ liệu kết quả thuật toán
    INV_TINY_ALPHABET,
    TINY_ALPHABET,
    CribCandidate,
    FullRC4Result,
    KSAStep,
    KeystreamAttackResult,
    PRGAStep,
    TestCaseComparison,
    TinyRC4Result,
)
from src.core.tiny_rc4 import parse_tiny_input, parse_tiny_key, run_tiny_rc4  # file nội bộ của dự án: thuật toán TinyRC4 3-bit
from src.core.rc4 import rc4_ksa, rc4_crypt, rc4_crypt_with_details, rc4_crypt_chunks  # file nội bộ của dự án: mã RC4 chuẩn 8-bit
from src.core.analysis import (  # file nội bộ của dự án: phân tích an toàn và đo tốc độ
    keystream_bias_counts,
    run_rc4_benchmark,
    score_readable,
    simulate_keystream_reuse_attack,
)
from src.core.keys import (  # file nội bộ của dự án: tạo và chuẩn hóa khóa bí mật
    KHOA_TOI_DA_RC4,
    KHOA_TOI_DA_TINY,
    sinh_khoa_rc4,
    khoa_tu_chuoi,
    khoa_tu_hex,
    sinh_khoa_tiny,
)
from src.core.encoding import (  # file nội bộ của dự án: đổi dạng bytes, số và chuỗi hex
    bytes_sang_so,
    so_sang_bytes,
    bytes_sang_hex,
    hex_sang_bytes,
)

__all__ = [
    "TINY_ALPHABET",
    "INV_TINY_ALPHABET",
    "KSAStep",
    "PRGAStep",
    "TinyRC4Result",
    "FullRC4Result",
    "TestCaseComparison",
    "KeystreamAttackResult",
    "CribCandidate",
    "parse_tiny_input",
    "parse_tiny_key",
    "run_tiny_rc4",
    "rc4_ksa",
    "rc4_crypt",
    "rc4_crypt_with_details",
    "rc4_crypt_chunks",
    "score_readable",
    "simulate_keystream_reuse_attack",
    "run_rc4_benchmark",
    "keystream_bias_counts",
    "KHOA_TOI_DA_RC4",
    "KHOA_TOI_DA_TINY",
    "sinh_khoa_rc4",
    "khoa_tu_chuoi",
    "khoa_tu_hex",
    "sinh_khoa_tiny",
    "bytes_sang_so",
    "so_sang_bytes",
    "bytes_sang_hex",
    "hex_sang_bytes",
]
