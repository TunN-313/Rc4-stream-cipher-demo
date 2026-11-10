"""
GÓI LÕI THUẬT TOÁN RC4 (src/core/__init__.py)
Tập hợp và công bố toàn bộ các hàm toán học, mô hình dữ liệu và công cụ phân tích RC4
từ 4 module phân theo thứ tự 4 bước xử lý nghiệp vụ.
"""

from __future__ import annotations

# Bước 1: Xử lý đầu vào, UTF-8 & Quản lý khóa
from src.core.buoc1_xu_ly_dau_vao import (
    TINY_ALPHABET,
    INV_TINY_ALPHABET,
    KHOA_TOI_DA_RC4,
    KHOA_TOI_DA_TINY,
    Utf8CharBreakdown,
    Utf8Rc4Step,
    Utf8DecodeFailure,
    van_ban_sang_bytes,
    bytes_sang_van_ban,
    bytes_sang_hex,
    hex_sang_bytes,
    bytes_sang_so,
    so_sang_bytes,
    phan_tich_ky_tu_utf8,
    trace_rc4_utf8_xor,
    kiem_tra_giai_ma_utf8_ban_ma,
    sinh_khoa_rc4,
    khoa_tu_chuoi,
    khoa_tu_hex,
    sinh_khoa_tiny,
    tiny_chuoi_sang_so,
    tiny_so_sang_chuoi,
)

# Bước 2: Khởi tạo hoán vị KSA
from src.core.buoc2_khoi_tao_ksa import (
    KSAStep,
    rc4_ksa,
    ksa_tiny_rc4,
)

# Bước 3: Sinh dòng khóa PRGA & Mã hóa
from src.core.buoc3_sinh_so_prga import (
    PRGAStep,
    TinyRC4Result,
    FullRC4Result,
    rc4_crypt,
    rc4_crypt_with_details,
    rc4_crypt_chunks,
    parse_tiny_input,
    parse_tiny_key,
    run_tiny_rc4,
)

# Bước 4: Thám mã & Phân tích an toàn (FMS WEP & Benchmark)
from src.core.buoc4_tham_ma_be_khoa import (
    FMSByteResult,
    FMSAttackResult,
    fms_partial_ksa,
    fms_predict_first_output,
    simulate_fms_wep_attack,
    run_rc4_benchmark,
)
