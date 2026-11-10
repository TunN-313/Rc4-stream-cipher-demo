"""
BƯỚC 2: KHỞI TẠO HOÁN VỊ KSA (src/core/buoc2_khoi_tao_ksa.py)
Nhiệm vụ: Cài đặt thuật toán xáo trộn mảng S bằng khóa K (Key-Scheduling Algorithm)
cho cả mô hình TinyRC4 3-bit (modulo 8) và RC4 Chuẩn 8-bit (modulo 256).
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import List, Tuple, Dict, Any


@dataclass
class KSAStep:
    """Lưu chi tiết 1 vòng lặp trong giai đoạn KSA."""
    step_i: int
    j_before: int
    s_i_before: int
    t_i: int
    j_after: int
    swapped_pair: str
    s_array: List[int]


def rc4_ksa(key_bytes: bytes) -> List[int]:
    """
    KSA cho RC4 chuẩn 8-bit (256 phần tử, modulo 256):
    Khởi tạo S[i] = i, xáo trộn bằng T[i] = K[i % len(K)].
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


def ksa_tiny_rc4(khoa_so: List[int]) -> Tuple[List[int], List[KSAStep]]:
    """
    KSA cho TinyRC4 (N=8 phần tử, Modulo 8):
    Khởi tạo mảng S = [0..7], dùng khóa K để hoán vị 8 vòng.
    """
    if not khoa_so:
        raise ValueError("Khóa TinyRC4 không được để trống.")

    N = 8
    S = list(range(N))
    T = [khoa_so[i % len(khoa_so)] for i in range(N)]
    steps: List[KSAStep] = []

    j = 0
    for i in range(N):
        j_before = j
        s_i_before = S[i]
        t_i = T[i]
        j = (j + S[i] + T[i]) % N
        S[i], S[j] = S[j], S[i]
        steps.append(
            KSAStep(
                step_i=i,
                j_before=j_before,
                s_i_before=s_i_before,
                t_i=t_i,
                j_after=j,
                swapped_pair=f"S[{i}]={s_i_before} <-> S[{j}]={S[i]}",
                s_array=list(S),
            )
        )

    return S, steps
