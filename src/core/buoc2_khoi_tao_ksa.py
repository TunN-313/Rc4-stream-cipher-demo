"""Bước 2: Thuật toán sinh hoán vị KSA cho TinyRC4 và RC4."""

from __future__ import annotations
from dataclasses import dataclass
from typing import List, Tuple, Dict, Any


@dataclass
class KSAStep:
    """Lưu vết trạng thái mảng S và các biến chỉ mục tại từng vòng lặp KSA."""
    step_i: int
    j_before: int
    s_i_before: int
    t_i: int
    j_after: int
    swapped_pair: str
    s_array: List[int]


def rc4_ksa(key_bytes: bytes) -> List[int]:
    """Khởi tạo và xáo trộn mảng S 256 phần tử theo modulo 256."""
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
    """Khởi tạo và ghi nhận từng bước hoán vị mảng S (N=8 phần tử, modulo 8) cho TinyRC4."""
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
