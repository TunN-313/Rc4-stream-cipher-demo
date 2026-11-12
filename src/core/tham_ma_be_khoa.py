"""
THÁM MÃ & PHÂN TÍCH AN TOÀN MẬT MÃ (src/core/tham_ma_be_khoa.py)
Nhiệm vụ: Cung cấp thuật toán thám mã thực nghiệm an toàn mật mã:
  1. Tấn công FMS (Fluhrer–Mantin–Shamir) bẻ khóa WEP thông qua IV yếu.
  2. Đo tốc độ xử lý mã hóa RC4 (Benchmark).
"""

from __future__ import annotations
import random
import secrets
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any, Sequence, Union

from src.core.buoc2_khoi_tao_ksa import rc4_ksa
from src.core.buoc3_sinh_so_prga import rc4_crypt


# ==============================================================================
# CẤU TRÚC DỮ LIỆU THÁM MÃ FMS
# ==============================================================================

@dataclass
class FMSByteResult:
    """Kết quả suy luận thống kê cho một byte của khóa bí mật trong FMS WEP."""
    byte_index: int
    true_byte: int
    recovered_byte: int
    matched: bool
    top_votes: int
    total_samples: int
    top_candidates: List[Tuple[int, int]] = field(default_factory=list)
    all_votes: List[int] = field(default_factory=list)


@dataclass
class FMSAttackResult:
    """Kết quả tấn công khôi phục khóa FMS trên WEP."""
    secret_key_bytes: bytes
    recovered_key_bytes: bytes
    all_matched: bool
    samples_per_byte: int
    p0_byte: int
    byte_results: List[FMSByteResult] = field(default_factory=list)
    verified_packets: int = 0
    total_verified_packets: int = 50
    elapsed_ms: float = 0.0
    collected_packets_count: int = 0


# ==============================================================================
# TẤN CÔNG BẺ KHÓA FMS TRÊN GIAO THỨC WEP
# ==============================================================================

def fms_partial_ksa(known_bytes: Sequence[int]) -> Tuple[List[int], int]:
    """KSA từng phần cho dãy byte đã biết (IV + các byte khóa trước)."""
    S = list(range(256))
    j = 0
    m = len(known_bytes)
    for i in range(m):
        j = (j + S[i] + known_bytes[i]) % 256
        S[i], S[j] = S[j], S[i]
    return S, j


def fms_predict_first_output(full_key: Sequence[int]) -> int:
    """Sinh byte đầu tiên của dòng khóa Z0."""
    S = rc4_ksa(bytes(full_key))
    i = 1
    j = S[1]
    S[1], S[j] = S[j], S[1]
    return S[(S[1] + S[j]) % 256]


def simulate_fms_wep_attack(
    key_bytes: Union[bytes, str, None] = None,
    samples_per_byte: int = 1500,
    p0: int = 0xAA,
    num_verify: int = 50,
    seed: Optional[int] = None,
    *,
    secret_key: Union[bytes, str, None] = None,
    target_verified: Optional[int] = None,
) -> FMSAttackResult:
    """Mô phỏng tấn công bẻ khóa FMS WEP khôi phục khóa bí mật."""
    raw_key = secret_key if secret_key is not None else key_bytes
    if isinstance(raw_key, str):
        actual_key = raw_key.encode("utf-8")
    elif isinstance(raw_key, (bytes, bytearray)):
        actual_key = bytes(raw_key)
    else:
        actual_key = b"KEY_1"

    actual_verify = target_verified if target_verified is not None else num_verify
    rng = random.Random(seed) if seed is not None else None

    start_time = time.perf_counter()
    key_len = len(actual_key)
    recovered = bytearray()
    byte_results: List[FMSByteResult] = []

    for A in range(key_len):
        votes = [0] * 256
        iv_byte_0 = A + 3
        iv_byte_1 = 255

        for _ in range(samples_per_byte):
            iv_byte_2 = rng.randint(0, 255) if rng is not None else secrets.randbelow(256)
            iv = (iv_byte_0, iv_byte_1, iv_byte_2)
            known_prefix = list(iv) + list(recovered)
            full_packet_key = list(iv) + list(actual_key)

            z0 = fms_predict_first_output(full_packet_key)
            c0 = p0 ^ z0
            z0_observed = c0 ^ p0

            S_part, j_part = fms_partial_ksa(known_prefix)
            step_i = len(known_prefix)
            candidate = (z0_observed - j_part - S_part[step_i]) % 256
            votes[candidate] += 1

        top_cand = sorted([(val, votes[val]) for val in range(256)], key=lambda x: x[1], reverse=True)
        winner_byte = top_cand[0][0]
        true_b = actual_key[A]
        matched = (winner_byte == true_b)

        recovered.append(winner_byte)
        byte_results.append(
            FMSByteResult(
                byte_index=A,
                true_byte=true_b,
                recovered_byte=winner_byte,
                matched=matched,
                top_votes=top_cand[0][1],
                total_samples=samples_per_byte,
                top_candidates=top_cand[:5],
                all_votes=votes,
            )
        )

    all_matched = (bytes(recovered) == actual_key)
    verified_count = 0
    if all_matched:
        for _ in range(actual_verify):
            rand_iv = bytes(rng.getrandbits(8) for _ in range(3)) if rng is not None else secrets.token_bytes(3)
            real_out = fms_predict_first_output(rand_iv + actual_key)
            rec_out = fms_predict_first_output(rand_iv + bytes(recovered))
            if real_out == rec_out:
                verified_count += 1

    elapsed_ms = (time.perf_counter() - start_time) * 1000.0

    return FMSAttackResult(
        secret_key_bytes=actual_key,
        recovered_key_bytes=bytes(recovered),
        all_matched=all_matched,
        samples_per_byte=samples_per_byte,
        p0_byte=p0,
        byte_results=byte_results,
        verified_packets=verified_count,
        total_verified_packets=actual_verify,
        elapsed_ms=elapsed_ms,
        collected_packets_count=key_len * samples_per_byte,
    )


# ==============================================================================
# BENCHMARK TỐC ĐỘ XỬ LÝ RC4
# ==============================================================================

def run_rc4_benchmark(sizes_kb: Optional[List[int]] = None) -> List[Dict[str, Any]]:
    """Đo tốc độ mã hóa RC4 trên các kích thước dữ liệu khác nhau."""
    if sizes_kb is None:
        sizes_kb = [1, 10, 100, 500]

    key = b"BenchmarkKey1234"
    results = []
    for kb in sizes_kb:
        data = secrets.token_bytes(kb * 1024)
        t0 = time.perf_counter()
        _ = rc4_crypt(data, key)
        elapsed = time.perf_counter() - t0
        speed_mb_s = (kb / 1024.0) / elapsed if elapsed > 0 else 0.0
        results.append({
            "size_kb": kb,
            "elapsed_ms": elapsed * 1000.0,
            "speed_mb_s": speed_mb_s,
        })
    return results
