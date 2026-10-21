"""
Module Đo Hiệu Năng & Tốc Độ Mã Hóa RC4 — Backend Core
======================================================
Đo thời gian thực thi RC4 theo kích thước dữ liệu đầu vào (KB) để vẽ biểu đồ tốc độ.
"""

from __future__ import annotations
from typing import Dict, List, Optional, Union

from src.core.rc4 import rc4_crypt_with_details


def run_rc4_benchmark(
    sizes_kb: Optional[List[int]] = None,
) -> List[Dict[str, Union[float, int, str]]]:
    """
    Đo thời gian thực thi RC4 theo kích thước dữ liệu đầu vào (KB) để vẽ biểu đồ.
    """
    if sizes_kb is None:
        sizes_kb = [1, 10, 50, 100, 250, 500, 1024]
    key = b"NEU-CNTT-RC4-Benchmark-Key"
    results: List[Dict[str, Union[float, int, str]]] = []

    for kb in sizes_kb:
        n_bytes = kb * 1024
        payload = (b"AnToanBaoMatThongTin-RC4-" * ((n_bytes // 25) + 1))[:n_bytes]
        res = rc4_crypt_with_details(payload, key, preview_len=0)
        throughput_mb_s = (
            (n_bytes / (1024 * 1024)) / (res.elapsed_ms / 1000.0)
            if res.elapsed_ms > 0
            else 0.0
        )
        results.append(
            {
                "size_kb": kb,
                "size_label": f"{kb} KB",
                "bytes": n_bytes,
                "elapsed_ms": round(res.elapsed_ms, 3),
                "throughput_mb_s": round(throughput_mb_s, 2),
            }
        )
    return results
