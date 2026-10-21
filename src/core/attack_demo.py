"""
Minh họa Tấn Công Dùng Lại Dòng Khóa (Keystream Reuse / Two-Time Pad)
=====================================================================
Nguyên lý: Khi C1 = P1 ^ S và C2 = P2 ^ S => C1 ^ C2 = P1 ^ P2 (loại bỏ hoàn toàn khóa S).
Kỹ thuật Crib-dragging: Nếu đoán trước 1 từ/cụm từ (crib) xuất hiện trong P1,
ta tính (C1 ^ C2) ^ crib để giải mã trực tiếp một phần của P2 mà không cần biết khóa K.
"""

from __future__ import annotations
from typing import List, Tuple

from src.core.models import KeystreamAttackResult
from src.core.rc4 import rc4_crypt


def simulate_keystream_reuse_attack(
    p1_text: str, p2_text: str, key_text: str, crib_word: str = ""
) -> KeystreamAttackResult:
    """
    Minh họa tấn công dùng lại dòng khóa (Keystream Reuse / Two-Time Pad Attack).
    """
    b1 = p1_text.encode("utf-8")
    b2 = p2_text.encode("utf-8")
    min_len = min(len(b1), len(b2))
    b1 = b1[:min_len]
    b2 = b2[:min_len]
    k_bytes = key_text.encode("utf-8")

    c1 = rc4_crypt(b1, k_bytes)
    c2 = rc4_crypt(b2, k_bytes)

    xor_c1_c2 = bytes(x ^ y for x, y in zip(c1, c2))
    xor_p1_p2 = bytes(x ^ y for x, y in zip(b1, b2))

    crib_matches: List[Tuple[int, str, str]] = []
    crib_bytes = crib_word.encode("utf-8")
    if crib_bytes and len(crib_bytes) <= min_len:
        w_len = len(crib_bytes)
        for pos in range(min_len - w_len + 1):
            segment = xor_c1_c2[pos : pos + w_len]
            candidate_bytes = bytes(x ^ y for x, y in zip(segment, crib_bytes))
            # Kiểm tra xem chuỗi giải ra có phải ký tự ASCII đọc được không
            if all(32 <= b <= 126 for b in candidate_bytes):
                candidate_str = candidate_bytes.decode("utf-8", errors="replace")
                crib_matches.append((pos, crib_word, candidate_str))

    return KeystreamAttackResult(
        p1_text=b1.decode("utf-8", errors="replace"),
        p2_text=b2.decode("utf-8", errors="replace"),
        key_text=key_text,
        c1_hex=c1.hex().upper(),
        c2_hex=c2.hex().upper(),
        xor_c1_c2_hex=xor_c1_c2.hex().upper(),
        xor_p1_p2_hex=xor_p1_p2.hex().upper(),
        streams_equal=(xor_c1_c2 == xor_p1_p2),
        crib_word=crib_word,
        crib_matches=crib_matches,
    )
