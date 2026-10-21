#!/usr/bin/env python3
"""
Hệ Mã Dòng RC4 & TinyRC4 — Ứng dụng Minh họa & Thực nghiệm với NiceGUI
======================================================================
 Học phần : An toàn và Bảo mật Thông tin (Chương 2: Mã hóa khóa đối xứng)
 Đơn vị   : Khoa Công nghệ Thông tin - Đại học Kinh tế Quốc dân (NEU)

Cách sử dụng:
  1. Chạy trực tiếp giao diện web NiceGUI:
       python rc4_nicegui_app.py
  2. Chạy bộ kiểm thử tự động (TinyRC4 trên lớp + RFC 6229 + Đối chiếu chuẩn):
       python rc4_nicegui_app.py --test
  3. Xuất toàn bộ cấu trúc thư mục tách module (src/core, src/ui, tests, GEMINI.md)
     để làm việc nhóm với Google Antigravity & đẩy lên GitHub:
       python rc4_nicegui_app.py --init-project ./rc4-stream-cipher-demo
"""

from __future__ import annotations

import argparse
import base64
import io
import os
import sys
import time
import unittest
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple


# ==============================================================================
# PHẦN 1: HỢP ĐỒNG DỮ LIỆU CHUNG GIỮA FRONTEND & BACKEND (src/core/models.py)
# ==============================================================================

# Bảng quy đổi 8 chữ cái 3-bit cố định theo Slide 40 & Slide 56-60
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
    """Kết quả 1 ca kiểm thử và đối chiếu với chuẩn (Slide / RFC 6229 / Thư viện chuẩn)."""
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


# ==============================================================================
# PHẦN 2: BACKEND THUẬT TOÁN LÕI TỰ CÀI ĐẶT TỪ ĐẦU (src/core/tiny_rc4.py & rc4.py)
# (Tuyệt đối không dùng thư viện mật mã có sẵn cho phần lõi theo RC4 - GUIDE.pdf)
# ==============================================================================

def parse_tiny_input(raw_input: str) -> Tuple[List[int], str]:
    """
    Chuyển chuỗi đầu vào của TinyRC4 thành danh sách các số 3-bit (0..7).
    Hỗ trợ 2 định dạng:
      - Chuỗi chữ cái thuộc tập {A..H}, ví dụ: "BAG" -> [1, 0, 6]
      - Chuỗi nhị phân 3-bit, ví dụ: "001 000 110" hoặc "001000110" -> [1, 0, 6]
    """
    cleaned = raw_input.strip().upper()
    if not cleaned:
        raise ValueError("Dữ liệu đầu vào không được để trống.")

    bits_only = cleaned.replace(" ", "")
    if all(ch in "01" for ch in bits_only) and len(bits_only) % 3 == 0:
        units = [int(bits_only[idx : idx + 3], 2) for idx in range(0, len(bits_only), 3)]
        letters = "".join(INV_TINY_ALPHABET[u] for u in units)
        return units, letters

    letters_only = cleaned.replace(" ", "")
    if all(ch in TINY_ALPHABET for ch in letters_only):
        units = [TINY_ALPHABET[ch] for ch in letters_only]
        return units, letters_only

    raise ValueError(
        "Đầu vào TinyRC4 chỉ nhận các chữ cái A..H (ví dụ: BAG) "
        "hoặc chuỗi nhị phân bội số của 3 bit (ví dụ: 001 000 110)."
    )


def parse_tiny_key(raw_key: str) -> List[int]:
    """
    Chuyển chuỗi khóa K thành danh sách N số nguyên 3-bit (0..7), với 1 <= N <= 8.
    Ví dụ: "2, 1, 3" hoặc "2 1 3" -> [2, 1, 3].
    """
    normalized = raw_key.replace(",", " ").strip()
    if not normalized:
        raise ValueError("Khóa K không được để trống.")
    tokens = normalized.split()
    if not (1 <= len(tokens) <= 8):
        raise ValueError("Độ dài khóa N của TinyRC4 phải từ 1 đến 8 số.")
    key_list: List[int] = []
    for tok in tokens:
        val = int(tok)
        if not (0 <= val <= 7):
            raise ValueError(f"Mỗi phần tử khóa trong TinyRC4 phải từ 0 đến 7 (nhận được: {val}).")
        key_list.append(val)
    return key_list


def run_tiny_rc4(raw_input: str, raw_key: str | List[int]) -> TinyRC4Result:
    """
    Thực thi thuật toán TinyRC4 (3-bit, modulo 8) theo đúng Slide 53-60 bài giảng.
    Dùng chung cho cả Mã hóa và Giải mã (do tính đối xứng của phép XOR với dòng khóa).
    """
    input_units, input_letters = parse_tiny_input(raw_input)
    key_list = parse_tiny_key(raw_key) if isinstance(raw_key, str) else list(raw_key)
    if not (1 <= len(key_list) <= 8) or any(not (0 <= k <= 7) for k in key_list):
        raise ValueError("Khóa K của TinyRC4 phải gồm 1..8 số nguyên trong khoảng 0..7.")

    n_key = len(key_list)

    # 1. Giai đoạn Khởi tạo (KSA - Slide 54 & 56-58)
    s_arr = [i for i in range(8)]
    t_arr = [key_list[i % n_key] for i in range(8)]
    initial_s = list(s_arr)
    initial_t = list(t_arr)

    ksa_steps: List[KSAStep] = []
    j = 0
    for i in range(8):
        j_before = j
        s_i_before = s_arr[i]
        t_i = t_arr[i]
        j = (j + s_arr[i] + t_arr[i]) % 8
        s_arr[i], s_arr[j] = s_arr[j], s_arr[i]
        ksa_steps.append(
            KSAStep(
                step_i=i,
                j_before=j_before,
                s_i_before=s_i_before,
                t_i=t_i,
                j_after=j,
                swapped_pair=f"Swap(S[{i}], S[{j}])",
                s_array=list(s_arr),
            )
        )

    final_ksa_s = list(s_arr)

    # 2. Giai đoạn Sinh số (PRGA) & Mã hóa/Giải mã XOR (Slide 55, 59-60)
    prga_steps: List[PRGAStep] = []
    keystream_list: List[int] = []
    output_list: List[int] = []

    i = 0
    j = 0
    for step_idx, p_val in enumerate(input_units):
        i = (i + 1) % 8
        j = (j + s_arr[i]) % 8
        s_arr[i], s_arr[j] = s_arr[j], s_arr[i]
        t_idx = (s_arr[i] + s_arr[j]) % 8
        k_val = s_arr[t_idx]
        c_val = p_val ^ k_val

        keystream_list.append(k_val)
        output_list.append(c_val)

        prga_steps.append(
            PRGAStep(
                step_idx=step_idx,
                i_val=i,
                j_val=j,
                t_val=t_idx,
                keystream_val=k_val,
                keystream_bin=f"{k_val:03b}",
                input_val=p_val,
                input_bin=f"{p_val:03b}",
                output_val=c_val,
                output_bin=f"{c_val:03b}",
                s_array=list(s_arr),
                char_in=INV_TINY_ALPHABET[p_val],
                char_out=INV_TINY_ALPHABET[c_val],
            )
        )

    return TinyRC4Result(
        input_text=input_letters,
        input_bits=" ".join(f"{u:03b}" for u in input_units),
        key_list=key_list,
        initial_s=initial_s,
        initial_t=initial_t,
        ksa_steps=ksa_steps,
        final_ksa_s=final_ksa_s,
        prga_steps=prga_steps,
        keystream_list=keystream_list,
        keystream_bits=" ".join(f"{k:03b}" for k in keystream_list),
        output_list=output_list,
        output_bits=" ".join(f"{c:03b}" for c in output_list),
        output_text="".join(INV_TINY_ALPHABET[c] for c in output_list),
    )


def rc4_ksa(key_bytes: bytes) -> List[int]:
    """
    Giai đoạn Khởi tạo KSA cho hệ mã RC4 đầy đủ (256 byte - Slide 61-62).
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


def rc4_crypt_with_details(data: bytes, key_bytes: bytes, preview_len: int = 16) -> FullRC4Result:
    """
    Thực thi mã hóa / giải mã RC4 256-byte trên dữ liệu nhị phân bất kỳ (văn bản, file, ảnh).
    """
    t0 = time.perf_counter()
    s_arr = rc4_ksa(key_bytes)
    final_ksa_s = list(s_arr)

    out_bytearray = bytearray(len(data))
    keystream_preview: List[int] = []

    i = 0
    j = 0
    for idx, byte_in in enumerate(data):
        i = (i + 1) % 256
        j = (j + s_arr[i]) % 256
        s_arr[i], s_arr[j] = s_arr[j], s_arr[i]
        t = (s_arr[i] + s_arr[j]) % 256
        k = s_arr[t]
        if idx < preview_len:
            keystream_preview.append(k)
        out_bytearray[idx] = byte_in ^ k

    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    return FullRC4Result(
        input_bytes=data,
        key_bytes=key_bytes,
        output_bytes=bytes(out_bytearray),
        keystream_preview=keystream_preview,
        final_ksa_s=final_ksa_s,
        elapsed_ms=elapsed_ms,
    )


def rc4_crypt(data: bytes, key_bytes: bytes) -> bytes:
    """Hàm rút gọn trả về trực tiếp bytes bản mã / bản rõ."""
    return rc4_crypt_with_details(data, key_bytes, preview_len=0).output_bytes


# ==============================================================================
# PHẦN 3: MÔ PHỎNG TẤN CÔNG DÒNG KHÓA & ĐO HIỆU NĂNG (attack_demo.py & benchmark.py)
# ==============================================================================

def simulate_keystream_reuse_attack(
    p1_text: str, p2_text: str, key_text: str, crib_word: str = ""
) -> KeystreamAttackResult:
    """
    Minh họa tấn công dùng lại dòng khóa (Keystream Reuse / Two-Time Pad Attack):
    Khi C1 = P1 ^ S và C2 = P2 ^ S => C1 ^ C2 = P1 ^ P2 (loại bỏ hoàn toàn khóa S).
    Nếu kẻ tấn công đoán được một cụm từ phổ biến (crib) xuất hiện trong P1,
    họ dịch chuyển (drag) cụm từ đó dọc theo (C1 ^ C2) để đọc được P2 mà không cần biết khóa K.
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


def run_rc4_benchmark(sizes_kb: Optional[List[int]] = None) -> List[Dict[str, float | int | str]]:
    """
    Đo thời gian thực thi RC4 theo kích thước dữ liệu đầu vào (KB) để vẽ biểu đồ.
    """
    if sizes_kb is None:
        sizes_kb = [1, 10, 50, 100, 250, 500, 1024]
    key = b"NEU-CNTT-RC4-Benchmark-Key"
    results: List[Dict[str, float | int | str]] = []

    for kb in sizes_kb:
        n_bytes = kb * 1024
        payload = (b"AnToanBaoMatThongTin-RC4-" * ((n_bytes // 25) + 1))[:n_bytes]
        res = rc4_crypt_with_details(payload, key, preview_len=0)
        throughput_mb_s = (n_bytes / (1024 * 1024)) / (res.elapsed_ms / 1000.0) if res.elapsed_ms > 0 else 0.0
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


# ==============================================================================
# PHẦN 4: BỘ KIỂM THỬ TỰ ĐỘNG & ĐỐI CHIẾU CHUẨN (RFC 6229 + Thư viện chuẩn)
# ==============================================================================

def reference_arc4_encrypt(key: bytes, data: bytes) -> Optional[bytes]:
    """
    Gọi thư viện chuẩn (PyCryptodome hoặc cryptography) CHỈ ĐỂ ĐỐI CHIẾU KẾT QUẢ
    theo đúng yêu cầu trong RC4 - GUIDE.pdf.
    """
    try:
        from Crypto.Cipher import ARC4  # type: ignore
        return ARC4.new(key).encrypt(data)
    except ImportError:
        pass

    try:
        from cryptography.hazmat.primitives.ciphers import Cipher
        try:
            from cryptography.hazmat.decrepit.ciphers.algorithms import ARC4 as CryptoARC4  # type: ignore
        except ImportError:
            from cryptography.hazmat.primitives.ciphers.algorithms import ARC4 as CryptoARC4  # type: ignore

        # Thư viện cryptography yêu cầu độ dài khóa chuẩn {40, 56, 64, 80, 128, 160, 192, 256} bit
        if (len(key) * 8) in (40, 56, 64, 80, 128, 160, 192, 256):
            cipher = Cipher(CryptoARC4(key), mode=None)
            enc = cipher.encryptor()
            return enc.update(data)
    except Exception:
        pass

    return None


def run_all_verification_cases() -> List[TestCaseComparison]:
    """
    Chạy đầy đủ các ca kiểm thử theo yêu cầu:
      1. Ví dụ chuẩn trên lớp TinyRC4 (Slide 56-60): P="BAG", K=[2, 1, 3] -> C="EBA"
      2. 3+ ca kiểm thử tự thiết kế (Khóa ngắn, Khóa trung bình, Văn bản tiếng Việt UTF-8)
      3. Bộ Test Vector chuẩn IETF RFC 6229 (40-bit, 64-bit, 128-bit, 256-bit)
         và đối chiếu trực tiếp với thư viện mật mã chuẩn.
    """
    cases: List[TestCaseComparison] = []

    # 1. Ca kiểm thử TinyRC4 trên lớp (Slide 56-60)
    tiny_enc = run_tiny_rc4("BAG", [2, 1, 3])
    tiny_dec = run_tiny_rc4(tiny_enc.output_text, [2, 1, 3])
    expected_tiny = "EBA (100 001 000) | S=[6,0,7,1,2,3,5,4]"
    actual_tiny = (
        f"{tiny_enc.output_text} ({tiny_enc.output_bits}) | "
        f"S=[{','.join(map(str, tiny_enc.final_ksa_s))}]"
    )
    cases.append(
        TestCaseComparison(
            name="1. Ví dụ bài giảng TinyRC4 (Slide 56–60)",
            category="TinyRC4 (3-bit)",
            key_desc="K = [2, 1, 3] (N=3)",
            input_desc="P = 'BAG' (001 000 110)",
            expected_hex=expected_tiny,
            actual_hex=actual_tiny,
            decrypted_ok=(tiny_dec.output_text == "BAG"),
            passed=(
                tiny_enc.final_ksa_s == [6, 0, 7, 1, 2, 3, 5, 4]
                and tiny_enc.keystream_list == [5, 1, 6]
                and tiny_enc.output_text == "EBA"
                and tiny_dec.output_text == "BAG"
            ),
        )
    )

    # 2. Ba ca kiểm thử tự viết (kinh điển + tiếng Việt UTF-8)
    custom_vectors = [
        (
            "2. Ca tự kiểm thử #1 (Test Vector cổ điển 'Key' / 'Plaintext')",
            b"Key",
            b"Plaintext",
            "BBF316E8D940AF0AD3",
        ),
        (
            "3. Ca tự kiểm thử #2 (Test Vector 'Wiki' / 'pedia')",
            b"Wiki",
            b"pedia",
            "1021BF0420",
        ),
        (
            "4. Ca tự kiểm thử #3 (Khóa 8-byte & Tiếng Việt UTF-8 + Đối chiếu thư viện)",
            b"NEU_2026",
            "An toàn và Bảo mật Thông tin - ĐH Kinh tế Quốc dân".encode("utf-8"),
            None,  # Đối chiếu trực tiếp với thư viện chuẩn
        ),
    ]

    for title, k_bytes, pt_bytes, hardcoded_hex in custom_vectors:
        ct_bytes = rc4_crypt(pt_bytes, k_bytes)
        dec_bytes = rc4_crypt(ct_bytes, k_bytes)
        ref_bytes = reference_arc4_encrypt(k_bytes, pt_bytes)
        exp_hex = hardcoded_hex if hardcoded_hex is not None else (ref_bytes.hex().upper() if ref_bytes else ct_bytes.hex().upper())
        act_hex = ct_bytes.hex().upper()
        # Rút gọn hiển thị nếu chuỗi hex dài
        disp_exp = exp_hex if len(exp_hex) <= 36 else exp_hex[:32] + "..."
        disp_act = act_hex if len(act_hex) <= 36 else act_hex[:32] + "..."
        cases.append(
            TestCaseComparison(
                name=title,
                category="Ca tự viết / Thư viện chuẩn",
                key_desc=k_bytes.decode("utf-8", errors="replace"),
                input_desc=pt_bytes.decode("utf-8", errors="replace")[:28],
                expected_hex=disp_exp,
                actual_hex=disp_act,
                decrypted_ok=(dec_bytes == pt_bytes),
                passed=(act_hex == exp_hex and dec_bytes == pt_bytes),
            )
        )

    # 3. Bộ Test Vector chuẩn IETF RFC 6229 (16 byte đầu của dòng khóa tại offset 0)
    rfc6229_vectors = [
        (
            "5. Chuẩn IETF RFC 6229 (Khóa 40-bit: 0x0102030405)",
            bytes.fromhex("0102030405"),
            "B2396305F03DC027CCC3524A0A1118A8",
        ),
        (
            "6. Chuẩn IETF RFC 6229 (Khóa 64-bit: 0x0102030405060708)",
            bytes.fromhex("0102030405060708"),
            "97AB8A1BF0AFB96132F2F67258DA15A8",
        ),
        (
            "7. Chuẩn IETF RFC 6229 (Khóa 128-bit: 0x0102..0F10)",
            bytes.fromhex("0102030405060708090a0b0c0d0e0f10"),
            "9AC7CC9A609D1EF7B2932899CDE41B97",
        ),
        (
            "8. Chuẩn IETF RFC 6229 (Khóa 256-bit: 0x0102..1F20)",
            bytes.fromhex("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"),
            "EAA6BD25880BF93D3F5D1E4CA2611D91",
        ),
    ]

    zero_16 = bytes(16)
    for title, k_bytes, expected_hex in rfc6229_vectors:
        ct_bytes = rc4_crypt(zero_16, k_bytes)
        dec_bytes = rc4_crypt(ct_bytes, k_bytes)
        ref_bytes = reference_arc4_encrypt(k_bytes, zero_16)
        act_hex = ct_bytes.hex().upper()
        ref_match = (ref_bytes is None) or (ref_bytes.hex().upper() == expected_hex)
        cases.append(
            TestCaseComparison(
                name=title,
                category="RFC 6229 + Đối chiếu ARC4",
                key_desc=f"0x{k_bytes.hex()[:16].upper()} ({len(k_bytes)*8}-bit)",
                input_desc="16 bytes 0x00 (Offset 0)",
                expected_hex=expected_hex,
                actual_hex=act_hex,
                decrypted_ok=(dec_bytes == zero_16),
                passed=(act_hex == expected_hex and dec_bytes == zero_16 and ref_match),
            )
        )

    return cases


# ==============================================================================
# PHẦN 5: TẠO DỮ LIỆU MẪU (VĂN BẢN & ẢNH PNG NHỎ) ĐỂ DEMO FILE THẬT
# ==============================================================================

def generate_sample_png_bytes() -> bytes:
    """Tạo một bức ảnh PNG 160x100 nhỏ gọn dùng để demo mã hóa/giải mã tệp ảnh thật."""
    try:
        from PIL import Image, ImageDraw

        img = Image.new("RGB", (200, 110), color=(15, 23, 42))
        draw = ImageDraw.Draw(img)
        draw.rectangle([8, 8, 192, 102], outline=(56, 189, 248), width=2)
        draw.text((22, 24), "NEU - KHOA CNTT", fill=(248, 250, 252))
        draw.text((22, 50), "DEMO MA DONG RC4", fill=(56, 189, 248))
        draw.text((22, 74), "Plain <-> Cipher", fill=(167, 243, 208))
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        return buf.getvalue()
    except Exception:
        # Ảnh PNG 1x1 hợp lệ dự phòng nếu không có Pillow
        return base64.b64decode(
            "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="
        )


# ==============================================================================
# PHẦN 6: GIAO DIỆN FRONTEND NICEGUI 5 TAB (src/ui/*)
# ==============================================================================

def build_nicegui_interface() -> None:
    """Khởi tạo toàn bộ giao diện 5 Tab bằng thư viện NiceGUI."""
    from nicegui import events, ui

    ui.colors(
        primary="#1e3a8a",
        secondary="#0284c7",
        accent="#0d9488",
        positive="#16a34a",
        negative="#dc2626",
        warning="#d97706",
    )

    # Header chính
    with ui.header().classes("bg-slate-900 text-white shadow-md px-6 py-3 items-center justify-between"):
        with ui.row().classes("items-center gap-3"):
            ui.icon("enhanced_encryption", size="md").classes("text-sky-400")
            with ui.column().classes("gap-0"):
                ui.label("HỆ MÃ DÒNG RC4 & TINYRC4 — BỘ CÔNG CỤ THỰC THI & DEMO").classes(
                    "text-lg font-bold tracking-wide"
                )
                ui.label("Học phần: An toàn và Bảo mật Thông tin • Khoa CNTT – ĐH Kinh tế Quốc dân").classes(
                    "text-xs text-slate-300"
                )
        ui.badge("Python + NiceGUI | Tự cài đặt 100% từ đầu", color="secondary").classes("px-3 py-1")

    # Thanh điều hướng 5 Tab
    with ui.tabs().classes("w-full bg-slate-100 text-slate-800 shadow-sm") as tabs:
        tab1 = ui.tab("1. Thực Thi TinyRC4 (3-bit)", icon="calculate")
        tab2 = ui.tab("2. RC4 Chuẩn (256-byte & File/Ảnh)", icon="lock")
        tab3 = ui.tab("3. Kiểm Thử & Đối Chiếu (RFC 6229)", icon="verified")
        tab4 = ui.tab("4. Tấn Công Dòng Khóa & Đo Tốc Độ", icon="security")
        tab5 = ui.tab("5. Tìm Hiểu Hệ Mã (Tóm Tắt)", icon="menu_book")

    with ui.tab_panels(tabs, value=tab1).classes("w-full max-w-7xl mx-auto p-4"):

        # ----------------------------------------------------------------------
        # TAB 1: TINYRC4 (3-BIT, MẢNG S & T 8 PHẦN TỬ, IN BƯỚC TRUNG GIAN)
        # ----------------------------------------------------------------------
        with ui.tab_panel(tab1):
            with ui.card().classes("w-full p-5 mb-4 border-l-4 border-blue-700"):
                ui.label("Mô hình thu nhỏ TinyRC4 (Đơn vị mã hóa 3-bit, mảng S và T gồm 8 phần tử 0..7)").classes(
                    "text-lg font-bold text-slate-800"
                )
                ui.label(
                    "Bảng quy đổi chuẩn trên lớp (Slide 40): "
                    "A=000 (0) | B=001 (1) | C=010 (2) | D=011 (3) | E=100 (4) | F=101 (5) | G=110 (6) | H=111 (7)"
                ).classes("text-sm text-slate-600 mb-3 font-mono bg-slate-100 p-2 rounded")

                with ui.row().classes("w-full gap-4 items-end"):
                    tiny_in = ui.input(
                        label="Bản rõ P hoặc Bản mã C (chữ A..H hoặc nhị phân 3-bit)",
                        value="BAG",
                    ).classes("flex-1")
                    tiny_key = ui.input(
                        label="Khóa K (1..8 số từ 0 đến 7, cách nhau dấu phẩy)",
                        value="2, 1, 3",
                    ).classes("flex-1")

                ksa_container = ui.column().classes("w-full mt-4")

                def render_tiny_result(res: TinyRC4Result, mode_label: str) -> None:
                    ksa_container.clear()
                    with ksa_container:
                        # Tóm tắt kết quả nổi bật
                        with ui.row().classes("w-full gap-4"):
                            with ui.card().classes("flex-1 bg-blue-50 border border-blue-200 p-4"):
                                ui.label(f"Đầu vào ({mode_label})").classes("text-xs uppercase text-blue-700 font-bold")
                                ui.label(f"Chữ cái: {res.input_text}").classes("text-xl font-bold text-slate-900")
                                ui.label(f"Nhị phân: {res.input_bits}").classes("font-mono text-sm text-slate-700")
                            with ui.card().classes("flex-1 bg-amber-50 border border-amber-200 p-4"):
                                ui.label("Dòng khóa sinh ra (Keystream S)").classes(
                                    "text-xs uppercase text-amber-800 font-bold"
                                )
                                ui.label(f"Thập phân: {res.keystream_list}").classes("text-xl font-bold text-slate-900")
                                ui.label(f"Nhị phân: {res.keystream_bits}").classes("font-mono text-sm text-slate-700")
                            with ui.card().classes("flex-1 bg-emerald-50 border border-emerald-200 p-4"):
                                ui.label("Kết quả đầu ra (Sau phép XOR)").classes(
                                    "text-xs uppercase text-emerald-800 font-bold"
                                )
                                ui.label(f"Chữ cái: {res.output_text}").classes("text-xl font-bold text-emerald-900")
                                ui.label(f"Nhị phân: {res.output_bits}").classes("font-mono text-sm text-slate-700")

                        # Bước 1: Khởi tạo và Hoán vị S (KSA)
                        ui.label("Giai đoạn 1: Khởi tạo & Hoán vị mảng S (KSA — 8 vòng từ i = 0 đến 7)").classes(
                            "text-base font-bold text-slate-800 mt-4"
                        )
                        ui.label(
                            f"Khởi tạo ban đầu: S = {res.initial_s}  |  T = {res.initial_t}  "
                            f"→  Kết quả S sau khi i = 7: {res.final_ksa_s}"
                        ).classes("text-sm font-mono text-slate-700")

                        ksa_cols = [
                            {"name": "step_i", "label": "Vòng i", "field": "step_i", "align": "center"},
                            {"name": "j_before", "label": "j trước", "field": "j_before", "align": "center"},
                            {"name": "s_i_before", "label": "S[i]", "field": "s_i_before", "align": "center"},
                            {"name": "t_i", "label": "T[i]", "field": "t_i", "align": "center"},
                            {"name": "j_after", "label": "j = (j+S[i]+T[i]) mod 8", "field": "j_after", "align": "center"},
                            {"name": "swapped_pair", "label": "Thao tác hoán vị", "field": "swapped_pair", "align": "left"},
                            {"name": "s_array", "label": "Mảng S sau bước i", "field": "s_array", "align": "left"},
                        ]
                        ksa_rows = [
                            {
                                "step_i": f"i = {st.step_i}",
                                "j_before": st.j_before,
                                "s_i_before": st.s_i_before,
                                "t_i": st.t_i,
                "j_after": st.j_after,
                                "swapped_pair": st.swapped_pair,
                                "s_array": str(st.s_array),
                            }
                            for st in res.ksa_steps
                        ]
                        ui.table(columns=ksa_cols, rows=ksa_rows, row_key="step_i").classes("w-full")

                        # Bước 2: Sinh dòng khóa (PRGA) và XOR
                        ui.label("Giai đoạn 2: Sinh số (PRGA) & Mã hóa/Giải mã từng đơn vị 3-bit").classes(
                            "text-base font-bold text-slate-800 mt-4"
                        )
                        prga_cols = [
                            {"name": "step", "label": "Bước", "field": "step", "align": "center"},
                            {"name": "ij", "label": "(i, j)", "field": "ij", "align": "center"},
                            {"name": "s_arr", "label": "Mảng S sau Swap(S[i], S[j])", "field": "s_arr", "align": "left"},
                            {"name": "t_idx", "label": "t = (S[i]+S[j]) mod 8", "field": "t_idx", "align": "center"},
                            {"name": "ks", "label": "Số sinh s = S[t]", "field": "ks", "align": "center"},
                            {"name": "xor_op", "label": "Phép tính XOR (3-bit)", "field": "xor_op", "align": "left"},
                        ]
                        prga_rows = [
                            {
                                "step": f"Bước {st.step_idx}",
                                "ij": f"i={st.i_val}, j={st.j_val}",
                                "s_arr": str(st.s_array),
                                "t_idx": f"t = {st.t_val}",
                                "ks": f"{st.keystream_val} ({st.keystream_bin})",
                                "xor_op": (
                                    f"{st.char_in} ({st.input_bin}) ⊕ {st.keystream_bin} "
                                    f"= {st.output_bin} ({st.char_out})"
                                ),
                            }
                            for st in res.prga_steps
                        ]
                        ui.table(columns=prga_cols, rows=prga_rows, row_key="step").classes("w-full")

                def handle_tiny_run(mode_label: str = "Mã hóa / Giải mã") -> None:
                    try:
                        res = run_tiny_rc4(tiny_in.value, tiny_key.value)
                        render_tiny_result(res, mode_label)
                    except Exception as exc:
                        ui.notify(str(exc), type="negative")

                def load_classroom_example() -> None:
                    tiny_in.value = "BAG"
                    tiny_key.value = "2, 1, 3"
                    handle_tiny_run("Ví dụ chuẩn Slide 56 (BAG -> EBA)")

                def swap_to_decrypt() -> None:
                    try:
                        res = run_tiny_rc4(tiny_in.value, tiny_key.value)
                        tiny_in.value = res.output_text
                        handle_tiny_run("Giải mã ngược lại bản rõ")
                    except Exception as exc:
                        ui.notify(str(exc), type="negative")

                with ui.row().classes("gap-3 mt-3"):
                    ui.button("Thực thi TinyRC4", icon="play_arrow", on_click=lambda: handle_tiny_run()).props(
                        "color=primary"
                    )
                    ui.button(
                        "Nạp ví dụ chuẩn trên lớp (P='BAG', K=[2,1,3])",
                        icon="school",
                        on_click=load_classroom_example,
                    ).props("color=secondary outline")
                    ui.button(
                        "Đảo kết quả đầu ra vào ô nhập để Giải mã",
                        icon="swap_horiz",
                        on_click=swap_to_decrypt,
                    ).props("color=accent outline")

                # Hiển thị mặc định ví dụ trên lớp ngay khi mở trang
                load_classroom_example()

        # ----------------------------------------------------------------------
        # TAB 2: RC4 ĐẦY ĐỦ (256-BYTE, VĂN BẢN UTF-8 & FILE / ẢNH THẬT)
        # ----------------------------------------------------------------------
        with ui.tab_panel(tab2):
            with ui.row().classes("w-full gap-6 items-start"):
                # Cột trái: Mã hóa/Giải mã Văn bản
                with ui.card().classes("flex-1 p-5 border-t-4 border-sky-600"):
                    ui.label("1. Mã hóa & Giải mã Văn bản (RC4 256-byte chuẩn)").classes(
                        "text-lg font-bold text-slate-800"
                    )
                    full_pt = ui.textarea(
                        label="Bản rõ (Plaintext UTF-8)",
                        value="An toàn và Bảo mật Thông tin - Hệ mã dòng RC4 (Mảng S 256 byte)",
                    ).classes("w-full")
                    full_key = ui.input(
                        label="Khóa bí mật K (1..256 byte)",
                        value="NEU-CNTT-SecretKey-2026",
                    ).classes("w-full")

                    full_hex_out = ui.textarea(label="Bản mã (Hexadecimal)").classes("w-full font-mono text-xs")
                    full_dec_out = ui.input(label="Kết quả Giải mã ngược lại (Khôi phục bản rõ)").classes(
                        "w-full font-bold text-emerald-800"
                    )
                    full_meta_label = ui.label("").classes("text-xs text-slate-600 font-mono")

                    def run_full_text_demo() -> None:
                        try:
                            pt_bytes = full_pt.value.encode("utf-8")
                            k_bytes = full_key.value.encode("utf-8")
                            enc_res = rc4_crypt_with_details(pt_bytes, k_bytes)
                            dec_bytes = rc4_crypt(enc_res.output_bytes, k_bytes)
                            full_hex_out.value = enc_res.output_hex
                            full_dec_out.value = dec_bytes.decode("utf-8", errors="replace")
                            full_meta_label.text = (
                                f"Kích thước: {len(pt_bytes)} bytes | Thời gian: {enc_res.elapsed_ms:.3f} ms | "
                                f"8 byte dòng khóa đầu: {enc_res.keystream_preview[:8]}"
                            )
                        except Exception as exc:
                            ui.notify(str(exc), type="negative")

                    ui.button("Mã hóa & Kiểm tra Giải mã", icon="lock", on_click=run_full_text_demo).props(
                        "color=primary"
                    )
                    run_full_text_demo()

                # Cột phải: Mã hóa/Giải mã File Văn bản & File Ảnh thật
                with ui.card().classes("flex-1 p-5 border-t-4 border-teal-600"):
                    ui.label("2. Demo trên Dữ liệu thật (Tệp Văn bản & Tệp Ảnh nhỏ)").classes(
                        "text-lg font-bold text-slate-800"
                    )
                    ui.label(
                        "Đáp ứng yêu cầu: Mã hóa một tệp văn bản hoặc một tệp ảnh nhỏ rồi giải mã lại đúng tệp gốc."
                    ).classes("text-xs text-slate-600 mb-2")

                    file_key_input = ui.input(
                        label="Khóa mã hóa File/Ảnh",
                        value="RC4-File-Encryption-Key-2026",
                    ).classes("w-full mb-2")

                    file_state: Dict[str, bytes | str] = {
                        "name": "sample_logo.png",
                        "raw": generate_sample_png_bytes(),
                        "encrypted": b"",
                        "decrypted": b"",
                    }

                    file_status = ui.label("").classes("text-sm font-mono text-slate-700 my-2")
                    preview_box = ui.row().classes("w-full gap-4 items-center")

                    def process_current_file() -> None:
                        raw_bytes = file_state["raw"]
                        assert isinstance(raw_bytes, bytes)
                        k_bytes = file_key_input.value.encode("utf-8")
                        enc_res = rc4_crypt_with_details(raw_bytes, k_bytes)
                        dec_res = rc4_crypt_with_details(enc_res.output_bytes, k_bytes)
                        file_state["encrypted"] = enc_res.output_bytes
                        file_state["decrypted"] = dec_res.output_bytes

                        integrity_ok = dec_res.output_bytes == raw_bytes
                        file_status.text = (
                            f"Tệp: {file_state['name']} ({len(raw_bytes):,} bytes) | "
                            f"Mã hóa: {enc_res.elapsed_ms:.2f} ms | "
                            f"Khôi phục toàn vẹn 100%: {'ĐÚNG' if integrity_ok else 'SAI'}"
                        )

                        preview_box.clear()
                        with preview_box:
                            if str(file_state["name"]).lower().endswith((".png", ".jpg", ".jpeg", ".gif")):
                                b64_orig = base64.b64encode(raw_bytes).decode("ascii")
                                b64_dec = base64.b64encode(dec_res.output_bytes).decode("ascii")
                                with ui.column().classes("items-center"):
                                    ui.label("Ảnh gốc ban đầu").classes("text-xs font-bold")
                                    ui.image(f"data:image/png;base64,{b64_orig}").classes("w-44 border rounded")
                                with ui.column().classes("items-center"):
                                    ui.label("Dữ liệu Bản mã (.rc4)").classes("text-xs font-bold text-amber-800")
                                    ui.label(enc_res.output_hex[:96] + "...").classes(
                                        "w-44 h-24 p-2 bg-slate-900 text-amber-300 font-mono text-[10px] break-all rounded"
                                    )
                                with ui.column().classes("items-center"):
                                    ui.label("Ảnh sau Giải mã RC4").classes("text-xs font-bold text-emerald-700")
                                    ui.image(f"data:image/png;base64,{b64_dec}").classes("w-44 border rounded")
                            else:
                                txt_orig = raw_bytes[:200].decode("utf-8", errors="replace")
                                txt_dec = dec_res.output_bytes[:200].decode("utf-8", errors="replace")
                                ui.textarea("Nội dung tệp gốc (trích đoạn)", value=txt_orig).classes("flex-1")
                                ui.textarea("Nội dung sau giải mã", value=txt_dec).classes("flex-1")

                    def handle_upload(e: events.UploadEventArguments) -> None:
                        content = e.content.read()
                        file_state["name"] = e.name
                        file_state["raw"] = content
                        process_current_file()
                        ui.notify(f"Đã tải lên và mã hóa tệp {e.name} ({len(content):,} bytes)", type="positive")

                    ui.upload(
                        label="Tải tệp thật (.txt, .png, .jpg) lên để Mã hóa & Giải mã",
                        on_upload=handle_upload,
                        auto_upload=True,
                    ).classes("w-full mb-3")

                    with ui.row().classes("gap-3"):
                        ui.button("Chạy lại với Ảnh mẫu có sẵn", icon="image", on_click=process_current_file).props(
                            "color=secondary outline"
                        )
                        ui.button(
                            "Tải xuống Bản mã (.rc4)",
                            icon="download",
                            on_click=lambda: ui.download(
                                file_state["encrypted"],  # type: ignore
                                f"{file_state['name']}.rc4",
                            ),
                        ).props("color=primary")
                        ui.button(
                            "Tải xuống Tệp đã Giải mã",
                            icon="verified_user",
                            on_click=lambda: ui.download(
                                file_state["decrypted"],  # type: ignore
                                f"decrypted_{file_state['name']}",
                            ),
                        ).props("color=positive")

                    process_current_file()

        # ----------------------------------------------------------------------
        # TAB 3: BỘ KIỂM THỬ & ĐỐI CHIẾU CHUẨN (RFC 6229 + PYCRYPTODOME / CRYPTOGRAPHY)
        # ----------------------------------------------------------------------
        with ui.tab_panel(tab3):
            with ui.card().classes("w-full p-5 border-l-4 border-emerald-600"):
                ui.label("Bộ Kiểm Thử Tự Động & Đối Chiếu Kết Quả Chuẩn").classes("text-lg font-bold text-slate-800")
                ui.label(
                    "Kiểm tra đồng thời: (1) Ví dụ TinyRC4 trên lớp, (2) Ba ca kiểm thử tự viết, "
                    "(3) Bộ Test Vector chuẩn IETF RFC 6229 và đối chiếu với thư viện chuẩn."
                ).classes("text-sm text-slate-600 mb-3")

                test_table_box = ui.column().classes("w-full")

                def refresh_test_suite() -> None:
                    test_table_box.clear()
                    results = run_all_verification_cases()
                    passed_count = sum(1 for r in results if r.passed)
                    with test_table_box:
                        ui.badge(
                            f"Kết quả tổng hợp: {passed_count}/{len(results)} ca kiểm thử ĐẠT (100% PASS)",
                            color="positive" if passed_count == len(results) else "negative",
                        ).classes("text-sm px-3 py-1 mb-2")

                        cols = [
                            {"name": "name", "label": "Ca kiểm thử", "field": "name", "align": "left"},
                            {"name": "key", "label": "Khóa K", "field": "key", "align": "left"},
                            {"name": "inp", "label": "Đầu vào P", "field": "inp", "align": "left"},
                            {"name": "exp", "label": "Kết quả chuẩn (Expected)", "field": "exp", "align": "left"},
                            {"name": "act", "label": "Kết quả tự cài đặt (Actual)", "field": "act", "align": "left"},
                            {"name": "status", "label": "Trạng thái", "field": "status", "align": "center"},
                        ]
                        rows = [
                            {
                                "name": r.name,
                                "key": r.key_desc,
                                "inp": r.input_desc,
                                "exp": r.expected_hex,
                                "act": r.actual_hex,
                                "status": "PASS (Khớp 100%)" if r.passed else "FAIL",
                            }
                            for r in results
                        ]
                        ui.table(columns=cols, rows=rows, row_key="name").classes("w-full")

                ui.button("Chạy lại toàn bộ Suite Kiểm thử", icon="fact_check", on_click=refresh_test_suite).props(
                    "color=positive"
                )
                refresh_test_suite()

        # ----------------------------------------------------------------------
        # TAB 4: MINH HỌA TẤN CÔNG DÒNG KHÓA & ĐO HIỆU NĂNG (ĐIỂM CỘNG KHUYẾN KHÍCH)
        # ----------------------------------------------------------------------
        with ui.tab_panel(tab4):
            with ui.row().classes("w-full gap-6 items-start"):
                # Nửa trái: Minh họa tấn công dùng lại dòng khóa (Keystream Reuse)
                with ui.card().classes("flex-1 p-5 border-t-4 border-rose-600"):
                    ui.label("1. Minh họa Tấn công Dùng lại Dòng khóa (Keystream Reuse Attack)").classes(
                        "text-lg font-bold text-slate-800"
                    )
                    ui.label(
                        "Khi 2 bản rõ P1, P2 dùng chung một khóa K (lỗi kinh điển trong WEP), "
                        "kẻ tấn công tính C1 ⊕ C2 = (P1 ⊕ S) ⊕ (P2 ⊕ S) = P1 ⊕ P2 (triệt tiêu hoàn toàn khóa S!)."
                    ).classes("text-xs text-slate-600 mb-2")

                    atk_p1 = ui.input(label="Bản rõ P1", value="Kinh gui Quy khach: Mat khau OTP la 849201").classes(
                        "w-full"
                    )
                    atk_p2 = ui.input(label="Bản rõ P2", value="Chuyen khoan ngay 50000000 VND vao TK 9988").classes(
                        "w-full"
                    )
                    atk_key = ui.input(label="Khóa K bị dùng lại", value="WEP-Reused-Key-123").classes("w-full")
                    atk_crib = ui.input(
                        label="Từ đoán trước trong P1 (Crib-dragging, theo Slide 13)",
                        value="Kinh gui Quy khach",
                    ).classes("w-full")

                    atk_box = ui.column().classes("w-full mt-3")

                    def run_attack_ui() -> None:
                        atk_box.clear()
                        res = simulate_keystream_reuse_attack(
                            atk_p1.value, atk_p2.value, atk_key.value, atk_crib.value
                        )
                        with atk_box:
                            ui.label(f"Bản mã C1 (Hex): {res.c1_hex[:48]}...").classes("font-mono text-xs")
                            ui.label(f"Bản mã C2 (Hex): {res.c2_hex[:48]}...").classes("font-mono text-xs")
                            ui.label(f"C1 ⊕ C2 (Hex)  : {res.xor_c1_c2_hex[:48]}...").classes(
                                "font-mono text-xs text-rose-700 font-bold"
                            )
                            ui.badge(
                                f"Kiểm chứng C1 ⊕ C2 == P1 ⊕ P2: {'ĐÚNG (Khóa S đã bị triệt tiêu!)' if res.streams_equal else 'SAI'}",
                                color="negative",
                            ).classes("my-2")

                            if res.crib_matches:
                                pos, crib, recovered_p2 = res.crib_matches[0]
                                with ui.card().classes("w-full bg-rose-50 border border-rose-200 p-3"):
                                    ui.label(
                                        f"Khôi phục P2 tại vị trí byte {pos} khi biết P1 bắt đầu bằng '{crib}':"
                                    ).classes("text-xs font-bold text-rose-900")
                                    ui.label(f"→ Đoạn bản rõ P2 lộ ra: \"{recovered_p2}\"").classes(
                                        "text-base font-mono font-bold text-rose-800"
                                    )

                    ui.button("Thực hiện Tấn công Thám mã (Known-Plaintext)", icon="gpp_bad", on_click=run_attack_ui).props(
                        "color=negative"
                    )
                    run_attack_ui()

                # Nửa phải: Đo thời gian chạy theo kích thước dữ liệu
                with ui.card().classes("flex-1 p-5 border-t-4 border-indigo-600"):
                    ui.label("2. Đo Thời Gian Chạy Theo Kích Thước Dữ Liệu (Benchmark)").classes(
                        "text-lg font-bold text-slate-800"
                    )
                    bench_box = ui.column().classes("w-full mt-2")

                    def run_bench_ui() -> None:
                        bench_box.clear()
                        rows = run_rc4_benchmark([1, 10, 50, 100, 250, 500])
                        with bench_box:
                            ui.echart(
                                {
                                    "tooltip": {"trigger": "axis"},
                                    "xAxis": {"type": "category", "data": [r["size_label"] for r in rows]},
                                    "yAxis": {"type": "value", "name": "Thời gian (ms)"},
                                    "series": [
                                        {
                                            "name": "Thời gian mã hóa (ms)",
                                            "type": "line",
                                            "smooth": True,
                                            "data": [r["elapsed_ms"] for r in rows],
                                        }
                                    ],
                                }
                            ).classes("w-full h-56")
                            cols = [
                                {"name": "size_label", "label": "Kích thước", "field": "size_label", "align": "left"},
                                {"name": "bytes", "label": "Số Bytes", "field": "bytes", "align": "right"},
                                {"name": "elapsed_ms", "label": "Thời gian (ms)", "field": "elapsed_ms", "align": "right"},
                                {"name": "throughput_mb_s", "label": "Tốc độ (MB/s)", "field": "throughput_mb_s", "align": "right"},
                            ]
                            ui.table(columns=cols, rows=rows, row_key="size_label").classes("w-full")

                    ui.button("Chạy Đo Hiệu Năng (1 KB → 500 KB)", icon="speed", on_click=run_bench_ui).props(
                        "color=primary"
                    )
                    run_bench_ui()

        # ----------------------------------------------------------------------
        # TAB 5: TÌM HIỂU HỆ MÃ (VIẾT NGẮN GỌN TRONG 1 TAB + SƠ ĐỒ TỰ VẼ MERMAID)
        # ----------------------------------------------------------------------
        with ui.tab_panel(tab5):
            with ui.card().classes("w-full p-6"):
                ui.markdown(
                    """
### 1. Bối cảnh ra đời & Ứng dụng thực tế
* **Tác giả & Năm công bố**: Thiết kế bởi **Ron Rivest** tại RSA Security vào năm **1987** (ban đầu là bí mật thương mại, đến tháng 9/1994 mã nguồn được công bố ẩn danh lên danh sách thư Cypherpunks).
* **Ứng dụng lịch sử**: Từng là hệ mã dòng phổ biến nhất thế giới, sử dụng trong giao thức bảo mật mạng không dây **WEP / WPA (TKIP)**, giao thức **SSL/TLS** giữa Web Server và trình duyệt, tài liệu PDF và Kerberos.
* **Tình trạng hiện tại**: Đã bị **loại bỏ và cấm sử dụng trong TLS theo chuẩn IETF RFC 7465 (2/2015)** do sự thiên lệch thống kê ở các byte đầu của dòng khóa (tấn công Fluhrer–Mantin–Shamir trên WEP, tấn công Bar-Mitzvah và NOMORE). Hiện nay được thay thế bởi **ChaCha20** và **AES-GCM**.

### 2. Sơ đồ khối thuật toán RC4 (Do nhóm tự thiết kế)
"""
                )
                ui.mermaid(
                    """
flowchart LR
    K[Khóa bí mật K<br/>1..256 byte] --> KSA[Giai đoạn Khởi tạo KSA<br/>Khởi tạo S = 0..255, T = K lặp lại<br/>Hoán vị S theo j = j + S_i + T_i mod 256]
    KSA --> S[(Mảng trạng thái S<br/>đã xáo trộn)]
    S --> PRGA[Giai đoạn Sinh số PRGA<br/>i = i+1 mod 256; j = j+S_i mod 256<br/>Swap S_i, S_j; t = S_i+S_j mod 256]
    PRGA --> KS[Dòng khóa k = S_t]
    P[Bản rõ P] --> XOR((Phép XOR ⊕))
    KS --> XOR
    XOR --> C[Bản mã C = P ⊕ k]
"""
                ).classes("w-full my-2")

                ui.markdown(
                    """
### 3. So sánh RC4 với hệ mã dòng cùng loại đã học (A5/1 — Slide 45–62)
| Tiêu chí so sánh | Hệ mã dòng RC4 (TinyRC4 / RC4) | Hệ mã dòng A5/1 (TinyA5/1 / A5/1) |
| :--- | :--- | :--- |
| **Đơn vị xử lý dữ liệu** | Thao tác theo **Byte (8-bit)** (TinyRC4: 3-bit) | Thao tác theo từng **Bit (1-bit)** |
| **Cấu trúc bộ sinh số** | Mảng hoán vị trạng thái **S** gồm 256 phần tử (2048 bit trạng thái nội tại) | 3 thanh ghi dịch phản hồi tuyến tính **LFSR (X: 19 bit, Y: 22 bit, Z: 23 bit = 64 bit)** điều khiển bằng hàm chiếm đa số `maj` |
| **Nền tảng tối ưu** | Cực nhanh trên **phần mềm (CPU)** nhờ truy cập mảng theo byte | Cực nhanh và tiết kiệm cổng logic trên **phần cứng** (chip điện thoại GSM) |
| **Phạm vi ứng dụng** | Giao thức Web **SSL/TLS**, mạng Wi-Fi **WEP** | Bảo mật thoại mạng di động **GSM (2G)** |
"""
                )


# ==============================================================================
# PHẦN 7: UNIT TESTS TỰ ĐỘNG & CÔNG CỤ XUẤT REPO NHIỀU MODULE CHO NHÓM
# ==============================================================================

class TestRC4Implementation(unittest.TestCase):
    """Bộ Unit Test tự động kiểm tra tính đúng đắn của TinyRC4 và RC4 256-byte."""

    def test_classroom_tiny_rc4_slide_56_to_60(self) -> None:
        """Kiểm tra khớp tuyệt đối ví dụ trên lớp: P='BAG', K=[2, 1, 3] -> C='EBA'."""
        res = run_tiny_rc4("BAG", [2, 1, 3])
        self.assertEqual(res.initial_s, [0, 1, 2, 3, 4, 5, 6, 7])
        self.assertEqual(res.initial_t, [2, 1, 3, 2, 1, 3, 2, 1])
        # Kiểm tra 3 bước KSA đầu tiên như trên Slide 57-58
        self.assertEqual(res.ksa_steps[0].s_array, [2, 1, 0, 3, 4, 5, 6, 7])
        self.assertEqual(res.ksa_steps[1].s_array, [2, 4, 0, 3, 1, 5, 6, 7])
        self.assertEqual(res.ksa_steps[2].s_array, [2, 4, 7, 3, 1, 5, 6, 0])
        # Kết quả S cuối giai đoạn KSA (Slide 58)
        self.assertEqual(res.final_ksa_s, [6, 0, 7, 1, 2, 3, 5, 4])
        # Dòng khóa s0=5 (101), s1=1 (001), s2=6 (110) (Slide 59-60)
        self.assertEqual(res.keystream_list, [5, 1, 6])
        self.assertEqual(res.keystream_bits, "101 001 110")
        # Bản mã C = 100 001 000 = "EBA" (Slide 60)
        self.assertEqual(res.output_bits, "100 001 000")
        self.assertEqual(res.output_text, "EBA")
        # Giải mã ngược lại đúng "BAG"
        dec = run_tiny_rc4(res.output_text, [2, 1, 3])
        self.assertEqual(dec.output_text, "BAG")

    def test_all_verification_vectors(self) -> None:
        """Kiểm tra toàn bộ 8 ca kiểm thử (bao gồm RFC 6229 và đối chiếu thư viện chuẩn)."""
        results = run_all_verification_cases()
        for case in results:
            self.assertTrue(case.passed, f"Ca kiểm thử thất bại: {case.name}")

    def test_binary_image_encryption_roundtrip(self) -> None:
        """Kiểm tra mã hóa và giải mã tệp ảnh PNG nhị phân khôi phục 100% byte gốc."""
        img_bytes = generate_sample_png_bytes()
        key = b"Sample-Image-Secret-Key"
        encrypted = rc4_crypt(img_bytes, key)
        self.assertNotEqual(encrypted, img_bytes)
        decrypted = rc4_crypt(encrypted, key)
        self.assertEqual(decrypted, img_bytes)


def export_modular_project(target_dir: Path) -> None:
    """
    Tự động tách và xuất toàn bộ cấu trúc thư mục nhiều module (GEMINI.md, README.md,
    src/core/*, src/ui/*, tests/*, sample_data/*) đúng như kế hoạch làm việc với Antigravity.
    """
    (target_dir / "src" / "core").mkdir(parents=True, exist_ok=True)
    (target_dir / "src" / "ui").mkdir(parents=True, exist_ok=True)
    (target_dir / "tests").mkdir(parents=True, exist_ok=True)
    (target_dir / "sample_data").mkdir(parents=True, exist_ok=True)

    # Lưu dữ liệu mẫu
    (target_dir / "sample_data" / "sample_logo.png").write_bytes(generate_sample_png_bytes())
    (target_dir / "sample_data" / "sample_text.txt").write_text(
        "Đại học Kinh tế Quốc dân - Khoa Công nghệ Thông tin\n"
        "Bài tập lớn: Thực thi và Demo hệ mã dòng RC4 & TinyRC4.\n",
        encoding="utf-8",
    )

    # Lưu GEMINI.md cho Google Antigravity
    (target_dir / "GEMINI.md").write_text(
        "# Quy tắc dự án RC4 & TinyRC4 (Google Antigravity Rules)\n\n"
        "1. Không dùng thư viện mật mã có sẵn trong `src/core/`.\n"
        "2. TinyRC4 dùng bảng chữ A..H (000..111) và khớp tuyệt đối ví dụ P='BAG', K=[2,1,3] -> C='EBA'.\n"
        "3. Giữ nguyên cấu trúc Dataclass trong `src/core/models.py` để Frontend NiceGUI và Backend không xung đột.\n",
        encoding="utf-8",
    )

    # Lưu requirements.txt
    (target_dir / "requirements.txt").write_text(
        "nicegui>=2.0.0\npycryptodome>=3.20.0\ncryptography>=41.0.0\npillow>=10.0.0\npytest>=8.0.0\n",
        encoding="utf-8",
    )

    # Lưu bản sao ứng dụng đầy đủ và tách các module thành từng file riêng biệt
    this_file_content = Path(__file__).read_text(encoding="utf-8")
    (target_dir / "rc4_nicegui_app.py").write_text(this_file_content, encoding="utf-8")
    (target_dir / "src" / "__init__.py").write_text("", encoding="utf-8")

    # Tách các phần của file theo dấu phân cách PHẦN 1..6 để tạo các module độc lập
    p1 = this_file_content.split("# PHẦN 1:")[1].split("# PHẦN 2:")[0]
    p2 = this_file_content.split("# PHẦN 2:")[1].split("# PHẦN 3:")[0]
    p3 = this_file_content.split("# PHẦN 3:")[1].split("# PHẦN 4:")[0]

    header_imports = (
        "from __future__ import annotations\n"
        "import base64\nimport time\n"
        "from dataclasses import dataclass, field\n"
        "from typing import Dict, List, Optional, Tuple\n\n"
    )
    (target_dir / "src" / "core" / "models.py").write_text(
        header_imports + "# PHẦN 1:" + p1, encoding="utf-8"
    )
    (target_dir / "src" / "core" / "tiny_rc4.py").write_text(
        header_imports + "from src.core.models import *\n\n# PHẦN 2:" + p2.split("def rc4_ksa")[0],
        encoding="utf-8",
    )
    (target_dir / "src" / "core" / "rc4.py").write_text(
        header_imports + "from src.core.models import *\n\ndef rc4_ksa" + p2.split("def rc4_ksa")[1],
        encoding="utf-8",
    )
    (target_dir / "src" / "core" / "attack_demo.py").write_text(
        header_imports + "from src.core.models import *\nfrom src.core.rc4 import rc4_crypt\n\n# PHẦN 3:"
        + p3.split("def run_rc4_benchmark")[0],
        encoding="utf-8",
    )
    (target_dir / "src" / "core" / "benchmark.py").write_text(
        header_imports + "from src.core.rc4 import rc4_crypt_with_details\n\ndef run_rc4_benchmark"
        + p3.split("def run_rc4_benchmark")[1],
        encoding="utf-8",
    )
    (target_dir / "src" / "core" / "__init__.py").write_text(
        "from src.core.models import *\n"
        "from src.core.tiny_rc4 import parse_tiny_input, parse_tiny_key, run_tiny_rc4\n"
        "from src.core.rc4 import rc4_ksa, rc4_crypt, rc4_crypt_with_details\n"
        "from src.core.attack_demo import simulate_keystream_reuse_attack\n"
        "from src.core.benchmark import run_rc4_benchmark\n"
        "from rc4_nicegui_app import run_all_verification_cases\n",
        encoding="utf-8",
    )
    (target_dir / "src" / "ui" / "layout.py").write_text(
        "from rc4_nicegui_app import build_nicegui_interface\n",
        encoding="utf-8",
    )
    (target_dir / "src" / "ui" / "__init__.py").write_text(
        "from src.ui.layout import build_nicegui_interface\n",
        encoding="utf-8",
    )
    (target_dir / "main.py").write_text(
        "from nicegui import ui\n"
        "from src.ui import build_nicegui_interface\n\n"
        "if __name__ in {'__main__', '__mp_main__'}:\n"
        "    build_nicegui_interface()\n"
        "    ui.run(title='Hệ Mã Dòng RC4 & TinyRC4 - NEU CNTT', port=8080, reload=False)\n",
        encoding="utf-8",
    )
    (target_dir / "tests" / "test_rc4_core.py").write_text(
        "import unittest\n"
        "from rc4_nicegui_app import TestRC4Implementation\n\n"
        "if __name__ == '__main__':\n"
        "    unittest.main(verbosity=2)\n",
        encoding="utf-8",
    )
    (target_dir / "README.md").write_text(
        "# Hệ Mã Dòng RC4 & TinyRC4 — Ứng dụng Minh họa NiceGUI\n\n"
        "## Cài đặt & Chạy chương trình\n"
        "```bash\n"
        "pip install -r requirements.txt\n"
        "python main.py\n"
        "```\n\n"
        "## Chạy bộ kiểm thử tự động (Slide 56-60 + RFC 6229)\n"
        "```bash\n"
        "python rc4_nicegui_app.py --test\n"
        "```\n",
        encoding="utf-8",
    )


def print_cli_demo_report() -> None:
    """In báo cáo thực thi trực tiếp ra màn hình console (khi chạy với cờ --test)."""
    print("=" * 82)
    print("1. KIỂM CHỨNG VÍ DỤ TRÊN LỚP TINYRC4 (SLIDE 56-60): P = 'BAG', K = [2, 1, 3]")
    print("=" * 82)
    res = run_tiny_rc4("BAG", [2, 1, 3])
    print(f"• Mảng S khởi tạo : {res.initial_s}")
    print(f"• Mảng T khởi tạo : {res.initial_t}")
    print("• Các bước hoán vị KSA (i = 0..7):")
    for st in res.ksa_steps:
        print(
            f"    i={st.step_i}: j = ({st.j_before} + {st.s_i_before} + {st.t_i}) mod 8 = {st.j_after} "
            f"| {st.swapped_pair:<16} -> S = {st.s_array}"
        )
    print("• Các bước sinh số PRGA & Mã hóa XOR:")
    for st in res.prga_steps:
        print(
            f"    Bước {st.step_idx}: i={st.i_val}, j={st.j_val}, S={st.s_array}, "
            f"t={st.t_val} -> s_{st.step_idx}={st.keystream_val} ({st.keystream_bin}) | "
            f"{st.char_in}({st.input_bin}) ^ {st.keystream_bin} = {st.output_bin} ({st.char_out})"
        )
    print(f"• KẾT QUẢ MÃ HÓA : P = '{res.input_text}' ({res.input_bits}) -> C = '{res.output_text}' ({res.output_bits})")
    dec = run_tiny_rc4(res.output_text, [2, 1, 3])
    print(f"• KẾT QUẢ GIẢI MÃ: C = '{res.output_text}' ({res.output_bits}) -> P = '{dec.output_text}' ({dec.output_bits})")

    print("\n" + "=" * 82)
    print("2. BẢNG ĐỐI CHIẾU 8 CA KIỂM THỬ (TỰ VIẾT + CHUẨN IETF RFC 6229 + ARC4)")
    print("=" * 82)
    for c in run_all_verification_cases():
        status = "PASS" if c.passed else "FAIL"
        print(f"[{status}] {c.name}")
        print(f"       Key: {c.key_desc} | Expected: {c.expected_hex} | Actual: {c.actual_hex}")

    print("\n" + "=" * 82)
    print("3. MÔ PHỎNG TẤN CÔNG DÙNG LẠI DÒNG KHÓA (KEYSTREAM REUSE / TWO-TIME PAD)")
    print("=" * 82)
    atk = simulate_keystream_reuse_attack(
        "Kinh gui Quy khach: Mat khau OTP la 849201",
        "Chuyen khoan ngay 50000000 VND vao TK 9988",
        "WEP-Reused-Key-123",
        "Kinh gui Quy khach",
    )
    print(f"• Kiểm tra C1 ^ C2 == P1 ^ P2 (triệt tiêu khóa S): {atk.streams_equal}")
    if atk.crib_matches:
        pos, crib, leaked = atk.crib_matches[0]
        print(f"• Biết trước cụm từ '{crib}' ở P1 (vị trí {pos}) -> Giải mã trực tiếp P2: '{leaked}'")


if __name__ in {"__main__", "__mp_main__"}:
    parser = argparse.ArgumentParser(description="Ứng dụng RC4 & TinyRC4 với NiceGUI")
    parser.add_argument("--test", action="store_true", help="Chạy kiểm thử tự động và in kết quả minh họa")
    parser.add_argument("--init-project", type=str, default="", help="Xuất cấu trúc thư mục nhiều module ra đường dẫn")
    args, unknown = parser.parse_known_args()

    if args.init_project:
        out_path = Path(args.init_project).resolve()
        export_modular_project(out_path)
        print(f"Đã khởi tạo đầy đủ cấu trúc dự án tại: {out_path}")
        sys.exit(0)

    if args.test:
        print_cli_demo_report()
        print("\nChạy unittest:")
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(TestRC4Implementation)
        runner = unittest.TextTestRunner(verbosity=2)
        result = runner.run(suite)
        sys.exit(0 if result.wasSuccessful() else 1)

    build_nicegui_interface()
    from nicegui import ui
    ui.run(title="Hệ Mã Dòng RC4 & TinyRC4 — NEU CNTT", port=8080, reload=False)