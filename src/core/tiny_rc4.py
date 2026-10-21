"""
Thuật toán TinyRC4 (3-bit, Modulo 8) — Backend Core
===================================================
Quy chuẩn: Theo bài giảng An toàn và Bảo mật Thông tin (Khoa CNTT - ĐH Kinh tế Quốc dân)
Ràng buộc: TUYỆT ĐỐI KHÔNG dùng thư viện mật mã có sẵn (chỉ dùng %, ^ và hoán vị list).
"""

from __future__ import annotations
from typing import List, Tuple, Union

from src.core.models import (
    INV_TINY_ALPHABET,
    TINY_ALPHABET,
    KSAStep,
    PRGAStep,
    TinyRC4Result,
)


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


def run_tiny_rc4(raw_input: str, raw_key: Union[str, List[int]]) -> TinyRC4Result:
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
