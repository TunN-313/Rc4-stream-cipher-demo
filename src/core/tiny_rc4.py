"""
Thuật toán mô phỏng TinyRC4 thu nhỏ 3-bit (src/core/tiny_rc4.py)
Minh họa trực quan từng phép toán KSA và PRGA trên mảng S gồm 8 phần tử (0..7) và modulo 8.
Được gọi bởi: phân hệ trực quan hóa từng bước TinyRC4 (tab_tiny_rc4) và test suite.
Gọi đến: src.core.models (chứa bảng chữ cái và các lớp lưu trữ kết quả).
Thuật ngữ: modulo 8 là phép chia lấy dư quay vòng 8 số (0..7), ví dụ (5 + 4) % 8 = 1;
S-box 3-bit là mảng hoán vị S ban đầu [0, 1, 2, 3, 4, 5, 6, 7];
XOR là phép cộng modulo 2 trên từng bit (1 ^ 0 = 1, 1 ^ 1 = 0).
"""

from __future__ import annotations  # dùng để kích hoạt tính năng kiểm tra kiểu dữ liệu tĩnh
from typing import List, Tuple, Union  # dùng để định nghĩa kiểu dữ liệu danh sách, bộ và kiểu kết hợp

from src.core.models import (  # file nội bộ của dự án: cấu trúc lưu bước KSA, PRGA và bảng ký tự
    INV_TINY_ALPHABET,
    TINY_ALPHABET,
    KSAStep,
    PRGAStep,
    TinyRC4Result,
)


def parse_tiny_input(raw_input: str) -> Tuple[List[int], str]:
    """
    Chuyển đổi chuỗi văn bản đầu vào thành danh sách các số nguyên 3-bit (từ 0 đến 7).
    Chấp nhận chữ cái thuộc bảng chữ cái A-H hoặc chuỗi bit nhị phân độ dài chia hết cho 3.

    Tham số:
        raw_input (str): Chuỗi đầu vào (ví dụ: "BAG" hoặc "001 000 110").

    Trả về:
        Tuple[List[int], str]: Cặp gồm danh sách giá trị số [1, 0, 6] và chuỗi chữ cái chuẩn "BAG".

    Ví dụ:
        parse_tiny_input("BAG") -> ([1, 0, 6], 'BAG')
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
    Chuyển chuỗi khóa bí mật thành danh sách N số nguyên 3-bit (mỗi số từ 0 đến 7).
    Cho phép nhập cách nhau bằng dấu phẩy hoặc dấu cách, độ dài N từ 1 đến 8 số.

    Tham số:
        raw_key (str): Chuỗi khóa người dùng nhập (ví dụ: "2, 1, 3" hoặc "2 1 3").

    Trả về:
        List[int]: Danh sách các số nguyên biểu diễn khóa (ví dụ: [2, 1, 3]).

    Ví dụ:
        parse_tiny_key("2, 1, 3") -> [2, 1, 3]
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
    Thực thi mô phỏng thuật toán TinyRC4 (3-bit, modulo 8) theo đúng Slide 53-60 bài giảng NEU.
    Dùng chung cho cả Mã hóa và Giải mã (do tính chất tự nghịch đảo của phép XOR: C ^ K = P).

    Tham số:
        raw_input (str): Bản rõ hoặc bản mã (ví dụ: "BAG" hoặc "001 000 110").
        raw_key (Union[str, List[int]]): Khóa bí mật (ví dụ: "2, 1, 3" hoặc [2, 1, 3]).

    Trả về:
        TinyRC4Result: Đối tượng chứa chi tiết từng bước KSA, PRGA, dòng khóa và bản mã ra.

    Ví dụ:
        run_tiny_rc4("BAG", [2, 1, 3]).output_text -> "EBA"
    """
    input_units, input_letters = parse_tiny_input(raw_input)
    key_list = parse_tiny_key(raw_key) if isinstance(raw_key, str) else list(raw_key)
    if not (1 <= len(key_list) <= 8) or any(not (0 <= k <= 7) for k in key_list):
        raise ValueError("Khóa K của TinyRC4 phải gồm 1..8 số nguyên trong khoảng 0..7.")

    n_key = len(key_list)

    # 1. Giai đoạn Khởi tạo (KSA - Key-Scheduling Algorithm, Slide 54 & 56-58)
    # Khởi tạo mảng hoán vị S ban đầu với 8 số 0..7: S = [0, 1, 2, 3, 4, 5, 6, 7]
    s_arr = [i for i in range(8)]
    # Khởi tạo mảng T sao chép tuần hoàn khóa K: T[i] = K[i % len(K)] (ví dụ K=[2,1,3] -> T=[2,1,3,2,1,3,2,1])
    t_arr = [key_list[i % n_key] for i in range(8)]
    initial_s = list(s_arr)
    initial_t = list(t_arr)

    ksa_steps: List[KSAStep] = []
    j = 0
    # Lặp qua 8 vòng (i từ 0 đến 7) để xáo mảng S bằng khóa T
    for i in range(8):
        j_before = j
        s_i_before = s_arr[i]
        t_i = t_arr[i]
        # Cộng dồn chỉ số j: j = (j + S[i] + T[i]) mod 8 (ví dụ bước 0: j = (0 + 0 + 2) % 8 = 2)
        j = (j + s_arr[i] + t_arr[i]) % 8
        # Hoán vị hai phần tử S[i] và S[j] (ví dụ bước 0: đổi S[0] và S[2], S thành [2, 1, 0, 3, 4, 5, 6, 7])
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
    # Với mỗi ký tự 3-bit của bản rõ, thực hiện một vòng lặp PRGA sinh 1 số dòng khóa
    for step_idx, p_val in enumerate(input_units):
        # 1. Tăng con trỏ i thêm 1 theo vòng tròn modulo 8 (ví dụ: i=(0+1)%8=1)
        i = (i + 1) % 8
        # 2. Cộng con trỏ j với S[i] mod 8 để chọn vị trí đảo (ví dụ: j=(0+S[1])%8=(0+0)%8=0)
        j = (j + s_arr[i]) % 8
        # 3. Hoán vị hai phần tử S[i] và S[j] để xáo trộn lại mảng S sau mỗi ký tự
        s_arr[i], s_arr[j] = s_arr[j], s_arr[i]
        # 4. Tính chỉ số trích khóa t = (S[i] + S[j]) mod 8 (ví dụ: t=(0+6)%8=6)
        t_idx = (s_arr[i] + s_arr[j]) % 8
        # 5. Lấy số dòng khóa k = S[t] từ mảng hoán vị S (ví dụ: k = S[6] = 5)
        k_val = s_arr[t_idx]
        # 6. Thực hiện phép XOR giữa ký tự đầu vào và dòng khóa: c = p ^ k (ví dụ: 1 ^ 5 = 4)
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
