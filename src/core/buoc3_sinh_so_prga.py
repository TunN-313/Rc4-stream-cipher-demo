"""Bước 3: Sinh dòng khóa PRGA và mã hóa đối xứng XOR."""

from __future__ import annotations
import base64
import time
from dataclasses import dataclass
from typing import Dict, Iterator, List, Optional, Sequence, Tuple, Union

from src.core.buoc1_xu_ly_dau_vao import (
    INV_TINY_ALPHABET,
    TINY_ALPHABET,
    bytes_sang_hex,
    tiny_chuoi_sang_so,
    tiny_so_sang_chuoi,
)
from src.core.buoc2_khoi_tao_ksa import KSAStep, ksa_tiny_rc4, rc4_ksa


# -----------------------------------------------------------------------------
# Cấu trúc dữ liệu kết quả thuật toán
# -----------------------------------------------------------------------------

@dataclass
class PRGAStep:
    """Lưu vết trạng thái mảng S, chỉ mục và kết quả XOR tại một bước PRGA."""
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
    """Kết quả mô phỏng toàn bộ quy trình KSA và PRGA trên mô hình TinyRC4 3-bit."""
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
    """Kết quả thực thi mã hóa/giải mã RC4 8-bit."""
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


# -----------------------------------------------------------------------------
# Thuật toán RC4 8-bit
# -----------------------------------------------------------------------------

def rc4_crypt_chunks(
    data: bytes,
    key_bytes: bytes,
    chunk_size: int = 65536,
) -> Iterator[bytes]:
    """Mã hóa/giải mã theo khối để xử lý tệp dung lượng lớn mà không tốn nhiều bộ nhớ."""
    if not data:
        return

    s_arr = rc4_ksa(key_bytes)
    i = 0
    j = 0
    total_len = len(data)

    for offset in range(0, total_len, chunk_size):
        chunk = data[offset : offset + chunk_size]
        out_chunk = bytearray(len(chunk))
        for idx, byte_val in enumerate(chunk):
            i = (i + 1) % 256
            j = (j + s_arr[i]) % 256
            s_arr[i], s_arr[j] = s_arr[j], s_arr[i]
            t = (s_arr[i] + s_arr[j]) % 256
            out_chunk[idx] = byte_val ^ s_arr[t]
        yield bytes(out_chunk)


def rc4_crypt(data: bytes, key_bytes: bytes) -> bytes:
    """Mã hóa hoặc giải mã dữ liệu bằng RC4 8-bit (phép XOR tự nghịch đảo)."""
    if not data:
        return b""
    return b"".join(rc4_crypt_chunks(data, key_bytes, chunk_size=65536))


def rc4_crypt_with_details(
    data: bytes,
    key_bytes: bytes,
    preview_limit: int = 16,
) -> FullRC4Result:
    """Thực thi RC4 kèm đo thời gian và trích xuất mẫu dòng khóa ban đầu."""
    start_time = time.perf_counter()
    s_after_ksa = rc4_ksa(key_bytes)

    # Trích xuất một số byte dòng khóa đầu tiên phục vụ hiển thị trực quan mà không tiêu hao mảng trạng thái chính
    s_preview = list(s_after_ksa)
    keystream_preview: List[int] = []
    i = j = 0
    num_samples = min(len(data) if data else 16, preview_limit)
    for _ in range(num_samples):
        i = (i + 1) % 256
        j = (j + s_preview[i]) % 256
        s_preview[i], s_preview[j] = s_preview[j], s_preview[i]
        keystream_preview.append(s_preview[(s_preview[i] + s_preview[j]) % 256])

    output = rc4_crypt(data, key_bytes)
    elapsed_ms = (time.perf_counter() - start_time) * 1000.0

    return FullRC4Result(
        input_bytes=data,
        key_bytes=key_bytes,
        output_bytes=output,
        keystream_preview=keystream_preview,
        final_ksa_s=s_after_ksa,
        elapsed_ms=elapsed_ms,
    )


# -----------------------------------------------------------------------------
# Thuật toán TinyRC4 3-bit
# -----------------------------------------------------------------------------

def parse_tiny_input(raw: str) -> Tuple[List[int], str, str]:
    """Chuẩn hóa dữ liệu đầu vào TinyRC4 từ chuỗi chữ cái (A..H) hoặc chuỗi số (0..7)."""
    clean = raw.strip().upper()
    if not clean:
        raise ValueError("Dữ liệu bản rõ không được để trống.")
    nums: List[int] = []
    chars: List[str] = []
    for ch in clean:
        if ch in TINY_ALPHABET:
            nums.append(TINY_ALPHABET[ch])
            chars.append(ch)
        elif ch.isdigit() and 0 <= int(ch) <= 7:
            num = int(ch)
            nums.append(num)
            chars.append(INV_TINY_ALPHABET[num])
        elif ch in (" ", ",", ";", "\t", "\n"):
            continue
        else:
            raise ValueError(f"Ký tự '{ch}' không thuộc bảng chữ cái 3-bit (chỉ chấp nhận A-H hoặc số 0-7).")

    bits = " ".join(f"{n:03b}" for n in nums)
    text = "".join(chars)
    return nums, text, bits


def parse_tiny_key(raw: Union[str, Sequence[int]]) -> List[int]:
    """Chuẩn hóa khóa TinyRC4 thành danh sách số nguyên modulo 8."""
    if isinstance(raw, str):
        cleaned = raw.replace(";", ",").replace(" ", ",")
        tokens = [tok.strip() for tok in cleaned.split(",") if tok.strip()]
        if not tokens:
            cleaned_str = raw.replace(" ", "")
            tokens = [c for c in cleaned_str if c]

        key_nums: List[int] = []
        for tok in tokens:
            if tok.isdigit():
                key_nums.append(int(tok) % 8)
            elif tok.upper() in TINY_ALPHABET:
                key_nums.append(TINY_ALPHABET[tok.upper()])
            else:
                raise ValueError(f"Khóa không hợp lệ tại phần tử '{tok}'.")
    else:
        key_nums = [int(k) % 8 for k in raw]

    if not key_nums:
        raise ValueError("Khóa không được để trống.")
    if len(key_nums) > 8:
        raise ValueError("Độ dài khóa TinyRC4 tối đa 8 phần tử.")
    return key_nums


def run_tiny_rc4(
    raw_input: str,
    raw_key: Union[str, Sequence[int]],
) -> TinyRC4Result:
    """Thực thi đầy đủ quy trình KSA và PRGA của TinyRC4 (N=8, modulo 8)."""
    input_nums, input_text, input_bits = parse_tiny_input(raw_input)
    key_list = parse_tiny_key(raw_key)

    N = 8
    initial_s = list(range(N))
    initial_t = [key_list[i % len(key_list)] for i in range(N)]

    s_arr, ksa_steps = ksa_tiny_rc4(key_list)
    final_ksa_s = list(s_arr)

    i = 0
    j = 0
    prga_steps: List[PRGAStep] = []
    keystream_list: List[int] = []
    output_list: List[int] = []

    for step_idx, p_val in enumerate(input_nums):
        i = (i + 1) % N
        j = (j + s_arr[i]) % N
        s_arr[i], s_arr[j] = s_arr[j], s_arr[i]
        t = (s_arr[i] + s_arr[j]) % N
        k_val = s_arr[t]
        c_val = p_val ^ k_val

        keystream_list.append(k_val)
        output_list.append(c_val)

        char_in = INV_TINY_ALPHABET.get(p_val, "?")
        char_out = INV_TINY_ALPHABET.get(c_val, "?")

        prga_steps.append(
            PRGAStep(
                step_idx=step_idx + 1,
                i_val=i,
                j_val=j,
                t_val=t,
                keystream_val=k_val,
                keystream_bin=f"{k_val:03b}",
                input_val=p_val,
                input_bin=f"{p_val:03b}",
                output_val=c_val,
                output_bin=f"{c_val:03b}",
                s_array=list(s_arr),
                char_in=char_in,
                char_out=char_out,
            )
        )

    keystream_bits = " ".join(f"{k:03b}" for k in keystream_list)
    output_bits = " ".join(f"{c:03b}" for c in output_list)
    output_text = "".join(INV_TINY_ALPHABET.get(c, "?") for c in output_list)

    return TinyRC4Result(
        input_text=input_text,
        input_bits=input_bits,
        key_list=key_list,
        initial_s=initial_s,
        initial_t=initial_t,
        ksa_steps=ksa_steps,
        final_ksa_s=final_ksa_s,
        prga_steps=prga_steps,
        keystream_list=keystream_list,
        keystream_bits=keystream_bits,
        output_list=output_list,
        output_bits=output_bits,
        output_text=output_text,
    )
