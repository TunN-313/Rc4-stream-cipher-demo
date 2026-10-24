"""
Phân Tích An Toàn và Đo Lường Hiệu Năng RC4 (src/core/analysis.py)
Gồm 3 phần: tấn công Two-Time Pad & Crib-dragging, đo thiên lệch byte và đo tốc độ mã hóa.
Được gọi bởi: phân hệ thám mã & benchmark (tab_attack_bench) và test suite.
Gọi đến: src.core.models (chứa kết quả thám mã) và src.core.rc4 (thuật toán mã hóa RC4).
Thuật ngữ: Two-Time Pad là lỗ hổng dùng lại một dòng khóa khiến C1 ^ C2 = P1 ^ P2 mất an toàn;
Crib là từ ngữ dự đoán trước (ví dụ 'Kinh gui') để kéo trượt qua bản XOR khôi phục bản rõ;
Bias là hiện tượng thiên lệch xác suất, ví dụ byte thứ 2 về 0x00 với tỷ lệ 1/128 thay vì 1/256.
"""

from __future__ import annotations  # dùng để kích hoạt tính năng kiểm tra kiểu dữ liệu tĩnh
import random  # dùng để sinh các khóa ngẫu nhiên phục vụ phân tích thực nghiệm thiên lệch byte
from typing import Dict, List, Optional, Tuple, Union  # dùng để định nghĩa kiểu dữ liệu chuẩn

from src.core.models import CribCandidate, KeystreamAttackResult  # file nội bộ: cấu trúc thám mã
from src.core.rc4 import rc4_crypt, rc4_crypt_with_details  # file nội bộ: hàm mã hóa RC4


# =============================================================================
# 1. Tấn công dùng lại dòng khóa
# =============================================================================

def score_readable(text: str) -> float:
    """
    Tính điểm khả năng đọc được của một chuỗi văn bản phục vụ xếp hạng từ đoán.
    Chữ cái/khoảng trắng tính 1.0, chữ số tính 0.5, dấu câu cơ bản tính 0.25, còn lại 0.0.

    Tham số:
        text (str): Chuỗi ký tự cần chấm điểm đọc được.

    Trả về:
        float: Điểm trung bình từ 0.0 đến 1.0 (càng gần 1.0 càng giống tiếng người đọc).

    Ví dụ:
        score_readable("Xin chao 123") -> 0.875
    """
    if not text:
        return 0.0
    total = 0.0
    for ch in text:
        if ch.isalpha() or ch == " ":
            total += 1.0
        elif ch.isdigit():
            total += 0.5
        elif ch in ".,:-":
            total += 0.25
    return total / len(text)


def simulate_keystream_reuse_attack(
    p1_text: str,
    p2_text: str,
    key_text: str,
    crib_word: str = "",
    crib_in: str = "p1",
) -> KeystreamAttackResult:
    """
    Mô phỏng tấn công thám mã Two-Time Pad khi hai bản rõ P1 và P2 bị mã hóa cùng một khóa K.
    Thực hiện kéo từ đoán trước (crib-dragging) qua chuỗi C1 ^ C2 để giải mã một phần bản còn lại.

    Tham số:
        p1_text (str): Bản rõ thứ nhất dạng văn bản.
        p2_text (str): Bản rõ thứ hai dạng văn bản.
        key_text (str): Khóa bí mật dùng chung cho cả hai bản rõ.
        crib_word (str): Từ ngữ đoán trước (crib) cần thử nghiệm kéo trượt (mặc định "").
        crib_in (str): Vị trí giả định từ đoán ("p1" là thuộc P1, "p2" là thuộc P2).

    Trả về:
        KeystreamAttackResult: Kết quả mô phỏng gồm chuỗi XOR và danh sách các ứng viên giải mã.

    Ví dụ:
        simulate_keystream_reuse_attack("Hello", "World", "Key", "Hel").streams_equal -> True
    """
    raw_b1 = p1_text.encode("utf-8")
    raw_b2 = p2_text.encode("utf-8")
    len_p1 = len(raw_b1)
    len_p2 = len(raw_b2)
    min_len = min(len_p1, len_p2)

    b1 = raw_b1[:min_len]
    b2 = raw_b2[:min_len]
    k_bytes = key_text.encode("utf-8")

    c1 = rc4_crypt(b1, k_bytes)
    c2 = rc4_crypt(b2, k_bytes)

    # Phép XOR giữa hai bản mã C1 ^ C2 triệt tiêu hoàn toàn dòng khóa: (P1 ^ K) ^ (P2 ^ K) = P1 ^ P2
    xor_c1_c2 = bytes(x ^ y for x, y in zip(c1, c2))
    xor_p1_p2 = bytes(x ^ y for x, y in zip(b1, b2))

    other_text = p1_text if crib_in.lower() == "p2" else p2_text

    crib_matches: List[Tuple[int, str, str]] = []
    crib_candidates: List[CribCandidate] = []
    crib_bytes = crib_word.encode("utf-8")

    # Kéo trượt từ đoán trước (crib) qua từng vị trí của chuỗi XOR
    if crib_bytes and len(crib_bytes) <= min_len:
        w_len = len(crib_bytes)
        for pos in range(min_len - w_len + 1):
            segment = xor_c1_c2[pos : pos + w_len]
            candidate_bytes = bytes(x ^ y for x, y in zip(segment, crib_bytes))
            # Kiểm tra xem chuỗi giải ra có phải ký tự ASCII đọc được không (32..126)
            if all(32 <= b <= 126 for b in candidate_bytes):
                candidate_str = candidate_bytes.decode("utf-8", errors="replace")
                crib_matches.append((pos, crib_word, candidate_str))

                is_real = candidate_str == other_text[pos : pos + len(crib_word)]
                sc = score_readable(candidate_str)
                crib_candidates.append(
                    CribCandidate(
                        pos=pos,
                        crib=crib_word,
                        recovered=candidate_str,
                        score=sc,
                        matches_real=is_real,
                    )
                )

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
        crib_candidates=crib_candidates,
        crib_in=crib_in,
        len_p1=len_p1,
        len_p2=len_p2,
    )


# =============================================================================
# 2. Thiên lệch dòng khóa
# =============================================================================

def keystream_bias_counts(
    num_keys: int,
    key_len: int = 16,
    byte_index: int = 2,
    rng: Optional[random.Random] = None,
) -> List[int]:
    """
    Đo phân bố tần suất xuất hiện của byte dòng khóa thứ `byte_index` trên `num_keys` khóa ngẫu nhiên.
    Minh họa hiện tượng thiên lệch xác suất Mantin-Shamir (byte thứ 2 có xu hướng bằng 0x00 cao gấp đôi).

    Tham số:
        num_keys (int): Số lượng khóa ngẫu nhiên cần sinh để đo (num_keys >= 1).
        key_len (int): Độ dài mỗi khóa tính bằng byte (1..256 byte, mặc định 16).
        byte_index (int): Vị trí byte dòng khóa cần quan sát, đếm từ 1 (mặc định vị trí 2).
        rng (Optional[random.Random]): Bộ sinh số ngẫu nhiên có kiểm soát hạt giống (tùy chọn).

    Trả về:
        List[int]: Mảng 256 phần tử, phần tử thứ b là số lần xuất hiện của giá trị byte b.

    Ví dụ:
        counts = keystream_bias_counts(1000, 16, 2); print(counts[0]) -> số lần byte 0 xuất hiện
    """
    if num_keys < 1:
        raise ValueError("num_keys phải >= 1")
    if not (1 <= key_len <= 256):
        raise ValueError("key_len phải nằm trong khoảng 1..256")
    if not (1 <= byte_index <= 256):
        raise ValueError("byte_index phải nằm trong khoảng 1..256")

    gen = rng if rng is not None else random.Random()
    counts = [0] * 256
    dummy_input = bytes(byte_index)
    target_idx = byte_index - 1

    # Tạo khóa ngẫu nhiên và trích byte dòng khóa tại vị trí cần quan sát
    for _ in range(num_keys):
        key = gen.randbytes(key_len)
        keystream_byte = rc4_crypt(dummy_input, key)[target_idx]
        counts[keystream_byte] += 1

    return counts


# =============================================================================
# 3. Đo hiệu năng
# =============================================================================

def run_rc4_benchmark(
    sizes_kb: Optional[List[int]] = None,
) -> List[Dict[str, Union[float, int, str]]]:
    """
    Đo thời gian thực thi và thông lượng mã hóa RC4 (MB/giây) trên các kích thước dữ liệu khác nhau.
    Dữ liệu đo đạc phục vụ vẽ biểu đồ đường hoặc cột trên giao diện người dùng.

    Tham số:
        sizes_kb (Optional[List[int]]): Danh sách kích thước dữ liệu thử nghiệm tính bằng KB.

    Trả về:
        List[Dict[str, Union[float, int, str]]]: Danh sách kết quả đo gồm kích cỡ, mili-giây và MB/s.

    Ví dụ:
        run_rc4_benchmark([1, 10])[0]["size_label"] -> '1 KB'
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

