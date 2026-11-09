"""
Phân Tích An Toàn và Đo Lường Hiệu Năng RC4 (src/core/phan_tich_an_toan.py)
Gồm 3 phần: tấn công Two-Time Pad & Crib-dragging, đo thiên lệch byte và đo tốc độ mã hóa.
Được gọi bởi: phân hệ thám mã & benchmark (tab_tham_ma) và test suite.
Gọi đến: src.core.mo_hinh_du_lieu (chứa kết quả thám mã) và src.core.rc4_chuan (thuật toán mã hóa RC4).
Thuật ngữ: Two-Time Pad là lỗ hổng dùng lại một dòng khóa khiến C1 ^ C2 = P1 ^ P2 mất an toàn;
Crib là từ ngữ dự đoán trước (ví dụ 'Kinh gui') để kéo trượt qua bản XOR khôi phục bản rõ;
Bias là hiện tượng thiên lệch xác suất, ví dụ byte thứ 2 về 0x00 với tỷ lệ 1/128 thay vì 1/256.
"""

from __future__ import annotations  # dùng để kích hoạt tính năng kiểm tra kiểu dữ liệu tĩnh
import random  # dùng để sinh các khóa ngẫu nhiên phục vụ phân tích thực nghiệm thiên lệch byte
import time  # dùng để bấm giờ thực thi các đòn tấn công và benchmark
from typing import Dict, List, Optional, Tuple, Union  # dùng để định nghĩa kiểu dữ liệu chuẩn

from src.core.mo_hinh_du_lieu import (  # file nội bộ: cấu trúc thám mã và kết quả tấn công
    CribCandidate,
    FMSAttackResult,
    FMSByteResult,
    KeystreamAttackResult,
)
from src.core.rc4_chuan import rc4_crypt, rc4_crypt_with_details  # file nội bộ: hàm mã hóa RC4


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


# =============================================================================
# 4. Tấn công khôi phục khóa FMS trong WEP (Mục 2.7 & 2.8)
# =============================================================================

def fms_partial_ksa(known_bytes: Union[bytes, List[int]]) -> Tuple[List[int], int]:
    """
    Mô phỏng KSA từng phần cho chuỗi byte khóa đã biết (gồm 3 byte IV và A byte bí mật K[0..A-1]).
    Thực hiện khởi tạo mảng S và hoán vị đến hết vòng thứ len(known_bytes) - 1.

    Tham số:
        known_bytes (Union[bytes, List[int]]): Dãy byte đã biết gồm IV công khai và các byte khóa trước đó.

    Trả về:
        Tuple[List[int], int]: Mảng trạng thái S và giá trị biến j tại thời điểm trước vòng kế tiếp.
    """
    # Khoi tao day so S va T
    # S[i] = i; T[i] duoc dai dien bang cac byte known_bytes
    S = list(range(256))

    # Hoan vi day S
    j = 0
    for i in range(len(known_bytes)):
        j = (j + S[i] + known_bytes[i]) % 256
        S[i], S[j] = S[j], S[i]

    return S, j


def fms_predict_first_output(S: List[int], j: int, i_round: int, guess: int) -> int:
    """
    Dự đoán byte đầu tiên của dòng khóa Z0 nếu byte khóa tại vòng i_round nhận giá trị `guess`.
    Sử dụng kỹ thuật tráo đổi tại chỗ (in-place swap & swap-back) để đạt hiệu năng tối đa.

    Tham số:
        S (List[int]): Mảng trạng thái S tại đầu vòng i_round (bị thay đổi tạm thời và hoàn tác).
        j (int): Giá trị chỉ số j tại đầu vòng i_round.
        i_round (int): Chỉ số vòng KSA hiện tại (ví dụ A + 3).
        guess (int): Giá trị byte ứng viên đang thử nghiệm (0..255).

    Trả về:
        int: Byte dòng khóa đầu tiên Z0 dự đoán được.
    """
    jj = (j + S[i_round] + guess) % 256
    # Hoán vị tạm thời hai phần tử S[i_round] và S[jj]
    S[i_round], S[jj] = S[jj], S[i_round]
    idx = (S[1] + S[S[1]]) % 256
    predicted_z0 = S[idx]
    # Hoàn tác (swap-back) để giữ nguyên mảng S gốc mà không cần gọi S.copy()
    S[i_round], S[jj] = S[jj], S[i_round]
    return predicted_z0


def simulate_fms_wep_attack(
    secret_key: Union[bytes, str, List[int]],
    samples_per_byte: int = 600,
    p0: int = 0xAA,
    num_verify: int = 50,
    seed: Optional[int] = 42,
) -> FMSAttackResult:
    """
    Mô phỏng toàn diện tấn công khôi phục khóa FMS (Fluhrer, Mantin, Shamir) trên giao thức WEP.
    Theo sát 5 giai đoạn lý thuyết Bảng 2.17 và kịch bản thực nghiệm mục 2.8:
    1. Xác định dòng khóa đầu: Z0 = C0 ^ P0
    2. Mô phỏng KSA từng phần cho IV và A byte đã biết
    3. Thử 256 ứng viên cho K[A] qua hàm fms_predict_first_output
    4. Tích lũy phiếu thống kê qua các gói tin mang IV yếu (A+3, 255, X)
    5. Kiểm chứng độc lập trên num_verify gói tin ngẫu nhiên để xác nhận khóa chính xác 100%

    Tham số:
        secret_key (Union[bytes, str, List[int]]): Khóa bí mật dùng chung (ví dụ "KEY_1" = 5 byte).
        samples_per_byte (int): Số lượng gói tin IV yếu thu thập cho mỗi byte khóa (mặc định 600).
        p0 (int): Byte bản rõ đầu tiên đã biết trước (mặc định 0xAA, tiêu đề SNAP/LLC).
        num_verify (int): Số gói kiểm chứng độc lập ở giai đoạn cuối (mặc định 50).
        seed (Optional[int]): Hạt giống ngẫu nhiên (mặc định 42 để kết quả tái lập chuẩn xác).

    Trả về:
        FMSAttackResult: Đối tượng chứa khóa khôi phục, chi tiết phiếu bầu và tỷ lệ kiểm chứng.
    """
    t_start = time.perf_counter()

    if isinstance(secret_key, str):
        sec_key_bytes = secret_key.encode("utf-8")
    elif isinstance(secret_key, list):
        sec_key_bytes = bytes(secret_key)
    else:
        sec_key_bytes = secret_key

    if not sec_key_bytes:
        raise ValueError("Khóa bí mật không được để trống.")

    rng = random.Random(seed) if seed is not None else random.Random()
    recovered: List[int] = []
    byte_results: List[FMSByteResult] = []
    collected_packets: List[Tuple[List[int], int]] = []

    key_len = len(sec_key_bytes)

    # Lặp qua từng byte của khóa bí mật K[B] (B = 0..key_len - 1)
    for B in range(key_len):
        votes = [0] * 256
        for _ in range(samples_per_byte):
            X = rng.randint(0, 255)
            # Lớp IV yếu kinh điển: (A + 3, 0xFF, X)
            iv = [B + 3, 0xFF, X]
            packet_key = bytes(iv) + sec_key_bytes
            # Mã hóa gói tin thực tế bằng RC4 chuẩn
            z0_true = rc4_crypt(bytes(1), packet_key)[0]
            c0 = z0_true ^ p0
            collected_packets.append((iv, c0))

            # Phía kẻ tấn công: chỉ dùng thông tin quan sát được trên mạng (IV và C0)
            z0_observed = c0 ^ p0
            known_bytes = iv + recovered
            s_state, j_state = fms_partial_ksa(known_bytes)
            i_round = len(known_bytes)  # bằng B + 3

            # Bỏ phiếu cho 256 ứng viên byte khóa
            for g in range(256):
                if fms_predict_first_output(s_state, j_state, i_round, g) == z0_observed:
                    votes[g] += 1

        ranked = sorted(range(256), key=lambda g: votes[g], reverse=True)
        best = ranked[0]
        recovered.append(best)

        top_candidates = [(g, votes[g]) for g in ranked[:5]]
        true_b = sec_key_bytes[B]
        byte_results.append(
            FMSByteResult(
                byte_index=B,
                true_byte=true_b,
                recovered_byte=best,
                matched=(best == true_b),
                top_votes=votes[best],
                total_samples=samples_per_byte,
                top_candidates=top_candidates,
                all_votes=list(votes),
            )
        )

    # Giai đoạn 5: Kiểm chứng khóa ứng viên trên num_verify gói ngẫu nhiên
    verify_sample_size = min(num_verify, len(collected_packets))
    sample_check = rng.sample(collected_packets, verify_sample_size) if verify_sample_size > 0 else []
    verified_count = 0
    rec_bytes = bytes(recovered)

    for iv, c0 in sample_check:
        cand_packet_key = bytes(iv) + rec_bytes
        z0_pred = rc4_crypt(bytes(1), cand_packet_key)[0]
        if (z0_pred ^ p0) == c0:
            verified_count += 1

    t_end = time.perf_counter()
    all_matched = (rec_bytes == sec_key_bytes)

    return FMSAttackResult(
        secret_key_bytes=sec_key_bytes,
        recovered_key_bytes=rec_bytes,
        all_matched=all_matched,
        samples_per_byte=samples_per_byte,
        p0_byte=p0,
        byte_results=byte_results,
        verified_packets=verified_count,
        total_verified_packets=verify_sample_size,
        elapsed_ms=round((t_end - t_start) * 1000.0, 2),
        collected_packets_count=len(collected_packets),
    )


