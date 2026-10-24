"""
Bộ kiểm thử tự động toàn diện dự án RC4 Lab (tests/test_rc4_lab.py)
Kiểm tra độ chính xác của thuật toán RC4/TinyRC4, stream chunk, sinh khóa và giao diện.
Được gọi bởi: công cụ kiểm thử pytest hoặc lệnh unittest khi chạy CI/CD và chấm điểm.
Gọi đến: toàn bộ các module trong src/core/ và các phân hệ giao diện trong src/ui/.
"""

from __future__ import annotations  # dùng để hỗ trợ kiểm tra kiểu dữ liệu tĩnh hiện đại
import inspect  # dùng để kiểm tra tính chất hàm và generator của Python
import io  # dùng để tạo luồng dữ liệu byte trong bộ nhớ RAM phục vụ upload tệp giả lập
import random  # dùng để sinh dữ liệu ngẫu nhiên có hạt giống cố định (seed) để kiểm thử
import unittest  # dùng để xây dựng các lớp ca kiểm thử theo cấu trúc TestCase chuẩn
from pathlib import Path  # dùng để thao tác đường dẫn tệp tin độc lập hệ điều hành
from typing import Iterator  # dùng để khai báo kiểu dữ liệu trình sinh tuần tự

import pytest  # dùng để phát hiện lỗi, chạy kiểm thử tham số và kiểm tra ngoại lệ
from starlette.datastructures import Headers, UploadFile  # dùng để tạo gói tin HTTP upload tệp tin

from nicegui import ui  # dùng để khởi tạo và truy vấn các thành phần giao diện web
from nicegui.elements.upload_files import create_file_upload  # dùng để giả lập sự kiện tải tệp lên
from nicegui.testing import User  # dùng để đóng vai người dùng tương tác tự động với trình duyệt

import src.core  # file nội bộ của dự án: gói lõi thuật toán mật mã
from src.core.analysis import (  # file nội bộ của dự án: phân tích an toàn và đo hiệu năng
    keystream_bias_counts,
    score_readable,
    simulate_keystream_reuse_attack,
)
from src.core.encoding import (  # file nội bộ của dự án: chuyển đổi bytes, hex và số 3-bit
    bytes_sang_hex,
    bytes_sang_so,
    hex_sang_bytes,
    so_sang_bytes,
)
from src.core.keys import (  # file nội bộ của dự án: sinh và xác thực khóa bí mật
    KHOA_TOI_DA_RC4,
    KHOA_TOI_DA_TINY,
    khoa_tu_chuoi,
    khoa_tu_hex,
    sinh_khoa_rc4,
    sinh_khoa_tiny,
)
from src.core.models import CribCandidate, KeystreamAttackResult  # file nội bộ: cấu trúc dữ liệu kết quả
from src.core.rc4 import rc4_crypt, rc4_crypt_chunks  # file nội bộ của dự án: thuật toán mã hóa RC4
from src.core.tiny_rc4 import run_tiny_rc4  # file nội bộ của dự án: thuật toán TinyRC4 3-bit
import src.ui.file_pipeline as file_pipeline  # file nội bộ của dự án: quy trình mã hóa tệp 3 bước
from src.ui.file_pipeline import build_file_pipeline  # file nội bộ của dự án: giao diện mã hóa tệp
from src.ui.tab_attack_bench import build_tab_attack_bench  # file nội bộ của dự án: tab thám mã
from src.ui.tab_testing import run_all_verification_cases  # file nội bộ của dự án: bộ vector kiểm thử

pytest_plugins = ["nicegui.testing.user_plugin"]  # plugin của NiceGUI hỗ trợ người dùng ảo kiểm thử


# =====================================================================
# 1. RC4 lõi và vector chuẩn
# =====================================================================

class TestRC4Core(unittest.TestCase):
    """Kiểm tra tính đúng đắn của thuật toán mã hóa TinyRC4 và RC4 đầy đủ."""

    def test_classroom_tiny_rc4_slide_56_to_60(self) -> None:
        """Kiểm tra khớp slide bài giảng NEU (BAG -> EBA) nhằm đảm bảo thuật toán chuẩn theo giáo trình."""
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

        # Giải mã đối xứng ngược lại đúng "BAG"
        dec = run_tiny_rc4(res.output_text, [2, 1, 3])
        self.assertEqual(dec.output_text, "BAG")

    def test_all_verification_vectors(self) -> None:
        """Kiểm tra toàn bộ 8 vector kiểm thử nhằm bảo đảm tính tuân thủ tiêu chuẩn mật mã quốc tế."""
        results = run_all_verification_cases()
        self.assertGreaterEqual(len(results), 8)
        for case in results:
            self.assertTrue(case.passed, f"Ca kiểm thử thất bại: {case.name}")

    def test_binary_image_encryption_roundtrip(self) -> None:
        """Kiểm tra mã hóa/giải mã ảnh nhị phân nhằm đảm bảo dữ liệu gốc được khôi phục 100% toàn vẹn."""
        sample_path = Path("sample_data") / "sample_logo.png"
        img_bytes = sample_path.read_bytes() if sample_path.exists() else b"PNG_FAKE_SAMPLE_12345678"
        key = b"Sample-Image-Secret-Key"
        encrypted = rc4_crypt(img_bytes, key)
        self.assertNotEqual(encrypted, img_bytes)
        decrypted = rc4_crypt(encrypted, key)
        self.assertEqual(decrypted, img_bytes)


# =====================================================================
# 2. Chunked streaming
# =====================================================================

class TestRC4Chunks(unittest.TestCase):
    """Kiểm thử toàn diện generator rc4_crypt_chunks chia nhỏ luồng mã hóa."""

    def setUp(self) -> None:
        """Thiết lập dữ liệu ngẫu nhiên cố định để đảm bảo tính tái lập."""
        rng = random.Random(42)
        self.random_5000 = bytes(rng.randint(0, 255) for _ in range(5000))
        self.key = b"RC4-Secret-Test-Key-2026"
        self.wrong_key = b"RC4-Wrong-Secret-Key-999"

    def test_export_in_src_core(self) -> None:
        """Kiểm tra export rc4_crypt_chunks ở src/core nhằm bảo đảm giao diện package luôn nhất quán."""
        self.assertTrue(hasattr(src.core, "rc4_crypt_chunks"))
        self.assertIn("rc4_crypt_chunks", src.core.__all__)
        self.assertIs(src.core.rc4_crypt_chunks, rc4_crypt_chunks)

    def test_is_generator_function(self) -> None:
        """Kiểm tra rc4_crypt_chunks là generator nhằm tiết kiệm RAM khi mã hóa tệp dữ liệu lớn."""
        self.assertTrue(inspect.isgeneratorfunction(rc4_crypt_chunks))
        gen = rc4_crypt_chunks(b"test", self.key)
        self.assertTrue(isinstance(gen, Iterator))

    def test_chunked_equals_oneshot_5000_bytes(self) -> None:
        """Kiểm tra chia khối khớp hoàn toàn với xử lý một lần nhằm bảo toàn tính toàn vẹn dữ liệu."""
        expected_ciphertext = rc4_crypt(self.random_5000, self.key)
        test_chunk_sizes = [1, 7, 256, 1000, 4999, 5000, 65536]

        for chunk_size in test_chunk_sizes:
            with self.subTest(chunk_size=chunk_size):
                chunks = list(rc4_crypt_chunks(self.random_5000, self.key, chunk_size=chunk_size))

                # Kiểm tra kích thước của từng khối sinh ra
                for i, chunk in enumerate(chunks):
                    if i < len(chunks) - 1:
                        self.assertEqual(
                            len(chunk),
                            chunk_size,
                            f"Khối trung gian thứ {i} không đúng kích thước {chunk_size}",
                        )
                    else:
                        self.assertLessEqual(
                            len(chunk),
                            chunk_size,
                            f"Khối cuối cùng vượt quá kích thước {chunk_size}",
                        )

                # Nối tất cả các khối phải khớp 100% với one-shot rc4_crypt
                combined = b"".join(chunks)
                self.assertEqual(
                    combined,
                    expected_ciphertext,
                    f"Kết quả nối khối không khớp với one-shot khi chunk_size={chunk_size}",
                )

    def test_roundtrip_correct_key(self) -> None:
        """Kiểm tra mã hóa rồi giải mã đúng khóa nhằm xác nhận tính đối xứng phục hồi nguyên vẹn dữ liệu."""
        test_sizes = [1, 7, 256, 1000, 5000, 65536]
        for enc_chunk in test_sizes:
            for dec_chunk in [7, 1000, 65536]:
                with self.subTest(enc_chunk=enc_chunk, dec_chunk=dec_chunk):
                    # Mã hóa theo enc_chunk
                    encrypted = b"".join(
                        rc4_crypt_chunks(self.random_5000, self.key, chunk_size=enc_chunk)
                    )
                    self.assertNotEqual(encrypted, self.random_5000)

                    # Giải mã theo dec_chunk (bất đối xứng kích thước khối)
                    decrypted = b"".join(
                        rc4_crypt_chunks(encrypted, self.key, chunk_size=dec_chunk)
                    )
                    self.assertEqual(
                        decrypted,
                        self.random_5000,
                        f"Round-trip thất bại khi mã hóa chunk={enc_chunk}, giải mã chunk={dec_chunk}",
                    )

    def test_wrong_key_gives_different_result(self) -> None:
        """Kiểm tra giải mã bằng sai khóa nhằm đảm bảo tính bảo mật và không thể lộ nội dung gốc."""
        encrypted = b"".join(rc4_crypt_chunks(self.random_5000, self.key, chunk_size=1000))
        decrypted_wrong = b"".join(
            rc4_crypt_chunks(encrypted, self.wrong_key, chunk_size=1000)
        )
        self.assertNotEqual(
            decrypted_wrong,
            self.random_5000,
            "Giải mã bằng khóa sai không được phép ra bản rõ gốc",
        )

    def test_empty_key_raises_value_error(self) -> None:
        """Kiểm tra từ chối khóa rỗng bằng ValueError nhằm ngăn chặn lỗ hổng không có khóa bảo vệ."""
        with self.assertRaises(ValueError):
            list(rc4_crypt_chunks(self.random_5000, b""))

        with self.assertRaises(ValueError):
            list(rc4_crypt_chunks(b"", b""))

    def test_oversized_key_raises_value_error(self) -> None:
        """Kiểm tra chặn khóa vượt 256 byte bằng ValueError nhằm tuân thủ giới hạn kiến trúc mảng S."""
        oversized_key = b"A" * 257
        with self.assertRaises(ValueError):
            list(rc4_crypt_chunks(self.random_5000, oversized_key))

    def test_invalid_chunk_size_raises_value_error(self) -> None:
        """Kiểm tra chặn kích thước khối nhỏ hơn 1 bằng ValueError nhằm ngăn ngừa vòng lặp vô hạn."""
        invalid_sizes = [0, -1, -500]
        for cs in invalid_sizes:
            with self.subTest(chunk_size=cs):
                with self.assertRaises(ValueError):
                    list(rc4_crypt_chunks(self.random_5000, self.key, chunk_size=cs))

    def test_empty_data(self) -> None:
        """Kiểm tra dữ liệu rỗng b'' sinh ra 0 khối nhằm xử lý an toàn trường hợp biên không lỗi."""
        chunks = list(rc4_crypt_chunks(b"", self.key, chunk_size=256))
        self.assertEqual(chunks, [])
        self.assertEqual(b"".join(chunks), b"")
        self.assertEqual(b"".join(chunks), rc4_crypt(b"", self.key))

    def test_default_chunk_size(self) -> None:
        """Kiểm tra kích thước khối mặc định 64KB nhằm tối ưu tốc độ đọc ghi tệp tin dung lượng lớn."""
        combined = b"".join(rc4_crypt_chunks(self.random_5000, self.key))
        self.assertEqual(combined, rc4_crypt(self.random_5000, self.key))

    def test_classic_rfc_test_vectors(self) -> None:
        """Kiểm tra các test vector kinh điển của Wikipedia nhằm xác thực tính chuẩn mực của generator."""
        # Key = b"Key", Plaintext = b"Plaintext" -> BBF316E8D940AF0AD3
        c1 = b"".join(rc4_crypt_chunks(b"Plaintext", b"Key", chunk_size=2))
        self.assertEqual(c1.hex().upper(), "BBF316E8D940AF0AD3")

        # Key = b"Wiki", Plaintext = b"pedia" -> 1021BF0420
        c2 = b"".join(rc4_crypt_chunks(b"pedia", b"Wiki", chunk_size=3))
        self.assertEqual(c2.hex().upper(), "1021BF0420")


# =====================================================================
# 3. Khóa và encoding
# =====================================================================

def test_wikipedia_test_vectors():
    """Kiểm tra test vector kinh điển Wikipedia nhằm chứng minh hàm mã hóa khớp hoàn toàn chuẩn."""
    wiki_cases = [
        ("Key", "Plaintext", "BBF316E8D940AF0AD3"),
        ("Wiki", "pedia", "1021BF0420"),
        ("Secret", "Attack at dawn", "45A01F645FC35B383552544B9BF5"),
    ]
    for key_text, pt_text, expected_hex in wiki_cases:
        key_bytes = khoa_tu_chuoi(key_text)
        pt_bytes = pt_text.encode("utf-8")
        ct_bytes = rc4_crypt(pt_bytes, key_bytes)
        assert bytes_sang_hex(ct_bytes) == expected_hex


def test_rfc6229_test_vectors():
    """Kiểm tra vector IETF RFC 6229 nhằm chứng minh thuật toán tuân thủ đặc tả mật mã quốc tế."""
    rfc_cases = [
        ("0102030405", "B2396305F03DC027CCC3524A0A1118A8"),
        ("01020304050607", "293F02D47F37C9B633F2AF5285FEB46B"),
        ("0102030405060708", "97AB8A1BF0AFB96132F2F67258DA15A8"),
        ("0102030405060708090A", "EDE3B04643E586CC907DC21851709902"),
    ]
    zero_16 = bytes(16)
    for key_hex, expected_hex in rfc_cases:
        key_bytes = khoa_tu_hex(key_hex)
        ct_bytes = rc4_crypt(zero_16, key_bytes)
        assert ct_bytes.hex().upper() == expected_hex
        assert bytes_sang_hex(ct_bytes) == expected_hex


def test_key_validation_errors():
    """Kiểm tra phát hiện và bắt các lỗi khóa sai nhằm bảo vệ an toàn cho toàn bộ hệ thống mã hóa."""
    # Hex có số ký tự lẻ
    with pytest.raises(
        ValueError, match="Khoá hex chỉ gồm ký tự 0-9, A-F và số ký tự phải chẵn"
    ):
        khoa_tu_hex("ABC")

    # Hex chứa ký tự không hợp lệ
    with pytest.raises(
        ValueError, match="Khoá hex chỉ gồm ký tự 0-9, A-F và số ký tự phải chẵn"
    ):
        khoa_tu_hex("ZZ")

    # Khóa chuỗi rỗng (0 byte)
    with pytest.raises(ValueError, match="0 byte"):
        khoa_tu_chuoi("")

    # Khóa chuỗi vượt quá 256 byte
    with pytest.raises(ValueError, match="257 byte"):
        khoa_tu_chuoi("a" * 257)

    # Khóa hex vượt quá 256 byte (514 hex chars = 257 bytes)
    with pytest.raises(ValueError):
        khoa_tu_hex("00" * 257)

    # sinh_khoa_rc4 ngoài khoảng 1..256
    with pytest.raises(ValueError):
        sinh_khoa_rc4(0)

    with pytest.raises(ValueError):
        sinh_khoa_rc4(257)

    # sinh_khoa_tiny ngoài khoảng 1..8
    with pytest.raises(ValueError):
        sinh_khoa_tiny(0)

    with pytest.raises(ValueError):
        sinh_khoa_tiny(9)


def test_key_generation_lengths_and_ranges():
    """Kiểm tra độ dài và miền giá trị khóa ngẫu nhiên nhằm đảm bảo khóa sinh ra đủ chuẩn an toàn."""
    rc4_key = sinh_khoa_rc4(16)
    assert isinstance(rc4_key, bytes)
    assert len(rc4_key) == 16

    tiny_key = sinh_khoa_tiny(3, n=3)
    assert isinstance(tiny_key, list)
    assert len(tiny_key) == 3
    assert all(0 <= val < 8 for val in tiny_key)


def test_bytes_sang_so_and_so_sang_bytes_roundtrip():
    """Kiểm tra chuyển đổi byte và số 3-bit qua lại nhằm bảo đảm bản rõ không sai lệch khi mã hóa."""
    d = "Xin chào".encode("utf-8")
    encoded_nums = bytes_sang_so(d, n=3)
    decoded_bytes = so_sang_bytes(encoded_nums, n=3, do_dai_goc=len(d))
    assert decoded_bytes == d

    # Kiểm tra thêm khi không truyền do_dai_goc (tự động cắt theo số byte nguyên)
    assert so_sang_bytes(encoded_nums, n=3) == d

    # Kiểm tra với mảng rỗng
    assert bytes_sang_so(b"") == []
    assert so_sang_bytes([]) == b""


def test_hex_conversion_roundtrip():
    """Kiểm tra chuyển đổi bytes và hex hai chiều nhằm phục vụ hiển thị chính xác trên giao diện."""
    d = "Xin chào".encode("utf-8")
    hex_str = bytes_sang_hex(d)
    assert hex_str.isupper()
    assert hex_sang_bytes(hex_str) == d

    # Kiểm tra hex_sang_bytes bỏ dấu cách
    assert hex_sang_bytes("01 02 03 04") == b"\x01\x02\x03\x04"

    # Kiểm tra lỗi hex không hợp lệ
    with pytest.raises(ValueError):
        hex_sang_bytes("ABC")  # lẻ

    with pytest.raises(ValueError):
        hex_sang_bytes("GG")  # sai ký tự


# =====================================================================
# 4. Tấn công crib-dragging
# =====================================================================

P1_ATTACK = "Kinh gui Quy khach: Mat khau OTP la 849201"
P2_ATTACK = "Chuyen khoan ngay 50000000 VND vao TK 9988"
K_ATTACK = "WEP-Reused-Key-123"


def test_score_readable():
    """Kiểm tra thuật toán chấm điểm văn bản đọc được nhằm nhận diện tự động bản rõ khi thám mã."""
    assert score_readable("") == 0.0
    assert score_readable("Hello World") == 1.0
    assert score_readable("1234") == 0.5
    assert score_readable(".,:-") == 0.25
    assert score_readable("@#$%") == 0.0
    # "A 1." -> 4 ký tự: chữ cái (1.0) + dấu cách (1.0) + chữ số (0.5) + dấu chấm (0.25) = 2.75 / 4 = 0.6875
    assert score_readable("A 1.") == pytest.approx(2.75 / 4)


def test_crib_dragging_primary_candidate():
    """Kiểm tra thám mã crib-dragging tìm đúng từ mẫu nhằm minh họa lỗ hổng tái sử dụng khóa."""
    crib = "Kinh gui Quy khach"
    res = simulate_keystream_reuse_attack(P1_ATTACK, P2_ATTACK, K_ATTACK, crib)

    assert len(res.crib_candidates) > 0
    cand_0 = next(c for c in res.crib_candidates if c.pos == 0)
    assert cand_0.recovered == "Chuyen khoan ngay "
    assert cand_0.matches_real is True

    max_score = max(c.score for c in res.crib_candidates)
    assert cand_0.score == max_score


def test_multiple_crib_words_match_real():
    """Kiểm tra thám mã với nhiều từ mẫu khác nhau nhằm khẳng định hiệu quả của đòn tấn công crib."""
    for crib in ["OTP", "Mat khau", "Mat khau OTP"]:
        res = simulate_keystream_reuse_attack(P1_ATTACK, P2_ATTACK, K_ATTACK, crib)
        expected_pos = P1_ATTACK.find(crib)
        assert expected_pos != -1

        matching_cands = [c for c in res.crib_candidates if c.pos == expected_pos]
        assert len(matching_cands) == 1
        cand = matching_cands[0]
        assert cand.matches_real is True
        assert cand.recovered == P2_ATTACK[expected_pos : expected_pos + len(crib)]


def test_matches_real_condition_for_all_candidates():
    """Kiểm tra đối chiếu mọi ứng viên với bản rõ thực tế nhằm đánh giá độ tin cậy của thuật toán."""
    for crib in ["Kinh", "OTP", "Mat khau", "khach"]:
        res = simulate_keystream_reuse_attack(P1_ATTACK, P2_ATTACK, K_ATTACK, crib, crib_in="p1")
        for c in res.crib_candidates:
            expected_match = c.recovered == P2_ATTACK[c.pos : c.pos + len(crib)]
            assert c.matches_real == expected_match


def test_crib_in_p2():
    """Kiểm tra crib-dragging khi từ mẫu thuộc P2 nhằm chứng minh tính đối xứng hai chiều của XOR."""
    crib = "Chuyen khoan"
    res = simulate_keystream_reuse_attack(P1_ATTACK, P2_ATTACK, K_ATTACK, crib, crib_in="p2")

    assert res.crib_in == "p2"
    cand_0 = next(c for c in res.crib_candidates if c.pos == 0)
    assert cand_0.recovered == "Kinh gui Quy"
    assert cand_0.matches_real is True


def test_asymmetric_lengths():
    """Kiểm tra xử lý hai bản rõ lệch độ dài nhằm đảm bảo phép XOR tự động cắt về độ dài chung an toàn."""
    p2_extended = P2_ATTACK + "XYZ"
    res = simulate_keystream_reuse_attack(P1_ATTACK, p2_extended, K_ATTACK, "Kinh")

    assert res.len_p1 == 42
    assert res.len_p2 == 45

    # Phép tính cắt về min_len = 42
    assert len(res.p1_text.encode("utf-8")) == 42
    assert len(res.p2_text.encode("utf-8")) == 42
    assert len(bytes.fromhex(res.c1_hex)) == 42
    assert len(bytes.fromhex(res.c2_hex)) == 42
    assert len(bytes.fromhex(res.xor_c1_c2_hex)) == 42


def test_empty_or_oversized_crib():
    """Kiểm tra từ mẫu rỗng hoặc vượt độ dài nhằm tránh lỗi ngoại lệ khi người dùng nhập sai."""
    # Crib rỗng
    res_empty = simulate_keystream_reuse_attack(P1_ATTACK, P2_ATTACK, K_ATTACK, "")
    assert res_empty.crib_candidates == []
    assert res_empty.crib_matches == []

    # Crib dài hơn bản rõ
    res_long = simulate_keystream_reuse_attack(P1_ATTACK, P2_ATTACK, K_ATTACK, "A" * 50)
    assert res_long.crib_candidates == []
    assert res_long.crib_matches == []


def test_streams_equal():
    """Kiểm tra tính chất triệt tiêu dòng khóa (C1^C2 = P1^P2) nhằm xác nhận nguyên lý Two-Time Pad."""
    res = simulate_keystream_reuse_attack(P1_ATTACK, P2_ATTACK, K_ATTACK, "Kinh")
    assert res.streams_equal is True


# =====================================================================
# 5. Thiên lệch dòng khóa
# =====================================================================

def test_bias_counts_sum():
    """Kiểm tra tổng tần suất bằng đúng số khóa thử nghiệm nhằm đảm bảo tính toàn vẹn của thống kê."""
    num_keys = 100
    counts = keystream_bias_counts(num_keys=num_keys, key_len=16, byte_index=2)
    assert len(counts) == 256
    assert sum(counts) == num_keys


def test_second_byte_bias_detected():
    """Kiểm tra thiên lệch byte 2 (P(byte=0) cao gấp đôi) nhằm chứng minh điểm yếu bảo mật của RC4."""
    rng = random.Random(2026)
    num_keys = 20000
    counts = keystream_bias_counts(num_keys=num_keys, key_len=16, byte_index=2, rng=rng)

    ratio = (counts[0] / num_keys) * 256
    assert ratio >= 1.5


def test_third_byte_unbiased():
    """Kiểm tra byte thứ 3 phân phối đều nhằm chứng minh hiện tượng thiên lệch chỉ ở các byte đầu."""
    rng = random.Random(2026)
    num_keys = 20000
    counts = keystream_bias_counts(num_keys=num_keys, key_len=16, byte_index=3, rng=rng)

    ratio = (counts[0] / num_keys) * 256
    assert ratio < 1.5


def test_reproducible_with_same_seed():
    """Kiểm tra tính tái lập khi dùng cùng seed ngẫu nhiên nhằm phục vụ kiểm thử và demo ổn định."""
    counts1 = keystream_bias_counts(num_keys=1000, key_len=16, byte_index=2, rng=random.Random(42))
    counts2 = keystream_bias_counts(num_keys=1000, key_len=16, byte_index=2, rng=random.Random(42))
    assert counts1 == counts2


def test_invalid_parameters_raise_value_error():
    """Kiểm tra bắt lỗi các tham số phân tích không hợp lệ nhằm ngăn chặn tính toán sai quy chuẩn."""
    # num_keys < 1
    with pytest.raises(ValueError):
        keystream_bias_counts(num_keys=0)
    with pytest.raises(ValueError):
        keystream_bias_counts(num_keys=-5)

    # key_len ngoài 1..256
    with pytest.raises(ValueError):
        keystream_bias_counts(num_keys=10, key_len=0)
    with pytest.raises(ValueError):
        keystream_bias_counts(num_keys=10, key_len=257)

    # byte_index ngoài 1..256
    with pytest.raises(ValueError):
        keystream_bias_counts(num_keys=10, byte_index=0)
    with pytest.raises(ValueError):
        keystream_bias_counts(num_keys=10, byte_index=257)


# =====================================================================
# 6. Giao diện (luồng ảnh, tab tấn công)
# =====================================================================

# Thiết lập alias _sample_bytes nếu cần
_sample_bytes = getattr(file_pipeline, "_sample_bytes", file_pipeline.get_default_sample_bytes)
if not hasattr(file_pipeline, "_sample_bytes"):
    file_pipeline._sample_bytes = file_pipeline.get_default_sample_bytes  # type: ignore


def _page_pipeline() -> None:
    """Đăng ký route '/' với build_file_pipeline phục vụ kiểm thử giao diện."""
    @ui.page("/")
    def index() -> None:
        build_file_pipeline()


def _page_attack() -> None:
    """Đăng ký route '/' với build_tab_attack_bench phục vụ kiểm thử giao diện."""
    @ui.page("/")
    def index() -> None:
        build_tab_attack_bench()


async def _upload_helper(
    user: User,
    filename: str,
    content: bytes,
    content_type: str = "application/octet-stream",
) -> None:
    """Hỗ trợ nạp tệp giả lập qua Starlette UploadFile để kiểm thử tải lên NiceGUI."""
    upload_file = UploadFile(
        file=io.BytesIO(content),
        filename=filename,
        headers=Headers({"content-type": content_type}),
    )
    res = create_file_upload(upload_file)
    fu = await res if inspect.isawaitable(res) else res
    upload_elem = user.find(kind=ui.upload).elements.pop()
    handle_res = upload_elem.handle_uploads([fu])
    if inspect.isawaitable(handle_res):
        await handle_res


@pytest.mark.asyncio
async def test_encrypt_then_decrypt_success(user: User) -> None:
    """Kiểm tra luồng mã hóa rồi giải mã trên UI nhằm đảm bảo trải nghiệm người dùng liền mạch."""
    _page_pipeline()
    await user.open("/")

    # Tắt 'Trình diễn chậm' trước khi mã hóa
    user.find(kind=ui.switch).elements.pop().set_value(False)

    # Bấm 'Mã hóa'
    user.find(kind=ui.button, content="Mã hóa").click()
    await user.should_see("Mã hóa xong")

    # Bấm 'Giải mã'
    user.find(kind=ui.button, content="Giải mã").click()
    await user.should_see("KHỚP 100% BẢN GỐC")


@pytest.mark.asyncio
async def test_wrong_key_decryption(user: User) -> None:
    """Kiểm tra cảnh báo khi giải mã bằng sai khóa trên UI nhằm ngăn lộ dữ liệu sai lệch."""
    _page_pipeline()
    await user.open("/")

    # Tắt 'Trình diễn chậm' trước khi mã hóa
    user.find(kind=ui.switch).elements.pop().set_value(False)

    # Bấm 'Mã hóa'
    user.find(kind=ui.button, content="Mã hóa").click()
    await user.should_see("Mã hóa xong")

    # Bấm 'Điền khóa sai'
    user.find(kind=ui.button, content="Điền khóa sai").click()

    # Bấm 'Giải mã'
    user.find(kind=ui.button, content="Giải mã").click()
    await user.should_see("KHÔNG KHỚP BẢN GỐC")
    await user.should_see("KHÔNG phải ảnh hợp lệ")


@pytest.mark.asyncio
async def test_upload_custom_image(user: User) -> None:
    """Kiểm tra tính năng tải ảnh tùy chọn của người dùng nhằm đảm bảo tương thích mọi tệp ảnh."""
    _page_pipeline()
    await user.open("/")

    # Upload anh_cua_toi.png
    sample_data = _sample_bytes()
    await _upload_helper(user, "anh_cua_toi.png", sample_data, content_type="image/png")
    await user.should_see("anh_cua_toi.png")

    # Tắt 'Trình diễn chậm' trước khi mã hóa
    user.find(kind=ui.switch).elements.pop().set_value(False)

    # Bấm 'Mã hóa'
    user.find(kind=ui.button, content="Mã hóa").click()
    await user.should_see("Mã hóa xong")

    # Bấm 'Giải mã'
    user.find(kind=ui.button, content="Giải mã").click()
    await user.should_see("KHỚP 100% BẢN GỐC")


@pytest.mark.asyncio
async def test_upload_rc4_file_decryption(user: User) -> None:
    """Kiểm tra giải mã tệp tin .rc4 tải lên nhằm hỗ trợ xử lý các tệp đã được mã hóa từ trước."""
    _page_pipeline()
    await user.open("/")

    # Tạo dữ liệu bản mã từ ảnh mẫu
    raw_sample = _sample_bytes()
    rc4_key = b"RC4-File-Encryption-Key-2026"
    encrypted_bytes = rc4_crypt(raw_sample, rc4_key)

    # Upload tệp logo.png.rc4
    await _upload_helper(user, "logo.png.rc4", encrypted_bytes, content_type="application/octet-stream")
    await user.should_see("chỉ có bản mã")

    # Tắt 'Trình diễn chậm' trước khi giải mã
    user.find(kind=ui.switch).elements.pop().set_value(False)

    # Bấm 'Giải mã'
    user.find(kind=ui.button, content="Giải mã").click()
    await user.should_see("Giải mã xong")
    await user.should_see("Không có bản gốc để đối chiếu")


@pytest.mark.asyncio
async def test_upload_oversized_file(user: User) -> None:
    """Kiểm tra chặn tệp vượt quá 8 MiB nhằm bảo vệ máy chủ khỏi nguy cơ tràn bộ nhớ và quá tải."""
    _page_pipeline()
    await user.open("/")

    # Tạo tệp vượt quá 8 MiB đúng 1 byte
    oversized_data = b"0" * (8 * 1024 * 1024 + 1)
    await _upload_helper(user, "oversized_test.bin", oversized_data)
    await user.should_see("quá lớn")


@pytest.mark.asyncio
async def test_hex_mode_encrypt_decrypt_success(user: User) -> None:
    """Kiểm tra chế độ nhập khóa Hex trên UI nhằm hỗ trợ người dùng kiểm thử các khóa nhị phân."""
    _page_pipeline()
    await user.open("/")

    # Tắt 'Trình diễn chậm' trước khi mã hóa
    user.find(kind=ui.switch).elements.pop().set_value(False)

    # Chọn toggle Hex
    user.find(kind=ui.toggle).elements.pop().set_value("Hex")

    # Nhập khóa hex hợp lệ ở cả hai ô
    valid_hex_key = "0102030405060708090A0B0C0D0E0F10"
    for inp in user.find(kind=ui.input).elements:
        inp.set_value(valid_hex_key)

    # Bấm 'Mã hóa'
    user.find(kind=ui.button, content="Mã hóa").click()
    await user.should_see("Mã hóa xong")

    # Bấm 'Giải mã'
    user.find(kind=ui.button, content="Giải mã").click()
    await user.should_see("KHỚP 100% BẢN GỐC")


@pytest.mark.asyncio
async def test_hex_mode_odd_length_error(user: User) -> None:
    """Kiểm tra bắt lỗi khóa Hex có độ dài lẻ trên UI nhằm hướng dẫn người dùng nhập đúng định dạng."""
    _page_pipeline()
    await user.open("/")

    # Chọn toggle Hex
    user.find(kind=ui.toggle).elements.pop().set_value("Hex")

    # Nhập 'ABC' vào ô khóa mã hóa
    for inp in user.find(kind=ui.input).elements:
        if "mã hóa" in (inp._props.get("label", "") or "").lower():
            inp.set_value("ABC")

    # Bấm 'Mã hóa'
    user.find(kind=ui.button, content="Mã hóa").click()
    await user.should_see("phải chẵn")


@pytest.mark.asyncio
async def test_attack_ui_shows_candidates(user: User) -> None:
    """Kiểm tra tab thám mã hiển thị danh sách ứng viên nhằm trực quan hóa đòn tấn công dùng lại khóa."""
    _page_attack()
    await user.open("/")

    # Kiểm tra sự xuất hiện của dòng thống kê ứng viên
    await user.should_see("ứng viên")

    # Kiểm tra nhãn kiểm chứng dòng khóa
    await user.should_see("Dòng khóa bị triệt tiêu")

    # Kiểm tra toggle "Crib nằm trong"
    await user.should_see("Crib nằm trong")

    # Kiểm tra công tắc "Xếp theo điểm"
    await user.should_see("Xếp theo điểm")


@pytest.mark.asyncio
async def test_attack_ui_toggle_p2_and_custom_crib(user: User) -> None:
    """Kiểm tra tùy chọn chuyển đổi vị trí từ mẫu trên UI nhằm tăng tính tương tác khi phân tích."""
    _page_attack()
    await user.open("/")

    # Tìm ô nhập Crib và gán 'Mat khau OTP'
    crib_input = next(
        elem for elem in user.find(kind=ui.input).elements
        if "Từ đoán trước" in (elem._props.get("label") or "")
    )
    crib_input.set_value("Mat khau OTP")

    # Tìm toggle 'Crib nằm trong' và chuyển sang 'P2'
    crib_toggle = user.find(kind=ui.toggle).elements.pop()
    crib_toggle.set_value("P2")

    # Bấm nút Thực hiện Thám mã Known-Plaintext
    user.find(kind=ui.button, content="Thực hiện Thám mã Known-Plaintext").click()

    # Kiểm tra thấy '6 ứng viên'
    await user.should_see("6 ứng viên")


@pytest.mark.asyncio
async def test_bias_card_ui_experiment(user: User) -> None:
    """Kiểm tra thẻ thực nghiệm thiên lệch Mantin-Shamir nhằm trực quan hóa kết quả thống kê xác suất."""
    _page_attack()
    await user.open("/")

    # Kiểm tra thẻ 3 hiển thị đầy đủ
    await user.should_see("3. Thiên Lệch Dòng Khóa (Mantin–Shamir)")
    await user.should_see("Số khóa thử")
    await user.should_see("Chạy thực nghiệm")

    # Giảm số khóa thử xuống 1000 để test chạy nhanh trong 0.1s
    num_input = next(
        elem for elem in user.find(kind=ui.number).elements
        if "Số khóa thử" in (elem._props.get("label") or "")
    )
    num_input.set_value(1000)

    # Bấm nút Chạy thực nghiệm
    user.find(kind=ui.button, content="Chạy thực nghiệm").click()

    # Chờ kết quả hiển thị
    await user.should_see("Mức đều lý thuyết = 1/256 = 0,0039")
    await user.should_see("P(byte = 0)")


if __name__ == "__main__":
    unittest.main(verbosity=2)
