"""
Bộ kiểm thử tự động toàn diện dự án RC4 Lab (tests/test_kiem_thu_toan_dien.py)
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
from src.core.phan_tich_an_toan import (  # file nội bộ của dự án: phân tích an toàn và đo hiệu năng
    fms_partial_ksa,
    fms_predict_first_output,
    keystream_bias_counts,
    score_readable,
    simulate_fms_wep_attack,
    simulate_keystream_reuse_attack,
)
from src.core.chuyen_doi_du_lieu import (  # file nội bộ của dự án: chuyển đổi bytes, hex và số 3-bit
    bytes_sang_hex,
    bytes_sang_so,
    hex_sang_bytes,
    kiem_tra_giai_ma_utf8_ban_ma,
    phan_tich_ky_tu_utf8,
    so_sang_bytes,
    trace_rc4_utf8_xor,
)
from src.core.quan_ly_khoa import (  # file nội bộ của dự án: sinh và xác thực khóa bí mật
    KHOA_TOI_DA_RC4,
    KHOA_TOI_DA_TINY,
    khoa_tu_chuoi,
    khoa_tu_hex,
    sinh_khoa_rc4,
    sinh_khoa_tiny,
)
from src.core.mo_hinh_du_lieu import CribCandidate, FMSAttackResult, KeystreamAttackResult  # file nội bộ: cấu trúc dữ liệu kết quả
from src.core.rc4_chuan import rc4_crypt, rc4_crypt_chunks  # file nội bộ của dự án: thuật toán mã hóa RC4
from src.core.rc4_thu_nho import run_tiny_rc4  # file nội bộ của dự án: thuật toán TinyRC4 3-bit
import src.ui.tab_rc4_tep_tin as file_pipeline  # file nội bộ của dự án: quy trình mã hóa tệp 3 bước
from src.ui.tab_rc4_tep_tin import dung_tab_rc4_tep_tin  # file nội bộ của dự án: giao diện mã hóa tệp
from src.ui.khung_giao_dien import dung_khung_giao_dien  # file nội bộ của dự án: bố cục giao diện chính
from src.ui.tab_tham_ma import dung_tab_tham_ma  # file nội bộ của dự án: tab thám mã
from src.ui.tab_rc4_van_ban import dung_tab_rc4_van_ban  # file nội bộ của dự án: tab mã hóa văn bản UTF-8
from src.ui.tab_kiem_thu import dung_tab_kiem_thu, chay_tat_ca_ca_kiem_thu  # file nội bộ: giao diện & vector kiểm thử

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
        """Kiểm tra toàn bộ 20 ca kiểm thử chuẩn hóa theo 4 bảng Chương 4."""
        results = chay_tat_ca_ca_kiem_thu()
        self.assertEqual(len(results), 20)
        test_ids = [r.test_id for r in results]
        self.assertIn("TINY-01", test_ids)
        self.assertIn("RC4-01", test_ids)
        self.assertIn("DATA-01", test_ids)
        self.assertIn("SPECIAL-01", test_ids)
        for case in results:
            self.assertTrue(case.passed, f"Ca kiểm thử thất bại: {case.test_id} - {case.name}")

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
# 4b. Tấn công khôi phục khóa FMS trong WEP (Mục 2.7 & 2.8)
# =====================================================================

def test_fms_partial_ksa_and_predict():
    """Kiểm tra mô phỏng KSA từng phần và dự đoán byte đầu ra Z0 của FMS."""
    iv = [3, 0xFF, 42]
    S, j = fms_partial_ksa(iv)
    assert len(S) == 256
    # Sau vòng 1 với key=0xFF, S[1] phải bằng 0 theo điều kiện resolved
    assert S[1] == 0
    # Kiểm tra hàm dự đoán không làm biến dạng mảng S (swap-back thành công)
    original_S = list(S)
    pred = fms_predict_first_output(S, j, i_round=3, guess=75)
    assert 0 <= pred <= 255
    assert S == original_S


def test_fms_attack_reproduces_md_table_seed42():
    """
    Kiểm tra thuật toán FMS tái lập chính xác 100% bảng kết quả thực nghiệm trong tài liệu mục 2.8.5.
    Khóa bí mật: b'KEY_1', 600 mẫu/byte, seed=42 -> khôi phục b'KEY_1' và 50/50 gói kiểm chứng khớp.
    """
    res: FMSAttackResult = simulate_fms_wep_attack(
        secret_key="KEY_1",
        samples_per_byte=600,
        p0=0xAA,
        num_verify=50,
        seed=42,
    )
    assert res.all_matched is True
    assert res.recovered_key_bytes == b"KEY_1"
    assert res.verified_packets == 50
    assert res.total_verified_packets == 50
    assert len(res.byte_results) == 5

    # Đối chiếu chính xác các giá trị byte và số phiếu dẫn đầu theo Bảng 2.8.5:
    # K[0]: 'K' (75), 31 phiếu
    assert res.byte_results[0].true_byte == 75
    assert res.byte_results[0].recovered_byte == 75
    assert res.byte_results[0].top_votes == 31
    assert res.byte_results[0].matched is True

    # K[1]: 'E' (69), 23 phiếu
    assert res.byte_results[1].true_byte == 69
    assert res.byte_results[1].recovered_byte == 69
    assert res.byte_results[1].top_votes == 23
    assert res.byte_results[1].matched is True

    # K[2]: 'Y' (89), 31 phiếu
    assert res.byte_results[2].true_byte == 89
    assert res.byte_results[2].recovered_byte == 89
    assert res.byte_results[2].top_votes == 31
    assert res.byte_results[2].matched is True

    # K[3]: '_' (95), 41 phiếu
    assert res.byte_results[3].true_byte == 95
    assert res.byte_results[3].recovered_byte == 95
    assert res.byte_results[3].top_votes == 41
    assert res.byte_results[3].matched is True

    # K[4]: '1' (49), 17 phiếu (byte sít sao)
    assert res.byte_results[4].true_byte == 49
    assert res.byte_results[4].recovered_byte == 49
    assert res.byte_results[4].top_votes == 17
    assert res.byte_results[4].matched is True


def test_fms_attack_custom_key():
    """Kiểm tra khôi phục thành công với khóa tùy chỉnh khác b'TEST1'."""
    res = simulate_fms_wep_attack(
        secret_key=b"TEST1",
        samples_per_byte=800,
        p0=0xAA,
        num_verify=30,
        seed=123,
    )
    assert res.all_matched is True
    assert res.recovered_key_bytes == b"TEST1"
    assert res.verified_packets == 30



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
    """Đăng ký route '/' với dung_tab_rc4_tep_tin phục vụ kiểm thử giao diện."""
    @ui.page("/")
    def index() -> None:
        dung_tab_rc4_tep_tin()


def _page_attack() -> None:
    """Đăng ký route '/' với dung_tab_tham_ma phục vụ kiểm thử giao diện."""
    @ui.page("/")
    def index() -> None:
        dung_tab_tham_ma()


def _page_rc4_text() -> None:
    """Đăng ký route '/' với dung_tab_rc4_van_ban phục vụ kiểm thử giao diện phân hệ văn bản UTF-8."""
    @ui.page("/")
    def index() -> None:
        dung_tab_rc4_van_ban()


def _page_layout() -> None:
    """Đăng ký route '/' với dung_khung_giao_dien phục vụ kiểm thử toàn bộ khung giao diện."""
    @ui.page("/")
    def index() -> None:
        dung_khung_giao_dien()


def _page_testing() -> None:
    """Đăng ký route '/' với dung_tab_kiem_thu phục vụ kiểm thử giao diện phân hệ đối chiếu chuẩn."""
    @ui.page("/")
    def index() -> None:
        dung_tab_kiem_thu()


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
async def test_attack_ui_three_practical_cards(user: User) -> None:
    """Kiểm tra Tab 4 hiển thị đúng 3 phân hệ tấn công thực hành và đã loại bỏ hoàn toàn thẻ đo hiệu năng."""
    _page_attack()
    await user.open("/")

    # Phân hệ 1: Tấn công FMS khôi phục khóa K
    await user.should_see("1. Tấn Công Bẻ Khóa FMS trong WEP")
    await user.should_see("Chạy Bẻ Khóa FMS")

    # Phân hệ 2: Tấn công dùng lại dòng khóa (Two-Time Pad)
    await user.should_see("2. Tấn Công Dùng Lại Dòng Khóa (Two-Time Pad)")
    await user.should_see("Thực hiện Thám mã Known-Plaintext")

    # Phân hệ 3: Thiên lệch dòng khóa Mantin-Shamir
    await user.should_see("3. Thiên Lệch Dòng Khóa (Mantin–Shamir)")
    await user.should_see("Chạy thực nghiệm")


@pytest.mark.asyncio
async def test_layout_navigation_structure(user: User) -> None:
    """Kiểm tra thanh menu điều hướng chỉ gồm 4 phân hệ thực hành và đã loại bỏ hoàn toàn tab Lý thuyết."""
    _page_layout()
    await user.open("/")

    await user.should_see("TinyRC4 (3-bit)")
    await user.should_see("RC4 Chuẩn & File")
    await user.should_see("Kiểm Thử (RFC 6229)")
    await user.should_see("Thám Mã & Tấn Công")


@pytest.mark.asyncio
async def test_tab_testing_ui_elements(user: User) -> None:
    """Kiểm tra giao diện Tab 3 hiển thị đầy đủ 20 ca kiểm thử, thẻ môi trường, bộ lọc nhóm và khối tùy biến."""
    _page_testing()
    await user.open("/")

    await user.should_see("Bộ Kiểm Thử Tự Động & Đối Chiếu Chuẩn")
    await user.should_see("20 Ca Kiểm Thử")
    await user.should_see("20/20 (100%)")
    await user.should_see("Kiểm Thử Ca Tùy Biến")
    await user.should_see("Bản rõ (Plaintext P)")
    await user.should_see("Khóa bí mật (Key K)")
    await user.should_see("Kiểm Chứng Ngay")
    await user.should_see("Thêm Vào Bảng")
    await user.should_see("Lọc nhóm ca kiểm thử:")

    # Thử bấm "Kiểm Chứng Ngay" cho ca tùy biến mặc định
    user.find(kind=ui.button, content="Kiểm Chứng Ngay").click()
    await user.should_see("Bản mã sinh ra:")
    await user.should_see("Dòng khóa (Keystream):")


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


@pytest.mark.asyncio
async def test_fms_ui_elements(user: User) -> None:
    """Kiểm tra thẻ mô phỏng tấn công bẻ khóa FMS WEP trên giao diện Tab 4."""
    _page_attack()
    await user.open("/")

    # Kiểm tra tiêu đề và các thành phần chính của FMS
    await user.should_see("Tấn Công Bẻ Khóa FMS trong WEP")
    await user.should_see("Chạy Bẻ Khóa FMS")
    await user.should_see("Cố định seed=42")
    await user.should_see("Khóa bí mật K")

    # Kiểm tra kết quả tự động chạy lần đầu (seed=42)
    await user.should_see("Trùng khớp 100%")
    await user.should_see("Kiểm chứng độc lập")
    await user.should_see("Bảng Kết Quả Từng Byte Khóa")

    tbl = next(elem for elem in user.find(kind=ui.table).elements if "byte_name" in str(elem._props.get("columns")))
    assert len(tbl.rows) == 5
    assert tbl.rows[0]["byte_name"] == "K[0]"
    assert tbl.rows[0]["true_val"] == "75 (K)"
    assert [s.get("byte_name") for s in tbl.selected] == ["K[0]"]


@pytest.mark.asyncio
async def test_fms_p0_validation_error(user: User) -> None:
    """Kiểm tra cảnh báo khi người dùng nhập P0 không hợp lệ hoặc lớn hơn 255."""
    _page_attack()
    await user.open("/")

    p0_input = next(
        elem for elem in user.find(kind=ui.input).elements
        if "Byte bản rõ đầu P0" in (elem._props.get("label") or "")
    )
    p0_input.set_value("821")

    user.find(kind=ui.button, content="Chạy Bẻ Khóa FMS").click()
    await user.should_see("khoảng 0..255")


@pytest.mark.asyncio
async def test_fms_ui_run_custom_key_july(user: User) -> None:
    """Kiểm tra người dùng đổi khóa thành 'JULY' và chạy bẻ khóa FMS cập nhật giao diện mượt mà."""
    _page_attack()
    await user.open("/")

    key_input = next(
        elem for elem in user.find(kind=ui.input).elements
        if "Khóa bí mật K" in (elem._props.get("label") or "")
    )
    key_input.set_value("JULY")

    # Giảm số mẫu xuống 150 để test chạy nhanh trong unit test
    samples_input = next(
        elem for elem in user.find(kind=ui.number).elements
        if "Số mẫu IV yếu / byte" in (elem._props.get("label") or "")
    )
    samples_input.set_value(150)

    user.find(kind=ui.button, content="Chạy Bẻ Khóa FMS").click()
    await user.should_see("Đã hoàn thành bẻ khóa FMS")
    await user.should_see("b'JULY'")

    tbl = next(elem for elem in user.find(kind=ui.table).elements if "byte_name" in str(elem._props.get("columns")))
    assert len(tbl.rows) == 4
    assert tbl.rows[0]["byte_name"] == "K[0]"
    assert "74 (J)" in tbl.rows[0]["true_val"]
    assert tbl.rows[1]["byte_name"] == "K[1]"
    assert "85 (U)" in tbl.rows[1]["true_val"]
    assert tbl.rows[2]["byte_name"] == "K[2]"
    assert "76 (L)" in tbl.rows[2]["true_val"]
    assert tbl.rows[3]["byte_name"] == "K[3]"
    assert "89 (Y)" in tbl.rows[3]["true_val"]


# =============================================================================
# CÁC CA KIỂM THỬ ĐẶC TẢ UTF-8 TRONG RC4 (MỤC 2.1.4 GIÁO TRÌNH)
# =============================================================================


class TestUtf8Rc4Spec(unittest.TestCase):
    """Bộ kiểm thử kiểm chứng tính toán phân rã UTF-8 và bảng diễn giải 8-bit XOR theo Mục 2.1.4."""

    def test_utf8_breakdown_sample_a_a(self) -> None:
        """Kiểm tra phân tích chuỗi 'Aà' thành các byte và mẫu bit chuẩn Bảng 2.2, 2.3, 2.4."""
        chars = phan_tich_ky_tu_utf8("Aà")
        self.assertEqual(len(chars), 2)

        # Ký tự 'A' (1 byte)
        cA = chars[0]
        self.assertEqual(cA.char, "A")
        self.assertEqual(cA.codepoint, "U+0041")
        self.assertEqual(cA.codepoint_dec, 65)
        self.assertEqual(cA.byte_count, 1)
        self.assertEqual(cA.pattern, "0xxxxxxx")
        self.assertEqual(cA.hex_str, "41")
        self.assertEqual(cA.bin_str, "01000001")
        self.assertEqual(cA.byte_dec_list, [65])

        # Ký tự 'à' (2 byte)
        ca_grave = chars[1]
        self.assertEqual(ca_grave.char, "à")
        self.assertEqual(ca_grave.codepoint, "U+00E0")
        self.assertEqual(ca_grave.codepoint_dec, 224)
        self.assertEqual(ca_grave.byte_count, 2)
        self.assertEqual(ca_grave.pattern, "110xxxxx 10xxxxxx")
        self.assertEqual(ca_grave.data_bits, "00011 100000")
        self.assertEqual(ca_grave.bin_str, "11000011 10100000")
        self.assertEqual(ca_grave.hex_str, "C3 A0")
        self.assertEqual(ca_grave.byte_dec_list, [195, 160])

    def test_utf8_rc4_trace_rfc6229(self) -> None:
        """Kiểm chứng bảng diễn giải 8-bit XOR chuỗi 'Aà' với khóa RFC 6229 [1, 2, 3, 4, 5] (Bảng 2.5)."""
        key = bytes([1, 2, 3, 4, 5])
        steps = trace_rc4_utf8_xor("Aà", key)

        # Chuỗi 'Aà' gồm 2 ký tự nhưng 3 byte: m = 3 bước XOR
        self.assertEqual(len(steps), 3)

        # Bước r=1: P_1 = 65 ('A'), Z_1 = 178 -> C_1 = 243 (F3)
        self.assertEqual(steps[0].r, 1)
        self.assertEqual(steps[0].p_val, 65)
        self.assertEqual(steps[0].z_val, 178)
        self.assertEqual(steps[0].c_val, 243)
        self.assertEqual(steps[0].c_hex, "F3")
        self.assertEqual(steps[0].p_bin, "01000001")
        self.assertEqual(steps[0].z_bin, "10110010")
        self.assertEqual(steps[0].c_bin, "11110011")

        # Bước r=2: P_2 = 195 ('à' byte 1), Z_2 = 57 -> C_2 = 250 (FA)
        self.assertEqual(steps[1].r, 2)
        self.assertEqual(steps[1].p_val, 195)
        self.assertEqual(steps[1].z_val, 57)
        self.assertEqual(steps[1].c_val, 250)
        self.assertEqual(steps[1].c_hex, "FA")
        self.assertEqual(steps[1].p_bin, "11000011")
        self.assertEqual(steps[1].z_bin, "00111001")
        self.assertEqual(steps[1].c_bin, "11111010")

        # Bước r=3: P_3 = 160 ('à' byte 2), Z_3 = 99 -> C_3 = 195 (C3)
        self.assertEqual(steps[2].r, 3)
        self.assertEqual(steps[2].p_val, 160)
        self.assertEqual(steps[2].z_val, 99)
        self.assertEqual(steps[2].c_val, 195)
        self.assertEqual(steps[2].c_hex, "C3")
        self.assertEqual(steps[2].p_bin, "10100000")
        self.assertEqual(steps[2].z_bin, "01100011")
        self.assertEqual(steps[2].c_bin, "11000011")

        # Toàn bộ bản mã C = [243, 250, 195], Hex = 'F3FAC3'
        cipher_bytes = bytes([s.c_val for s in steps])
        self.assertEqual(list(cipher_bytes), [243, 250, 195])
        self.assertEqual(cipher_bytes.hex().upper(), "F3FAC3")

    def test_utf8_decode_probe_failure(self) -> None:
        """Kiểm chứng thí nghiệm phản chứng giải mã UTF-8 trên bản mã C=[243, 250, 195] (Mục 2.1.4)."""
        cipher_bytes = bytes([243, 250, 195])
        ok, msg, failure = kiem_tra_giai_ma_utf8_ban_ma(cipher_bytes)

        self.assertFalse(ok)
        self.assertIsNotNone(failure)
        assert failure is not None

        # Byte đầu tiên gây lỗi ở vị trí 0 (giá trị 243, tiền tố 11110)
        self.assertEqual(failure.err_index, 0)
        self.assertEqual(failure.err_byte_val, 243)
        self.assertEqual(failure.err_byte_bin, "11110011")
        self.assertTrue(failure.err_byte_bin.startswith("11110"))

        # Byte kế tiếp (giá trị 250, bắt đầu bằng 111110 != 10)
        self.assertEqual(failure.next_byte_val, 250)
        self.assertEqual(failure.next_byte_bin, "11111010")
        self.assertFalse(failure.next_byte_bin.startswith("10"))

        # Kiểm tra nội dung chẩn đoán
        self.assertIn("11110", failure.violation_reason)
        self.assertIn("111110", failure.violation_reason)
        self.assertIn("UnicodeDecodeError", msg)


@pytest.mark.asyncio
async def test_utf8_tab_rc4_text_ui(user: User) -> None:
    """Kiểm tra toàn bộ các thành phần hiển thị của Card 1 và Card 2 trong Tab RC4 Văn bản."""
    _page_rc4_text()
    await user.open("/")

    # Card 1: Mã Hóa & Giải Mã Văn Bản Tổng Quát
    await user.should_see("1. Mã Hóa & Giải Mã Văn Bản (UTF-8)")
    await user.should_see("Mã hóa & Kiểm tra Giải mã")
    await user.should_see("Bản mã (Hexadecimal)")
    await user.should_see("Bản mã (Base64)")

    # Card 2: Minh Họa Biểu Diễn UTF-8 Trong RC4
    await user.should_see("Minh Họa Biểu Diễn UTF-8 Trong RC4")
    await user.should_see("MÔ PHỎNG UTF-8")

    # Bảng 1 và Bảng 2
    await user.should_see("Bảng 1: Phân Rã Cấu Trúc Biểu Diễn Ký Tự Sang UTF-8")
    await user.should_see("Bảng 2: Diễn Giải Từng Byte Qua Lõi RC4")
    await user.should_see("Bản mã C = [250, 88, 11, 100] (Hex: FA580B64)")

    # Giải thích ngắn gọn tại sao không giải mã trực tiếp
    await user.should_see("Tại sao không thể giải mã UTF-8 trực tiếp trên bản mã?")
    await user.should_see("UnicodeDecodeError")


if __name__ == "__main__":
    unittest.main(verbosity=2)
