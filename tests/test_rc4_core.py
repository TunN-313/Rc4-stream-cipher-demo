"""
Bộ Kiểm Thử Tự Động Thuật Toán RC4 & TinyRC4 (tests/test_rc4_core.py)
=====================================================================
Kiểm tra trực tiếp các module Backend trong src/core/ độc lập với giao diện NiceGUI.
Chạy bằng lệnh:
    pytest tests/ -v
hoặc:
    python -m unittest tests/test_rc4_core.py
"""

from __future__ import annotations
import unittest
from pathlib import Path

from src.core.tiny_rc4 import run_tiny_rc4
from src.core.rc4 import rc4_crypt
from src.ui.tab_testing import run_all_verification_cases


class TestRC4Core(unittest.TestCase):
    """Kiểm tra tính đúng đắn của TinyRC4 và RC4 đầy đủ."""

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

        # Giải mã đối xứng ngược lại đúng "BAG"
        dec = run_tiny_rc4(res.output_text, [2, 1, 3])
        self.assertEqual(dec.output_text, "BAG")

    def test_all_verification_vectors(self) -> None:
        """Kiểm tra toàn bộ 8 ca kiểm thử (bao gồm RFC 6229 và đối chiếu thư viện chuẩn)."""
        results = run_all_verification_cases()
        self.assertGreaterEqual(len(results), 8)
        for case in results:
            self.assertTrue(case.passed, f"Ca kiểm thử thất bại: {case.name}")

    def test_binary_image_encryption_roundtrip(self) -> None:
        """Kiểm tra mã hóa và giải mã tệp ảnh PNG nhị phân khôi phục 100% byte gốc."""
        sample_path = Path("sample_data") / "sample_logo.png"
        img_bytes = sample_path.read_bytes() if sample_path.exists() else b"PNG_FAKE_SAMPLE_12345678"
        key = b"Sample-Image-Secret-Key"
        encrypted = rc4_crypt(img_bytes, key)
        self.assertNotEqual(encrypted, img_bytes)
        decrypted = rc4_crypt(encrypted, key)
        self.assertEqual(decrypted, img_bytes)


if __name__ == "__main__":
    unittest.main(verbosity=2)
