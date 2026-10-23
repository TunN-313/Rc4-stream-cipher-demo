"""
Bộ Kiểm Thử Tự Động cho rc4_crypt_chunks (tests/test_rc4_chunks.py)
==================================================================
Kiểm thử tính tương thích giữa hàm generator rc4_crypt_chunks và rc4_crypt:
1. chunked == one-shot trên các kích thước chunk: 1, 7, 256, 1000, 4999, 5000, 65536.
2. Round-trip giải mã phục hồi chính xác dữ liệu gốc khi đúng khóa.
3. Sai khóa cho kết quả khác bản gốc.
4. Xử lý ngoại lệ: Khóa rỗng, chunk_size < 1, khóa quá 256 byte.
5. Export đầy đủ trong src.core.
"""

from __future__ import annotations
import inspect
import random
import unittest
from typing import Iterator

import src.core
from src.core.rc4 import rc4_crypt, rc4_crypt_chunks


class TestRC4Chunks(unittest.TestCase):
    """Kiểm thử toàn diện generator rc4_crypt_chunks."""

    def setUp(self) -> None:
        """Thiết lập dữ liệu ngẫu nhiên cố định để đảm bảo tính tái lập."""
        rng = random.Random(42)
        self.random_5000 = bytes(rng.randint(0, 255) for _ in range(5000))
        self.key = b"RC4-Secret-Test-Key-2026"
        self.wrong_key = b"RC4-Wrong-Secret-Key-999"

    def test_export_in_src_core(self) -> None:
        """Kiểm tra rc4_crypt_chunks được export đúng chuẩn trong src/core/__init__.py."""
        self.assertTrue(hasattr(src.core, "rc4_crypt_chunks"))
        self.assertIn("rc4_crypt_chunks", src.core.__all__)
        self.assertIs(src.core.rc4_crypt_chunks, rc4_crypt_chunks)

    def test_is_generator_function(self) -> None:
        """Kiểm tra rc4_crypt_chunks là generator function trả về Iterator[bytes]."""
        self.assertTrue(inspect.isgeneratorfunction(rc4_crypt_chunks))
        gen = rc4_crypt_chunks(b"test", self.key)
        self.assertTrue(isinstance(gen, Iterator))

    def test_chunked_equals_oneshot_5000_bytes(self) -> None:
        """Kiểm tra chunked == one-shot với các kích cỡ khối: 1, 7, 256, 1000, 4999, 5000, 65536."""
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
        """Kiểm tra mã hóa và giải mã đối xứng round-trip phục hồi 100% dữ liệu gốc."""
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
        """Kiểm tra giải mã với sai khóa cho kết quả hoàn toàn khác bản gốc."""
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
        """Khóa rỗng phải ném ra ValueError."""
        with self.assertRaises(ValueError):
            list(rc4_crypt_chunks(self.random_5000, b""))

        with self.assertRaises(ValueError):
            list(rc4_crypt_chunks(b"", b""))

    def test_oversized_key_raises_value_error(self) -> None:
        """Khóa vượt quá 256 byte phải ném ra ValueError."""
        oversized_key = b"A" * 257
        with self.assertRaises(ValueError):
            list(rc4_crypt_chunks(self.random_5000, oversized_key))

    def test_invalid_chunk_size_raises_value_error(self) -> None:
        """chunk_size < 1 phải ném ra ValueError."""
        invalid_sizes = [0, -1, -500]
        for cs in invalid_sizes:
            with self.subTest(chunk_size=cs):
                with self.assertRaises(ValueError):
                    list(rc4_crypt_chunks(self.random_5000, self.key, chunk_size=cs))

    def test_empty_data(self) -> None:
        """Dữ liệu rỗng b'' sinh ra 0 khối và nối lại bằng b''."""
        chunks = list(rc4_crypt_chunks(b"", self.key, chunk_size=256))
        self.assertEqual(chunks, [])
        self.assertEqual(b"".join(chunks), b"")
        self.assertEqual(b"".join(chunks), rc4_crypt(b"", self.key))

    def test_default_chunk_size(self) -> None:
        """Không truyền chunk_size mặc định là 65536."""
        combined = b"".join(rc4_crypt_chunks(self.random_5000, self.key))
        self.assertEqual(combined, rc4_crypt(self.random_5000, self.key))

    def test_classic_rfc_test_vectors(self) -> None:
        """Kiểm tra đối chiếu các test vector kinh điển với generator."""
        # Key = b"Key", Plaintext = b"Plaintext" -> BBF316E8D940AF0AD3
        c1 = b"".join(rc4_crypt_chunks(b"Plaintext", b"Key", chunk_size=2))
        self.assertEqual(c1.hex().upper(), "BBF316E8D940AF0AD3")

        # Key = b"Wiki", Plaintext = b"pedia" -> 1021BF0420
        c2 = b"".join(rc4_crypt_chunks(b"pedia", b"Wiki", chunk_size=3))
        self.assertEqual(c2.hex().upper(), "1021BF0420")


if __name__ == "__main__":
    unittest.main(verbosity=2)
