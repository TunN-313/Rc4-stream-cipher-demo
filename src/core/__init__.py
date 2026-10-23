"""Module Backend xử lý logic thuật toán mật mã RC4 và TinyRC4."""

from src.core.models import (
    INV_TINY_ALPHABET,
    TINY_ALPHABET,
    FullRC4Result,
    KSAStep,
    KeystreamAttackResult,
    PRGAStep,
    TestCaseComparison,
    TinyRC4Result,
)
from src.core.tiny_rc4 import parse_tiny_input, parse_tiny_key, run_tiny_rc4
from src.core.rc4 import rc4_ksa, rc4_crypt, rc4_crypt_with_details, rc4_crypt_chunks
from src.core.attack_demo import simulate_keystream_reuse_attack
from src.core.benchmark import run_rc4_benchmark

__all__ = [
    "TINY_ALPHABET",
    "INV_TINY_ALPHABET",
    "KSAStep",
    "PRGAStep",
    "TinyRC4Result",
    "FullRC4Result",
    "TestCaseComparison",
    "KeystreamAttackResult",
    "parse_tiny_input",
    "parse_tiny_key",
    "run_tiny_rc4",
    "rc4_ksa",
    "rc4_crypt",
    "rc4_crypt_with_details",
    "rc4_crypt_chunks",
    "simulate_keystream_reuse_attack",
    "run_rc4_benchmark",
]
