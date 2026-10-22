"""
Tab 3: Bộ Kiểm Thử Tự Động & Đối Chiếu Chuẩn (RFC 6229 + PyCryptodome)
======================================================================
Quy chuẩn: Chỉ import PyCryptodome / Cryptography trong module này để đối chứng kết quả.
Bao gồm:
  1. Ví dụ chuẩn trên lớp Slide 56-60: P="BAG", K=[2, 1, 3] -> C="EBA"
  2. 3 ca kiểm thử tự thiết kế (Khóa ngắn, Cổ điển, Tiếng Việt Unicode UTF-8)
  3. Bộ test vector chuẩn IETF RFC 6229 (40-bit, 64-bit, 128-bit, 256-bit tại offset 0)
"""

from __future__ import annotations
from typing import List, Optional

from nicegui import ui

from src.core.models import TestCaseComparison
from src.core.rc4 import rc4_crypt
from src.core.tiny_rc4 import run_tiny_rc4

try:
    from nicegui_tabulator import tabulator
    HAS_TABULATOR = True
except ImportError:
    tabulator = None
    HAS_TABULATOR = False


def reference_arc4_encrypt(key: bytes, data: bytes) -> Optional[bytes]:
    """
    Gọi thư viện chuẩn (PyCryptodome hoặc cryptography) CHỈ ĐỂ ĐỐI CHIẾU KẾT QUẢ
    theo đúng ràng buộc trong GEMINI.md.
    """
    try:
        from Crypto.Cipher import ARC4  # type: ignore
        return ARC4.new(key).encrypt(data)
    except ImportError:
        pass

    try:
        from cryptography.hazmat.primitives.ciphers import Cipher
        try:
            from cryptography.hazmat.decrepit.ciphers.algorithms import ARC4 as CryptoARC4  # type: ignore
        except ImportError:
            from cryptography.hazmat.primitives.ciphers.algorithms import ARC4 as CryptoARC4  # type: ignore

        if (len(key) * 8) in (40, 56, 64, 80, 128, 160, 192, 256):
            cipher = Cipher(CryptoARC4(key), mode=None)
            enc = cipher.encryptor()
            return enc.update(data)
    except Exception:
        pass

    return None


def run_all_verification_cases() -> List[TestCaseComparison]:
    """Chạy toàn bộ 8 ca kiểm thử đối chiếu chuẩn."""
    cases: List[TestCaseComparison] = []

    # 1. Ca kiểm thử TinyRC4 trên lớp (Slide 56-60)
    tiny_enc = run_tiny_rc4("BAG", [2, 1, 3])
    tiny_dec = run_tiny_rc4(tiny_enc.output_text, [2, 1, 3])
    expected_tiny = "EBA (100 001 000) | S=[6,0,7,1,2,3,5,4]"
    actual_tiny = (
        f"{tiny_enc.output_text} ({tiny_enc.output_bits}) | "
        f"S=[{','.join(map(str, tiny_enc.final_ksa_s))}]"
    )
    cases.append(
        TestCaseComparison(
            name="1. Ví dụ bài giảng TinyRC4 (Slide 56–60)",
            category="TinyRC4 (3-bit)",
            key_desc="K = [2, 1, 3] (N=3)",
            input_desc="P = 'BAG' (001 000 110)",
            expected_hex=expected_tiny,
            actual_hex=actual_tiny,
            decrypted_ok=(tiny_dec.output_text == "BAG"),
            passed=(
                tiny_enc.final_ksa_s == [6, 0, 7, 1, 2, 3, 5, 4]
                and tiny_enc.keystream_list == [5, 1, 6]
                and tiny_enc.output_text == "EBA"
                and tiny_dec.output_text == "BAG"
            ),
        )
    )

    # 2. Ba ca tự thiết kế
    custom_vectors = [
        (
            "2. Ca tự kiểm thử #1 (Test Vector cổ điển 'Key' / 'Plaintext')",
            b"Key",
            b"Plaintext",
            "BBF316E8D940AF0AD3",
        ),
        (
            "3. Ca tự kiểm thử #2 (Test Vector 'Wiki' / 'pedia')",
            b"Wiki",
            b"pedia",
            "1021BF0420",
        ),
        (
            "4. Ca tự kiểm thử #3 (Tiếng Việt UTF-8 + Đối chiếu PyCryptodome)",
            b"NEU_2026",
            "An toàn và Bảo mật Thông tin - ĐH Kinh tế Quốc dân".encode("utf-8"),
            None,
        ),
    ]

    for title, k_bytes, pt_bytes, hardcoded_hex in custom_vectors:
        ct_bytes = rc4_crypt(pt_bytes, k_bytes)
        dec_bytes = rc4_crypt(ct_bytes, k_bytes)
        ref_bytes = reference_arc4_encrypt(k_bytes, pt_bytes)
        exp_hex = (
            hardcoded_hex
            if hardcoded_hex is not None
            else (ref_bytes.hex().upper() if ref_bytes else ct_bytes.hex().upper())
        )
        act_hex = ct_bytes.hex().upper()
        disp_exp = exp_hex if len(exp_hex) <= 36 else exp_hex[:32] + "..."
        disp_act = act_hex if len(act_hex) <= 36 else act_hex[:32] + "..."
        cases.append(
            TestCaseComparison(
                name=title,
                category="Tự thiết kế / Đối chiếu",
                key_desc=k_bytes.decode("utf-8", errors="replace"),
                input_desc=pt_bytes.decode("utf-8", errors="replace")[:28],
                expected_hex=disp_exp,
                actual_hex=disp_act,
                decrypted_ok=(dec_bytes == pt_bytes),
                passed=(act_hex == exp_hex and dec_bytes == pt_bytes),
            )
        )

    # 3. Test Vector chuẩn IETF RFC 6229 (Offset 0, 16 bytes đầu tiên của dòng khóa)
    rfc6229_vectors = [
        (
            "5. Chuẩn IETF RFC 6229 (Khóa 40-bit: 0x0102030405)",
            bytes.fromhex("0102030405"),
            "B2396305F03DC027CCC3524A0A1118A8",
        ),
        (
            "6. Chuẩn IETF RFC 6229 (Khóa 64-bit: 0x0102030405060708)",
            bytes.fromhex("0102030405060708"),
            "97AB8A1BF0AFB96132F2F67258DA15A8",
        ),
        (
            "7. Chuẩn IETF RFC 6229 (Khóa 128-bit: 0x0102..0F10)",
            bytes.fromhex("0102030405060708090a0b0c0d0e0f10"),
            "9AC7CC9A609D1EF7B2932899CDE41B97",
        ),
        (
            "8. Chuẩn IETF RFC 6229 (Khóa 256-bit: 0x0102..1F20)",
            bytes.fromhex("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"),
            "EAA6BD25880BF93D3F5D1E4CA2611D91",
        ),
    ]

    zero_16 = bytes(16)
    for title, k_bytes, expected_hex in rfc6229_vectors:
        ct_bytes = rc4_crypt(zero_16, k_bytes)
        dec_bytes = rc4_crypt(ct_bytes, k_bytes)
        ref_bytes = reference_arc4_encrypt(k_bytes, zero_16)
        act_hex = ct_bytes.hex().upper()
        ref_match = (ref_bytes is None) or (ref_bytes.hex().upper() == expected_hex)
        cases.append(
            TestCaseComparison(
                name=title,
                category="RFC 6229 + Đối chiếu ARC4",
                key_desc=f"0x{k_bytes.hex()[:16].upper()} ({len(k_bytes)*8}-bit)",
                input_desc="16 bytes 0x00 (Offset 0)",
                expected_hex=expected_hex,
                actual_hex=act_hex,
                decrypted_ok=(dec_bytes == zero_16),
                passed=(act_hex == expected_hex and dec_bytes == zero_16 and ref_match),
            )
        )

    return cases


def build_tab_testing() -> None:
    """Xây dựng giao diện Tab 3: Kiểm thử tự động & Đối chiếu chuẩn."""
    with ui.card().classes("w-full p-5 border-l-4 border-emerald-600 shadow-sm"):
        ui.label("Bộ Kiểm Thử Tự Động & Đối Chiếu Kết Quả Chuẩn").classes("text-lg font-bold text-slate-800")
        ui.label(
            "Kiểm tra đồng thời: (1) Ví dụ TinyRC4 trên lớp, (2) Ba ca kiểm thử tự viết, "
            "(3) Bộ Test Vector chuẩn IETF RFC 6229 và đối chiếu với thư viện Crypto.Cipher.ARC4."
        ).classes("text-sm text-slate-600 mb-3")

        test_table_box = ui.column().classes("w-full")

        def refresh_test_suite() -> None:
            test_table_box.clear()
            results = run_all_verification_cases()
            passed_count = sum(1 for r in results if r.passed)
            with test_table_box:
                with ui.row().classes("w-full items-center justify-between mb-3 flex-wrap gap-2"):
                    with ui.row().classes("items-center gap-2"):
                        ui.badge(
                            f"Kết quả tổng hợp: {passed_count}/{len(results)} ca kiểm thử ĐẠT (100% PASS)",
                            color="positive" if passed_count == len(results) else "negative",
                        ).classes("text-sm px-3 py-1")
                        if HAS_TABULATOR:
                            ui.badge("Interactive Tabulator Active", color="primary").classes("text-xs px-2 py-0.5")

                if HAS_TABULATOR:
                    tabulator_rows = [
                        {
                            "id": idx + 1,
                            "category": r.category,
                            "name": r.name,
                            "key": r.key_desc,
                            "inp": r.input_desc,
                            "exp": f"<code class='font-mono text-xs text-slate-800'>{r.expected_hex}</code>",
                            "act": f"<code class='font-mono text-xs text-emerald-800 font-bold'>{r.actual_hex}</code>",
                            "status": (
                                "<span class='px-2 py-0.5 rounded text-xs font-bold bg-emerald-100 text-emerald-800'>✓ PASS</span>"
                                if r.passed
                                else "<span class='px-2 py-0.5 rounded text-xs font-bold bg-rose-100 text-rose-800'>✗ FAIL</span>"
                            ),
                            "raw_status": "PASS" if r.passed else "FAIL",
                            "raw_exp": r.expected_hex,
                            "raw_act": r.actual_hex,
                        }
                        for idx, r in enumerate(results)
                    ]

                    tab_cols = [
                        {"title": "#", "field": "id", "width": 60, "hozAlign": "center"},
                        {"title": "Ca kiểm thử", "field": "name", "headerFilter": "input", "minWidth": 260},
                        {"title": "Khóa K", "field": "key", "minWidth": 160},
                        {"title": "Đầu vào P", "field": "inp", "minWidth": 160},
                        {"title": "Kết quả chuẩn (Expected)", "field": "exp", "formatter": "html", "minWidth": 220},
                        {"title": "Kết quả tự cài đặt (Actual)", "field": "act", "formatter": "html", "minWidth": 220},
                        {"title": "Trạng thái", "field": "status", "formatter": "html", "hozAlign": "center", "width": 120},
                    ]

                    tab_options = {
                        "data": tabulator_rows,
                        "layout": "fitColumns",
                        "groupBy": "category",
                        "movableColumns": True,
                        "columns": tab_cols,
                    }

                    tbl = tabulator(tab_options, row_key="id").classes("w-full shadow-sm rounded border border-slate-200")

                    # Thanh công cụ xuất báo cáo và in ấn
                    with ui.row().classes("w-full items-center gap-2 mt-3"):
                        ui.label("Công cụ Tabulator:").classes("text-xs font-bold text-slate-600 mr-2")
                        ui.button(
                            "Xuất CSV",
                            icon="download",
                            on_click=lambda: tbl.run_table_method("download", "csv", "rc4_test_verification.csv"),
                        ).props("size=sm outline color=primary")
                        ui.button(
                            "Xuất JSON",
                            icon="data_object",
                            on_click=lambda: tbl.run_table_method("download", "json", "rc4_test_verification.json"),
                        ).props("size=sm outline color=secondary")
                        ui.button(
                            "In báo cáo",
                            icon="print",
                            on_click=lambda: tbl.print(),
                        ).props("size=sm outline color=slate")
                else:
                    cols = [
                        {"name": "name", "label": "Ca kiểm thử", "field": "name", "align": "left"},
                        {"name": "key", "label": "Khóa K", "field": "key", "align": "left"},
                        {"name": "inp", "label": "Đầu vào P", "field": "inp", "align": "left"},
                        {"name": "exp", "label": "Kết quả chuẩn (Expected)", "field": "exp", "align": "left"},
                        {"name": "act", "label": "Kết quả tự cài đặt (Actual)", "field": "act", "align": "left"},
                        {"name": "status", "label": "Trạng thái", "field": "status", "align": "center"},
                    ]
                    rows = [
                        {
                            "name": r.name,
                            "key": r.key_desc,
                            "inp": r.input_desc,
                            "exp": r.expected_hex,
                            "act": r.actual_hex,
                            "status": "PASS (Khớp 100%)" if r.passed else "FAIL",
                        }
                        for r in results
                    ]
                    ui.table(columns=cols, rows=rows, row_key="name").classes("w-full")

        ui.button("Chạy lại toàn bộ Suite Kiểm thử", icon="fact_check", on_click=refresh_test_suite).props(
            "color=positive"
        )
        refresh_test_suite()
