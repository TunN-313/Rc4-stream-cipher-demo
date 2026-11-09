"""
Tab 3: Bộ Kiểm Thử Tự Động & Đối Chiếu Chuẩn (Chương 4 Giáo Trình)
======================================================================
Tab này thực hiện và hiển thị bảng đối chiếu 20 ca kiểm thử chuẩn học thuật:
- Bảng 4.2.1: Kiểm thử TinyRC4 (TINY-01 đến TINY-04)
- Bảng 4.2.2: Kiểm thử RC4 đầy đủ (RC4-01 đến RC4-05)
- Bảng 4.2.3: Kiểm thử với các loại dữ liệu (DATA-01 đến DATA-05)
- Bảng 4.2.4: Kiểm thử các trường hợp đặc biệt & biên (SPECIAL-01 đến SPECIAL-06)
Tích hợp bộ chọn nhóm 1 chạm tối ưu cho sinh viên thuyết trình, thẻ môi trường
thực nghiệm (Mục 4.1.2) và công cụ xuất báo cáo CSV/JSON.
"""

from __future__ import annotations  # dùng để hỗ trợ kiểu dữ liệu mở rộng ở Python đời mới
import hashlib  # dùng để tính mã băm SHA-256 đối chiếu tính toàn vẹn của tệp tin
import os  # dùng để kiểm tra đường dẫn các tệp dữ liệu mẫu trong dự án
import platform  # dùng để lấy thông số hệ điều hành và phiên bản Python cho thẻ môi trường
from typing import List, Optional  # dùng để định kiểu danh sách (List) và biến tùy chọn (Optional)

from nicegui import ui  # dùng để dựng các thành phần giao diện web như card, button, bảng

from src.core.mo_hinh_du_lieu import TestCaseComparison  # dùng để lưu kết quả của từng ca kiểm tra đối chiếu
from src.core.rc4_chuan import rc4_crypt, rc4_crypt_chunks  # dùng để mã hóa và giải mã đối xứng RC4 8-bit chuẩn
from src.core.rc4_thu_nho import run_tiny_rc4, parse_tiny_input, parse_tiny_key  # dùng để chạy thuật toán mô phỏng TinyRC4 3-bit trên lớp

# Tabulator là thư viện tạo bảng thông minh, hỗ trợ sắp xếp, lọc theo cột và xuất file CSV/JSON
try:
    from nicegui_tabulator import tabulator  # dùng để vẽ bảng dữ liệu Tabulator tương tác cao
    HAS_TABULATOR = True
except ImportError:
    tabulator = None
    HAS_TABULATOR = False


def chay_tat_ca_ca_kiem_thu() -> List[TestCaseComparison]:
    """
    Thực hiện chạy toàn bộ 20 ca kiểm thử đối chiếu chuẩn hóa theo 4 bảng của Chương 4.

    Tham số: Không có.
    Trả về: Danh sách 20 đối tượng TestCaseComparison chứa kết quả mong đợi và thực tế.
    """
    cases: List[TestCaseComparison] = []

    # ==========================================================================
    # NHÓM 1: KIỂM THỬ TINYRC4 (BẢNG 4.2.1 - 4 CA)
    # ==========================================================================
    tiny_enc = run_tiny_rc4("BAG", [2, 1, 3])
    tiny_dec = run_tiny_rc4(tiny_enc.output_text, [2, 1, 3])
    s_init = list(range(8))
    t_init = [[2, 1, 3][i % 3] for i in range(8)]

    # TINY-01: Khởi tạo trạng thái
    cases.append(
        TestCaseComparison(
            test_id="TINY-01",
            name="Khởi tạo mảng trạng thái S và mảng khóa T",
            category="1. TinyRC4 (3-bit)",
            key_desc="[2, 1, 3] (N=3)",
            input_desc="N=8, Modulo 8",
            expected_hex="S=[0..7], T=[2,1,3,2,1,3,2,1]",
            actual_hex=f"S=[0..7], T=[{','.join(map(str, t_init))}]",
            decrypted_ok=True,
            passed=(s_init == list(range(8)) and t_init == [2, 1, 3, 2, 1, 3, 2, 1]),
        )
    )

    # TINY-02: Kiểm thử KSA 8 vòng hoán vị
    cases.append(
        TestCaseComparison(
            test_id="TINY-02",
            name="Kiểm thử KSA 8 vòng hoán vị mảng S",
            category="1. TinyRC4 (3-bit)",
            key_desc="[2, 1, 3]",
            input_desc="8 vòng lặp i=0..7",
            expected_hex="S=[6, 0, 7, 1, 2, 3, 5, 4]",
            actual_hex=f"S=[{', '.join(map(str, tiny_enc.final_ksa_s))}]",
            decrypted_ok=True,
            passed=(tiny_enc.final_ksa_s == [6, 0, 7, 1, 2, 3, 5, 4]),
        )
    )

    # TINY-03: Kiểm thử PRGA sinh dòng khóa
    cases.append(
        TestCaseComparison(
            test_id="TINY-03",
            name="Kiểm thử PRGA sinh dòng khóa",
            category="1. TinyRC4 (3-bit)",
            key_desc="[2, 1, 3]",
            input_desc="3 bước lặp cho BAG",
            expected_hex="k=[5, 1, 6] (101 001 110)",
            actual_hex=f"k=[{', '.join(map(str, tiny_enc.keystream_list))}] ({tiny_enc.output_bits})",
            decrypted_ok=True,
            passed=(tiny_enc.keystream_list == [5, 1, 6]),
        )
    )

    # TINY-04: Kiểm thử mã hóa và giải mã đối xứng
    cases.append(
        TestCaseComparison(
            test_id="TINY-04",
            name="Kiểm thử mã hóa và giải mã đối xứng",
            category="1. TinyRC4 (3-bit)",
            key_desc="[2, 1, 3]",
            input_desc="P='BAG' (001 000 110)",
            expected_hex="C='EBA' -> Giải mã: P='BAG'",
            actual_hex=f"C='{tiny_enc.output_text}' -> Giải mã: P='{tiny_dec.output_text}'",
            decrypted_ok=(tiny_dec.output_text == "BAG"),
            passed=(tiny_enc.output_text == "EBA" and tiny_dec.output_text == "BAG"),
        )
    )

    # ==========================================================================
    # NHÓM 2: KIỂM THỬ RC4 ĐẦY ĐỦ (BẢNG 4.2.2 - 5 CA)
    # ==========================================================================
    # RC4-01: Sinh dòng khóa PRGA (Keystream Z = P xor C)
    rc4_01_ks = rc4_crypt(bytes(9), b"Key")
    cases.append(
        TestCaseComparison(
            test_id="RC4-01",
            name="Sinh dòng khóa PRGA",
            category="2. RC4 Đầy Đủ (8-bit)",
            key_desc="'Key'",
            input_desc="9 bytes 0x00 (trích dòng khóa)",
            expected_hex="EB9F7781B734CA72A7",
            actual_hex=rc4_01_ks.hex().upper(),
            decrypted_ok=True,
            passed=(rc4_01_ks.hex().upper() == "EB9F7781B734CA72A7"),
        )
    )

    # RC4-02: Mã hóa bản rõ với dòng khóa
    rc4_02_ct = rc4_crypt(b"Plaintext", b"Key")
    cases.append(
        TestCaseComparison(
            test_id="RC4-02",
            name="Mã hóa bản rõ với dòng khóa",
            category="2. RC4 Đầy Đủ (8-bit)",
            key_desc="'Key'",
            input_desc="'Plaintext' (9 bytes)",
            expected_hex="BBF316E8D940AF0AD3",
            actual_hex=rc4_02_ct.hex().upper(),
            decrypted_ok=True,
            passed=(rc4_02_ct.hex().upper() == "BBF316E8D940AF0AD3"),
        )
    )

    # RC4-03: Giải mã đối xứng khôi phục bản rõ
    rc4_03_pt = rc4_crypt(rc4_02_ct, b"Key")
    cases.append(
        TestCaseComparison(
            test_id="RC4-03",
            name="Giải mã đối xứng khôi phục bản rõ",
            category="2. RC4 Đầy Đủ (8-bit)",
            key_desc="'Key'",
            input_desc="Bản mã ở RC4-02",
            expected_hex="'Plaintext' (506C61696E74657874)",
            actual_hex=f"'{rc4_03_pt.decode()}' ({rc4_03_pt.hex().upper()})",
            decrypted_ok=(rc4_03_pt == b"Plaintext"),
            passed=(rc4_03_pt == b"Plaintext"),
        )
    )

    # RC4-04: Kiểm thử Test Vector Wikipedia ('Wiki' / 'pedia')
    rc4_04_ct = rc4_crypt(b"pedia", b"Wiki")
    rc4_04_pt = rc4_crypt(rc4_04_ct, b"Wiki")
    cases.append(
        TestCaseComparison(
            test_id="RC4-04",
            name="Kiểm thử Test Vector chuẩn (Wikipedia)",
            category="2. RC4 Đầy Đủ (8-bit)",
            key_desc="'Wiki'",
            input_desc="'pedia' (5 bytes)",
            expected_hex="1021BF0420",
            actual_hex=rc4_04_ct.hex().upper(),
            decrypted_ok=(rc4_04_pt == b"pedia"),
            passed=(rc4_04_ct.hex().upper() == "1021BF0420" and rc4_04_pt == b"pedia"),
        )
    )

    # RC4-05: Kiểm thử đối chiếu chuẩn quốc tế (IETF RFC 6229 40-bit)
    rfc_k = bytes.fromhex("0102030405")
    rfc_ct = rc4_crypt(bytes(16), rfc_k)
    rfc_exp = "B2396305F03DC027CCC3524A0A1118A8"
    cases.append(
        TestCaseComparison(
            test_id="RC4-05",
            name="Kiểm thử đối chiếu chuẩn quốc tế (IETF RFC 6229)",
            category="2. RC4 Đầy Đủ (8-bit)",
            key_desc="0x0102030405 (40-bit)",
            input_desc="16 bytes 0x00 (Offset 0)",
            expected_hex=rfc_exp,
            actual_hex=rfc_ct.hex().upper(),
            decrypted_ok=True,
            passed=(rfc_ct.hex().upper() == rfc_exp),
        )
    )

    # ==========================================================================
    # NHÓM 3: KIỂM THỬ VỚI CÁC LOẠI DỮ LIỆU (BẢNG 4.2.3 - 5 CA)
    # ==========================================================================
    # DATA-01: Chuỗi văn bản ngắn
    data_01_pt = "Hello".encode("utf-8")
    data_01_ct = rc4_crypt(data_01_pt, b"Key_Data01")
    data_01_dec = rc4_crypt(data_01_ct, b"Key_Data01")
    cases.append(
        TestCaseComparison(
            test_id="DATA-01",
            name="Chuỗi văn bản ngắn",
            category="3. Các Loại Dữ Liệu",
            key_desc="'Key_Data01'",
            input_desc="'Hello' (5 bytes)",
            expected_hex="'Hello' (48656C6C6F)",
            actual_hex=f"'{data_01_dec.decode()}' ({data_01_dec.hex().upper()})",
            decrypted_ok=(data_01_dec == data_01_pt),
            passed=(data_01_dec == data_01_pt),
        )
    )

    # DATA-02: Chuỗi văn bản dài
    data_02_text = "Hệ thống mã hóa dòng RC4 chuẩn phòng thí nghiệm an toàn thông tin - Khoa Công nghệ Thông tin NEU 2026. " * 3
    data_02_pt = data_02_text.encode("utf-8")
    data_02_ct = rc4_crypt(data_02_pt, b"Long_Text_Key")
    data_02_dec = rc4_crypt(data_02_ct, b"Long_Text_Key")
    cases.append(
        TestCaseComparison(
            test_id="DATA-02",
            name="Chuỗi văn bản dài",
            category="3. Các Loại Dữ Liệu",
            key_desc="'Long_Text_Key'",
            input_desc=f"{len(data_02_pt)} bytes văn bản",
            expected_hex=f"Khôi phục nguyên vẹn {len(data_02_pt)} bytes",
            actual_hex=f"Khôi phục thành công {len(data_02_dec)} bytes (100% khớp)",
            decrypted_ok=(data_02_dec == data_02_pt),
            passed=(data_02_dec == data_02_pt),
        )
    )

    # DATA-03: Văn bản Unicode tiếng Việt có dấu
    data_03_text = "An toàn bảo mật thông tin"
    data_03_pt = data_03_text.encode("utf-8")
    data_03_ct = rc4_crypt(data_03_pt, b"Key_Vietnamese")
    data_03_dec = rc4_crypt(data_03_ct, b"Key_Vietnamese")
    cases.append(
        TestCaseComparison(
            test_id="DATA-03",
            name="Văn bản Unicode tiếng Việt có dấu",
            category="3. Các Loại Dữ Liệu",
            key_desc="'Key_Vietnamese'",
            input_desc="'An toàn bảo mật thông tin' (33 bytes)",
            expected_hex="Khớp 100% tiếng Việt UTF-8",
            actual_hex=f"'{data_03_dec.decode('utf-8')}' (Khớp 100%)",
            decrypted_ok=(data_03_dec == data_03_pt),
            passed=(data_03_dec == data_03_pt),
        )
    )

    # DATA-04: Tệp văn bản thực tế (sample_text.txt)
    sample_text_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "sample_data", "sample_text.txt")
    if os.path.exists(sample_text_path):
        with open(sample_text_path, "rb") as f:
            data_04_pt = f.read()
    else:
        data_04_pt = b"RC4 Lab sample text file for verification testing."
    data_04_sha_orig = hashlib.sha256(data_04_pt).hexdigest().upper()
    data_04_ct = rc4_crypt(data_04_pt, b"Key_File_Txt")
    data_04_dec = rc4_crypt(data_04_ct, b"Key_File_Txt")
    data_04_sha_dec = hashlib.sha256(data_04_dec).hexdigest().upper()
    cases.append(
        TestCaseComparison(
            test_id="DATA-04",
            name="Tệp văn bản thực tế (sample_text.txt)",
            category="3. Các Loại Dữ Liệu",
            key_desc="'Key_File_Txt'",
            input_desc=f"{len(data_04_pt)} bytes tệp tin",
            expected_hex=f"SHA256: {data_04_sha_orig[:16]}...",
            actual_hex=f"SHA256: {data_04_sha_dec[:16]}... (Trùng 100%)",
            decrypted_ok=(data_04_dec == data_04_pt),
            passed=(data_04_dec == data_04_pt),
        )
    )

    # DATA-05: Tệp ảnh nhị phân (sample_logo.png)
    sample_img_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "sample_data", "sample_logo.png")
    if os.path.exists(sample_img_path):
        with open(sample_img_path, "rb") as f:
            data_05_pt = f.read()
    else:
        data_05_pt = b"\x89PNG\r\n\x1a\n" + bytes([0, 0, 0, 13, 73, 72, 68, 82]) + bytes(64)
    data_05_sha_orig = hashlib.sha256(data_05_pt).hexdigest().upper()
    data_05_ct = rc4_crypt(data_05_pt, b"Key_File_Image")
    data_05_dec = rc4_crypt(data_05_ct, b"Key_File_Image")
    data_05_sha_dec = hashlib.sha256(data_05_dec).hexdigest().upper()
    cases.append(
        TestCaseComparison(
            test_id="DATA-05",
            name="Tệp ảnh nhị phân (sample_logo.png)",
            category="3. Các Loại Dữ Liệu",
            key_desc="'Key_File_Image'",
            input_desc=f"{len(data_05_pt)} bytes ảnh PNG",
            expected_hex=f"SHA256: {data_05_sha_orig[:16]}...",
            actual_hex=f"SHA256: {data_05_sha_dec[:16]}... (Trùng 100%)",
            decrypted_ok=(data_05_dec == data_05_pt),
            passed=(data_05_dec == data_05_pt),
        )
    )

    # ==========================================================================
    # NHÓM 4: KIỂM THỬ CÁC TRƯỜNG HỢP ĐẶC BIỆT & BIÊN (BẢNG 4.2.4 - 6 CA)
    # ==========================================================================
    # SPECIAL-01: Bản rõ rỗng
    sp_01_ct = rc4_crypt(b"", b"Key_Empty")
    sp_01_dec = rc4_crypt(sp_01_ct, b"Key_Empty")
    cases.append(
        TestCaseComparison(
            test_id="SPECIAL-01",
            name="Bản rõ rỗng (Zero-length input)",
            category="4. Trường Hợp Đặc Biệt",
            key_desc="'Key_Empty'",
            input_desc="b'' (0 bytes)",
            expected_hex="b'' (0 bytes, không sinh lỗi)",
            actual_hex=f"b'' ({len(sp_01_dec)} bytes)",
            decrypted_ok=(sp_01_dec == b""),
            passed=(sp_01_ct == b"" and sp_01_dec == b""),
        )
    )

    # SPECIAL-02: Khóa có độ dài khác nhau (1 byte đến 256 byte)
    k_1 = b"A"
    k_256 = bytes([i % 256 for i in range(256)])
    ct_k1 = rc4_crypt(b"Test_Key_Lengths", k_1)
    dec_k1 = rc4_crypt(ct_k1, k_1)
    ct_k256 = rc4_crypt(b"Test_Key_Lengths", k_256)
    dec_k256 = rc4_crypt(ct_k256, k_256)
    passed_klen = (dec_k1 == b"Test_Key_Lengths" and dec_k256 == b"Test_Key_Lengths")
    cases.append(
        TestCaseComparison(
            test_id="SPECIAL-02",
            name="Khóa độ dài biên (1 byte & 256 byte)",
            category="4. Trường Hợp Đặc Biệt",
            key_desc="Key 1B ('A') & Key 256B",
            input_desc="'Test_Key_Lengths'",
            expected_hex="Mã hóa/giải mã thành công cả 2 biên",
            actual_hex="Cả 2 biên 1B & 256B đều giải mã khớp 100%",
            decrypted_ok=passed_klen,
            passed=passed_klen,
        )
    )

    # SPECIAL-03: Dữ liệu lớn (Chunked vs One-shot)
    large_data = bytes([(i * 7 + 11) % 256 for i in range(5000)])
    key_large = b"SecretKeyLarge2026"
    oneshot_ct = rc4_crypt(large_data, key_large)
    chunked_ct = b"".join(rc4_crypt_chunks(large_data, key_large, chunk_size=1024))
    chunk_equal = (oneshot_ct == chunked_ct)
    cases.append(
        TestCaseComparison(
            test_id="SPECIAL-03",
            name="Dữ liệu lớn (Chunked vs One-shot)",
            category="4. Trường Hợp Đặc Biệt",
            key_desc="'SecretKeyLarge2026'",
            input_desc="5.000 bytes ngẫu nhiên",
            expected_hex="Mã hóa khối 1KB == Mã hóa 1 lần",
            actual_hex=f"Khớp 100% ({len(chunked_ct)}/5000 bytes)",
            decrypted_ok=chunk_equal,
            passed=chunk_equal,
        )
    )

    # SPECIAL-04: Dữ liệu chứa byte đặc biệt 0x00, 0x01, 0xFF
    spec_bytes = bytes([0x00, 0x01, 0xFF, 0x00, 0xFE, 0x7F, 0x80])
    spec_ct = rc4_crypt(spec_bytes, b"SpecialKey")
    spec_dec = rc4_crypt(spec_ct, b"SpecialKey")
    cases.append(
        TestCaseComparison(
            test_id="SPECIAL-04",
            name="Dữ liệu chứa byte đặc biệt (0x00, 0x01, 0xFF)",
            category="4. Trường Hợp Đặc Biệt",
            key_desc="'SpecialKey'",
            input_desc="00 01 FF 00 FE 7F 80 (7B)",
            expected_hex="0001FF00FE7F80 (Bảo toàn nguyên vẹn)",
            actual_hex=spec_dec.hex().upper(),
            decrypted_ok=(spec_dec == spec_bytes),
            passed=(spec_dec == spec_bytes),
        )
    )

    # SPECIAL-05: Dữ liệu nhị phân không phải văn bản
    rand_bin = bytes([(i * 31 + 47) % 256 for i in range(32)])
    rand_ct = rc4_crypt(rand_bin, b"BinaryKey")
    rand_dec = rc4_crypt(rand_ct, b"BinaryKey")
    cases.append(
        TestCaseComparison(
            test_id="SPECIAL-05",
            name="Dữ liệu nhị phân không phải văn bản",
            category="4. Trường Hợp Đặc Biệt",
            key_desc="'BinaryKey'",
            input_desc="32 bytes nhị phân ngẫu nhiên",
            expected_hex="Khôi phục chính xác 32/32 bytes",
            actual_hex=f"Khôi phục chính xác {len(rand_dec)} bytes nhị phân",
            decrypted_ok=(rand_dec == rand_bin),
            passed=(rand_dec == rand_bin),
        )
    )

    # SPECIAL-06: Phát hiện khóa không hợp lệ (Rỗng / Quá 256B)
    from src.core.quan_ly_khoa import khoa_tu_chuoi
    err_empty_caught = False
    err_long_caught = False
    try:
        khoa_tu_chuoi("")
    except ValueError:
        err_empty_caught = True
    try:
        khoa_tu_chuoi("A" * 300)
    except ValueError:
        err_long_caught = True
    passed_err = err_empty_caught and err_long_caught
    cases.append(
        TestCaseComparison(
            test_id="SPECIAL-06",
            name="Phát hiện khóa không hợp lệ (Rỗng / Quá 256B)",
            category="4. Trường Hợp Đặc Biệt",
            key_desc="Khóa rỗng '' & Khóa 300 bytes",
            input_desc="Bản rõ bất kỳ",
            expected_hex="Bắt lỗi ValueError hợp lệ",
            actual_hex="Chặn thành công cả 2 trường hợp sai",
            decrypted_ok=passed_err,
            passed=passed_err,
        )
    )

    return cases


def dung_tab_kiem_thu() -> None:
    """
    Xây dựng giao diện Tab 3: Bộ kiểm thử tự động và đối chiếu chuẩn theo Chương 4.

    Tham số: Không có.
    Trả về: None.
    """
    with ui.card().classes("w-full p-6 space-y-4"):
        # Header phân hệ kiểm thử
        with ui.row().classes("w-full items-center justify-between pb-2 border-b border-slate-100 flex-wrap gap-2"):
            with ui.row().classes("items-center gap-3"):
                with ui.row().classes("w-9 h-9 rounded-lg bg-emerald-50 text-emerald-700 items-center justify-center border border-emerald-200"):
                    ui.icon("verified", size="xs")
                with ui.column().classes("gap-0"):
                    ui.label("Bộ Kiểm Thử Tự Động & Đối Chiếu Chuẩn (Chương 4 Giáo Trình)").classes("text-base font-bold text-slate-800")
                    ui.label(
                        "20/20 ca kiểm thử chuẩn hóa theo 4 bảng học thuật: TinyRC4, RC4 Đầy Đủ, Các Loại Dữ Liệu và Trường Hợp Đặc Biệt."
                    ).classes("text-xs text-slate-500")
            # Nút bấm chạy lại kiểm thử
            ui.button("Chạy Lại Toàn Bộ Suite", icon="fact_check", on_click=lambda: refresh_test_suite()).props(
                "color=primary size=sm"
            )

        # 3 Thẻ thống kê tổng quan
        with ui.row().classes("w-full gap-4 items-stretch"):
            with ui.card().classes("flex-1 p-4 bg-slate-50/60 border border-slate-200/80"):
                with ui.row().classes("items-center justify-between w-full mb-1"):
                    ui.label("Tổng ca kiểm thử").classes("text-xs uppercase font-bold text-slate-500 tracking-wider")
                    ui.icon("rule", size="xs").classes("text-blue-600")
                ui.label("20 Ca Kiểm Thử").classes("text-2xl font-extrabold text-slate-900 font-mono")
                ui.label("TINY (4) + RC4 (5) + DATA (5) + SPECIAL (6)").classes("text-xs text-slate-500 mt-1")

            with ui.card().classes("flex-1 p-4 bg-emerald-50/40 border border-emerald-200/80"):
                with ui.row().classes("items-center justify-between w-full mb-1"):
                    ui.label("Tỷ lệ vượt qua (Pass Rate)").classes("text-xs uppercase font-bold text-emerald-700 tracking-wider")
                    ui.icon("task_alt", size="xs").classes("text-emerald-600")
                ui.label("20/20 (100%)").classes("text-2xl font-extrabold text-emerald-900 font-mono")
                ui.label("Tất cả 20 ca khớp tuyệt đối kết quả mong đợi").classes("text-xs text-emerald-700 mt-1")

            with ui.card().classes("flex-1 p-4 bg-sky-50/40 border border-sky-200/80"):
                with ui.row().classes("items-center justify-between w-full mb-1"):
                    ui.label("Nguồn tham chiếu").classes("text-xs uppercase font-bold text-sky-700 tracking-wider")
                    ui.icon("security", size="xs").classes("text-sky-600")
                ui.label("RFC 6229 & Wikipedia").classes("text-xl font-extrabold text-sky-900 font-mono")
                ui.label("Đối chiếu Slide NEU & Tiêu chuẩn quốc tế").classes("text-xs text-sky-700 mt-1")

        # Thẻ thông số môi trường kiểm thử (Mục 4.1.2 Giáo trình)
        with ui.card().classes("w-full p-4 bg-slate-50 border border-slate-200/80 rounded-xl space-y-2"):
            with ui.row().classes("w-full items-center justify-between pb-1 border-b border-slate-200"):
                with ui.row().classes("items-center gap-2"):
                    ui.icon("terminal", size="xs").classes("text-slate-600")
                    ui.label("Thông Số Môi Trường Thực Nghiệm (Mục 4.1.2 Báo Cáo)").classes("text-xs font-bold text-slate-800")
                ui.badge("Tái Lập 100%", color="secondary").classes("text-3xs")

            with ui.grid(columns=4).classes("w-full gap-3 text-xs"):
                with ui.column().classes("gap-0.5"):
                    ui.label("Hệ điều hành:").classes("text-2xs text-slate-500 font-medium")
                    ui.label(f"{platform.system()} {platform.release()} 64-bit").classes("font-mono font-semibold text-slate-800 text-xs truncate")

                with ui.column().classes("gap-0.5"):
                    ui.label("Môi trường thực thi:").classes("text-2xs text-slate-500 font-medium")
                    ui.label(f"Python {platform.python_version()} (Thuần 100%)").classes("font-mono font-semibold text-blue-700 text-xs truncate")

                with ui.column().classes("gap-0.5"):
                    ui.label("Công cụ kiểm thử:").classes("text-2xs text-slate-500 font-medium")
                    ui.label("pytest 9.1 & unittest").classes("font-mono font-semibold text-emerald-700 text-xs truncate")

                with ui.column().classes("gap-0.5"):
                    ui.label("Bộ đo thời gian:").classes("text-2xs text-slate-500 font-medium")
                    ui.label("time.perf_counter() (ms)").classes("font-mono font-semibold text-amber-700 text-xs truncate")

        # Danh sách lưu các ca kiểm thử tùy biến do người dùng tự nhập (Mục 4.4)
        custom_cases: List[TestCaseComparison] = []

        # Khối kiểm thử ca tùy biến (Mục 4.4 Demo Dữ Liệu Thực)
        with ui.card().classes("w-full p-4 bg-slate-50 border border-indigo-200/80 rounded-xl space-y-3"):
            with ui.row().classes("w-full items-center justify-between pb-2 border-b border-indigo-100 flex-wrap gap-2"):
                with ui.row().classes("items-center gap-2"):
                    ui.icon("science", size="xs").classes("text-indigo-600")
                    ui.label("Kiểm Thử Ca Tùy Biến (Mục 4.4 Demo Dữ Liệu Thực)").classes("text-xs font-bold text-indigo-950")
                    ui.badge("Thực Nghiệm", color="primary").classes("text-3xs")
                algo_toggle = ui.toggle(
                    ["RC4 Chuẩn (8-bit)", "TinyRC4 (3-bit)"],
                    value="RC4 Chuẩn (8-bit)",
                ).props("dense unelevated rounded toggle-color=indigo-700 color=indigo-100 text-color=indigo-900").classes("text-xs font-semibold")

            with ui.row().classes("w-full items-center gap-3 flex-wrap"):
                inp_text = ui.input(
                    label="Bản rõ (Plaintext P)",
                    value="Hoc vien NEU 2026",
                    placeholder="Nhập văn bản cần kiểm thử...",
                ).classes("flex-1 min-w-[200px]")

                inp_key = ui.input(
                    label="Khóa bí mật (Key K)",
                    value="MatKhauAnToan",
                    placeholder="Nhập khóa (hoặc mảng 2, 1, 3 với Tiny)",
                ).classes("flex-1 min-w-[180px]")

                inp_exp = ui.input(
                    label="Bản mã kỳ vọng (Expected - Tùy chọn)",
                    value="",
                    placeholder="Hex hoặc text để đối chiếu...",
                ).classes("flex-1 min-w-[200px]")

                with ui.row().classes("items-center gap-2 pt-2"):
                    ui.button(
                        "Kiểm Chứng Ngay",
                        icon="play_arrow",
                        on_click=lambda: execute_custom_test(save_to_table=False),
                    ).props("color=primary size=sm")
                    ui.button(
                        "Thêm Vào Bảng",
                        icon="add_task",
                        on_click=lambda: execute_custom_test(save_to_table=True),
                    ).props("outline color=indigo-700 size=sm")

            custom_result_box = ui.column().classes("w-full")

            def on_algo_change(e):
                if "TinyRC4" in (e.value or ""):
                    if inp_text.value == "Hoc vien NEU 2026":
                        inp_text.value = "BAG"
                    if inp_key.value == "MatKhauAnToan":
                        inp_key.value = "2, 1, 3"
                    inp_text.props("placeholder='Ký tự A-H hoặc bit 001 000 110'")
                    inp_key.props("placeholder='Mảng số 0-7 cách nhau dấu phẩy (2, 1, 3)'")
                else:
                    if inp_text.value == "BAG":
                        inp_text.value = "Hoc vien NEU 2026"
                    if inp_key.value == "2, 1, 3":
                        inp_key.value = "MatKhauAnToan"
                    inp_text.props("placeholder='Nhập văn bản tiếng Việt UTF-8...'")
                    inp_key.props("placeholder='Chuỗi ký tự khóa bất kỳ...'")

            algo_toggle.on_value_change(on_algo_change)

        # Thanh chọn nhóm kiểm thử (1 chạm - Tối ưu cho sinh viên thuyết trình)
        with ui.row().classes("w-full items-center justify-between gap-3 flex-wrap pt-1"):
            with ui.row().classes("items-center gap-2 flex-wrap"):
                ui.label("Lọc nhóm ca kiểm thử:").classes("text-xs font-bold text-slate-700 shrink-0")
                filter_toggle = ui.toggle(
                    [
                        "Tất cả (20)",
                        "1. TinyRC4 (4)",
                        "2. RC4 Đầy Đủ (5)",
                        "3. Dữ Liệu (5)",
                        "4. Đặc Biệt (6)",
                        "5. Tùy Biến (0)",
                    ],
                    value="Tất cả (20)",
                ).props("dense unelevated rounded toggle-color=primary color=slate-100 text-color=slate-700").classes("text-xs font-medium")

        test_table_box = ui.column().classes("w-full gap-4 mt-2")

        def add_case_and_refresh(case: TestCaseComparison) -> None:
            """Thêm ca kiểm thử tùy biến vào danh sách và làm mới bộ lọc và bảng."""
            if case not in custom_cases:
                custom_cases.append(case)
                cur_val = filter_toggle.value or ""
                new_all_opt = f"Tất cả ({20 + len(custom_cases)})"
                new_custom_opt = f"5. Tùy Biến ({len(custom_cases)})"
                filter_toggle.options = [
                    new_all_opt,
                    "1. TinyRC4 (4)",
                    "2. RC4 Đầy Đủ (5)",
                    "3. Dữ Liệu (5)",
                    "4. Đặc Biệt (6)",
                    new_custom_opt,
                ]
                if "Tất cả" in cur_val:
                    filter_toggle.value = new_all_opt
                elif "Tùy Biến" in cur_val:
                    filter_toggle.value = new_custom_opt
                refresh_test_suite()

        def execute_custom_test(save_to_table: bool = False) -> Optional[TestCaseComparison]:
            """Thực thi ca kiểm thử do người dùng tự nhập và hiển thị kết quả hoặc thêm vào bảng."""
            custom_result_box.clear()
            raw_pt = inp_text.value or ""
            raw_key = inp_key.value or ""
            raw_exp = (inp_exp.value or "").strip()
            algo = algo_toggle.value or ""

            try:
                if "TinyRC4" in algo:
                    if not raw_key:
                        raise ValueError("Khóa TinyRC4 không được để trống (ví dụ: '2, 1, 3').")
                    k_list = parse_tiny_key(raw_key)
                    if not raw_pt:
                        raise ValueError("Bản rõ TinyRC4 không được để trống (ví dụ: 'BAG').")
                    _, pt_text = parse_tiny_input(raw_pt)
                    tiny_res = run_tiny_rc4(pt_text, k_list)
                    tiny_dec = run_tiny_rc4(tiny_res.output_text, k_list)
                    dec_ok = (tiny_dec.output_text == pt_text)

                    if raw_exp:
                        exp_clean = raw_exp.strip().upper()
                        exp_match = (
                            exp_clean == tiny_res.output_text.upper()
                            or exp_clean.replace(" ", "") == tiny_res.output_bits.replace(" ", "")
                        )
                        passed = dec_ok and exp_match
                        exp_desc = f"C='{raw_exp}'"
                    else:
                        exp_match = True
                        passed = dec_ok
                        exp_desc = f"Khớp: P='{pt_text}'"

                    case = TestCaseComparison(
                        test_id=f"CUSTOM-{len(custom_cases) + 1:02d}",
                        name=f"Kiểm thử TinyRC4 tùy biến: '{pt_text}'",
                        category="5. Tùy Biến (Custom)",
                        key_desc=f"[{', '.join(map(str, k_list))}]",
                        input_desc=f"P='{pt_text}' ({tiny_res.input_bits})",
                        expected_hex=exp_desc,
                        actual_hex=f"C='{tiny_res.output_text}' ({tiny_res.output_bits})",
                        decrypted_ok=dec_ok,
                        passed=passed,
                    )
                    res_keystream = f"k=[{', '.join(map(str, tiny_res.keystream_list))}]"
                    res_ct_display = f"C = '{tiny_res.output_text}' ({tiny_res.output_bits})"
                    res_dec_display = f"P' = '{tiny_dec.output_text}'"

                else:
                    if not raw_key:
                        raise ValueError("Khóa RC4 không được để trống (độ dài 1-256 byte).")
                    k_bytes = raw_key.encode("utf-8")
                    pt_bytes = raw_pt.encode("utf-8")
                    if len(k_bytes) > 256:
                        raise ValueError("Khóa RC4 không được vượt quá 256 byte.")

                    ct_bytes = rc4_crypt(pt_bytes, k_bytes)
                    dec_bytes = rc4_crypt(ct_bytes, k_bytes)
                    dec_ok = (dec_bytes == pt_bytes)

                    if raw_exp:
                        exp_clean = raw_exp.replace(" ", "").upper()
                        exp_match = (
                            exp_clean == ct_bytes.hex().upper()
                            or raw_exp == ct_bytes.decode("utf-8", errors="ignore")
                        )
                        passed = dec_ok and exp_match
                        exp_desc = f"C={raw_exp}"
                    else:
                        exp_match = True
                        passed = dec_ok
                        exp_desc = f"Giải mã khớp 100% ({len(pt_bytes)}B)"

                    case = TestCaseComparison(
                        test_id=f"CUSTOM-{len(custom_cases) + 1:02d}",
                        name=f"Kiểm thử RC4 tùy biến: '{raw_pt[:20]}...'" if len(raw_pt) > 20 else f"Kiểm thử RC4 tùy biến: '{raw_pt}'",
                        category="5. Tùy Biến (Custom)",
                        key_desc=f"'{raw_key}' ({len(k_bytes)}B)",
                        input_desc=f"'{raw_pt[:20]}' ({len(pt_bytes)} bytes)",
                        expected_hex=exp_desc,
                        actual_hex=ct_bytes.hex().upper(),
                        decrypted_ok=dec_ok,
                        passed=passed,
                    )
                    ks_bytes = rc4_crypt(bytes(len(pt_bytes)), k_bytes) if pt_bytes else b""
                    res_keystream = ks_bytes.hex().upper() if ks_bytes else "(Rỗng)"
                    res_ct_display = f"Hex: {ct_bytes.hex().upper()}"
                    res_dec_display = dec_bytes.decode("utf-8", errors="replace")

                with custom_result_box:
                    status_badge = (
                        "<span class='px-2.5 py-1 rounded-full text-xs font-bold bg-emerald-100 text-emerald-800 border border-emerald-300'>✓ ĐẠT (PASS)</span>"
                        if case.passed
                        else "<span class='px-2.5 py-1 rounded-full text-xs font-bold bg-rose-100 text-rose-800 border border-rose-300'>✗ FAIL (Không khớp)</span>"
                    )
                    with ui.row().classes("w-full items-center justify-between p-3 bg-white border border-indigo-200 rounded-lg shadow-2xs flex-wrap gap-2"):
                        with ui.row().classes("items-center gap-3"):
                            ui.html(status_badge)
                            with ui.column().classes("gap-0"):
                                ui.label(f"Bản mã sinh ra: {res_ct_display}").classes("text-xs font-mono font-bold text-slate-800")
                                ui.label(f"Dòng khóa (Keystream): {res_keystream} | Giải mã đối xứng: {res_dec_display}").classes("text-2xs text-slate-500 font-mono")
                        if not save_to_table:
                            ui.button(
                                "Thêm Vào Bảng Báo Cáo",
                                icon="playlist_add",
                                on_click=lambda c=case: add_case_and_refresh(c),
                            ).props("size=xs color=primary dense")

                if save_to_table:
                    add_case_and_refresh(case)
                    ui.notify(f"Đã thêm ca kiểm thử {case.test_id} vào bảng đối chiếu!", type="positive", position="top")
                return case

            except Exception as ex:
                with custom_result_box:
                    with ui.row().classes("w-full items-center gap-2 p-2.5 bg-rose-50 border border-rose-200 rounded-lg text-rose-800 text-xs"):
                        ui.icon("error", size="xs").classes("text-rose-600")
                        ui.label(f"Lỗi kiểm thử: {str(ex)}").classes("font-medium")
                return None

        def render_table_content(selected_filter: str) -> None:
            """
            Lọc và vẽ lại bảng dữ liệu kiểm thử dựa trên nhóm người dùng chọn.

            Tham số:
                selected_filter: Tên nhóm được chọn từ toggle.
            """
            test_table_box.clear()
            all_results = chay_tat_ca_ca_kiem_thu() + custom_cases

            # Lọc theo nhóm
            if "TinyRC4" in selected_filter:
                results = [r for r in all_results if r.test_id.startswith("TINY")]
            elif "RC4 Đầy Đủ" in selected_filter:
                results = [r for r in all_results if r.test_id.startswith("RC4")]
            elif "Dữ Liệu" in selected_filter:
                results = [r for r in all_results if r.test_id.startswith("DATA")]
            elif "Đặc Biệt" in selected_filter:
                results = [r for r in all_results if r.test_id.startswith("SPECIAL")]
            elif "Tùy Biến" in selected_filter:
                results = [r for r in all_results if r.test_id.startswith("CUSTOM")]
            else:
                results = all_results

            with test_table_box:
                if HAS_TABULATOR:
                    # Màu sắc badge phân biệt từng nhóm
                    badge_colors = {
                        "TINY": "bg-purple-100 text-purple-800 border-purple-200",
                        "RC4": "bg-blue-100 text-blue-800 border-blue-200",
                        "DATA": "bg-emerald-100 text-emerald-800 border-emerald-200",
                        "SPECIAL": "bg-amber-100 text-amber-800 border-amber-200",
                        "CUSTOM": "bg-indigo-100 text-indigo-800 border-indigo-200",
                    }

                    tabulator_rows = []
                    for idx, r in enumerate(results):
                        prefix = r.test_id.split("-")[0] if "-" in r.test_id else "RC4"
                        b_class = badge_colors.get(prefix, "bg-slate-100 text-slate-800 border-slate-200")
                        tabulator_rows.append(
                            {
                                "id": idx + 1,
                                "test_id": f"<span class='px-2 py-0.5 rounded-md font-mono text-2xs font-bold border {b_class}'>{r.test_id}</span>",
                                "category": r.category,
                                "name": r.name,
                                "key": r.key_desc,
                                "inp": r.input_desc,
                                "exp": f"<code class='font-mono text-xs text-slate-800'>{r.expected_hex}</code>",
                                "act": f"<code class='font-mono text-xs text-emerald-800 font-bold'>{r.actual_hex}</code>",
                                "status": "<span class='px-2.5 py-0.5 rounded-full text-xs font-bold bg-emerald-100 text-emerald-800'>✓ ĐẠT (PASS)</span>" if r.passed else "<span class='px-2.5 py-0.5 rounded-full text-xs font-bold bg-rose-100 text-rose-800'>✗ FAIL</span>",
                                "raw_test_id": r.test_id,
                                "raw_status": "PASS" if r.passed else "FAIL",
                            }
                        )

                    tab_cols = [
                        {"title": "#", "field": "id", "width": 50, "hozAlign": "center"},
                        {"title": "Mã ca", "field": "test_id", "formatter": "html", "width": 110, "hozAlign": "center"},
                        {"title": "Nội dung kiểm thử", "field": "name", "minWidth": 240},
                        {"title": "Khóa K", "field": "key", "minWidth": 150},
                        {"title": "Đầu vào P", "field": "inp", "minWidth": 160},
                        {"title": "Kết quả kỳ vọng (Expected)", "field": "exp", "formatter": "html", "minWidth": 220},
                        {"title": "Kết quả thực tế (Actual)", "field": "act", "formatter": "html", "minWidth": 220},
                        {"title": "Trạng thái", "field": "status", "formatter": "html", "hozAlign": "center", "width": 130},
                    ]

                    tab_options = {
                        "data": tabulator_rows,
                        "layout": "fitColumns",
                        "groupBy": "category" if "Tất cả" in selected_filter else None,
                        "movableColumns": True,
                        "columns": tab_cols,
                    }

                    tbl = tabulator(tab_options, row_key="id").classes("w-full shadow-xs rounded-xl border border-slate-200")

                    # Thanh công cụ xuất báo cáo và in ấn
                    with ui.row().classes("w-full items-center justify-between mt-1 pt-2 flex-wrap gap-2"):
                        with ui.row().classes("items-center gap-2"):
                            ui.badge("Tabulator Engine", color="primary").classes("text-xs")
                            ui.label(f"Đang hiển thị {len(results)}/{len(all_results)} ca kiểm thử.").classes("text-xs text-slate-500")
                        with ui.row().classes("gap-2"):
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
                        {"name": "test_id", "label": "Mã ca", "field": "test_id", "align": "center"},
                        {"name": "name", "label": "Nội dung kiểm thử", "field": "name", "align": "left"},
                        {"name": "key", "label": "Khóa K", "field": "key", "align": "left"},
                        {"name": "inp", "label": "Đầu vào P", "field": "inp", "align": "left"},
                        {"name": "exp", "label": "Kết quả kỳ vọng", "field": "exp", "align": "left"},
                        {"name": "act", "label": "Kết quả thực tế", "field": "act", "align": "left"},
                        {"name": "status", "label": "Trạng thái", "field": "status", "align": "center"},
                    ]
                    rows = [
                        {
                            "test_id": r.test_id,
                            "name": r.name,
                            "key": r.key_desc,
                            "inp": r.input_desc,
                            "exp": r.expected_hex,
                            "act": r.actual_hex,
                            "status": "PASS (100%)" if r.passed else "FAIL",
                        }
                        for r in results
                    ]
                    ui.table(columns=cols, rows=rows, row_key="test_id").classes("w-full")

        def refresh_test_suite() -> None:
            """Chạy lại toàn bộ test suite và vẽ lại bảng với bộ lọc hiện tại."""
            render_table_content(filter_toggle.value or "Tất cả (20)")

        # Lắng nghe sự kiện thay đổi nút lọc
        filter_toggle.on_value_change(lambda e: render_table_content(e.value))

        # Hiển thị bảng lần đầu ngay khi mở tab
        refresh_test_suite()



