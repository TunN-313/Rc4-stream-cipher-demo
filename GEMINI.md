# Quy tắc dự án RC4 & TinyRC4 (GEMINI.md)

## 1. Mục tiêu và Ràng buộc Học thuật
- Dự án xây dựng và minh họa hệ mã dòng **TinyRC4** (3-bit, mảng S và T gồm 8 phần tử 0..7) và **RC4 đầy đủ** (8-bit, mảng S và T gồm 256 phần tử 0..255).
- **TUYỆT ĐỐI KHÔNG** sử dụng thư viện mật mã có sẵn (như `pycryptodome`, `cryptography`, `openssl`, `hashlib`) bên trong `src/core/tiny_rc4.py` và `src/core/rc4.py`. Toàn bộ thuật toán KSA, PRGA và phép XOR phải được cài đặt thuần Python từ đầu bằng các toán tử cơ bản (`%`, `^`, hoán vị list).
- Thư viện `Crypto.Cipher.ARC4` (từ `pycryptodome`) và `cryptography` **CHỈ** được phép import trong `tests/` và `src/ui/tab_testing.py` với mục đích làm đối chứng kiểm tra tính đúng đắn của kết quả mã hóa.

## 2. Chuẩn Toán học TinyRC4 (Theo Slide Chương 2 - Khoa CNTT, ĐH Kinh tế Quốc dân)
- Bảng chữ cái 3-bit cố định:
  - `A = 000 (0)`
  - `B = 001 (1)`
  - `C = 010 (2)`
  - `D = 011 (3)`
  - `E = 100 (4)`
  - `F = 101 (5)`
  - `G = 110 (6)`
  - `H = 111 (7)`
- Giai đoạn KSA (TinyRC4):
  - Khởi tạo mảng: `S = [0, 1, 2, 3, 4, 5, 6, 7]`, `T[i] = K[i % len(K)]` với `i = 0..7`.
  - `j = 0`. Lặp `i` từ `0` đến `7`:
    - `j = (j + S[i] + T[i]) % 8`
    - Hoán vị `S[i], S[j] = S[j], S[i]`
- Giai đoạn PRGA (TinyRC4):
  - Khởi tạo `i = 0, j = 0`. Với mỗi đơn vị 3-bit của bản rõ:
    - `i = (i + 1) % 8`
    - `j = (j + S[i]) % 8`
    - Hoán vị `S[i], S[j] = S[j], S[i]`
    - `t = (S[i] + S[j]) % 8`
    - Dòng khóa `k = S[t]`
    - Bản mã `c = p ^ k`
- **Test Vector Bắt Buộc Khớp Tuyệt Đối Trên Lớp (Slide 56–60)**:
  - Bản rõ: `P = "BAG"` (`001 000 110`, tương ứng `[1, 0, 6]`)
  - Khóa: `K = [2, 1, 3]` ($N=3$)
  - Mảng `S` sau 8 vòng KSA: `[6, 0, 7, 1, 2, 3, 5, 4]`
  - Dòng khóa sinh ra (PRGA): `k = [5, 1, 6]` (`101 001 110`)
  - Bản mã: `C = "EBA"` (`100 001 000`, tương ứng `[4, 1, 0]`)
  - Giải mã đối xứng: `C = "EBA"` với `K = [2, 1, 3]` giải mã ra đúng `P = "BAG"`.

## 3. Chuẩn RC4 Đầy Đủ (8-bit) & Đối Chiếu Chuẩn
- KSA và PRGA modulo 256 trên mảng S gồm 256 phần tử `0..255`.
- Xử lý mảng `bytes` cho cả văn bản UTF-8 và tệp tin nhị phân bất kỳ (ảnh PNG/JPG, file TXT, file nhị phân).
- Bộ đối chiếu chuẩn bắt buộc phải pass:
  1. Test vector cổ điển: `Key = b"Key"`, `Plaintext = b"Plaintext"` -> Ciphertext Hex: `BBF316E8D940AF0AD3`.
  2. Test vector cổ điển: `Key = b"Wiki"`, `Plaintext = b"pedia"` -> Ciphertext Hex: `1021BF0420`.
  3. Test vector tiếng Việt UTF-8 (đối chiếu PyCryptodome).
  4. Test vector IETF RFC 6229 (40-bit, 64-bit, 128-bit, 256-bit tại offset 0).

## 4. Phân Tách Kiến Trúc (Frontend UI & Backend Core)
- `src/core/` [BACKEND]:
  - Chỉ chứa logic toán học và thuật toán thuần Python.
  - TUYỆT ĐỐI KHÔNG import `nicegui` trong `src/core/`.
  - Mọi hàm trả về đối tượng Dataclass chuẩn được quy định trong `src/core/models.py`.
- `src/ui/` [FRONTEND]:
  - Chỉ chứa giao diện NiceGUI gồm Header, Layout và 5 Tab chức năng riêng biệt:
    - `tab_tiny_rc4.py`: Tab 1 - Trực quan hóa từng bước TinyRC4.
    - `tab_full_rc4.py`: Tab 2 - RC4 256-byte, mã hóa văn bản & file/ảnh thật.
    - `tab_testing.py`: Tab 3 - Suite kiểm thử tự động, RFC 6229 & đối chiếu PyCryptodome.
    - `tab_attack_bench.py`: Tab 4 - Tấn công Two-Time Pad & Biểu đồ tốc độ echart.
    - `tab_theory.py`: Tab 5 - Lý thuyết, sơ đồ khối Mermaid tự vẽ & so sánh A5/1.
  - Sử dụng Mock Adapter từ `models.py` khi Backend chưa hoàn thiện để phát triển giao diện độc lập.
- `src/core/models.py`:
  - Hợp đồng dữ liệu duy nhất giữa FE và BE. Bất kỳ thay đổi cấu trúc nào phải được thống nhất giữa cả hai thành viên.
