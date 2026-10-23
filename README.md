# Hệ Mã Dòng RC4 & TinyRC4 — Phòng Thí Nghiệm Thu Nhỏ

Ứng dụng trực quan hóa và thực nghiệm hệ mã dòng **TinyRC4** (3-bit) và **RC4 chuẩn** (8-bit) xây dựng trên nền tảng **Python thuần** và giao diện hiện đại **NiceGUI**.

> **Học phần**: An toàn và Bảo mật Thông tin   
> **Đơn vị**: Khoa Công nghệ Thông tin — Đại học Kinh tế Quốc dân (NEU)  
> **Repository**: [https://github.com/TunN-313/Rc4-stream-cipher-demo](https://github.com/TunN-313/Rc4-stream-cipher-demo)  

---

## 1. Phân Công Thành Viên Trong Nhóm

| Thành viên | Vai trò | Nhánh Git | Nội dung phụ trách chính |
| :--- | :--- | :--- | :--- |
| **Thành viên 1 (Frontend)** | Giao diện & Trực quan hóa | `feat/ui-nicegui` | Toàn bộ giao diện NiceGUI (`src/ui/*`), thanh điều hướng Side Menu Hover-to-Expand, bảng tương tác Tabulator, biểu đồ ECharts, tải file/ảnh và kiểm thử UI |
| **Thành viên 2 (Backend)** | Thuật toán lõi & Kiểm thử | `feat/core-backend` | Cài đặt KSA, PRGA, XOR thuần Python (`src/core/*`), logic tấn công dùng lại khóa (Two-Time Pad & Crib-dragging), benchmark tốc độ và unit tests (`tests/*`) |

---

---

## 2. Các Tính Năng Chính Của Ứng Dụng (5 Phân Hệ / Tabs)

### 📌 Tab 1: Trực Quan Hóa TinyRC4 (3-bit Step-by-Step)
- **Chuẩn hóa học thuật**: Mô phỏng hệ mã dòng 3-bit thu nhỏ trên không gian 8 phần tử ($N=8$, modulo 8) theo đúng bài giảng Khoa CNTT - ĐH Kinh tế Quốc dân (Slide 56–60).
- **Bộ chuyển đổi bảng chữ cái**: Ánh xạ ký tự chữ cái chuẩn `A`..`H` sang chuỗi 3-bit tương ứng `000`..`111` ($0..7$).
- **Chi tiết từng bước**:
  - Bảng 8 vòng hoán vị KSA ($i = 0..7$, chỉ số $j$, phép hoán vị $S[i] \leftrightarrow S[j]$).
  - Bảng sinh số PRGA và phép XOR nhị phân từng cụm 3-bit giữa bản rõ và dòng khóa.
- **Nút nạp ví dụ 1 chạm**: Tự động điền vector chuẩn trên lớp:
  - Bản rõ $P = \text{"BAG"}$ (`001 000 110`)
  - Khóa $K = [2, 1, 3]$
  - Trạng thái mảng $S$ sau 8 vòng KSA: `[6, 0, 7, 1, 2, 3, 5, 4]`
  - Dòng khóa PRGA: $k = [5, 1, 6]$ (`101 001 110`)
  - Bản mã sinh ra: $C = \text{"EBA"}$ (`100 001 000`)
- **Giải mã đối xứng 1 chạm**: Nút đảo chiều tự động chuyển bản mã $C = \text{"EBA"}$ thành bản rõ giải mã $P = \text{"BAG"}$ với cùng khóa $K$.

### 📌 Tab 2: RC4 Chuẩn (8-bit, Văn Bản UTF-8 & File/Ảnh Thật)
- **Thuần Python 100%**: Thuật toán KSA và PRGA modulo 256 xử lý mảng `bytes` nguyên bản, không sử dụng bất kỳ thư viện mật mã bên ngoài nào.
- **Mã hóa văn bản đa ngữ**: Hỗ trợ đầy đủ tiếng Việt UTF-8 và ký tự đặc biệt, xuất bản mã dưới dạng Hex và Base64.
- **Mã hóa tệp tin nhị phân & Tệp ảnh**:
  - Hỗ trợ tải lên tài liệu (`.txt`, `.pdf`) và tệp ảnh (`.png`, `.jpg`).
  - Xuất tệp mã hóa định dạng `.rc4`.
  - Giải mã khôi phục nguyên vẹn 100% từng byte dữ liệu gốc, hiển thị so sánh trực quan ảnh trước và sau khi giải mã.
- **Trực quan hóa S-Box 16x16**: Hiển thị bảng ma trận 256 phần tử của hoán vị $S$ trước và sau giai đoạn KSA/PRGA.

### 📌 Tab 3: Bộ Kiểm Thử Tự Động & Đối Chiếu Tiêu Chuẩn Quốc Tế
- **Tích hợp Tabulator hiện đại**: Bảng kiểm thử tương tác với tính năng tìm kiếm, phân trang và huy hiệu trạng thái `PASS` sinh động.
- **Tự động đối chiếu 8/8 Test Cases**:
  1. *Test Case 1*: Ví dụ trên lớp NEU Slide 56–60 ($P=\text{"BAG"}, K=[2,1,3] \to C=\text{"EBA"}$).
  2. *Test Case 2*: Vector cổ điển kinh điển (`Key = b"Key"`, `Plaintext = b"Plaintext"` $\to$ `BBF316E8D940AF0AD3`).
  3. *Test Case 3*: Vector Wikipedia (`Key = b"Wiki"`, `Plaintext = b"pedia"` $\to$ `1021BF0420`).
  4. *Test Case 4*: Văn bản tiếng Việt có dấu Unicode UTF-8 đối chiếu tính toàn vẹn.
  5. *Test Case 5–8*: Bộ 4 vector chuẩn quốc tế **IETF RFC 6229** tại vị trí offset 0 (40-bit, 64-bit, 128-bit, 256-bit).
- **Đối chiếu thư viện chuẩn**: So sánh song song kết quả của thuật toán tự xây dựng với `Crypto.Cipher.ARC4` (từ PyCryptodome) đảm bảo độ chính xác tuyệt đối 100%.

### 📌 Tab 4: Phân Tích Lỗ Hổng Dòng Khóa & Đo Tốc Độ Thực Nghiệm
- **Tấn công tái sử dụng dòng khóa (Two-Time Pad Attack)**:
  - Minh họa toán học: $C_1 \oplus C_2 = (P_1 \oplus K) \oplus (P_2 \oplus K) = P_1 \oplus P_2$.
  - Trực quan hóa việc loại bỏ hoàn toàn khóa bí mật khi kẻ tấn công bắt được hai bản mã dùng chung khóa.
- **Kỹ thuật thám mã Crib-dragging**:
  - Kéo trượt từ đoán trước (Crib) qua chuỗi $C_1 \oplus C_2$ để khôi phục từng phần bản rõ còn lại.
- **Đo hiệu năng thực tế (Benchmark)**:
  - Kiểm thử tốc độ mã hóa qua nhiều kích thước dữ liệu (1 KB, 10 KB, 100 KB, 1 MB).
  - Vẽ biểu đồ thông lượng (MB/s) trực quan tương tác bằng `ui.echart`.

### 📌 Tab 5: Tổng Quan Lý Thuyết, Sơ Đồ Khối & So Sánh A5/1
- **Lịch sử & Bối cảnh**: Nguồn gốc ra đời của RC4 (Ron Rivest, RSA Security 1987) và nguyên nhân bị cấm sử dụng trong TLS theo **IETF RFC 7465**.
- **Sơ đồ khối thuật toán**: Trực quan hóa quy trình KSA và PRGA bằng sơ đồ tương tác mã nguồn Mermaid.
- **Phân tích lỗ hổng sinh số ngẫu nhiên**: Điểm yếu thiên vị byte đầu tiên (Biased keystream) và đòn tấn công FMS (Fluhrer, Mantin, Shamir).
- **Bảng so sánh chuyên sâu RC4 vs A5/1 (GSM)**:
  - So sánh cấu trúc: Mảng hoán vị (S-Box) vs Thanh ghi dịch phản hồi tuyến tính (LFSR).
  - So sánh cơ chế điều khiển xung nhịp (Majority voting rule), kích thước trạng thái và ứng dụng thực tiễn.

---

## 3. Cài Đặt & Khởi Chạy Nhanh

### Yêu cầu môi trường
- **Python**: 3.9 trở lên
- **Trình duyệt**: Google Chrome, Microsoft Edge, Firefox, hoặc Safari

### 1. Cài đặt các thư viện phụ thuộc
```bash
pip install -r requirements.txt
```

*Nội dung các gói phụ thuộc chính:*
- `nicegui>=2.0.0`: Nền tảng xây dựng giao diện web tương tác bằng Python.
- `nicegui-tabulator>=0.3.1`: Hiển thị bảng kiểm thử tương tác cao cấp.
- `pycryptodome>=3.20.0`: Thư viện mật mã chuẩn dùng để đối chứng kiểm thử.
- `pillow>=10.0.0`: Xử lý tệp hình ảnh nhị phân.
- `pytest>=8.0.0`: Hỗ trợ chạy kịch bản unit test.

### 2. Khởi chạy ứng dụng
```bash
python main.py
```
Sau khi khởi chạy thành công, mở trình duyệt web và truy cập:  
👉 **[http://localhost:8080](http://localhost:8080)**

### 3. Tải & Cài Đặt Ứng Dụng (PWA Desktop / Mobile)
Ứng dụng hỗ trợ chuẩn **Progressive Web App (PWA)**, cho phép cài đặt trực tiếp thành phần mềm máy tính hoặc ứng dụng điện thoại độc lập:
- **Trên Máy Tính (Google Chrome, Microsoft Edge, Brave)**:
  - Khi mở giao diện, rê chuột vào chân thanh Side Menu bên trái và click vào nút **"Cài đặt RC4 Lab"** (hoặc biểu tượng máy tính cài đặt trên thanh địa chỉ URL).
  - Ứng dụng sẽ tự động tạo icon riêng trên Desktop và Start Menu/Taskbar, mở trong cửa sổ độc lập (**Standalone Window**) không có thanh URL trình duyệt.
- **Trên Điện Thoại (Android / iOS)**:
  - Mở trang web trên Chrome/Safari $\to$ Nhấn menu tùy chọn $\to$ Chọn **"Thêm vào màn hình chính" (Add to Home screen / Install app)**.

---

## 4. Chạy Kiểm Thử Tự Động (Unit Tests)

Chạy kiểm thử bằng lệnh `unittest` có sẵn trong Python:
```bash
python -m unittest tests/test_rc4_core.py -v
```

Hoặc chạy bằng `pytest`:
```bash
pytest tests/ -v
```

Kết quả kiểm thử tiêu chuẩn:
```text
test_all_verification_vectors (tests.test_rc4_core.TestRC4Core) ... ok
test_binary_image_encryption_roundtrip (tests.test_rc4_core.TestRC4Core) ... ok
test_classroom_tiny_rc4_slide_56_to_60 (tests.test_rc4_core.TestRC4Core) ... ok
----------------------------------------------------------------------
Ran 3 tests in 0.060s
OK
```

---

## 5. Cấu Trúc Thư Mục Dự Án

```text
.
├── .gitignore                    # Bỏ qua cache, venv và tệp tạm
├── README.md                     # Tài liệu hướng dẫn toàn diện dự án
├── requirements.txt              # Danh sách thư viện phụ thuộc
├── main.py                       # Điểm khởi chạy chính ứng dụng NiceGUI (Port 8080)
├── static/                       # Tài nguyên PWA tĩnh
│   └── pwa/                      # Web App Manifest, Service Worker & Icons
│       ├── manifest.webmanifest
│       ├── sw.js
│       ├── icon-192.png
│       ├── icon-512.png
│       └── favicon.ico
├── sample_data/                  # Dữ liệu thử nghiệm mẫu
│   ├── sample_logo.png           # Tệp ảnh mẫu để kiểm thử mã hóa nhị phân
│   └── sample_text.txt           # Tệp văn bản mẫu UTF-8
├── src/
│   ├── __init__.py
│   ├── core/                     # [BACKEND] - Thuật toán thuần Python (Không phụ thuộc UI)
│   │   ├── __init__.py
│   │   ├── models.py             # Hợp đồng dữ liệu chung (Dataclasses)
│   │   ├── tiny_rc4.py           # Thuật toán TinyRC4 (3-bit, modulo 8)
│   │   ├── rc4.py                # Thuật toán RC4 chuẩn (8-bit, 256 bytes)
│   │   ├── attack_demo.py        # Logic tấn công Two-Time Pad & Crib-dragging
│   │   └── benchmark.py          # Đo tốc độ mã hóa qua các kích thước tệp
│   └── ui/                       # [FRONTEND] - Giao diện SaaS Cryptographic Workbench
│       ├── __init__.py
│       ├── layout.py             # Khung Workbench, Sidebar Hover-to-Expand, Status Bar
│       ├── pwa.py                # Quản lý Web App Manifest, Service Worker & Install PWA
│       ├── tab_tiny_rc4.py       # Phân hệ 1: Trực quan hóa TinyRC4 từng bước
│       ├── tab_full_rc4.py       # Phân hệ 2: RC4 256-byte, Văn bản UTF-8 & File/Ảnh
│       ├── tab_testing.py        # Phân hệ 3: Bảng Tabulator kiểm thử 8/8 & RFC 6229
│       ├── tab_attack_bench.py   # Phân hệ 4: Mô phỏng Two-Time Pad & Biểu đồ ECharts
│       └── tab_theory.py         # Phân hệ 5: Lý thuyết, sơ đồ Mermaid & So sánh A5/1
└── tests/
    └── test_rc4_core.py          # Bộ kiểm thử tự động xác thực chuẩn xác 100%
```

---

