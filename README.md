# Hệ Mã Dòng RC4 & TinyRC4 — Ứng Dụng Minh Họa NiceGUI

Ứng dụng trực quan hóa và thực nghiệm hệ mã dòng **TinyRC4** (3-bit) và **RC4 chuẩn** (8-bit) xây dựng bằng **Python** và thư viện **NiceGUI**.

> **Học phần**: An toàn và Bảo mật Thông tin (Chương 2: Mã hóa khóa đối xứng)  
> **Đơn vị**: Khoa Công nghệ Thông tin — Đại học Kinh tế Quốc dân (NEU)  
> **Repository**: [https://github.com/TunN-313/Rc4-stream-cipher-demo](https://github.com/TunN-313/Rc4-stream-cipher-demo)

---

## 1. Phân Công Thành Viên Trong Nhóm

| Thành viên | Vai trò | Nhánh Git | Nội dung phụ trách chính |
| :--- | :--- | :--- | :--- |
| **Thành viên 1 (Frontend)** | Giao diện & Trực quan hóa | `feat/ui-nicegui` | Toàn bộ giao diện 5 Tab bằng NiceGUI (`src/ui/*`), bảng biểu KSA/PRGA, biểu đồ echart, tải file và kiểm thử UI |
| **Thành viên 2 (Backend)** | Thuật toán lõi & Kiểm thử | `feat/core-backend` | Cài đặt KSA, PRGA, XOR thuần Python (`src/core/*`), logic tấn công dùng lại khóa, benchmark và unit test (`tests/*`) |

---

## 2. Tính Năng Chính Của Ứng Dụng (5 Tab Giao Diện)

1. **Tab 1: Thực Thi TinyRC4 (3-bit Step-by-Step)**:
   - Tái hiện ví dụ bài giảng trên lớp (Slide 56–60): $P = \text{"BAG"}, K = [2, 1, 3] \to C = \text{"EBA"}$.
   - Hiển thị bảng chi tiết 8 vòng hoán vị KSA ($i = 0..7$, chỉ số $j$, phép hoán vị $S[i] \leftrightarrow S[j]$).
   - Hiển thị bảng sinh số PRGA và phép XOR nhị phân từng cụm 3-bit.
   - Nút nạp ví dụ 1 chạm và nút đảo chiều để giải mã đối xứng.
2. **Tab 2: RC4 Chuẩn (256-byte, Văn Bản UTF-8 & File/Ảnh Thật)**:
   - Mã hóa văn bản UTF-8 ra định dạng Hex và Base64; giải mã khôi phục bản rõ.
   - Trực quan hóa ma trận trạng thái hoán vị $S$ (256 byte) dưới dạng lưới 16x16.
   - Tải lên tệp văn bản (`.txt`) hoặc ảnh (`.png`, `.jpg`), mã hóa xuất file `.rc4`, giải mã khôi phục và hiển thị ảnh so sánh trực tiếp.
3. **Tab 3: Bộ Kiểm Thử Tự Động & Đối Chiếu Chuẩn**:
   - Chạy tự động 8 ca kiểm thử: (1) Ví dụ TinyRC4 trên lớp; (2) 3 ca tự thiết kế (cổ điển, tiếng Việt có dấu); (3) 4 ca kiểm thử vector chuẩn IETF RFC 6229 (40-bit, 64-bit, 128-bit, 256-bit).
   - Đối chiếu trực tiếp với thư viện `Crypto.Cipher.ARC4` của PyCryptodome.
4. **Tab 4: Đo Hiệu Năng & Tấn Công Dòng Khóa (Điểm Cộng)**:
   - Mô phỏng tấn công dùng lại dòng khóa (Keystream Reuse / Two-Time Pad Attack): $C_1 \oplus C_2 = P_1 \oplus P_2$.
   - Kỹ thuật thám mã Crib-dragging: Đoán trước 1 cụm từ của $P_1$ để giải mã một phần $P_2$.
   - Đo thông lượng mã hóa (MB/s) theo kích thước từ 1 KB đến 1 MB và vẽ biểu đồ đường bằng `ui.echart`.
5. **Tab 5: Tổng Quan Lý Thuyết & So Sánh Hệ Mã A5/1**:
   - Bối cảnh ra đời (Ron Rivest 1987) và lý do bị cấm theo chuẩn IETF RFC 7465.
   - Sơ đồ khối KSA & PRGA tự vẽ bằng mã Mermaid.
   - Bảng phân tích chi tiết so sánh giữa RC4 và A5/1 (GSM).

---

## 3. Cài Đặt & Khởi Chạy

### Yêu cầu môi trường
- Python 3.9 trở lên
- Trình duyệt web hiện đại (Chrome, Edge, Firefox)

### Cài đặt thư viện phụ thuộc
```bash
pip install -r requirements.txt
```

### Khởi chạy giao diện ứng dụng
```bash
python main.py
```
Sau khi khởi chạy thành công, truy cập trình duyệt tại địa chỉ: **[http://localhost:8080](http://localhost:8080)**

---

## 4. Chạy Bộ Kiểm Thử Tự Động (Unit Test)

Chạy kiểm thử bằng `pytest`:
```bash
pytest tests/ -v
```

Hoặc chạy bằng `unittest` có sẵn trong Python:
```bash
python -m unittest tests/test_rc4_core.py -v
```

---

## 5. Cấu Trúc Thư Mục Dự Án

```text
.
├── .gitignore                    # Bỏ qua cache và môi trường ảo
├── GEMINI.md                     # Quy tắc dự án cho Google Antigravity
├── README.md                     # Hướng dẫn và tài liệu dự án
├── requirements.txt              # Danh sách thư viện phụ thuộc
├── main.py                       # File chạy chính ứng dụng NiceGUI
├── sample_data/                  # Tệp văn bản và ảnh mẫu
│   ├── sample_logo.png
│   └── sample_text.txt
├── src/
│   ├── __init__.py
│   ├── core/                     # [BACKEND] - Thuật toán thuần Python
│   │   ├── __init__.py
│   │   ├── models.py             # Hợp đồng dữ liệu chung
│   │   ├── tiny_rc4.py           # Thuật toán TinyRC4 (3-bit)
│   │   ├── rc4.py                # Thuật toán RC4 chuẩn (256-byte)
│   │   ├── attack_demo.py        # Logic tấn công Two-Time Pad
│   │   └── benchmark.py          # Đo tốc độ mã hóa
│   └── ui/                       # [FRONTEND] - Giao diện NiceGUI
│       ├── __init__.py
│       ├── layout.py             # Header & Khung điều hướng 5 Tab
│       ├── tab_tiny_rc4.py       # Tab 1: Trực quan hóa TinyRC4
│       ├── tab_full_rc4.py       # Tab 2: RC4 256-byte & File/Ảnh
│       ├── tab_testing.py        # Tab 3: Bảng kiểm thử & RFC 6229
│       ├── tab_attack_bench.py   # Tab 4: Tấn công & Biểu đồ tốc độ
│       └── tab_theory.py         # Tab 5: Lý thuyết & Sơ đồ Mermaid
└── tests/
    └── test_rc4_core.py          # Bộ kiểm thử tự động
```
