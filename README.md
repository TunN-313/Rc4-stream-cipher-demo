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
| **Thành viên 2 (Backend)** | Thuật toán lõi & Kiểm thử | `feat/core-backend` | Cài đặt KSA, PRGA, XOR thuần Python (`src/core/*`), logic thám mã khôi phục khóa FMS, Two-Time Pad, Crib-dragging, Mantin-Shamir bias và unit tests (`tests/*`) |

---

---

## 2. Các Tính Năng Chính Của Ứng Dụng (4 Phân Hệ Thực Hành)

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
- **Biểu diễn văn bản UTF-8 chuẩn học thuật & Minh họa trực quan**:
  - **Bảng 1: Phân rã cấu trúc UTF-8**: Tách mã điểm Unicode, số byte, mẫu bit (`110xxxxx 10xxxxxx`), bit dữ liệu, nhị phân và Hex. Làm rõ việc một ký tự có thể nở thành nhiều byte nhị phân ($P$) và PRGA lặp đúng theo số byte $m$.
  - **Bảng 2: Diễn giải từng byte qua lõi RC4 (8-bit XOR)**: Trực quan hóa từng bước $r$, byte bản rõ $P_r$, dòng khóa $Z_r$, biểu thức nhị phân $P_r \oplus Z_r$ và byte bản mã $C_r$ (Dec & Hex).
  - **Giải thích cơ chế giải mã bản mã**: Làm rõ tại sao phép XOR tạo ra các byte ngẫu nhiên thường xuyên vi phạm cấu trúc tiền tố chuẩn của UTF-8, gây lỗi `UnicodeDecodeError`, từ đó khẳng định bản mã bắt buộc phải lưu nhị phân hoặc đóng gói qua Hex/Base64.
- **Mã hóa tệp tin nhị phân & Tệp ảnh**:
  - Hỗ trợ tải lên tài liệu (`.txt`, `.pdf`) và tệp ảnh (`.png`, `.jpg`).
  - Xuất tệp mã hóa định dạng `.rc4`.
  - Giải mã khôi phục nguyên vẹn 100% từng byte dữ liệu gốc, hiển thị so sánh trực quan ảnh trước và sau khi giải mã.
- **Trực quan hóa S-Box 16x16**: Hiển thị bảng ma trận 256 phần tử của hoán vị $S$ trước và sau giai đoạn KSA/PRGA.

### 📌 Tab 3: Bộ Kiểm Thử Tự Động & Đánh Giá Thực Nghiệm (20 Ca Chuẩn Hóa Theo Chương 4)
- **Thẻ môi trường thực nghiệm chuẩn hóa (Mục 4.1.2)**: Hiển thị tự động thông số hệ điều hành (OS), phiên bản Python, công cụ chạy kiểm thử (pytest / Runner) và bộ đếm thời gian phân giải cao (`time.perf_counter`).
- **Bộ chọn nhóm kiểm thử 1 chạm (5 chế độ lọc linh hoạt)**:
  - `Tất cả (20)`: Toàn bộ 20 kịch bản kiểm thử chuẩn hóa.
  - `1. TinyRC4 (4)`: Bộ 4 ca kiểm thử mô hình 3-bit: Khởi tạo S, KSA 8 vòng, PRGA sinh khóa và mã hóa/giải mã đối xứng (`TINY-01`..`04` - Bảng 4.2.1).
  - `2. RC4 Đầy Đủ (5)`: Bộ 5 ca kiểm thử RC4 8-bit: Dòng khóa PRGA, mã hóa bản rõ, vector Wikipedia, vector IETF RFC 6229 và kiểm tra giải mã đối xứng (`RC4-01`..`05` - Bảng 4.2.2).
  - `3. Dữ Liệu (5)`: Bộ 5 ca kiểm thử theo loại dữ liệu: Chuỗi rỗng, 1 byte đơn lẻ, văn bản dài, Unicode tiếng Việt UTF-8 và tệp hình ảnh nhị phân (`DATA-01`..`05` - Bảng 4.2.3).
  - `4. Đặc Biệt (6)`: Bộ 6 ca kiểm thử trường hợp biên & đặc biệt: Khóa cực ngắn 1 byte, khóa cực dài 256 bytes, khóa toàn 0x00, khóa toàn 0xFF, dữ liệu lặp chu kỳ và giải mã sai khóa (`SPECIAL-01`..`06` - Bảng 4.2.4).
- **Tích hợp Tabulator hiện đại & Xuất báo cáo đa định dạng**: Bảng kiểm thử tương tác với huy hiệu `PASS` chuẩn màu, ô tìm kiếm nhanh, phân trang và các nút xuất báo cáo `Xuất CSV`, `Xuất JSON` và `In báo cáo`.

### 📌 Tab 4: Thám Mã & Tấn Công Bẻ Khóa RC4 (FMS, Two-Time Pad & Bias)
- **1. Tấn công bẻ khóa bí mật FMS trong WEP (Key Recovery Attack)**:
  - Khôi phục chính xác toàn bộ khóa bí mật dùng chung $K$ (WEP 64-bit hoặc 128-bit).
  - Thu thập các gói tin mang Vector khởi tạo yếu $IV = (A+3, \text{0xFF}, X)$ và biết trước byte đầu $P_0 = \text{0xAA}$ (SNAP/LLC).
  - Mô phỏng KSA từng phần cho các byte đã biết và bỏ phiếu thống kê cho 256 ứng viên qua quan hệ $e^{-3} \approx 5\%$.
  - Tự động kiểm chứng độc lập trên 50 gói ngẫu nhiên để xác nhận khóa chính xác 100%, chống sai lệch dây chuyền.
  - Biểu đồ phân bố phiếu bầu tương tác (ECharts) làm nổi bật tín hiệu đúng so với mức nhiễu ngẫu nhiên.
- **2. Tấn công tái sử dụng dòng khóa (Two-Time Pad Attack)**:
  - Minh họa toán học: $C_1 \oplus C_2 = (P_1 \oplus K) \oplus (P_2 \oplus K) = P_1 \oplus P_2$.
  - Trực quan hóa việc loại bỏ hoàn toàn khóa bí mật khi kẻ tấn công bắt được hai bản mã dùng chung khóa.
  - Kỹ thuật thám mã Crib-dragging: Kéo trượt từ đoán trước (Crib) qua chuỗi $C_1 \oplus C_2$ để khôi phục từng phần bản rõ còn lại.
- **3. Thiên lệch dòng khóa (Mantin–Shamir Bias)**:
  - Kiểm chứng byte thứ 2 của dòng khóa bằng 0x00 với xác suất $\approx 1/128$ thay vì $1/256$.
  - Biểu đồ phân bố tần suất 256 byte thể hiện đột biến xác suất gấp đôi mức đều lý thuyết.

---

## 3. Cài Đặt & Khởi Chạy Nhanh

### Yêu cầu môi trường
- **Python**: 3.9 đến 3.14 (Khuyến nghị 3.10 trở lên)
- **Trình duyệt**: Google Chrome, Microsoft Edge, Firefox, hoặc Safari

---

### Bước 1: Tải mã nguồn về máy

Bạn có thể chọn **1 trong 2 cách** sau:

* **Cách A (Nếu máy đã cài Git - Khuyến nghị):**
  ```bash
  git clone https://github.com/TunN-313/Rc4-stream-cipher-demo.git
  cd Rc4-stream-cipher-demo
  ```

* **Cách B (Nếu máy chưa cài Git — Không cần cài thêm phần mềm):**
  1. Truy cập trực tiếp link tải file nén: 👉 **[Tải file ZIP mã nguồn (nhánh main)](https://github.com/TunN-313/Rc4-stream-cipher-demo/archive/refs/heads/main.zip)**  
     *(Hoặc vào trang GitHub dự án -> bấm nút xanh **`<> Code`** -> chọn **`Download ZIP`**)*.
  2. Giải nén tệp `Rc4-stream-cipher-demo-main.zip` vừa tải về máy.
  3. Mở thư mục vừa giải nén trong PowerShell / Terminal / Command Prompt rồi chuyển sang Bước 2.
  *(Nếu muốn cài đặt Git để tiện cập nhật code, bạn có thể tải tại [git-scm.com](https://git-scm.com/download/win) hoặc chạy `winget install --id Git.Git -e --source winget`).*

### Bước 2: Tạo và kích hoạt môi trường ảo (Khuyến nghị)
```bash
# Trên Windows PowerShell
python -m venv .venv
.venv\Scripts\Activate.ps1

# Mẹo: Nếu PowerShell báo lỗi kịch bản (ExecutionPolicy), hãy chạy:
# Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

# Trên Windows Command Prompt (cmd.exe)
python -m venv .venv
.venv\Scripts\activate.bat

# Trên Linux / macOS
python3 -m venv .venv
source .venv/bin/activate
```

### Bước 3: Cài đặt các thư viện phụ thuộc
```bash
# Nâng cấp pip lên bản mới nhất (khuyến nghị)
python -m pip install --upgrade pip

# Cài đặt toàn bộ thư viện phụ thuộc
pip install -r requirements.txt
```

*Nội dung các gói phụ thuộc chính:*
- `nicegui>=3.0,<4.0`: Nền tảng xây dựng giao diện web tương tác bằng Python.
- `nicegui-tabulator>=0.3.1`: Hiển thị bảng kiểm thử tương tác cao cấp (lọc cột, phân trang, xuất CSV/JSON).
- `pillow>=10.0.0`: Xử lý tệp hình ảnh nhị phân (PNG, JPG).
- `pytest>=8.0.0`: Khung kiểm thử tự động.
- `pytest-asyncio>=0.23`: Hỗ trợ kiểm thử bất đồng bộ cho ứng dụng NiceGUI.

### Bước 4: Khởi chạy ứng dụng
```bash
python main.py
```
Sau khi khởi chạy thành công, mở trình duyệt web và truy cập:  
👉 **[http://localhost:8080](http://localhost:8080)**

> [!TIP]
> **Xử lý trùng cổng (Port conflict)**: Mặc định ứng dụng chạy ở cổng `8080`. Nếu cổng này đang bị phần mềm khác chiếm dụng, bạn chỉ cần mở tệp `main.py` và sửa dòng `port=8080` thành cổng khác (ví dụ: `port=8888`), sau đó chạy lại.

> **Gợi ý tra cứu**: Để chuẩn bị nội dung thuyết trình hoặc giải thích mã nguồn cho người không chuyên, bạn có thể tham khảo tài liệu [docs/CHU_GIAI.md](docs/CHU_GIAI.md) chứa 3 bảng tra cứu nhanh thuật ngữ, thư viện và bản đồ hàm.

---

## 4. Chạy Kiểm Thử Tự Động (Unit Tests)

Bộ kiểm thử tự động toàn diện được đặt trong tệp `tests/test_kiem_thu_toan_dien.py`, bao gồm **56 ca kiểm thử** và **28 subtests** kiểm tra trọn vẹn 7 nhóm chức năng:
1. **Core RC4 & 20 Test Vectors chuẩn Chương 4**: Đối chiếu toàn bộ 20 ca kiểm thử chuẩn hóa thuộc 4 nhóm (TinyRC4 `TINY-01..04`, RC4 Đầy đủ `RC4-01..05`, Đa dạng dữ liệu `DATA-01..05`, Trường hợp đặc biệt `SPECIAL-01..06`), bảo đảm đối chiếu RFC 6229 và tính toàn vẹn 100%.
2. **Streaming Chunked**: Kiểm tra chia khối (chunks), tối ưu bộ nhớ RAM, bảo toàn tính đối xứng và xử lý ngoại lệ.
3. **Quản lý khóa & Mã hóa**: Sinh khóa ngẫu nhiên CSPRNG, chuyển đổi bytes, số nguyên và chuỗi Hex.
4. **Đặc tả & Minh họa UTF-8**: Phân rã cấu trúc Unicode/UTF-8 (Bảng 1), diễn giải từng bước 8-bit XOR (Bảng 2) và kiểm chứng cơ chế lỗi `UnicodeDecodeError` khi giải mã trực tiếp trên bản mã.
5. **Thám mã bẻ khóa FMS WEP**: KSA từng phần trên các lớp IV yếu $(A+3, \text{0xFF}, X)$, mô phỏng bỏ phiếu thống kê tìm từng byte khóa bí mật $K$, kiểm chứng độc lập 50 gói ngẫu nhiên.
6. **Lỗ hổng Two-Time Pad & Thiên lệch Bias**: Triệt tiêu dòng khóa $C_1 \oplus C_2$, kỹ thuật Crib-dragging, đo thiên lệch xác suất Mantin–Shamir tại byte thứ 2 của dòng khóa.
7. **Kiểm thử giao diện (UI Tests)**: Pipeline mã hóa tệp tin/hình ảnh, giao diện Tab 3 (thẻ môi trường, bộ lọc 5 nhóm, bảng Tabulator), kiểm thử cấu trúc 3 thẻ thám mã thực hành và thanh điều hướng 4 phân hệ.

### Lệnh chạy kiểm thử nhanh với pytest:
```bash
pytest -q
```

### Lệnh chạy kiểm thử chi tiết từng test case:
```bash
pytest tests/ -v
```

Hoặc chạy bằng `unittest` có sẵn trong Python:
```bash
python -m unittest tests/test_kiem_thu_toan_dien.py -v
```

Kết quả kiểm thử tiêu chuẩn:
```text
tests/test_kiem_thu_toan_dien.py::TestRC4Core::test_all_verification_vectors PASSED          [  2%]
tests/test_kiem_thu_toan_dien.py::TestRC4Core::test_binary_image_encryption_roundtrip PASSED [  4%]
tests/test_kiem_thu_toan_dien.py::TestRC4Core::test_classroom_tiny_rc4_slide_56_to_60 PASSED [  6%]
tests/test_kiem_thu_toan_dien.py::TestRC4Chunks::test_chunked_equals_oneshot_5000_bytes PASSED [  8%]
...
tests/test_kiem_thu_toan_dien.py::test_attack_ui_three_practical_cards PASSED                [ 94%]
tests/test_kiem_thu_toan_dien.py::test_layout_navigation_structure PASSED                    [ 96%]
tests/test_kiem_thu_toan_dien.py::test_fms_ui_elements PASSED                                [ 98%]
tests/test_kiem_thu_toan_dien.py::test_tab_testing_ui_elements PASSED                        [100%]

============================= 56 passed in 12.24s =============================
```

---

## 5. Cấu Trúc Thư Mục Dự Án (Chuẩn Hóa Tiếng Việt)

```text
.
├── .gitignore                          # Bỏ qua cache, venv và tệp tạm
├── README.md                           # Tài liệu hướng dẫn toàn diện dự án
├── pytest.ini                          # Cấu hình kiểm thử pytest (asyncio mode)
├── requirements.txt                    # Danh sách thư viện phụ thuộc chính
├── main.py                             # Điểm khởi chạy chính ứng dụng NiceGUI (Port 8080)
├── docs/                               # Tài liệu thuyết trình & học tập
│   └── CHU_GIAI.md                     # 3 bảng chú giải thuật ngữ, thư viện và bản đồ hàm
├── static/                             # Tài nguyên tĩnh
│   └── favicon.ico                     # Biểu tượng ứng dụng
├── sample_data/                        # Dữ liệu thử nghiệm mẫu
│   ├── sample_logo.png                 # Tệp ảnh mẫu để kiểm thử mã hóa nhị phân
│   └── sample_text.txt                 # Tệp văn bản mẫu UTF-8
├── src/
│   ├── __init__.py
│   ├── core/                           # [BACKEND] - Thuật toán thuần Python (Không phụ thuộc UI)
│   │   ├── __init__.py                 # Export toàn bộ giao diện hàm và hằng số
│   │   ├── mo_hinh_du_lieu.py          # Hợp đồng dữ liệu chung (Dataclasses kết quả)
│   │   ├── rc4_chuan.py                # Thuật toán RC4 chuẩn 8-bit (KSA, PRGA, streaming chunks)
│   │   ├── rc4_thu_nho.py              # Thuật toán mô phỏng TinyRC4 3-bit (modulo 8 trên lớp)
│   │   ├── quan_ly_khoa.py             # Quản lý & sinh khóa RC4/TinyRC4 (CSPRNG secrets)
│   │   ├── chuyen_doi_du_lieu.py       # Chuyển đổi định dạng dữ liệu (Bytes, n-bit, Hex, UTF-8)
│   │   └── phan_tich_an_toan.py        # Thám mã bẻ khóa FMS WEP, Two-Time Pad & Mantin-Shamir
│   └── ui/                             # [FRONTEND] - Giao diện NiceGUI
│       ├── __init__.py                 # Điểm khởi đầu gói giao diện
│       ├── khung_giao_dien.py          # Bố cục tổng thể, thanh điều hướng Sidebar Hover-to-Expand
│       ├── tab_rc4_thu_nho.py          # Phân hệ 1: Trực quan hóa TinyRC4 từng bước 3-bit
│       ├── tab_rc4_van_ban.py          # Phân hệ 2a: RC4 Văn Bản (UTF-8, Bảng 1, Bảng 2 & Mảng S)
│       ├── tab_rc4_tep_tin.py          # Phân hệ 2b: Quy trình nạp → mã hóa nhị phân → giải mã
│       ├── tab_kiem_thu.py             # Phân hệ 3: Kiểm thử tự động 20 ca chuẩn Chương 4 & Thẻ môi trường
│       └── tab_tham_ma.py              # Phân hệ 4: Phòng thực nghiệm thám mã FMS, Two-Time Pad, Bias
└── tests/                              # Bộ kiểm thử tự động toàn diện (pytest)
    └── test_kiem_thu_toan_dien.py      # Suite kiểm thử gộp toàn diện 7 nhóm (56/56 test cases)
```

---

