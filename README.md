# Hệ Mã Dòng RC4 & TinyRC4 

Demo thực nghiệm hệ mã dòng **TinyRC4** và **RC4 chuẩn** xây dựng trên nền tảng Python và NiceGUI.

> **Repository**: [https://github.com/TunN-313/Rc4-stream-cipher-demo](https://github.com/TunN-313/Rc4-stream-cipher-demo)  

---

## 1. Cài Đặt & Khởi Chạy Nhanh

### Yêu cầu môi trường
- **Python**: 3.9 đến 3.14 (khuyến nghị 3.10 trở lên)
- **Trình duyệt**: Google Chrome, Microsoft Edge, Firefox, hoặc Safari

---

### Bước 1: Tải mã nguồn về máy
```bash
git clone https://github.com/TunN-313/Rc4-stream-cipher-demo.git
cd Rc4-stream-cipher-demo
```

### Bước 2: Tạo và kích hoạt môi trường ảo
```bash
# Trên Windows PowerShell
python -m venv .venv
.venv\Scripts\Activate.ps1

# Trên Windows Command Prompt
python -m venv .venv
.venv\Scripts\activate.bat

# Trên Linux / macOS
python3 -m venv .venv
source .venv/bin/activate
```

### Bước 3: Cài đặt thư viện
```bash
pip install -r requirements.txt
```
*Các thư viện sử dụng:*
- `nicegui>=3.0,<4.0`: Giao diện web trực quan bằng GUI Python.
- `pillow>=10.0.0`: Xử lý hình ảnh nhị phân (.png, .jpg).
- `pycryptodome>=3.18.0`: Thư viện mật mã đối chiếu kiểm thử (ARC4).

### Bước 4: Khởi chạy ứng dụng
```bash
# Trên Windows
python main.py

# Trên Linux / macOS
python3 main.py
```
Sau khi khởi chạy thành công, mở trình duyệt web và truy cập:  
**[http://localhost:8080](http://localhost:8080)**

---

## 2. Cấu Trúc Thư Mục Dự Án

```text
RC4-demo/
├── sample_data/                        # Dữ liệu thử (logo.png, sample_text.txt)
├── src/                                # Mã nguồn chính của dự án
│   ├── core/                           #     Thuật toán mật mã
│   │   ├── buoc1_xu_ly_dau_vao.py      #     ~ BƯỚC 1: Chuẩn hóa dữ liệu UTF-8, Hex, sinh khóa & phân tích
│   │   ├── buoc2_khoi_tao_ksa.py       #     ~ BƯỚC 2: Khởi tạo mảng hoán vị KSA (modulo 8 & 256)
│   │   ├── buoc3_sinh_so_prga.py       #     ~ BƯỚC 3: Sinh keystream PRGA, TinyRC4 & RC4 (mã hóa XOR)
│   │   ├── tham_ma_be_khoa.py          #     Thám mã bẻ khóa FMS WEP & Benchmark hiệu năng
│   │   └── __init__.py                 #     Điểm xuất toàn bộ hàm và cấu trúc dữ liệu
│   ├── ui/                             #     Giao diện người dùng
│   │   ├── khung_giao_dien.py          #     Khung chính + Thanh Tab 
│   │   ├── tab_rc4_thu_nho.py          #     Tab 1: TinyRC4 3-bit
│   │   ├── tab_rc4_van_ban.py          #     Tab 2: Mã hóa văn bản UTF-8
│   │   ├── tab_rc4_tep_tin.py          #     Tab 3: Mã hóa tệp tin & ảnh 
│   │   ├── tab_kiem_thu.py             #     Tab 4: Kiểm thử thủ công
│   │   ├── tab_tham_ma.py              #     Tab 5: Thám mã bẻ khóa FMS WEP
│   │   └── __init__.py
│   └── __init__.py                     #     Khởi tạo gói gốc src
├── main.py                             # Điểm khởi chạy ứng dụng
├── .gitignore                          # Cấu hình bỏ qua tệp tạm
├── README.md                           # Tài liệu hướng dẫn
└── requirements.txt                    # Danh sách thư viện phụ thuộc
```

---

