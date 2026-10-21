# Kế Hoạch Xây Dựng Ứng Dụng RC4 & TinyRC4 Với NiceGUI Trên Google Antigravity

Tài liệu này là bản kế hoạch chi tiết giúp bạn triển khai phần **Frontend bằng [NiceGUI](https://nicegui.io/documentation)**, đồng thời định nghĩa sẵn **Hợp đồng giao tiếp (API Contract)** để hỗ trợ thành viên làm **Backend (Python thuần)** phát triển song song và thể hiện lịch sử đóng góp rõ ràng trên **GitHub**.

 Toàn bộ yêu cầu được thiết kế bám sát bài giảng *Chương 2: Mã hóa khóa đối xứng* (Khoa CNTT – ĐH Kinh tế Quốc dân) và tài liệu hướng dẫn bài tập lớn (`RC4 - GUIDE.pdf`).

## 1. Phân Tích Yêu Cầu Cốt Lõi Từ Đề Bài & Bài Giảng

Để đạt điểm tối đa khi chấm bài và demo (5–7 phút trên lớp), hệ thống cần thỏa mãn các chốt chặn kỹ thuật sau:

| Hạng mục | Yêu cầu bắt buộc từ `RC4 - GUIDE.pdf` & Slide bài giảng | Giải pháp trên Frontend (NiceGUI) & Backend (Python) |
| :--- | :--- | :--- |
| **Hai phiên bản thuật toán** | Cài đặt cả **TinyRC4** (3-bit, mảng $S, T$ gồm 8 phần tử `0..7`) và **RC4 đầy đủ** (8-bit, mảng $S, T$ gồm 256 byte `0..255`). | Tách 2 module độc lập `tiny_rc4.py` và `rc4.py` trong Backend; hiển thị ở 2 khu vực thực hành riêng trên UI. |
| **Khớp ví dụ trên lớp (Slide 56–60)** | Phiên bản TinyRC4 phải tái hiện đúng ví dụ trên lớp: Bản rõ `P = "BAG"` (`001 000 110`), khóa `K = [2, 1, 3]` ($N=3$) $\rightarrow$ Mảng $S$ sau KSA là `[6, 0, 7, 1, 2, 3, 5, 4]`, dòng khóa sinh ra là `101 001 110` (`[5, 1, 6]`), bản mã `C = "EBA"` (`100 001 000`). | Tạo nút **"Nạp ví dụ chuẩn trên lớp (BAG / K=2,1,3)"** trên Tab 1 để giảng viên kiểm tra chỉ bằng 1 cú nhấp chuột. |
| **Không dùng thư viện cho phần lõi** | Tự cài đặt KSA và PRGA từ đầu; thư viện chuẩn chỉ dùng để đối chiếu kết quả kiểm thử. | Phần lõi chỉ dùng toán tử Python cơ bản (`%`, `^`, hoán vị list); dùng [PyCryptodome (`Crypto.Cipher.ARC4`)](https://www.pycryptodome.org/src/cipher/arc4) trong module `tests/` và Tab Kiểm thử để đối chiếu. |
| **In bước trung gian (TinyRC4)** | Hiển thị rõ nội dung mảng $S, T$, chỉ số $i, j$, giá trị hoán vị từng vòng KSA và từng bước sinh khóa $s_i$ trong PRGA. | Dùng [`ui.table`](https://nicegui.io/documentation/table) kết hợp thanh trượt hoặc bảng trạng thái từng bước từ `i = 0` đến `i = 7`. |
| **Demo dữ liệu thật** | Không chỉ vài ký tự: mã hóa và giải mã một tệp văn bản (`.txt`) hoặc một tệp ảnh nhỏ (`.png`, `.jpg`). | Dùng [`ui.upload`](https://nicegui.io/documentation/upload) nhận file byte nhị phân, chạy RC4, cho phép tải về file đã mã hóa/giải mã và xem trước ảnh khôi phục. |
| **Điểm cộng khuyến khích** | (1) Có giao diện GUI/Web; (2) Đo thời gian chạy theo kích thước dữ liệu; (3) Minh họa 1 tình huống tấn công (dùng lại dòng khóa); (4) Bộ kiểm thử chuẩn. | Tích hợp biểu đồ tốc độ bằng [`ui.echart`](https://nicegui.io/documentation/echart), mô phỏng tấn công **Keystream Reuse (Two-Time Pad)** và bảng đối chiếu [RFC 6229](https://www.rfc-editor.org/info/rfc6229/). |
| **Tab Tìm hiểu ngắn gọn** | Bối cảnh ra đời, sơ đồ khối **do nhóm tự vẽ** (không chụp ảnh slide), ví dụ tính tay, phân tích an toàn & so sánh với hệ mã cùng loại (A5/1). | Gom gọn vào 1 Tab dùng [`ui.markdown`](https://nicegui.io/documentation/markdown) và vẽ sơ đồ khối trực tiếp bằng code Mermaid (`ui.mermaid`). |

## 2. Kiến Trúc Thư Mục Tách Biệt Frontend & Backend

Thiết kế cấu trúc thư mục dưới đây giúp **bạn (Frontend)** và **bạn cùng nhóm (Backend)** làm việc trên 2 thư mục khác nhau (`src/ui/` và `src/core/`), hạn chế tối đa xung đột code (merge conflict) khi gộp nhánh trên GitHub:

```text
rc4-stream-cipher-demo/
├── GEMINI.md                     # File Rules để Google Antigravity tự động đọc ngữ cảnh dự án
├── README.md                     # Hướng dẫn cài đặt, chạy chương trình & bảng phân công nhóm
├── requirements.txt              # nicegui, pycryptodome, pytest
├── main.py                       # Điểm chạy chính khởi động ứng dụng NiceGUI
├── sample_data/                  # Dữ liệu mẫu để bấm nút chạy demo ngay trên lớp
│   ├── sample_text.txt           # File văn bản tiếng Việt / tiếng Anh mẫu
│   └── sample_logo.png           # Ảnh nhỏ (< 100KB) để demo mã hóa/giải mã file nhị phân
├── src/
│   ├── __init__.py
│   ├── core/                     # [BACKEND TEAM PHỤ TRÁCH] - Thuật toán thuần Python
│   │   ├── __init__.py
│   │   ├── models.py             # Hợp đồng dữ liệu (Dataclasses chung giữa FE & BE)
│   │   ├── tiny_rc4.py           # Thuật toán TinyRC4 (3-bit, S & T 8 phần tử, bảng chữ A..H)
│   │   ├── rc4.py                # Thuật toán RC4 chuẩn (8-bit, S & T 256 phần tử, xử lý bytes)
│   │   ├── attack_demo.py        # Logic tấn công dùng lại dòng khóa (Keystream Reuse: C1 ^ C2)
│   │   └── benchmark.py          # Hàm đo thời gian mã hóa theo kích thước (1KB -> 5MB)
│   └── ui/                       # [FRONTEND (BẠN) PHỤ TRÁCH] - Giao diện NiceGUI
│       ├── __init__.py
│       ├── layout.py             # Header, khung điều hướng ui.tabs và theme màu sắc
│       ├── tab_tiny_rc4.py       # Tab 1: Thực thi & minh họa từng bước TinyRC4
│       ├── tab_full_rc4.py       # Tab 2: Thực thi RC4 chuẩn (Văn bản & File/Ảnh thật)
│       ├── tab_testing.py        # Tab 3: Bộ kiểm thử tự viết, RFC 6229 & đối chiếu PyCryptodome
│       ├── tab_attack_bench.py   # Tab 4: Minh họa tấn công Keystream Reuse & Đo hiệu năng
│       └── tab_theory.py         # Tab 5: Tóm tắt lý thuyết, sơ đồ khối Mermaid & so sánh A5/1
└── tests/                        # [CẢ HAI CÙNG PHỐI HỢP]
    └── test_rc4_core.py          # Unit tests chạy bằng pytest để chụp ảnh đưa vào Báo cáo
```

## 3. Hợp Đồng Giao Tiếp Giữa Frontend & Backend (`src/core/models.py`)

Đây là **bước quan trọng nhất để giúp thành viên làm Backend**: trước khi viết code riêng, bạn khởi tạo file `src/core/models.py` quy định rõ đầu vào (Input) và đầu ra (Output).

Khi có file này:
1. **Bạn (Frontend)** có thể tạo dữ liệu giả lập (Mock) để dựng toàn bộ bảng biểu, nút bấm NiceGUI mà không phải chờ Backend code xong.
2. **Thành viên Backend** chỉ cần viết hàm trả về đúng cấu trúc `TinyRC4Result` và `RC4Result` mà không cần biết gì về NiceGUI.

```python
# src/core/models.py
from dataclasses import dataclass
from typing import List, Optional

# Bảng quy đổi chuẩn theo Slide 40 của bài giảng
TINY_ALPHABET = {
    'A': 0b000, 'B': 0b001, 'C': 0b010, 'D': 0b011,
    'E': 0b100, 'F': 0b101, 'G': 0b110, 'H': 0b111
}
INV_TINY_ALPHABET = {v: k for k, v in TINY_ALPHABET.items()}

@dataclass
class KSAStep:
    step_i: int          # Giá trị i (0..7 với TinyRC4, 0..255 với RC4)
    j_before: int        # Giá trị j trước khi tính
    s_i_before: int      # Giá trị S[i] trước khi hoán vị
    t_i: int             # Giá trị T[i]
    j_after: int         # j = (j + S[i] + T[i]) mod M
    swapped_pair: str    # Mô tả "Swap(S[i], S[j])"
    s_array: List[int]   # Bản sao mảng S sau khi hoán vị ở bước i

@dataclass
class PRGAStep:
    step_idx: int        # Bước sinh số thứ mấy (0, 1, 2...)
    i_val: int           # i = (i + 1) mod M
    j_val: int           # j = (j + S[i]) mod M
    t_val: int           # t = (S[i] + S[j]) mod M
    keystream_val: int   # k = S[t] (số nguyên 3-bit hoặc 8-bit)
    keystream_bin: str   # Biểu diễn nhị phân (3 bit '101' hoặc 8 bit '01010101')
    input_val: int       # Đơn vị bản rõ/bản mã đầu vào (3-bit hoặc 8-bit)
    input_bin: str       # Nhị phân đầu vào
    output_val: int      # Kết quả XOR: input_val ^ keystream_val
    output_bin: str      # Nhị phân kết quả XOR
    s_array: List[int]   # Bản sao mảng S sau bước sinh số này
    char_in: Optional[str] = None   # Chữ cái A..H đầu vào (dành cho TinyRC4)
    char_out: Optional[str] = None  # Chữ cái A..H đầu ra (dành cho TinyRC4)

@dataclass
class TinyRC4Result:
    plaintext_str: str           # Ví dụ: "BAG"
    plaintext_bits: str          # Ví dụ: "001 000 110"
    key_list: List[int]          # Ví dụ: [2, 1, 3]
    initial_s: List[int]         # [0, 1, 2, 3, 4, 5, 6, 7]
    initial_t: List[int]         # [2, 1, 3, 2, 1, 3, 2, 1]
    ksa_steps: List[KSAStep]     # Đủ 8 bước i = 0..7
    prga_steps: List[PRGAStep]   # Các bước sinh số và XOR
    keystream_bits: str          # Ví dụ: "101 001 110"
    output_bits: str             # Ví dụ: "100 001 000"
    output_str: str              # Ví dụ: "EBA"

@dataclass
class TestCaseComparison:
    name: str                    # Tên ca kiểm thử (VD: "Slide 56 TinyRC4", "RFC 6229 Vector 1")
    key_desc: str                # Mô tả khóa
    input_desc: str              # Mô tả bản rõ
    expected_hex: str            # Kết quả chuẩn (từ tính tay / RFC 6229 / PyCryptodome)
    actual_hex: str              # Kết quả từ hàm tự cài đặt của nhóm
    decrypted_match: bool        # Giải mã ngược lại có khớp 100% bản rõ ban đầu không
    passed: bool                 # actual_hex == expected_hex và decrypted_match == True
```

## 4. Thiết Kế Chi Tiết 5 Tab Giao Diện NiceGUI

Giao diện được chia làm 5 Tab bằng [`ui.tabs`](https://nicegui.io/documentation/tabs) và `ui.tab_panels`, tập trung 85% không gian cho **Thực thi & Chạy Demo** và gom gọn phần **Tìm hiểu** vào Tab cuối.

| Thứ tự Tab | Tên Tab trên giao diện | Các thành phần NiceGUI chính & Luồng hoạt động khi thuyết trình |
| :--- | :--- | :--- |
| **Tab 1** | **Thực Thi TinyRC4 (3-bit Step-by-Step)** | • **Thanh công cụ nhanh**: Nút *"Nạp ví dụ bài giảng (P='BAG', K=[2,1,3])"* và nút *"Đảo chiều Giải mã (C='EBA' → P='BAG')"*.<br>• **Khung nhập liệu**: Ô nhập chuỗi chữ cái thuộc tập `{A..H}` hoặc chuỗi nhị phân bội số 3-bit; ô nhập dãy khóa $K$ (1–8 số từ `0..7`).<br>• **Khu vực trực quan hóa trung gian**: Hiển thị mảng $S_0, T_0$; bảng `ui.table` liệt kê 8 vòng hoán vị KSA (`i=0..7`, giá trị `j`, cặp `Swap(S[i], S[j])`, trạng thái mảng $S$); bảng `ui.table` liệt kê từng bước PRGA ($i, j, t, s_i$, phép XOR từng cụm 3-bit và chữ cái kết quả). |
| **Tab 2** | **Thực Thi RC4 Chuẩn (256-byte & File/Ảnh)** | • **Khu vực 1 – Văn bản**: Nhập Plaintext (UTF-8) và Key $\rightarrow$ Hiển thị Ciphertext ở dạng **Hex** và **Base64** + nút *"Giải mã ngay lập tức"* để chứng minh khôi phục đúng bản rõ.<br>• **Khu vực 2 – Dữ liệu thật (File/Ảnh)**: Dùng `ui.upload` tải lên tệp `.txt` hoặc ảnh `.png`/`.jpg` $\rightarrow$ Bấm *"Mã hóa File"* (hiển thị kích thước byte, thời gian xử lý ms, cho tải về file `.rc4`) $\rightarrow$ Bấm *"Giải mã File `.rc4`"* và hiển thị ảnh khôi phục ngay bên cạnh ảnh gốc để đối chiếu trực quan. |
| **Tab 3** | **Kiểm Thử & Đối Chiếu Chuẩn** | • Nút *"Chạy toàn bộ Suite Kiểm thử"*.<br>• Hiển thị bảng `ui.table` gồm: (1) Ca kiểm thử TinyRC4 trên lớp; (2) 3 ca kiểm thử nhóm tự thiết kế (khóa ngắn, khóa dài 256 byte, văn bản tiếng Việt Unicode); (3) Đối chiếu với bộ vector chuẩn [RFC 6229](https://www.rfc-editor.org/info/rfc6229/) và thư viện [PyCryptodome (`Crypto.Cipher.ARC4`)](https://www.pycryptodome.org/src/cipher/arc4).<br>• Cột trạng thái hiển thị huy hiệu `ui.badge("PASS", color="positive")`. |
| **Tab 4** | **Đo Hiệu Năng & Tấn Công Dòng Khóa** | • **Nửa trái – Tấn công dùng lại dòng khóa (Keystream Reuse Attack)**: Nhập 2 bản rõ $P_1, P_2$ mã hóa bằng cùng 1 khóa $K$ tạo ra $C_1, C_2$. Hiển thị công thức $C_1 \oplus C_2 = P_1 \oplus P_2$ (loại bỏ hoàn toàn dòng khóa $S$). Khi nhập thử 1 từ đoán trước (crib) của $P_1$, giao diện tự động giải ra phần tương ứng của $P_2$.<br>• **Nửa phải – Benchmark tốc độ**: Nút *"Đo thời gian theo kích thước (10KB, 100KB, 500KB, 1MB, 2MB)"* và vẽ biểu đồ đường trực tiếp trên `ui.echart`. |
| **Tab 5** | **Tổng Quan Lý Thuyết (Tóm tắt)** | • Trình bày gọn gàng trong 1 tab bằng `ui.markdown` và `ui.expansion`:<br>1. Bối cảnh ra đời (Ron Rivest 1987, WEP, SSL/TLS, lý do bị cấm theo [RFC 7465](https://www.rfc-editor.org/info/rfc7465/)).<br>2. Sơ đồ khối KSA & PRGA vẽ bằng `ui.mermaid` (đáp ứng yêu cầu sơ đồ tự vẽ, không cắt ảnh slide).<br>3. Ví dụ tính tay đầy đủ từng bước cho `P = "BAG"`, `K = [2, 1, 3]`.<br>4. Bảng so sánh RC4 với hệ mã dòng **A5/1 (TinyA5/1)** trong Chương 2. |

## 5. Quy Trình Làm Việc Với Google Antigravity

Trong [Google Antigravity](https://antigravity.google/), cách làm việc hiệu quả nhất cho dự án nhóm là kết hợp **Workspace Rules (`GEMINI.md`)** (để khóa chặt quy chuẩn kiến trúc giữa 2 thành viên) và lệnh **`/plan`** (để duyệt thiết kế trước khi AI sinh code).

### Bước 5.1: Tạo File `GEMINI.md` Ở Thư Mục Gốc Của Dự Án

Khi bạn tạo file `GEMINI.md` ở gốc repository và push lên GitHub, cả máy của bạn và máy của thành viên làm Backend khi mở [Antigravity Rules](https://antigravity.google/docs/rules/) đều sẽ tự động áp dụng chung một bộ quy tắc mà không cần nhắc lại trong từng câu chat:

```markdown
# Quy tắc dự án RC4 & TinyRC4 (GEMINI.md)

## 1. Mục tiêu và Ràng buộc Học thuật
- Dự án minh họa hệ mã dòng **TinyRC4** (3-bit, mảng S và T gồm 8 phần tử 0..7) và **RC4 đầy đủ** (8-bit, mảng S và T gồm 256 phần tử 0..255).
- **TUYỆT ĐỐI KHÔNG** sử dụng thư viện mật mã có sẵn (như `pycryptodome`, `cryptography`, `openssl`) bên trong `src/core/tiny_rc4.py` và `src/core/rc4.py`. Toàn bộ thuật toán KSA, PRGA và phép XOR phải cài đặt thuần Python từ đầu.
- Thư viện `Crypto.Cipher.ARC4` (từ `pycryptodome`) **CHỈ** được phép import trong `tests/` và `src/ui/tab_testing.py` để làm đối chứng kiểm thử.

## 2. Chuẩn Toán học TinyRC4 (Theo Slide Chương 2 - ĐH Kinh tế Quốc dân)
- Bảng chữ cái 3-bit cố định: `A=0 (000), B=1 (001), C=2 (010), D=3 (011), E=4 (100), F=5 (101), G=6 (110), H=7 (111)`.
- Giai đoạn KSA (TinyRC4):
  - `S = [0..7]`, `T[i] = K[i % len(K)]` với `i = 0..7`.
  - `j = 0`; lặp `i` từ `0` đến `7`: `j = (j + S[i] + T[i]) % 8`; hoán vị `S[i], S[j] = S[j], S[i]`.
- Giai đoạn PRGA (TinyRC4):
  - `i = 0, j = 0`. Với mỗi đơn vị 3-bit của bản rõ:
  - `i = (i + 1) % 8`; `j = (j + S[i]) % 8`; hoán vị `S[i], S[j] = S[j], S[i]`; `t = (S[i] + S[j]) % 8`; `k = S[t]`.
- Test vector bắt buộc phải khớp: `P = "BAG"` (`[1, 0, 6]`), `K = [2, 1, 3]` -> Mảng `S` sau KSA là `[6, 0, 7, 1, 2, 3, 5, 4]`, dòng khóa `k = [5, 1, 6]` (`101 001 110`), bản mã `C = "EBA"` (`[4, 1, 0]` hay `100 001 000`).

## 3. Phân tách Module (Architecture Boundaries)
- `src/core/` chỉ chứa thuật toán thuần Python và trả về dữ liệu theo `src/core/models.py`. Không import `nicegui` trong `src/core/`.
- `src/ui/` chỉ chứa giao diện NiceGUI, gọi hàm từ `src/core/` để hiển thị.
```

### Bước 5.2: Bộ 5 Lệnh `/plan` Copy-Paste Trực Tiếp Vào Antigravity

Theo tài liệu [Antigravity Plan (`/plan`)](https://antigravity.google/docs/plan/), thay vì yêu cầu viết tất cả cùng lúc, bạn hãy chạy tuần tự các lệnh `/plan` dưới đây. Sau mỗi bước, bấm **Proceed** để Antigravity thực thi, kiểm tra kết quả rồi commit lên GitHub.

#### Giai đoạn 1: Khởi tạo khung dự án, Hợp đồng dữ liệu (`models.py`) và Mock Backend (Bạn thực hiện)
```text
/plan Khởi tạo cấu trúc thư mục cho dự án RC4 theo quy tắc trong @GEMINI.md. Hãy tạo:
1. File requirements.txt (nicegui, pycryptodome, pytest) và file .gitignore chuẩn cho Python.
2. File src/core/models.py định nghĩa đầy đủ các dataclass: KSAStep, PRGAStep, TinyRC4Result, TestCaseComparison và từ điển TINY_ALPHABET (A=000 đến H=111).
3. Các file khung (stub/mock) trong src/core/tiny_rc4.py và src/core/rc4.py trả về dữ liệu mẫu của ví dụ P="BAG", K=[2,1,3] để tôi có thể phát triển và chạy thử giao diện NiceGUI ngay lập tức trước khi bạn cùng nhóm hoàn thiện phần Backend.
```

#### Giai đoạn 2: Xây dựng Khung Giao diện & Tab 1 (TinyRC4 Visualizer) (Bạn thực hiện)
```text
/plan Xây dựng giao diện chính trong main.py, src/ui/layout.py và Tab 1 trong src/ui/tab_tiny_rc4.py bằng thư viện NiceGUI. Yêu cầu:
1. Thiết kế Header chuyên nghiệp và thanh điều hướng gồm 5 tab: (1) TinyRC4 Step-by-Step, (2) RC4 256-byte & Mã hóa File, (3) Kiểm thử & Đối chiếu, (4) Tấn công & Hiệu năng, (5) Lý thuyết & So sánh.
2. Trong Tab 1 (tab_tiny_rc4.py):
   - Có ô nhập Bản rõ (chấp nhận chuỗi chữ A-H như "BAG" hoặc nhị phân 3-bit như "001 000 110") và ô nhập Khóa K (dãy số 0-7 cách nhau bởi dấu phẩy như "2, 1, 3").
   - Có nút "Nạp ví dụ chuẩn trên lớp (BAG | K=2,1,3)" và nút "Chuyển kết quả sang Giải mã".
   - Hiển thị rõ bảng quy đổi A..H -> 000..111, mảng S và T khởi tạo, bảng ui.table cho 8 bước KSA (i=0..7) và bảng ui.table cho từng bước sinh khóa PRGA + kết quả XOR.
```

#### Giai đoạn 3: Xây dựng Tab 2 (RC4 256-byte & Mã hóa File/Ảnh thật) (Bạn thực hiện)
```text
/plan Xây dựng Tab 2 trong src/ui/tab_full_rc4.py bằng NiceGUI để demo hệ mã RC4 đầy đủ (mảng S 256 byte) với 2 khu vực:
1. Khu vực Văn bản: Nhập văn bản UTF-8 và khóa K -> Mã hóa ra chuỗi Hex và Base64. Có nút "Giải mã ngược lại" để khôi phục văn bản gốc. Cho phép xem trạng thái ma trận S 256 byte (hiển thị dạng lưới 16x16) dưới dạng ui.expansion.
2. Khu vực Dữ liệu thật (File Văn bản & File Ảnh):
   - Sử dụng ui.upload để người dùng tải lên tệp .txt hoặc tệp ảnh (.png, .jpg) hoặc chọn tệp mẫu có sẵn trong thư mục sample_data/.
   - Khi bấm "Mã hóa File", hiển thị dung lượng (bytes), thời gian thực thi (ms), preview dữ liệu byte đã mã hóa và nút ui.download để tải file .rc4 về máy.
   - Khi bấm "Giải mã File", khôi phục lại đúng tệp ban đầu và hiển thị ảnh sau giải mã ngay cạnh ảnh gốc trên giao diện để chứng minh tính toàn vẹn.
```

#### Giai đoạn 4: Xây dựng Tab 3 (Kiểm thử), Tab 4 (Tấn công & Benchmark) và Tab 5 (Lý thuyết) (Bạn thực hiện)
```text
/plan Hoàn thiện 3 tab còn lại của giao diện NiceGUI:
1. src/ui/tab_testing.py (Tab 3): Tạo nút chạy tự động bộ kiểm thử gồm ví dụ TinyRC4 trên lớp, 3 test case tự viết, bộ test vector chuẩn RFC 6229 và đối chiếu trực tiếp với Crypto.Cipher.ARC4 của PyCryptodome. Hiển thị kết quả trên ui.table kèm badge PASS/FAIL.
2. src/ui/tab_attack_bench.py (Tab 4):
   - Phần 1: Mô phỏng tấn công dùng lại dòng khóa (Keystream Reuse / Two-Time Pad): Cho nhập 2 bản rõ P1, P2 dùng chung khóa K, hiển thị C1, C2 và C1 XOR C2 = P1 XOR P2, kèm ô nhập từ đoán trước (crib) để khôi phục bản rõ.
   - Phần 2: Đo thời gian chạy RC4 theo kích thước dữ liệu (10KB, 100KB, 500KB, 1MB) và vẽ biểu đồ trực quan bằng ui.echart.
3. src/ui/tab_theory.py (Tab 5): Viết tóm tắt ngắn gọn bối cảnh ra đời RC4 (Ron Rivest 1987, WEP, SSL/TLS, RFC 7465), vẽ sơ đồ khối KSA và PRGA bằng ui.mermaid (không dùng ảnh chụp slide), trình bày ví dụ tính tay P="BAG", K=[2,1,3] và bảng so sánh RC4 với hệ mã dòng A5/1 (TinyA5/1).
```

#### Giai đoạn 5: Prompt dành riêng cho Thành viên làm Backend (Gửi cho bạn cùng nhóm chạy trên Antigravity)
```text
/plan Hãy cài đặt đầy đủ thuật toán lõi từ đầu (không dùng thư viện mã hóa có sẵn) trong thư mục src/core/ và bộ kiểm thử trong tests/ tuân thủ chặt chẽ @GEMINI.md và các kiểu dữ liệu trong @src/core/models.py:
1. src/core/tiny_rc4.py: Cài đặt KSA và PRGA 3-bit (modulo 8), trả về đầy đủ TinyRC4Result. Đảm bảo đầu vào P="BAG" (001000110) và K=[2,1,3] cho ra mảng S sau KSA là [6, 0, 7, 1, 2, 3, 5, 4], dòng khóa [5, 1, 6] (101001110) và bản mã "EBA" (100001000), giải mã ngược lại ra "BAG".
2. src/core/rc4.py: Cài đặt KSA và PRGA 8-bit (modulo 256) hoạt động trên kiểu bytes cho cả văn bản UTF-8 và file nhị phân.
3. src/core/attack_demo.py và src/core/benchmark.py: Cài đặt hàm tính XOR hai bản mã (C1 ^ C2), hàm dò crib-dragging và hàm đo thời gian thực thi bằng time.perf_counter().
4. tests/test_rc4_core.py: Viết unit test bằng pytest kiểm tra TinyRC4, 3 ca kiểm thử tự chọn, test vector RFC 6229 và đối chiếu đầu ra với Crypto.Cipher.ARC4.
```

## 6. Chiến Lược Phân Nhánh & Lịch Sử Commit GitHub Cho Nhóm

Yêu cầu nộp bài nhấn mạnh: *"khuyến khích dùng GitHub và thể hiện được đóng góp của từng thành viên qua lịch sử commit"*. Để biểu đồ **Insights > Contributors** trên GitHub hiển thị đẹp và rõ ràng vai trò từng người, hai bạn nên tránh việc chỉ 1 người push toàn bộ code lên ở phút cuối. Hãy áp dụng lộ trình 10 bước commit sau:

| Thứ tự | Người thực hiện | Nhánh (Branch) | Nội dung Commit mẫu (Conventional Commits) | File thay đổi chính |
| :---: | :--- | :--- | :--- | :--- |
| **1** | **Bạn (FE)** | `main` | `chore: initialize repository structure, GEMINI.md rules and data contract` | `GEMINI.md`, `requirements.txt`, `src/core/models.py` |
| **2** | **Bạn (FE)** | `feat/ui-nicegui` | `feat(ui): create main NiceGUI layout, navigation tabs and mock adapters` | `main.py`, `src/ui/layout.py` |
| **3** | **Backend** | `feat/core-backend` | `feat(core): implement TinyRC4 3-bit KSA and PRGA with step tracing` | `src/core/tiny_rc4.py` |
| **4** | **Bạn (FE)** | `feat/ui-nicegui` | `feat(ui): build Tab 1 TinyRC4 step-by-step visualizer and classroom preset` | `src/ui/tab_tiny_rc4.py` |
| **5** | **Backend** | `feat/core-backend` | `feat(core): implement full 256-byte RC4 stream cipher for text and binary files` | `src/core/rc4.py` |
| **6** | **Bạn (FE)** | `feat/ui-nicegui` | `feat(ui): build Tab 2 full RC4 text, file and image encryption demo` | `src/ui/tab_full_rc4.py`, `sample_data/*` |
| **7** | **Backend** | `feat/core-backend` | `feat(core): add keystream reuse attack logic and performance benchmark` | `src/core/attack_demo.py`, `src/core/benchmark.py` |
| **8** | **Backend** | `feat/core-backend` | `test(core): add unit tests matching classroom slide, RFC 6229 and PyCryptodome` | `tests/test_rc4_core.py` |
| **9** | **Bạn (FE)** | `feat/ui-nicegui` | `feat(ui): add Tab 3 test runner, Tab 4 attack/benchmark charts and Tab 5 theory` | `src/ui/tab_testing.py`, `src/ui/tab_attack_bench.py`, `src/ui/tab_theory.py` |
| **10** | **Cả hai** | `main` | Tạo **Pull Request (PR)** từ `feat/core-backend` và `feat/ui-nicegui` vào `main`, review chéo cho nhau và cập nhật `README.md` | `README.md` |

## 7. Kịch Bản Chạy Demo 5–7 Phút Trên Lớp

Khi lên thuyết trình trực tiếp (hoặc quay video dự phòng 3–5 phút), bạn chỉ cần đi theo đúng thứ tự các Tab đã thiết kế:

1. **Phút 1 (Tab 5 – Lý thuyết & Sơ đồ khối)**: Giới thiệu nhanh nguyên lý mã dòng RC4, chỉ vào sơ đồ khối tự vẽ bằng Mermaid và điểm khác biệt với A5/1.
2. **Phút 2–3 (Tab 1 – TinyRC4 Step-by-Step)**: Bấm nút *"Nạp ví dụ chuẩn trên lớp (`P = BAG`, `K = 2, 1, 3`)"* $\rightarrow$ Đối chiếu trực tiếp mảng $S = [6, 0, 7, 1, 2, 3, 5, 4]$ sau bước `i = 7` và dòng khóa `101 001 110` cho ra bản mã `"EBA"`, sau đó bấm giải mã ngược lại về `"BAG"`.
3. **Phút 4 (Tab 2 – RC4 256-byte & Dữ liệu thật)**: Tải lên 1 bức ảnh `.png` hoặc file `.txt` $\rightarrow$ Mã hóa thành file `.rc4` $\rightarrow$ Giải mã ngược lại hiển thị bức ảnh nguyên vẹn trên giao diện.
4. **Phút 5 (Tab 3 – Kiểm thử & Đối chiếu)**: Bấm *"Chạy bộ kiểm thử"* để hiện loạt kết quả `PASS` khi đối chiếu với [RFC 6229](https://www.rfc-editor.org/info/rfc6229/) và [PyCryptodome ARC4](https://www.pycryptodome.org/src/cipher/arc4).
5. **Phút 6 (Tab 4 – Thực nghiệm Tấn công & Đo tốc độ)**: Trình diễn biểu đồ tốc độ mã hóa theo kích thước file và minh họa lỗ hổng khi dùng lại cùng một khóa $K$ cho hai bản tin khác nhau ($C_1 \oplus C_2 = P_1 \oplus P_2$).
