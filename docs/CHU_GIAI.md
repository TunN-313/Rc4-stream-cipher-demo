# BẢNG CHÚ GIẢI THUẬT NGỮ, THƯ VIỆN VÀ BẢN ĐỒ HÀM (RC4 LAB)

Tài liệu này cung cấp 3 bảng tra cứu nhanh phục vụ thuyết trình và tìm hiểu mã nguồn dự án RC4 Lab.
Để nắm bắt hệ thống dễ dàng nhất, bạn nên đọc mã nguồn theo thứ tự từ tầng thuật toán cốt lõi (`src/core/`) lên tầng giao diện người dùng (`src/ui/`).
Các thuật ngữ và thư viện trong tài liệu bám sát mã nguồn thực tế và được giải thích bằng ngôn ngữ đời thường dành cho sinh viên thương mại điện tử.

---

## Bảng 1 – Thuật ngữ mật mã

| Thuật ngữ | Nghĩa đời thường một câu | Ví dụ ngắn |
| :--- | :--- | :--- |
| **KSA** *(Key Scheduling Algorithm)* | Thuật toán xáo trộn một bộ bài theo quy luật của chìa khóa trước khi chia bài. | Khởi tạo mảng số từ 0 đến 255 rồi dùng mật khẩu để hoán đổi vị trí các phần tử. |
| **PRGA** *(Pseudo-Random Generation Algorithm)* | Cỗ máy tự động rút liên tục từng lá bài ngẫu nhiên để làm chìa khóa mã hóa từng chữ cái. | Rút ra dãy số `[5, 1, 6]` từ mảng đã xáo trộn để chuẩn bị ghép đôi với văn bản. |
| **S-box** *(Substitution Box)* | Một mảng nhớ chứa các con số hoán vị đóng vai trò như chiếc hộp xáo trộn dữ liệu bí mật. | Mảng gồm 256 số nguyên từ 0 đến 255 liên tục bị tráo vị trí trong suốt quá trình chạy. |
| **Keystream** *(Dòng khóa)* | Chuỗi ký tự ngẫu nhiên tuôn ra vô tận dùng để cộng dồn vào văn bản gốc để tạo ra bản mã. | Bản rõ là `BAG`, dòng khóa sinh ra là `[5, 1, 6]`, ghép lại tạo thành bản mã `EBA`. |
| **XOR** *(Phép loại trừ $\oplus$)* | Phép cộng nhị phân đặc biệt: 2 bit giống nhau ra 0, khác nhau ra 1, lặp lại 2 lần là về chỗ cũ. | $1 \oplus 1 = 0$; chữ cái 'A' đem XOR với khóa ra 'X', lấy 'X' đem XOR với khóa lại ra 'A'. |
| **Modulo** *(Phép chia lấy dư)* | Kim đồng hồ chạy hết 12 tiếng thì quay về số 1, giúp các phép toán không bao giờ tràn khỏi giới hạn. | Trong TinyRC4 lấy modulo 8: số 10 chia cho 8 dư 2, ta chỉ lấy giá trị 2. |
| **Mã dòng** *(Stream Cipher)* | Kiểu mã hóa từng ký tự một ngay khi nó vừa xuất hiện thay vì đợi gom đủ cả một khối lớn. | Giống như bảo vệ đóng dấu kiểm dịch lên từng kiện hàng đang trôi trên băng chuyền. |
| **TinyRC4** | Phiên bản RC4 thu nhỏ chỉ dùng 8 số (0–7) để sinh viên dễ dàng tính tay từng bước trên giấy. | Bảng chữ cái chỉ có 8 chữ từ A đến H; mã hóa từ `BAG` với khóa `[2, 1, 3]` ra chữ `EBA`. |
| **Two-Time Pad** | Lỗi chí mạng khi dùng chung một dòng khóa để bảo mật hai bức thư khác nhau, khiến dòng khóa biến mất. | Lấy bản mã 1 XOR với bản mã 2 thì dòng khóa bị triệt tiêu, chỉ còn lại hai bản rõ lồng vào nhau. |
| **Crib-dragging** | Kỹ thuật đoán mò một từ quen thuộc rồi trượt dọc theo bản tin để lôi ra bí mật của bức thư thứ hai. | Đoán trong thư có chữ "Chuyen khoan", trượt dần từng vị trí để khôi phục mật mã OTP bên kia. |
| **Thiên lệch** *(Bias)* | Hiện tượng một giá trị xuất hiện nhiều hơn bình thường do lỗi thiết kế của cỗ máy sinh số. | Tung đồng xu mà mặt ngửa ra tới 70%; byte thứ 2 của RC4 bằng số 0 với xác suất gấp đôi bình thường. |
| **RFC 6229** | Văn bản tiêu chuẩn kỹ thuật quốc tế công bố đáp án mẫu để các lập trình viên so sánh kiểm tra code. | Bộ đề thi mẫu có sẵn đáp án để kiểm tra xem thuật toán RC4 tự viết có khớp 100% chuẩn toàn cầu. |
| **SHA-256** | Cỗ máy băm văn bản thành một dấu vân tay số cố định 64 ký tự, sửa một dấu phẩy là đổi toàn bộ. | Kiểm tra file ảnh gốc và file ảnh đã mã hóa: chỉ cần băm ra mã SHA-256 là biết có toàn vẹn hay không. |

---

## Bảng 2 – Thư viện và module

| Tên thư viện / module | Loại | Dùng để làm gì | Dùng ở file nào |
| :--- | :--- | :--- | :--- |
| `__future__` | Thư viện chuẩn của Python | Bật tính năng chú thích kiểu dữ liệu mở rộng cho các phiên bản Python mới | Mọi file trong `src/core/` và `src/ui/` |
| `asyncio` | Thư viện chuẩn của Python | Chạy các tác vụ tốn thời gian ở chế độ nền để giao diện web không bị đơ hoặc treo | `src/ui/file_pipeline.py`, `src/ui/tab_attack_bench.py` |
| `base64` | Thư viện chuẩn của Python | Chuyển đổi dữ liệu nhị phân hoặc ảnh sang chuỗi ký tự chữ-số để nhúng trực tiếp vào web | `src/core/models.py`, `src/ui/file_pipeline.py` |
| `dataclasses` | Thư viện chuẩn của Python | Định nghĩa các lớp chứa dữ liệu rõ ràng, tự động tạo các hàm so sánh và lưu trữ | `src/core/models.py` |
| `hashlib` | Thư viện chuẩn của Python | Tính toán mã băm SHA-256 đóng vai trò làm dấu vân tay kiểm tra tính toàn vẹn của tệp | `src/ui/file_pipeline.py` |
| `html` | Thư viện chuẩn của Python | Chuyển các ký tự đặc biệt thành chuỗi an toàn để hiển thị trên trang web không bị lỗi | `src/ui/tab_attack_bench.py` |
| `inspect` | Thư viện chuẩn của Python | Kiểm tra tính chất của hàm xem đó là hàm thường hay hàm bất đồng bộ (coroutine) | `src/ui/file_pipeline.py` |
| `io` | Thư viện chuẩn của Python | Tạo luồng dữ liệu byte trong bộ nhớ tạm (BytesIO) để thao tác tệp ảnh mà không cần ghi xuống đĩa | `src/ui/file_pipeline.py` |
| `math` | Thư viện chuẩn của Python | Cung cấp hàm căn bậc hai số nguyên (isqrt) để tính kích thước ma trận ảnh vuông | `src/ui/file_pipeline.py` |
| `pathlib` | Thư viện chuẩn của Python | Thao tác và quản lý đường dẫn tệp tin, thư mục tương thích trên cả Windows và Linux | `main.py`, `src/ui/file_pipeline.py` |
| `random` | Thư viện chuẩn của Python | Sinh các số ngẫu nhiên phục vụ tạo khóa giả lập trong bài thí nghiệm thiên lệch byte | `src/core/analysis.py`, `src/ui/tab_attack_bench.py` |
| `secrets` | Thư viện chuẩn của Python | Sinh ngẫu nhiên dữ liệu bảo mật cao đạt chuẩn mật mã (CSPRNG) dùng làm khóa bí mật thực sự | `src/core/keys.py` |
| `time` | Thư viện chuẩn của Python | Bấm giờ với độ chính xác cao (perf_counter) để đo thời gian mã hóa từng phần nghìn giây | `src/core/rc4.py`, `src/ui/file_pipeline.py` |
| `typing` | Thư viện chuẩn của Python | Định nghĩa gợi ý kiểu dữ liệu (List, Dict, Tuple, Optional) giúp code rõ ràng và ít lỗi | Hầu hết các file trong `src/core/` và `src/ui/` |
| `nicegui` | Thư viện ngoài cài bằng pip | Khung ứng dụng xây dựng giao diện người dùng web tương tác trực tiếp bằng thuần Python | `main.py` và toàn bộ các file trong `src/ui/` |
| `nicegui_tabulator` | Thư viện ngoài cài bằng pip | Thành phần mở rộng giúp hiển thị bảng dữ liệu Tabulator thông minh với bộ lọc và xuất file | `src/ui/layout.py`, `src/ui/tab_testing.py`, `src/ui/tab_attack_bench.py` |
| `PIL` *(Pillow)* | Thư viện ngoài cài bằng pip | Thư viện xử lý hình ảnh, đọc định dạng PNG/JPG và xuất hình ảnh nhiễu sau mã hóa | `src/ui/file_pipeline.py` |
| `src.core.models` | File nội bộ của dự án | Khai báo các đối tượng cấu trúc dữ liệu chung trao đổi giữa thuật toán và giao diện | `src/core/__init__.py`, `rc4.py`, `tiny_rc4.py`, `tab_testing.py`, `tab_tiny_rc4.py` |
| `src.core.tiny_rc4` | File nội bộ của dự án | Cài đặt toàn bộ thuật toán mô phỏng hệ mã dòng TinyRC4 3-bit thu nhỏ phục vụ học tập | `src/core/__init__.py`, `src/ui/tab_tiny_rc4.py`, `src/ui/tab_testing.py` |
| `src.core.rc4` | File nội bộ của dự án | Cài đặt thuật toán mã dòng RC4 chuẩn 8-bit (KSA và PRGA) thuần túy không dùng thư viện mật mã | `src/core/__init__.py`, `file_pipeline.py`, `tab_rc4_text.py`, `tab_testing.py` |
| `src.core.analysis` | File nội bộ của dự án | Gom các thuật toán nghiên cứu an toàn: thám mã Two-Time Pad, kiểm thử thiên lệch và đo tốc độ | `src/core/__init__.py`, `src/ui/tab_attack_bench.py` |
| `src.core.keys` | File nội bộ của dự án | Chứa các hàm tiện ích tạo khóa ngẫu nhiên, chuyển đổi khóa từ chuỗi văn bản và số Hex | `src/core/__init__.py`, `src/ui/file_pipeline.py`, `src/ui/tab_rc4_text.py` |
| `src.core.encoding` | File nội bộ của dự án | Chứa các hàm chuyển đổi qua lại giữa mảng byte, danh sách số nguyên và chuỗi Hexadecimal | `src/core/__init__.py`, `src/ui/file_pipeline.py`, `src/ui/tab_rc4_text.py` |
| `src.ui` | File nội bộ của dự án | Điểm khởi đầu gói giao diện, cung cấp hàm dựng layout chính cho ứng dụng | `main.py` |
| `src.ui.layout` | File nội bộ của dự án | Thiết lập bố cục tổng thể gồm thanh tiêu đề, menu thu phóng bên hông và bộ chuyển tab | `src/ui/__init__.py` |
| `src.ui.file_pipeline` | File nội bộ của dự án | Giao diện quy trình xử lý tệp tin và hình ảnh nhị phân qua 3 bước (Tải lên - Mã hóa - Tải về) | `src/ui/layout.py` |
| `src.ui.tab_tiny_rc4` | File nội bộ của dự án | Giao diện trực quan hóa từng bước thuật toán TinyRC4 3-bit với các nút điều khiển | `src/ui/layout.py` |
| `src.ui.tab_rc4_text` | File nội bộ của dự án | Giao diện mã hóa và giải mã văn bản tiếng Việt UTF-8 bằng RC4 8-bit chuẩn | `src/ui/layout.py` |
| `src.ui.tab_testing` | File nội bộ của dự án | Giao diện bộ kiểm thử tự động, chấm điểm đối chiếu kết quả với chuẩn RFC 6229 | `src/ui/layout.py` |
| `src.ui.tab_attack_bench` | File nội bộ của dự án | Giao diện thực nghiệm thám mã dùng lại khóa, đo hiệu năng ECharts và kiểm tra thiên lệch | `src/ui/layout.py` |
| `src.ui.tab_theory` | File nội bộ của dự án | Giao diện tài liệu lý thuyết, hiển thị sơ đồ khối Mermaid tự vẽ và bảng đối chiếu A5/1 | `src/ui/layout.py` |

---

## Bảng 3 – Bản đồ hàm

| Tên hàm | File | Làm gì (một câu) |
| :--- | :--- | :--- |
| `score_readable` | `src/core/analysis.py` | Tính điểm khả tín của văn bản khôi phục dựa trên tỷ lệ phần trăm các ký tự chữ cái và số đọc được. |
| `simulate_keystream_reuse_attack` | `src/core/analysis.py` | Giả lập tấn công dùng lại dòng khóa (Two-Time Pad) và tự động thám mã bằng kỹ thuật trượt từ đoán trước (crib-dragging). |
| `keystream_bias_counts` | `src/core/analysis.py` | Đếm tần suất xuất hiện của 256 giá trị byte tại một vị trí xác định qua hàng nghìn khóa để đo thiên lệch Mantin-Shamir. |
| `run_rc4_benchmark` | `src/core/analysis.py` | Đo thời gian mã hóa (ms) và tính tốc độ xử lý (MB/s) của thuật toán RC4 trên nhiều kích cỡ tệp từ 1 KB đến 1 MB. |
| `bytes_sang_so` | `src/core/encoding.py` | Chuyển đổi một chuỗi byte nhị phân thành danh sách các số nguyên tương ứng từ 0 đến 255. |
| `so_sang_bytes` | `src/core/encoding.py` | Chuyển đổi danh sách các số nguyên từ 0 đến 255 thành chuỗi byte nhị phân gốc. |
| `bytes_sang_hex` | `src/core/encoding.py` | Đổi chuỗi byte nhị phân thành chuỗi ký tự hệ cơ số 16 (Hexadecimal) viết hoa để người dùng dễ quan sát. |
| `hex_sang_bytes` | `src/core/encoding.py` | Chuyển đổi ngược lại từ chuỗi ký tự Hexadecimal thành chuỗi byte nhị phân chuẩn. |
| `sinh_khoa_rc4` | `src/core/keys.py` | Tạo ngẫu nhiên một khóa bí mật an toàn với độ dài byte tùy chọn cho thuật toán RC4 8-bit. |
| `khoa_tu_chuoi` | `src/core/keys.py` | Chuyển một chuỗi ký tự văn bản thường (UTF-8) do người dùng nhập thành chuỗi byte làm khóa mã hóa. |
| `khoa_tu_hex` | `src/core/keys.py` | Chuyển một chuỗi ký tự dạng Hexadecimal thành chuỗi byte làm khóa mã hóa. |
| `sinh_khoa_tiny` | `src/core/keys.py` | Tạo ngẫu nhiên một khóa gồm các số nguyên từ 0 đến 7 với độ dài theo yêu cầu cho mô hình TinyRC4. |
| `rc4_ksa` | `src/core/rc4.py` | Chạy thuật toán xáo trộn khóa KSA để khởi tạo mảng hoán vị trạng thái S gồm 256 phần tử. |
| `rc4_crypt_chunks` | `src/core/rc4.py` | Vòng lặp PRGA sinh dòng khóa và mã hóa dữ liệu theo từng khối byte nhỏ (generator) giúp không bị đầy bộ nhớ. |
| `rc4_crypt` | `src/core/rc4.py` | Thực hiện mã hóa hoặc giải mã đối xứng toàn bộ khối dữ liệu bằng thuật toán RC4 chuẩn. |
| `rc4_crypt_with_details` | `src/core/rc4.py` | Mã hóa văn bản và trả về kết quả chi tiết gồm bản mã, thời gian đo được, mảng S sau KSA và dòng khóa mẫu. |
| `parse_tiny_input` | `src/core/tiny_rc4.py` | Phân tích và chuyển đổi chuỗi chữ cái A–H hoặc số nhập vào thành danh sách các số 3-bit từ 0 đến 7. |
| `parse_tiny_key` | `src/core/tiny_rc4.py` | Chuẩn hóa khóa người dùng nhập thành danh sách các số nguyên từ 0 đến 7 cho mô hình TinyRC4. |
| `run_tiny_rc4` | `src/core/tiny_rc4.py` | Thực thi toàn bộ quy trình KSA và PRGA của TinyRC4, lưu lại vết từng bước hoán vị để minh họa trên lớp. |
| `build_file_pipeline` | `src/ui/file_pipeline.py` | Dựng giao diện quy trình 3 bước xử lý tải lên, mã hóa nhị phân và tải về cho file và tệp hình ảnh. |
| `build_nicegui_interface` | `src/ui/layout.py` | Dựng toàn bộ khung sườn ứng dụng web gồm thanh tiêu đề, menu bên hông có hiệu ứng mở rộng và các tab nội dung. |
| `build_comparison_strip_html` | `src/ui/tab_attack_bench.py` | Tạo mã HTML dải màu trực quan so sánh vị trí tương ứng giữa hai bản rõ khi thực hiện thám mã. |
| `build_tab_attack_bench` | `src/ui/tab_attack_bench.py` | Dựng giao diện Tab 4: Thám mã Two-Time Pad bằng crib-dragging, đo tốc độ xử lý ECharts và kiểm chứng thiên lệch dòng khóa. |
| `build_tab_rc4_text` | `src/ui/tab_rc4_text.py` | Dựng giao diện Tab 2: Mã hóa và giải mã chuỗi văn bản tiếng Việt UTF-8 bằng RC4 8-bit chuẩn. |
| `build_tab_testing` | `src/ui/tab_testing.py` | Dựng giao diện Tab 3: Bảng kiểm thử tự động đối chiếu kết quả mã hóa với các test vector chuẩn quốc tế RFC 6229. |
| `build_tab_theory` | `src/ui/tab_theory.py` | Dựng giao diện Tab 5: Trình bày kiến thức lịch sử, sơ đồ khối thuật toán tự vẽ bằng Mermaid và bảng so sánh với A5/1. |
| `build_tab_tiny_rc4` | `src/ui/tab_tiny_rc4.py` | Dựng giao diện Tab 1: Trực quan hóa chi tiết từng bước hoán vị KSA và PRGA của thuật toán mô phỏng TinyRC4 3-bit. |
