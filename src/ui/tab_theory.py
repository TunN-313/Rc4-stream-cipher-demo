"""
Tab 5: Tổng Quan Lý Thuyết, Sơ Đồ Khối Mermaid & So Sánh Hệ Mã A5/1
===================================================================
Trình bày súc tích trong 1 tab duy nhất:
  1. Bối cảnh ra đời, ứng dụng và lỗ hổng bảo mật (RFC 7465)
  2. Sơ đồ khối KSA & PRGA tự vẽ bằng mã Mermaid (không dùng ảnh chụp)
  3. Bảng phân tích chi tiết ví dụ tính tay P="BAG", K=[2, 1, 3]
  4. Bảng so sánh chuyên sâu giữa RC4 và A5/1 (GSM)
"""

from __future__ import annotations
from nicegui import ui


def build_tab_theory() -> None:
    """Xây dựng giao diện Tab 5: Lý thuyết, sơ đồ khối & so sánh A5/1."""
    with ui.card().classes("w-full p-6 shadow-sm"):
        ui.markdown(
            """
### 1. Bối Cảnh Lịch Sử & Ứng Dụng Thực Tế
* **Tác giả & Năm công bố**: Thuật toán được thiết kế bởi **Ron Rivest** (chữ R trong hệ mã bất đối xứng RSA) tại hãng RSA Security vào năm **1987**. Ban đầu RC4 là bí mật thương mại độc quyền, đến tháng 9/1994, mã nguồn thuật toán bị rò rỉ ẩn danh lên danh sách thư *Cypherpunks*.
* **Vị thế lịch sử**: RC4 từng là hệ mã dòng thông dụng nhất thế giới, được tích hợp trong các tiêu chuẩn mạng phổ biến:
  - Giao thức bảo mật mạng không dây Wi-Fi: **WEP (Wired Equivalent Privacy)** và **WPA (TKIP)**.
  - Giao thức an toàn tầng truyền vận: **SSL 3.0 / TLS 1.0 - 1.2** giữa trình duyệt Web và máy chủ.
  - Mã hóa tài liệu PDF và xác thực mạng Microsoft Windows (Kerberos).
* **Lý do bị cấm sử dụng (RFC 7465)**:
  - RC4 có **thiên lệch thống kê (biases)** ở các byte đầu tiên của dòng khóa (nổi tiếng nhất là tấn công FMS trên WEP, tấn công Bar-Mitzvah và NOMORE trên HTTPS).
  - Tháng 2/2015, nhóm kỹ sư Internet Engineering Task Force (IETF) chính thức ban hành **[RFC 7465](https://www.rfc-editor.org/info/rfc7465)** nghiêm cấm mọi việc sử dụng RC4 trong các bộ mã hóa TLS. Hiện nay, các hệ mã dòng hiện đại như **ChaCha20** và mã khối chế độ dòng như **AES-GCM** đã thay thế hoàn toàn RC4.

---

### 2. Sơ Đồ Khối Thuật Toán RC4 (Nhóm Tự Thiết Kế Bằng Mermaid)
            """
        )

        ui.mermaid(
            """
flowchart LR
    subgraph KSA["1. Giai đoạn Khởi tạo Dãy Hoán vị (KSA)"]
        direction TB
        K[Khóa bí mật K<br/>1..256 byte] --> InitS["Khởi tạo S = [0, 1, ..., 255]<br/>Khởi tạo T[i] = K[i mod len(K)]"]
        InitS --> LoopKSA["Lặp i từ 0 đến 255:<br/>j = (j + S[i] + T[i]) mod 256<br/>Swap(S[i], S[j])"]
        LoopKSA --> StateS[("Mảng trạng thái S<br/>đã xáo trộn hoàn toàn")]
    end

    subgraph PRGA["2. Giai đoạn Sinh Dòng Khóa (PRGA) & Mã Hóa"]
        direction TB
        StateS --> LoopPRGA["Với mỗi byte bản rõ:<br/>i = (i + 1) mod 256<br/>j = (j + S[i]) mod 256<br/>Swap(S[i], S[j])<br/>t = (S[i] + S[j]) mod 256"]
        LoopPRGA --> GenK["Dòng khóa: k = S[t]"]
        GenK --> XOR((Phép XOR ⊕))
        PT[Bản rõ P] --> XOR
        XOR --> CT[Bản mã C = P ⊕ k]
    end

    classDef ksa fill:#eff6ff,stroke:#1d4ed8,stroke-width:1.5px;
    classDef prga fill:#f0fdf4,stroke:#15803d,stroke-width:1.5px;
    class KSA ksa;
    class PRGA prga;
"""
        ).classes("w-full my-4")

        ui.markdown(
            """
---

### 3. Ví Dụ Tính Tay Chi Tiết: $P = \\text{\"BAG\"}$, $K = [2, 1, 3]$ (Slide 56–60)
* **Bảng chữ cái 3-bit**: $A=000(0), B=001(1), C=010(2), D=011(3), E=100(4), F=101(5), G=110(6), H=111(7)$.
* **Bản rõ**: $P = \\text{\"BAG\"} \\to [1, 0, 6]$ (nhị phân: `001 000 110`).
* **Khóa bí mật**: $K = [2, 1, 3]$ ($N=3$).
* **Mảng $T$ 8 phần tử lặp lại**: $T = [2, 1, 3, 2, 1, 3, 2, 1]$.
* **Giai đoạn KSA (8 bước $i=0..7$, khởi đầu $j=0$ và $S=[0,1,2,3,4,5,6,7]$)**:
  - $i=0: j = (0 + 0 + 2) \\pmod 8 = 2 \\to \\text{Swap}(S[0], S[2]) \\to S = [2, 1, 0, 3, 4, 5, 6, 7]$
  - $i=1: j = (2 + 1 + 1) \\pmod 8 = 4 \\to \\text{Swap}(S[1], S[4]) \\to S = [2, 4, 0, 3, 1, 5, 6, 7]$
  - $i=2: j = (4 + 0 + 3) \\pmod 8 = 7 \\to \\text{Swap}(S[2], S[7]) \\to S = [2, 4, 7, 3, 1, 5, 6, 0]$
  - $i=3: j = (7 + 3 + 2) \\pmod 8 = 4 \\to \\text{Swap}(S[3], S[4]) \\to S = [2, 4, 7, 1, 3, 5, 6, 0]$
  - $i=4: j = (4 + 3 + 1) \\pmod 8 = 0 \\to \\text{Swap}(S[4], S[0]) \\to S = [3, 4, 7, 1, 2, 5, 6, 0]$
  - $i=5: j = (0 + 5 + 3) \\pmod 8 = 0 \\to \\text{Swap}(S[5], S[0]) \\to S = [5, 4, 7, 1, 2, 3, 6, 0]$
  - $i=6: j = (0 + 6 + 2) \\pmod 8 = 0 \\to \\text{Swap}(S[6], S[0]) \\to S = [6, 4, 7, 1, 2, 3, 5, 0]$
  - $i=7: j = (0 + 0 + 1) \\pmod 8 = 1 \\to \\text{Swap}(S[7], S[1]) \\to S = [6, 0, 7, 1, 2, 3, 5, 4]$
  - $\\implies$ **Mảng $S$ sau KSA**: $[6, 0, 7, 1, 2, 3, 5, 4]$.
* **Giai đoạn PRGA & XOR**:
  - $p_0 = 1$ ('B'): $i=1, j=(0+0)=0 \\to \\text{Swap}(S[1], S[0]) \\to S=[0, 6, 7, 1, 2, 3, 5, 4]$. $t=(6+0)=6 \\to k_0=S[6]=5$ (`101`). $c_0 = 1 \\oplus 5 = 4$ (`100` - chữ 'E').
  - $p_1 = 0$ ('A'): $i=2, j=(0+7)=7 \\to \\text{Swap}(S[2], S[7]) \\to S=[0, 6, 4, 1, 2, 3, 5, 7]$. $t=(4+7)=3 \\to k_1=S[3]=1$ (`001`). $c_1 = 0 \\oplus 1 = 1$ (`001` - chữ 'B').
  - $p_2 = 6$ ('G'): $i=3, j=(7+1)=0 \\to \\text{Swap}(S[3], S[0]) \\to S=[1, 6, 4, 0, 2, 3, 5, 7]$. $t=(0+1)=1 \\to k_2=S[1]=6$ (`110`). $c_2 = 6 \\oplus 6 = 0$ (`000` - chữ 'A').
* **Kết quả**: Dòng khóa $k = [5, 1, 6]$ (`101 001 110`), Bản mã $C = \\text{\"EBA\"}$ (`100 001 000`).

---

### 4. So Sánh RC4 Với Hệ Mã Dòng A5/1 (Chương 2)

| Tiêu Chí So Sánh | Hệ Mã Dòng RC4 / TinyRC4 | Hệ Mã Dòng A5/1 / TinyA5/1 |
| :--- | :--- | :--- |
| **Đơn vị xử lý** | Theo **Byte (8-bit)** (TinyRC4: 3-bit) | Theo từng **Bit đơn lẻ (1-bit)** |
| **Cấu trúc sinh số** | Mảng hoán vị trạng thái $S$ gồm **256 phần tử** ($256! \\approx 2^{1684}$ trạng thái) | **3 thanh ghi dịch hồi tiếp tuyến tính (LFSR)** có độ dài 19, 22, 23 bit (tổng 64 bit) |
| **Cơ chế điều khiển** | Hoán vị hai con trỏ chỉ số $(i, j)$ theo modulo cộng | Điều khiển xung nhịp không đều bằng **hàm chiếm đa số (Majority function - `maj`)** |
| **Hiệu năng phần mềm (CPU)** | **Rất nhanh**, tối ưu tuyệt đối trên kiến trúc bộ nhớ RAM và thanh ghi byte | Chậm hơn trên CPU đa năng do phải xử lý từng phép shift bit |
| **Hiệu năng phần cứng** | Tốn kém bộ nhớ RAM để lưu mảng $S$ (256 byte) | **Cực kỳ nhỏ gọn**, chỉ cần vài chục cổng Flip-Flop logic và XOR |
| **Lĩnh vực áp dụng** | Giao thức Web **SSL/TLS**, kết nối mạng **WEP/WPA** | Bảo vệ đàm thoại mạng di động **GSM (2G)** |
| **Tình trạng thám mã** | Bị cấm bởi RFC 7465 do thiên lệch thống kê byte đầu | Bị phá vỡ bằng tấn công Time-Memory Tradeoff (Rainbow Tables) |
"""
        )
