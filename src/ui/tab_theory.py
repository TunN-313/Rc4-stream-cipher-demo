"""
Tab 5: Tổng Quan Lý Thuyết, Sơ Đồ Khối Mermaid & So Sánh Hệ Mã A5/1
===================================================================
Trình bày súc tích trong 1 tab duy nhất:
  1. Bối cảnh ra đời, ứng dụng và lỗ hổng bảo mật (RFC 7465)
  2. Sơ đồ khối KSA & PRGA tự vẽ bằng mã Mermaid (không dùng ảnh chụp)
  3. Bảng phân tích chi tiết ví dụ tính tay P="BAG", K=[2, 1, 3] (hỗ trợ KaTeX Math)
  4. Bảng so sánh chuyên sâu giữa RC4 và A5/1 (GSM)
"""

from __future__ import annotations
from nicegui import ui


def build_tab_theory() -> None:
    """Xây dựng giao diện Tab 5: Lý thuyết, sơ đồ khối & so sánh A5/1."""
    with ui.card().classes("w-full p-6 shadow-sm"):
        ui.markdown(
            r"""
### 1. Bối Cảnh Lịch Sử & Ứng Dụng Thực Tế
* **Tác giả & Năm công bố**: Thuật toán được thiết kế bởi **Ron Rivest** (chữ **R** trong hệ mã bất đối xứng RSA) tại hãng RSA Security vào năm **1987**. Ban đầu RC4 là bí mật thương mại độc quyền, đến tháng 9/1994, mã nguồn thuật toán bị rò rỉ ẩn danh lên danh sách thư *Cypherpunks*.
* **Vị thế lịch sử**: RC4 từng là hệ mã dòng thông dụng nhất thế giới, được tích hợp trong các tiêu chuẩn mạng phổ biến:
  - Giao thức bảo mật mạng không dây Wi-Fi: **WEP (Wired Equivalent Privacy)** và **WPA (TKIP)**.
  - Giao thức an toàn tầng truyền vận: **SSL 3.0 / TLS 1.0 – 1.2** giữa trình duyệt Web và máy chủ.
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
            r"""
---

### 3. Ví Dụ Tính Tay Chi Tiết: $P = \text{BAG}$, $K = [2, 1, 3]$ (Slide 56–60)

* **Bảng chữ cái 3-bit**: $A=000(0)$, $B=001(1)$, $C=010(2)$, $D=011(3)$, $E=100(4)$, $F=101(5)$, $G=110(6)$, $H=111(7)$.
* **Bản rõ đầu vào**: $P = \text{BAG} \implies [1, 0, 6]$ (biểu diễn nhị phân: $\texttt{001 000 110}$).
* **Khóa bí mật**: $K = [2, 1, 3]$ với độ dài $N = 3$.
* **Mảng $T$ 8 phần tử lặp lại**: $T = [2, 1, 3, 2, 1, 3, 2, 1]$.

#### A. Giai đoạn Khởi tạo Dãy S (KSA — 8 bước từ $i=0$ đến $i=7$):
*Khởi tạo ban đầu:* $S = [0, 1, 2, 3, 4, 5, 6, 7]$ và $j = 0$. Công thức: $j = (j + S[i] + T[i]) \pmod{8}$:
* $i=0$: $j = (0 + S[0] + T[0]) \pmod{8} = (0 + 0 + 2) \pmod{8} = 2 \implies \text{Swap}(S[0], S[2]) \implies S = [2, 1, 0, 3, 4, 5, 6, 7]$
* $i=1$: $j = (2 + S[1] + T[1]) \pmod{8} = (2 + 1 + 1) \pmod{8} = 4 \implies \text{Swap}(S[1], S[4]) \implies S = [2, 4, 0, 3, 1, 5, 6, 7]$
* $i=2$: $j = (4 + S[2] + T[2]) \pmod{8} = (4 + 0 + 3) \pmod{8} = 7 \implies \text{Swap}(S[2], S[7]) \implies S = [2, 4, 7, 3, 1, 5, 6, 0]$
* $i=3$: $j = (7 + S[3] + T[3]) \pmod{8} = (7 + 3 + 2) \pmod{8} = 4 \implies \text{Swap}(S[3], S[4]) \implies S = [2, 4, 7, 1, 3, 5, 6, 0]$
* $i=4$: $j = (4 + S[4] + T[4]) \pmod{8} = (4 + 3 + 1) \pmod{8} = 0 \implies \text{Swap}(S[4], S[0]) \implies S = [3, 4, 7, 1, 2, 5, 6, 0]$
* $i=5$: $j = (0 + S[5] + T[5]) \pmod{8} = (0 + 5 + 3) \pmod{8} = 0 \implies \text{Swap}(S[5], S[0]) \implies S = [5, 4, 7, 1, 2, 3, 6, 0]$
* $i=6$: $j = (0 + S[6] + T[6]) \pmod{8} = (0 + 6 + 2) \pmod{8} = 0 \implies \text{Swap}(S[6], S[0]) \implies S = [6, 4, 7, 1, 2, 3, 5, 0]$
* $i=7$: $j = (0 + S[7] + T[7]) \pmod{8} = (0 + 0 + 1) \pmod{8} = 1 \implies \text{Swap}(S[7], S[1]) \implies S = [6, 0, 7, 1, 2, 3, 5, 4]$

$$\implies \mathbf{S_{\text{KSA}}} = [6, 0, 7, 1, 2, 3, 5, 4]$$

#### B. Giai đoạn Sinh số (PRGA) & Mã hóa XOR:
*Khởi tạo ban đầu:* $i = 0, j = 0$:
* **Bước 1** (Mã hóa ký tự $p_0 = 1$ hay 'B'):
  - $i = (0 + 1) \pmod{8} = 1$
  - $j = (0 + S[1]) \pmod{8} = (0 + 0) \pmod{8} = 0$
  - $\text{Swap}(S[1], S[0]) \implies S = [0, 6, 7, 1, 2, 3, 5, 4]$
  - $t = (S[1] + S[0]) \pmod{8} = (6 + 0) \pmod{8} = 6 \implies k_0 = S[6] = 5$ ($\texttt{101}$)
  - Bản mã: $c_0 = p_0 \oplus k_0 = 1 \oplus 5 = 4$ ($\texttt{100}$, tương ứng ký tự **'E'**)
* **Bước 2** (Mã hóa ký tự $p_1 = 0$ hay 'A'):
  - $i = (1 + 1) \pmod{8} = 2$
  - $j = (0 + S[2]) \pmod{8} = (0 + 7) \pmod{8} = 7$
  - $\text{Swap}(S[2], S[7]) \implies S = [0, 6, 4, 1, 2, 3, 5, 7]$
  - $t = (S[2] + S[7]) \pmod{8} = (4 + 7) \pmod{8} = 3 \implies k_1 = S[3] = 1$ ($\texttt{001}$)
  - Bản mã: $c_1 = p_1 \oplus k_1 = 0 \oplus 1 = 1$ ($\texttt{001}$, tương ứng ký tự **'B'**)
* **Bước 3** (Mã hóa ký tự $p_2 = 6$ hay 'G'):
  - $i = (2 + 1) \pmod{8} = 3$
  - $j = (7 + S[3]) \pmod{8} = (7 + 1) \pmod{8} = 0$
  - $\text{Swap}(S[3], S[0]) \implies S = [1, 6, 4, 0, 2, 3, 5, 7]$
  - $t = (S[3] + S[0]) \pmod{8} = (0 + 1) \pmod{8} = 1 \implies k_2 = S[1] = 6$ ($\texttt{110}$)
  - Bản mã: $c_2 = p_2 \oplus k_2 = 6 \oplus 6 = 0$ ($\texttt{000}$, tương ứng ký tự **'A'**)

**KẾT LUẬN VÍ DỤ TRÊN LỚP:**
* Dòng khóa sinh ra: $k = [5, 1, 6]$ ($\texttt{101 001 110}$)
* Bản mã thu được: $C = \text{EBA}$ ($\texttt{100 001 000}$)
* Quá trình giải mã đối xứng: $C \oplus k = [4, 1, 0] \oplus [5, 1, 6] = [1, 0, 6] \implies P = \text{BAG}$.

---

### 4. So Sánh RC4 Với Hệ Mã Dòng A5/1 (Chương 2)

| Tiêu Chí So Sánh | Hệ Mã Dòng RC4 / TinyRC4 | Hệ Mã Dòng A5/1 / TinyA5/1 |
| :--- | :--- | :--- |
| **Đơn vị xử lý** | Theo **Byte (8-bit)** (TinyRC4: 3-bit) | Theo từng **Bit đơn lẻ (1-bit)** |
| **Cấu trúc sinh số** | Mảng hoán vị trạng thái $S$ gồm **256 phần tử** ($256! \approx 2^{1684}$ trạng thái) | **3 thanh ghi dịch hồi tiếp tuyến tính (LFSR)** có độ dài 19, 22, 23 bit (tổng 64 bit) |
| **Cơ chế điều khiển** | Hoán vị hai con trỏ chỉ số $(i, j)$ theo modulo cộng | Điều khiển xung nhịp không đều bằng **hàm chiếm đa số ($\text{maj}(x, y, z)$)** |
| **Hiệu năng phần mềm (CPU)** | **Rất nhanh**, tối ưu tuyệt đối trên kiến trúc bộ nhớ RAM và thanh ghi byte | Chậm hơn trên CPU đa năng do phải xử lý từng phép shift bit |
| **Hiệu năng phần cứng** | Tốn kém bộ nhớ RAM để lưu mảng $S$ (256 byte) | **Cực kỳ nhỏ gọn**, chỉ cần vài chục cổng Flip-Flop logic và XOR |
| **Lĩnh vực áp dụng** | Giao thức Web **SSL/TLS**, kết nối mạng **WEP/WPA** | Bảo vệ đàm thoại mạng di động **GSM (2G)** |
| **Tình trạng thám mã** | Bị cấm bởi RFC 7465 do thiên lệch thống kê byte đầu | Bị phá vỡ bằng tấn công Time-Memory Tradeoff (Rainbow Tables) |
"""
        )
