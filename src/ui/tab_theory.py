"""
Tab 5: Tổng Quan Lý Thuyết, Sơ Đồ Khối Mermaid & So Sánh Hệ Mã A5/1
===================================================================
Trình bày súc tích trong 1 tab duy nhất:
  1. Bối cảnh ra đời, ứng dụng và lỗ hổng bảo mật (RFC 7465)
  2. Sơ đồ khối KSA & PRGA tự vẽ bằng mã Mermaid (không dùng ảnh chụp)
  3. Bảng phân tích chi tiết ví dụ tính tay P="BAG", K=[2, 1, 3] (dạng bảng Markdown chuẩn)
  4. Bảng so sánh chuyên sâu giữa RC4 và A5/1 (GSM)
"""

from __future__ import annotations
from nicegui import ui


def build_tab_theory() -> None:
    """Xây dựng giao diện Tab 5: Lý thuyết, sơ đồ khối Mermaid & so sánh A5/1 theo chuẩn Modular Flat Cards."""
    with ui.column().classes("w-full gap-5"):

        # ======================================================================
        # CARD 1: BỐI CẢNH LỊCH SỬ & CỘT MỐC BẢO MẬT RFC 7465
        # ======================================================================
        with ui.card().classes("w-full p-6 space-y-3"):
            with ui.row().classes("w-full items-center justify-between pb-2 border-b border-slate-100"):
                with ui.row().classes("items-center gap-3"):
                    with ui.row().classes("w-9 h-9 rounded-lg bg-blue-50 text-blue-700 items-center justify-center border border-blue-200"):
                        ui.icon("history_edu", size="xs")
                    with ui.column().classes("gap-0"):
                        ui.label("1. Bối Cảnh Lịch Sử & Lỗ Hổng Bảo Mật (RFC 7465)").classes("text-base font-bold text-slate-800")
                        ui.label("Ron Rivest (1987) • Chuẩn mã hóa phổ biến nhất thế giới • Lý do cấm sử dụng").classes("text-xs text-slate-500")
                ui.badge("Lịch sử mật mã", color="primary").classes("text-xs")

            ui.markdown(
                r"""
* **Tác giả & Năm công bố**: Thuật toán được thiết kế bởi **Ron Rivest** (chữ **R** trong hệ mã bất đối xứng RSA) tại hãng RSA Security vào năm **1987**. Ban đầu RC4 là bí mật thương mại độc quyền, đến tháng 9/1994, mã nguồn thuật toán bị rò rỉ ẩn danh lên danh sách thư *Cypherpunks*.
* **Vị thế lịch sử**: RC4 từng là hệ mã dòng thông dụng nhất thế giới, được tích hợp trong các tiêu chuẩn mạng phổ biến:
  - Giao thức bảo mật mạng không dây Wi-Fi: **WEP (Wired Equivalent Privacy)** và **WPA (TKIP)**.
  - Giao thức an toàn tầng truyền vận: **SSL 3.0 / TLS 1.0 – 1.2** giữa trình duyệt Web và máy chủ.
  - Mã hóa tài liệu PDF và xác thực mạng Microsoft Windows (Kerberos).
* **Lý do bị cấm sử dụng (RFC 7465)**:
  - RC4 có **thiên lệch thống kê (biases)** ở các byte đầu tiên của dòng khóa (nổi tiếng nhất là tấn công FMS trên WEP, tấn công Bar-Mitzvah và NOMORE trên HTTPS).
  - Tháng 2/2015, nhóm kỹ sư Internet Engineering Task Force (IETF) chính thức ban hành **[RFC 7465](https://www.rfc-editor.org/info/rfc7465)** nghiêm cấm mọi việc sử dụng RC4 trong các bộ mã hóa TLS. Hiện nay, các hệ mã dòng hiện đại như **ChaCha20** và mã khối chế độ dòng như **AES-GCM** đã thay thế hoàn toàn RC4.
                """
            )

        # ======================================================================
        # CARD 2: SƠ ĐỒ KHỐI THUẬT TOÁN MERMAID
        # ======================================================================
        with ui.card().classes("w-full p-6 space-y-3"):
            with ui.row().classes("w-full items-center justify-between pb-2 border-b border-slate-100"):
                with ui.row().classes("items-center gap-3"):
                    with ui.row().classes("w-9 h-9 rounded-lg bg-emerald-50 text-emerald-700 items-center justify-center border border-emerald-200"):
                        ui.icon("schema", size="xs")
                    with ui.column().classes("gap-0"):
                        ui.label("2. Sơ Đồ Khối Thuật Toán RC4 (KSA & PRGA)").classes("text-base font-bold text-slate-800")
                        ui.label("Mã Mermaid vẽ động trong trình duyệt • Không sử dụng hình ảnh chụp").classes("text-xs text-slate-500")
                ui.badge("Tự vẽ Mermaid", color="positive").classes("text-xs")

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
            ).classes("w-full my-2")

        # ======================================================================
        # CARD 3: VÍ DỤ TÍNH TAY CHI TIẾT (SLIDE 56-60)
        # ======================================================================
        with ui.card().classes("w-full p-6 space-y-4"):
            with ui.row().classes("w-full items-center justify-between pb-2 border-b border-slate-100"):
                with ui.row().classes("items-center gap-3"):
                    with ui.row().classes("w-9 h-9 rounded-lg bg-amber-50 text-amber-700 items-center justify-center border border-amber-200"):
                        ui.icon("school", size="xs")
                    with ui.column().classes("gap-0"):
                        ui.label("3. Ví Dụ Tính Tay Chi Tiết: Bản Rõ P = 'BAG', Khóa K = [2, 1, 3]").classes("text-base font-bold text-slate-800")
                        ui.label("Quy trình tính toán từng bước chi tiết (Khoa CNTT - ĐH Kinh tế Quốc dân)").classes("text-xs text-slate-500")
                ui.badge("Tính tay chi tiết", color="warning").classes("text-xs")

            ui.markdown(
                r"""
* **Bảng chữ cái 3-bit**: $A=000(0) \mid B=001(1) \mid C=010(2) \mid D=011(3) \mid E=100(4) \mid F=101(5) \mid G=110(6) \mid H=111(7)$.
* **Bản rõ đầu vào**: $P = \text{BAG} \implies [1, 0, 6]$ (nhị phân: `001 000 110`).
* **Khóa bí mật**: $K = [2, 1, 3]$ với độ dài $N = 3$.
* **Mảng T lặp chu kỳ 8 phần tử**: $T = [2, 1, 3, 2, 1, 3, 2, 1]$.
* **Mảng S khởi tạo ban đầu**: $S = [0, 1, 2, 3, 4, 5, 6, 7]$, bắt đầu với $j = 0$.

#### A. Bảng 8 Vòng Hoán Vị KSA ($i = 0 \dots 7$):
*Công thức cập nhật:* $j = (j + S[i] + T[i]) \pmod{8}$, sau đó hoán vị $\text{Swap}(S[i], S[j])$.

| Vòng lặp $i$ | $j$ trước | $S[i]$ | $T[i]$ | $j_{\text{mới}} = (j + S[i] + T[i]) \bmod 8$ | Thao tác hoán vị | Trạng thái mảng $S$ sau bước $i$ |
| :---: | :---: | :---: | :---: | :---: | :--- | :--- |
| **$i = 0$** | 0 | 0 | 2 | $(0 + 0 + 2) \bmod 8 = \mathbf{2}$ | $\text{Swap}(S[0], S[2])$ | $[2, 1, 0, 3, 4, 5, 6, 7]$ |
| **$i = 1$** | 2 | 1 | 1 | $(2 + 1 + 1) \bmod 8 = \mathbf{4}$ | $\text{Swap}(S[1], S[4])$ | $[2, 4, 0, 3, 1, 5, 6, 7]$ |
| **$i = 2$** | 4 | 0 | 3 | $(4 + 0 + 3) \bmod 8 = \mathbf{7}$ | $\text{Swap}(S[2], S[7])$ | $[2, 4, 7, 3, 1, 5, 6, 0]$ |
| **$i = 3$** | 7 | 3 | 2 | $(7 + 3 + 2) \bmod 8 = \mathbf{4}$ | $\text{Swap}(S[3], S[4])$ | $[2, 4, 7, 1, 3, 5, 6, 0]$ |
| **$i = 4$** | 4 | 3 | 1 | $(4 + 3 + 1) \bmod 8 = \mathbf{0}$ | $\text{Swap}(S[4], S[0])$ | $[3, 4, 7, 1, 2, 5, 6, 0]$ |
| **$i = 5$** | 0 | 5 | 3 | $(0 + 5 + 3) \bmod 8 = \mathbf{0}$ | $\text{Swap}(S[5], S[0])$ | $[5, 4, 7, 1, 2, 3, 6, 0]$ |
| **$i = 6$** | 0 | 6 | 2 | $(0 + 6 + 2) \bmod 8 = \mathbf{0}$ | $\text{Swap}(S[6], S[0])$ | $[6, 4, 7, 1, 2, 3, 5, 0]$ |
| **$i = 7$** | 0 | 0 | 1 | $(0 + 0 + 1) \bmod 8 = \mathbf{1}$ | $\text{Swap}(S[7], S[1])$ | $\mathbf{[6, 0, 7, 1, 2, 3, 5, 4]}$ |

$$\implies \text{Kết quả mảng } S \text{ sau giai đoạn KSA: } \mathbf{S_{\text{KSA}} = [6, 0, 7, 1, 2, 3, 5, 4]}$$

#### B. Bảng Sinh Số PRGA & Mã Hóa XOR:
*Khởi tạo:* $i = 0, j = 0$. Mỗi bước: $i = (i + 1) \bmod 8$, $j = (j + S[i]) \bmod 8$, $\text{Swap}(S[i], S[j])$, $t = (S[i] + S[j]) \bmod 8$, dòng khóa $k = S[t]$, bản mã $c = p \oplus k$.

| Bước | Đơn vị $p$ | Chỉ số $(i, j)$ | Mảng $S$ sau $\text{Swap}(S[i], S[j])$ | Chỉ số $t$ | Dòng khóa $k = S[t]$ | Phép tính XOR ($p \oplus k = c$) | Ký tự ra |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Bước 1** | $p_0 = 1$ ('B') | $i=1, j=0$ | $[0, 6, 7, 1, 2, 3, 5, 4]$ | $t = (6 + 0) \bmod 8 = \mathbf{6}$ | $k_0 = S[6] = \mathbf{5}$ (`101`) | $1 \oplus 5 = \mathbf{4}$ (`001` $\oplus$ `101` = `100`) | **'E'** |
| **Bước 2** | $p_1 = 0$ ('A') | $i=2, j=7$ | $[0, 6, 4, 1, 2, 3, 5, 7]$ | $t = (4 + 7) \bmod 8 = \mathbf{3}$ | $k_1 = S[3] = \mathbf{1}$ (`001`) | $0 \oplus 1 = \mathbf{1}$ (`000` $\oplus$ `001` = `001`) | **'B'** |
| **Bước 3** | $p_2 = 6$ ('G') | $i=3, j=0$ | $[1, 6, 4, 0, 2, 3, 5, 7]$ | $t = (0 + 1) \bmod 8 = \mathbf{1}$ | $k_2 = S[1] = \mathbf{6}$ (`110`) | $6 \oplus 6 = \mathbf{0}$ (`110` $\oplus$ `110` = `000`) | **'A'** |

**KẾT LUẬN VÍ DỤ TRÊN LỚP:**
* Dòng khóa sinh ra: $\mathbf{k = [5, 1, 6]}$ (nhị phân: `101 001 110`).
* Bản mã thu được: $\mathbf{C = \text{EBA}}$ (nhị phân: `100 001 000`).
* Giải mã đối xứng: $C \oplus k = [4, 1, 0] \oplus [5, 1, 6] = [1, 0, 6] \implies P = \text{BAG}$ (khôi phục chính xác 100%).
                """
            )

        # ======================================================================
        # CARD 4: SO SÁNH ĐA CHIỀU RC4 VỚI A5/1
        # ======================================================================
        with ui.card().classes("w-full p-6 space-y-3"):
            with ui.row().classes("w-full items-center justify-between pb-2 border-b border-slate-100"):
                with ui.row().classes("items-center gap-3"):
                    with ui.row().classes("w-9 h-9 rounded-lg bg-purple-50 text-purple-700 items-center justify-center border border-purple-200"):
                        ui.icon("compare_arrows", size="xs")
                    with ui.column().classes("gap-0"):
                        ui.label("4. So Sánh Chuyên Sâu: Hệ Mã RC4 / TinyRC4 và A5/1 (Chương 2)").classes("text-base font-bold text-slate-800")
                        ui.label("Phân tích cấu trúc mảng hoán vị vs Thanh ghi dịch LFSR, hiệu năng và bảo mật").classes("text-xs text-slate-500")
                ui.badge("Đối chiếu học phần", color="accent").classes("text-xs")

            ui.markdown(
                r"""
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
