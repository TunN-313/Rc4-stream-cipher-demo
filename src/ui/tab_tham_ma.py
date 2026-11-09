"""
Tab 4: Thám Mã & Tấn Công RC4 (FMS Attack, Two-Time Pad & Mantin-Shamir Bias)
======================================================================
Tab này mô phỏng các phương pháp thám mã và tấn công dòng khóa RC4:
1. Tấn công khôi phục khóa FMS (Fluhrer–Mantin–Shamir 2001) trên giao thức WEP.
2. Tấn công dùng lại dòng khóa (Two-Time Pad) và kỹ thuật thám mã Crib-dragging.
3. Phân tích thiên lệch xác suất byte dòng khóa (Mantin-Shamir).
Người dùng nhập bản rõ, từ đoán trước, số lượng khóa ngẫu nhiên và theo dõi kết quả trực quan.
Gọi các hàm phân tích từ src.core.analysis: simulate_fms_wep_attack, simulate_keystream_reuse_attack, keystream_bias_counts.
"""

from __future__ import annotations  # dùng để hỗ trợ chú thích kiểu dữ liệu hiện đại
import asyncio  # dùng để xử lý tác vụ bất đồng bộ, cập nhật giao diện mượt mà không bị treo
import html  # dùng để mã hóa an toàn các ký tự đặc biệt sang định dạng HTML
import random  # dùng để sinh số ngẫu nhiên phục vụ tạo khóa thử nghiệm
from typing import Optional  # dùng để định nghĩa kiểu dữ liệu có thể nhận giá trị None
from nicegui import ui  # dùng để xây dựng các thành phần giao diện web (nút, bảng, biểu đồ)

from src.core.phan_tich_an_toan import (  # dùng để gọi các hàm phân tích bảo mật từ tầng core
    fms_partial_ksa,
    fms_predict_first_output,
    keystream_bias_counts,
    simulate_fms_wep_attack,
    simulate_keystream_reuse_attack,
)
from src.core.mo_hinh_du_lieu import FMSAttackResult, FMSByteResult


def build_comparison_strip_html(
    p1_text: str,
    p2_text: str,
    pos: int,
    crib: str,
    recovered: str,
    matches_real: bool,
    crib_in: str,
) -> str:
    """
    Tạo chuỗi HTML hiển thị dải đối chiếu hai bản rõ P1 và P2 với màu sắc đánh dấu vị trí khớp.

    Tham số:
        p1_text: Nội dung bản rõ P1.
        p2_text: Nội dung bản rõ P2.
        pos: Vị trí byte bắt đầu trượt từ đoán (crib).
        crib: Từ đoán trước đưa vào thử nghiệm.
        recovered: Đoạn văn bản vừa khôi phục được từ phép XOR.
        matches_real: Kết quả khôi phục có khớp đúng với bản rõ gốc hay không.
        crib_in: Từ đoán đang nằm ở bản rõ "p1" hay "p2".
    Trả về: Chuỗi HTML định dạng 2 dòng monospace nổi bật vị trí từ đoán và từ khôi phục.
    """
    crib_style = (
        "background-color: #fef08a; color: #854d0e; "
        "padding: 1px 4px; border-radius: 4px; font-weight: bold; "
        "border: 1px solid #fde047;"
    )
    if matches_real:
        rec_style = (
            "background-color: #bbf7d0; color: #14532d; "
            "padding: 1px 4px; border-radius: 4px; font-weight: bold; "
            "border: 1px solid #86efac;"
        )
    else:
        rec_style = (
            "background-color: #fecdd3; color: #881337; "
            "padding: 1px 4px; border-radius: 4px; font-weight: bold; "
            "border: 1px solid #fda4af;"
        )

    if crib_in.lower() == "p2":
        # Crib thuộc P2, khôi phục đoạn P1
        p1_rendered = (
            html.escape(p1_text[:pos])
            + f'<span style="{rec_style}">{html.escape(recovered)}</span>'
            + html.escape(p1_text[pos + len(recovered):])
        )
        p2_rendered = (
            html.escape(p2_text[:pos])
            + f'<span style="{crib_style}">{html.escape(crib)}</span>'
            + html.escape(p2_text[pos + len(crib):])
        )
    else:
        # Mặc định: Crib thuộc P1, khôi phục đoạn P2
        p1_rendered = (
            html.escape(p1_text[:pos])
            + f'<span style="{crib_style}">{html.escape(crib)}</span>'
            + html.escape(p1_text[pos + len(crib):])
        )
        p2_rendered = (
            html.escape(p2_text[:pos])
            + f'<span style="{rec_style}">{html.escape(recovered)}</span>'
            + html.escape(p2_text[pos + len(recovered):])
        )

    return (
        '<div style="font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; '
        'font-size: 12px; line-height: 1.9; background-color: #f8fafc; '
        'border: 1px solid #e2e8f0; padding: 10px 14px; border-radius: 8px; '
        'word-break: break-all; color: #1e293b;">'
        f'<div><strong style="color: #64748b; user-select: none;">P1: </strong>{p1_rendered}</div>'
        f'<div><strong style="color: #64748b; user-select: none;">P2: </strong>{p2_rendered}</div>'
        '</div>'
    )


def build_fms_attack_card() -> None:
    """
    Xây dựng Khung Thử Nghiệm Tấn Công Khôi Phục Khóa FMS WEP.
    Minh họa bẻ khóa bí mật K qua lớp IV yếu (A+3, 255, X) và đối chiếu kiểm chứng 50 gói độc lập.
    """
    with ui.card().classes("w-full p-6 space-y-4"):
        with ui.row().classes("w-full items-center justify-between pb-2 border-b border-slate-100"):
            with ui.row().classes("items-center gap-3"):
                with ui.row().classes("w-9 h-9 rounded-lg bg-red-50 text-red-700 items-center justify-center border border-red-200"):
                    ui.icon("lock_open", size="xs")
                with ui.column().classes("gap-0"):
                    ui.label("1. Tấn Công Bẻ Khóa FMS trong WEP (Key Recovery Attack)").classes("text-base font-bold text-slate-800")
                    ui.label("Fluhrer–Mantin–Shamir (2001) • Khôi phục chính xác khóa bí mật K • Mô phỏng thực nghiệm WEP").classes("text-xs text-slate-500")
            ui.badge("Bẻ Khóa Thực Sự K", color="negative").classes("text-xs")

        with ui.column().classes("w-full bg-red-50/70 border border-red-200/80 p-3.5 rounded-xl gap-2"):
            with ui.row().classes("w-full items-start gap-2"):
                ui.icon("psychology", size="xs").classes("text-red-600 mt-0.5 shrink-0")
                ui.label(
                    "Nguyên lý Tấn công FMS: Khôi phục Khóa bí mật K chứ không chỉ đọc bản rõ hay quan sát thiên lệch:"
                ).classes("text-xs font-semibold text-red-950 leading-relaxed")
            ui.markdown(
                r"* **Cơ chế ghép khóa WEP**: Khóa gói tin được tạo bằng `K_gói = IV || K_bí_mật` với `IV` (3 byte) truyền công khai."
                "\n"
                r"* **Suy luận tuần tự**: Bằng cách thu thập các gói tin chứa lớp IV yếu `(A + 3, 0xFF, X)` và biết byte đầu `P_0 = 0xAA` (SNAP/LLC header), "
                r"kẻ tấn công mô phỏng KSA đã biết để bỏ phiếu tìm từng byte `K[A]` qua xác suất bảo toàn trạng thái (e⁻³ ≈ 5%). "
                r"Sau khi tìm đủ các byte, hệ thống kiểm chứng độc lập trên 50 gói để ngăn ngừa sai lệch dây chuyền."
            ).classes("text-xs text-red-900/90 leading-relaxed pl-6")

        # Điều khiển đầu vào
        with ui.row().classes("w-full items-center gap-3 flex-wrap"):
            fms_key_input = ui.input(
                label="Khóa bí mật K (chuỗi hoặc 0xHex)",
                value="KEY_1",
            ).classes("w-52")

            fms_p0_input = ui.input(
                label="Byte bản rõ đầu P0",
                value="0xAA",
            ).classes("w-32")

            fms_samples_input = ui.number(
                label="Số mẫu IV yếu / byte",
                value=600,
                min=100,
                max=2000,
                step=50,
            ).classes("w-36")

            fms_verify_input = ui.number(
                label="Số gói kiểm chứng",
                value=50,
                min=10,
                max=200,
                step=10,
            ).classes("w-36")

            fms_seed_check = ui.checkbox("Cố định seed=42", value=True).classes("text-xs text-slate-700")

            btn_run_fms = ui.button(
                "Chạy Bẻ Khóa FMS",
                icon="bolt",
            ).props("color=negative").classes("mt-1")

        fms_progress = ui.linear_progress(value=0.0, show_value=False).props("instant-feedback stripe color=negative").classes("w-full")
        fms_progress.visible = False

        # --- BỘ KHUNG TĨNH CỐ ĐỊNH (KHÔNG DÙNG .clear() TRÁNH CRASH VUE VIRTUAL DOM) ---
        with ui.column().classes("w-full gap-4"):
            # 1. Khung tóm tắt đối chiếu
            with ui.row().classes("w-full items-center justify-between p-3.5 bg-slate-50 rounded-xl border border-slate-200/80 flex-wrap gap-2"):
                with ui.row().classes("items-center gap-2"):
                    ui.label("Khóa bí mật:").classes("text-xs text-slate-500 font-bold")
                    lbl_sec_key = ui.label("").classes("font-mono text-xs font-bold text-slate-800")
                with ui.row().classes("items-center gap-2"):
                    ui.label("Khóa khôi phục:").classes("text-xs text-slate-500 font-bold")
                    lbl_rec_key = ui.label("").classes("font-mono text-xs font-bold")
                with ui.row().classes("items-center gap-2"):
                    badge_match = ui.badge("").classes("text-xs")
                    badge_verify = ui.badge("").classes("text-xs")
                    badge_time = ui.badge("").classes("text-xs")

            # 2. Bảng kết quả từng byte khóa (Bảng 2.8.5)
            cols = [
                {"name": "byte_name", "label": "Byte khóa", "field": "byte_name", "align": "center"},
                {"name": "true_val", "label": "Giá trị thật", "field": "true_val", "align": "left"},
                {"name": "rec_val", "label": "Khôi phục", "field": "rec_val", "align": "left"},
                {"name": "match", "label": "Trạng thái", "field": "match", "align": "center"},
                {"name": "votes", "label": "Phiếu dẫn đầu / Tổng", "field": "votes", "align": "right"},
                {"name": "top3", "label": "Top 3 Ứng viên (giá trị & số phiếu)", "field": "top3", "align": "left"},
            ]

            with ui.row().classes("w-full items-center justify-between"):
                ui.label("Bảng Kết Quả Từng Byte Khóa (Nhấp chọn hàng để xem phân bố phiếu bầu):").classes(
                    "text-xs font-bold text-slate-700 uppercase tracking-wider"
                )
                lbl_packet_count = ui.label("").classes("text-xs text-slate-500 font-mono")

            tbl = ui.table(columns=cols, rows=[], row_key="byte_name", selection="single").classes(
                "w-full border border-slate-200/80 rounded-xl overflow-hidden font-mono text-xs shadow-2xs"
            )
            # Không dùng slot 'body' vì xung đột với Quasar QTable Vue Virtual DOM khi cập nhật rows
            # Selection='single' của NiceGUI/Quasar tự động sinh cột checkbox/radio chuẩn xác 100%

            # Biểu đồ ECharts phân bố phiếu bầu cho byte được chọn
            with ui.column().classes("w-full gap-2"):
                chart_title = ui.label("Biểu đồ Phân Bố Phiếu Bầu:").classes("text-xs font-bold text-slate-700")
                initial_chart_opts = {
                    "tooltip": {"trigger": "axis"},
                    "grid": {"top": 20, "right": 20, "bottom": 30, "left": 50},
                    "xAxis": {
                        "type": "category",
                        "data": [str(i) for i in range(256)],
                        "axisLabel": {"interval": 31},
                        "name": "Giá trị byte (0..255)",
                    },
                    "yAxis": {"type": "value", "name": "Số phiếu bầu"},
                    "series": [{"type": "bar", "data": [0] * 256}],
                }
                chart = ui.echart(initial_chart_opts).classes("w-full h-52")

            # 3. Box nhận xét mật mã học chuyên sâu
            with ui.column().classes("w-full p-4 bg-slate-50 border border-slate-200/80 rounded-xl gap-2 text-xs text-slate-700"):
                ui.label("Nhận xét Mật Mã Học & Đánh Giá An Toàn:").classes("font-bold text-slate-800 text-sm")
                ui.markdown(
                    r"""
* **Tỷ lệ tín hiệu trên nhiễu**: Xác suất trạng thái KSA được bảo toàn để cho ra manh mối tin cậy chỉ khoảng $e^{-3} \approx 0.05$ (khoảng 20 gói tin mới có 1 gói hữu ích). Do đó, cần thu thập đủ lượng mẫu (ví dụ 600 gói/byte) thì giá trị đúng mới nhận số phiếu vượt trội khỏi mức nhiễu ngẫu nhiên.
* **Hiện tượng byte sít sao**: Byte cuối $K[4]$ chỉ dẫn đầu với cách biệt nhỏ (17 phiếu so với 11 phiếu của giá trị đứng nhì). Vì vậy, việc chọn ứng viên nhiều phiếu nhất chưa thể khẳng định 100% đúng nếu chưa qua bước kiểm chứng.
* **Tầm quan trọng của bước kiểm chứng**: Sau khi có khóa ứng viên, bắt buộc phải khởi tạo lại RC4 và đối chiếu đầu ra với dữ liệu bắt được trên 50 gói độc lập để ngăn chặn lỗi sai lệch dây chuyền.
* **4 Giới hạn mật mã**:
  1. *Phụ thuộc cơ chế tạo khóa*: FMS chỉ khai thác được khi giao thức ghép $IV \parallel K$; nếu các khóa được sinh độc lập, quan hệ này biến mất.
  2. *Cần byte đầu $P_0$*: Cần biết trước byte đầu (như SNAP/LLC header) để suy ra $Z_0$.
  3. *Phụ thuộc chất lượng và lượng mẫu*: Cần đủ các gói mang IV yếu thuộc lớp $(A+3, \text{0xFF}, X)$.
  4. *Không suy rộng sang TLS*: Các tấn công trong TLS (AlFardan, NOMORE) khai thác sai lệch dòng khóa để khôi phục bản rõ, hoàn toàn khác với việc bẻ khóa bí mật $K$ trong WEP.
"""
                )

        current_res: Optional[FMSAttackResult] = None
        fms_run_seq = 0

        def update_chart_for_byte(byte_idx: int) -> None:
            if not current_res or byte_idx < 0 or byte_idx >= len(current_res.byte_results):
                return
            b_info = current_res.byte_results[byte_idx]
            chart_title.text = f"Biểu đồ Phân Bố Phiếu Bầu Ứng Viên cho Byte K[{byte_idx}] (256 giá trị có thể):"
            chart_opts = {
                "tooltip": {"trigger": "axis"},
                "grid": {"top": 20, "right": 20, "bottom": 30, "left": 50},
                "xAxis": {
                    "type": "category",
                    "data": [str(i) for i in range(256)],
                    "axisLabel": {"interval": 31},
                    "name": "Giá trị byte (0..255)",
                },
                "yAxis": {"type": "value", "name": "Số phiếu bầu"},
                "series": [{
                    "type": "bar",
                    "data": [
                        {
                            "value": b_info.all_votes[i],
                            "itemStyle": {
                                "color": "#10b981" if i == b_info.true_byte else (
                                    "#ef4444" if i == b_info.recovered_byte and not b_info.matched else "#94a3b8"
                                )
                            },
                        }
                        for i in range(256)
                    ],
                    "markLine": {
                        "silent": True,
                        "symbol": "none",
                        "lineStyle": {"color": "#f59e0b", "type": "dashed"},
                        "data": [{"yAxis": round(b_info.total_samples / 256.0, 2), "name": "Mức ngẫu nhiên"}],
                    },
                }],
            }
            chart.options.clear()
            chart.options.update(chart_opts)
            chart.update()

        def render_fms_result(res: FMSAttackResult) -> None:
            nonlocal current_res, fms_run_seq
            current_res = res
            fms_run_seq += 1

            # Cập nhật thông tin tóm tắt
            lbl_sec_key.text = f"{res.secret_key_bytes} (Hex: {res.secret_key_bytes.hex().upper()})"
            lbl_rec_key.text = f"{res.recovered_key_bytes} (Hex: {res.recovered_key_bytes.hex().upper()})"
            lbl_rec_key.style(f"color: {'#047857' if res.all_matched else '#be123c'}")

            badge_match.text = "Trùng khớp 100%" if res.all_matched else "Chưa khớp hoàn toàn"
            badge_match.props(f"color={'positive' if res.all_matched else 'negative'}")

            pct = res.verified_packets / max(res.total_verified_packets, 1) * 100
            badge_verify.text = f"Kiểm chứng độc lập: {res.verified_packets}/{res.total_verified_packets} gói ({pct:.0f}%)"
            badge_verify.props(f"color={'positive' if res.verified_packets == res.total_verified_packets else 'warning'}")

            badge_time.text = f"Thời gian: {res.elapsed_ms:.1f} ms"
            badge_time.props("color=primary")

            lbl_packet_count.text = f"Tổng gói tin IV yếu đã xét: {res.collected_packets_count} gói"

            # Cập nhật dữ liệu bảng với id duy nhất theo lượt chạy để tránh xung đột Vue Virtual DOM
            rows = [
                {
                    "id": f"fms_{fms_run_seq}_{b.byte_index}",
                    "byte_name": f"K[{b.byte_index}]",
                    "byte_index": b.byte_index,
                    "true_val": f"{b.true_byte} ({chr(b.true_byte) if 32 <= b.true_byte <= 126 else '?'})",
                    "rec_val": f"{b.recovered_byte} ({chr(b.recovered_byte) if 32 <= b.recovered_byte <= 126 else '?'})",
                    "match": "✅ Khớp" if b.matched else "❌ Sai",
                    "matched": b.matched,
                    "votes": f"{b.top_votes} / {b.total_samples} ({b.top_votes / b.total_samples * 100:.1f}%)",
                    "top3": ", ".join(f"{v[0]} ({v[1]}p)" for v in b.top_candidates[:3]),
                }
                for b in res.byte_results
            ]
            tbl.selected.clear()
            tbl.rows = list(rows)
            tbl.selected = [rows[0]] if rows else []
            tbl.update()
            update_chart_for_byte(0)

        def on_table_select(e):
            if e.selection:
                update_chart_for_byte(e.selection[0]["byte_index"])

        tbl.on_select(on_table_select)

        async def run_fms_ui() -> None:
            raw_k = (fms_key_input.value or "").strip()
            if not raw_k:
                ui.notify("Vui lòng nhập khóa bí mật K.", type="warning")
                return

            try:
                if raw_k.lower().startswith("0x"):
                    sec_key = bytes.fromhex(raw_k[2:])
                else:
                    sec_key = raw_k.encode("utf-8")
            except ValueError:
                ui.notify("Khóa bí mật dạng Hex (0x...) không hợp lệ.", type="negative")
                return

            if len(sec_key) < 1:
                ui.notify("Khóa bí mật K phải có độ dài ít nhất 1 byte.", type="warning")
                return

            raw_p0 = (fms_p0_input.value or "").strip()
            if not raw_p0:
                ui.notify("Vui lòng nhập byte bản rõ đầu P0.", type="warning")
                return

            try:
                if raw_p0.lower().startswith("0x"):
                    p0_val = int(raw_p0, 16)
                else:
                    p0_val = int(raw_p0)
            except ValueError:
                ui.notify(f"Giá trị P0 '{raw_p0}' không hợp lệ. Vui lòng nhập số nguyên (0..255) hoặc mã Hex (0x00..0xFF).", type="negative")
                return

            if not (0 <= p0_val <= 255):
                ui.notify(f"Giá trị P0 ({p0_val}) vượt quá phạm vi! Byte bản rõ bắt buộc phải nằm trong khoảng 0..255 (hoặc 0x00..0xFF).", type="warning")
                return

            btn_run_fms.disable()
            fms_progress.visible = True
            await asyncio.sleep(0.01)
            try:
                samples = int(fms_samples_input.value or 600)
                num_v = int(fms_verify_input.value or 50)
                seed_val = 42 if fms_seed_check.value else None

                loop = asyncio.get_running_loop()
                res: FMSAttackResult = await loop.run_in_executor(
                    None,
                    lambda: simulate_fms_wep_attack(
                        secret_key=sec_key,
                        samples_per_byte=samples,
                        p0=p0_val,
                        num_verify=num_v,
                        seed=seed_val,
                    ),
                )
                render_fms_result(res)
                ui.notify(f"Đã hoàn thành bẻ khóa FMS ({len(res.recovered_key_bytes)} byte khóa)!", type="positive")
            except Exception as exc:
                ui.notify(f"Lỗi thực hiện FMS: {exc}", type="negative")
            finally:
                fms_progress.visible = False
                btn_run_fms.enable()

        btn_run_fms.on_click(run_fms_ui)

        # Hiển thị sẵn kết quả mẫu chuẩn ban đầu
        initial_fms_res = simulate_fms_wep_attack("KEY_1", 600, 0xAA, 50, 42)
        render_fms_result(initial_fms_res)


def dung_tab_tham_ma() -> None:
    """
    Xây dựng giao diện Tab 4: Tấn công FMS WEP, Keystream Reuse và thiên lệch Mantin-Shamir.

    Tham số: Không có.
    Trả về: None.
    """
    with ui.column().classes("w-full gap-6"):

        # ======================================================================
        # PHÂN HỆ 1: TẤN CÔNG KHÔI PHỤC KHÓA FMS TRONG WEP
        # ======================================================================
        build_fms_attack_card()

        # ======================================================================
        # PHÂN HỆ 2: TẤN CÔNG DÙNG LẠI DÒNG KHÓA (TWO-TIME PAD & CRIB-DRAGGING)
        # ======================================================================
        with ui.card().classes("w-full p-6 space-y-4"):
            with ui.row().classes("w-full items-center justify-between pb-2 border-b border-slate-100"):
                with ui.row().classes("items-center gap-3"):
                    with ui.row().classes("w-9 h-9 rounded-lg bg-rose-50 text-rose-700 items-center justify-center border border-rose-200"):
                        ui.icon("gpp_bad", size="xs")
                    with ui.column().classes("gap-0"):
                        ui.label("2. Tấn Công Dùng Lại Dòng Khóa (Two-Time Pad)").classes("text-base font-bold text-slate-800")
                        ui.label("Keystream Reuse & Kỹ thuật Crib-dragging thám mã không cần khóa K").classes("text-xs text-slate-500")
                ui.badge("Lỗ hổng WEP/WPA", color="negative").classes("text-xs")

            with ui.column().classes("w-full bg-rose-50/70 border border-rose-200/80 p-3.5 rounded-xl gap-2"):
                with ui.row().classes("w-full items-start gap-2"):
                    ui.icon("warning_amber", size="xs").classes("text-rose-600 mt-0.5 shrink-0")
                    ui.label(
                        "Khi hai bản rõ P₁ và P₂ bị mã hóa bằng cùng một khóa bí mật K (Keystream Reuse):"
                    ).classes("text-xs font-semibold text-rose-950 leading-relaxed")

                with ui.row().classes("w-full justify-center py-1 px-3 bg-white/90 rounded-lg border border-rose-200 shadow-2xs"):
                    ui.html(r"$$C_1 \oplus C_2 = (P_1 \oplus K) \oplus (P_2 \oplus K) = P_1 \oplus P_2$$").classes("text-sm text-rose-900 font-bold")

                ui.label(
                    "Dòng khóa bị triệt tiêu hoàn toàn! Kỹ thuật thám mã Crib-dragging cho phép khôi phục bản rõ P₂ khi dự đoán được một đoạn từ khóa (Crib) trong P₁."
                ).classes("text-2xs text-rose-800/90 italic leading-normal pl-6")

            # Ô nhập bản rõ P1 dùng để thử nghiệm tấn công dùng lại dòng khóa
            atk_p1 = ui.input(
                label="Bản rõ P1",
                value="Kinh gui Quy khach: Mat khau OTP la 849201",
            ).classes("w-full")
            # Ô nhập bản rõ P2 dùng để thử nghiệm tấn công dùng lại dòng khóa
            atk_p2 = ui.input(
                label="Bản rõ P2",
                value="Chuyen khoan ngay 50000000 VND vao TK 9988",
            ).classes("w-full")
            # Ô nhập khóa K dùng chung cho cả 2 bản rõ
            atk_key = ui.input(
                label="Khóa K dùng chung cho cả 2 bản rõ",
                value="WEP-Reused-Key-123",
            ).classes("w-full")

            with ui.row().classes("w-full items-center gap-3"):
                # Ô nhập từ đoán trước (crib) của kẻ tấn công
                atk_crib = ui.input(
                    label="Từ đoán trước (Crib Word)",
                    value="Kinh gui Quy khach",
                ).classes("flex-1")
                with ui.column().classes("gap-1 shrink-0"):
                    ui.label("Crib nằm trong").classes("text-xs text-slate-500 font-medium")
                    # ui.toggle: nút bấm chọn qua lại giữa 2 lựa chọn bản rõ P1 hoặc P2
                    atk_crib_in = ui.toggle(["P1", "P2"], value="P1")

            def run_attack_ui(notify_on_run: bool = False) -> None:
                """
                Hàm callback gọi simulate_keystream_reuse_attack trong core và cập nhật giao diện thám mã.

                Tham số: Không có (lấy trực tiếp từ các ô nhập giao diện).
                Trả về: None.
                """
                p1_val = (atk_p1.value or "").strip()
                p2_val = (atk_p2.value or "").strip()
                k_val = (atk_key.value or "").strip()
                crib_text = (atk_crib.value or "").strip()

                if not p1_val or not p2_val:
                    ui.notify("Vui lòng nhập nội dung cho cả hai bản rõ P1 và P2.", type="warning")
                    return
                if not k_val:
                    ui.notify("Vui lòng nhập khóa bí mật dùng chung K.", type="warning")
                    return
                if not crib_text:
                    ui.notify("Vui lòng nhập từ đoán trước (Crib).", type="warning")
                    return

                atk_box.clear()
                crib_in_val = (atk_crib_in.value or "P1").lower()
                res = simulate_keystream_reuse_attack(
                    p1_val,
                    p2_val,
                    k_val,
                    crib_text,
                    crib_in=crib_in_val,
                )
                with atk_box:
                    with ui.column().classes("w-full p-3 bg-slate-50 rounded-lg border border-slate-200/60 font-mono text-xs text-slate-700 gap-1"):
                        ui.label(f"Bản mã C1 (Hex): {res.c1_hex[:44]}...")
                        ui.label(f"Bản mã C2 (Hex): {res.c2_hex[:44]}...")
                        ui.label(f"C1 ⊕ C2 (Hex)  : {res.xor_c1_c2_hex[:44]}...").classes("text-rose-700 font-bold")

                    with ui.row().classes("items-center gap-2"):
                        ui.badge(
                            f"Kiểm chứng: C1 ⊕ C2 == P1 ⊕ P2 {'(Dòng khóa bị triệt tiêu hoàn toàn!)' if res.streams_equal else '(Lỗi)'}",
                            color="negative" if res.streams_equal else "warning",
                        ).classes("text-xs")

                    if res.len_p1 != res.len_p2:
                        with ui.row().classes(
                            "w-full items-center gap-2 px-3 py-2 bg-amber-50 border border-amber-300 rounded-lg text-amber-900 text-xs font-medium"
                        ):
                            ui.icon("warning_amber", size="xs").classes("text-amber-700 shrink-0")
                            ui.label(
                                f"P1 dài {res.len_p1} byte, P2 dài {res.len_p2} byte: chỉ dùng {min(res.len_p1, res.len_p2)} byte đầu"
                            )

                    n_cands = len(res.crib_candidates)
                    if n_cands > 0:
                        ui.label(f"{n_cands} ứng viên. Crib càng dài, ứng viên càng ít.").classes(
                            "text-xs text-slate-500 italic"
                        )

                        raw_rows = [
                            {
                                "pos": c.pos,
                                "crib": c.crib,
                                "recovered": c.recovered,
                                "score": c.score,
                                "score_str": f"{c.score:.2f}",
                                "match_icon": "✓" if c.matches_real else "✗",
                                "matches_real": c.matches_real,
                            }
                            for c in res.crib_candidates
                        ]

                        def get_sorted_rows(sort_by_score: bool) -> list[dict]:
                            """
                            Sắp xếp danh sách ứng viên theo điểm số khả tín hoặc theo vị trí byte.

                            Tham số: sort_by_score (True: xếp theo điểm giảm dần, False: theo vị trí).
                            Trả về: Danh sách hàng dữ liệu đã sắp xếp.
                            """
                            if sort_by_score:
                                return sorted(raw_rows, key=lambda r: (-r["score"], r["pos"]))
                            return sorted(raw_rows, key=lambda r: r["pos"])

                        with ui.row().classes("w-full items-center justify-between pt-1"):
                            ui.label("Bảng Ứng Viên Khôi Phục:").classes("text-xs font-bold text-slate-700 uppercase tracking-wider")
                            # ui.switch: công tắc gạt bật/tắt sắp xếp theo điểm số khả tín
                            sort_switch = ui.switch("Xếp theo điểm", value=False).props("dense")

                        columns = [
                            {"name": "pos", "label": "Vị trí (byte)", "field": "pos", "align": "center", "sortable": True},
                            {"name": "crib", "label": "Crib", "field": "crib", "align": "left"},
                            {"name": "recovered", "label": "Văn bản khôi phục", "field": "recovered", "align": "left"},
                            {"name": "score", "label": "Điểm", "field": "score_str", "align": "right", "sortable": True},
                            {"name": "match", "label": "Khớp thật", "field": "match_icon", "align": "center"},
                        ]

                        # ui.table: bảng hiển thị các ứng viên tìm được khi trượt crib
                        table = ui.table(
                            columns=columns,
                            rows=get_sorted_rows(False),
                            row_key="pos",
                            selection="single",
                        ).classes("w-full border border-slate-200/80 rounded-xl overflow-hidden font-mono text-xs shadow-2xs")

                        table.add_slot(
                            "body",
                            """
                            <q-tr :props="props" :key="props.key" :class="props.row.matches_real ? 'bg-emerald-50 text-emerald-950 font-medium' : ''" @click="props.selected = !props.selected" class="cursor-pointer">
                                <q-td auto-width @click.stop>
                                    <q-checkbox v-model="props.selected" dense />
                                </q-td>
                                <q-td v-for="col in props.cols" :key="col.name" :props="props">
                                    {{ props.row[col.field] }}
                                </q-td>
                            </q-tr>
                            """,
                        )

                        best_row = max(raw_rows, key=lambda r: (r["score"], -r["pos"]))
                        table.selected = [best_row]

                        strip_container = ui.column().classes("w-full space-y-1.5 pt-1")
                        with strip_container:
                            ui.label("Dải Đối Chiếu Vị Trí (So sánh hai bản rõ):").classes(
                                "text-xs font-bold text-slate-700 uppercase tracking-wider"
                            )
                            strip_html = ui.html(
                                build_comparison_strip_html(
                                    p1_text=atk_p1.value,
                                    p2_text=atk_p2.value,
                                    pos=best_row["pos"],
                                    crib=best_row["crib"],
                                    recovered=best_row["recovered"],
                                    matches_real=best_row["matches_real"],
                                    crib_in=crib_in_val,
                                ),
                                sanitize=False,
                            ).classes("w-full")

                        def update_strip(row_dict: Optional[dict]) -> None:
                            """
                            Cập nhật dải trực quan đối chiếu hai bản rõ khi người dùng chọn một hàng.

                            Tham số: row_dict chứa thông tin hàng ứng viên được chọn.
                            Trả về: None.
                            """
                            if row_dict is None:
                                strip_container.visible = False
                            else:
                                strip_container.visible = True
                                strip_html.content = build_comparison_strip_html(
                                    p1_text=atk_p1.value,
                                    p2_text=atk_p2.value,
                                    pos=row_dict["pos"],
                                    crib=row_dict["crib"],
                                    recovered=row_dict["recovered"],
                                    matches_real=row_dict["matches_real"],
                                    crib_in=crib_in_val,
                                )

                        def handle_table_select(e) -> None:
                            """
                            Hàm callback xử lý sự kiện chọn một hàng ứng viên trên bảng.

                            Tham số: e là đối tượng sự kiện chứa danh sách hàng được chọn.
                            Trả về: None.
                            """
                            if e.selection:
                                update_strip(e.selection[0])
                            else:
                                update_strip(None)

                        table.on_select(handle_table_select)

                        def on_sort_change(e) -> None:
                            """
                            Hàm callback khi người dùng gạt công tắc đổi tiêu chí sắp xếp.

                            Tham số: e là đối tượng sự kiện chứa giá trị True/False mới của switch.
                            Trả về: None.
                            """
                            table.rows = get_sorted_rows(e.value)
                            table.update()

                        sort_switch.on_value_change(on_sort_change)

                    else:
                        ui.label("Không có vị trí nào cho ra ký tự đọc được. Hãy thử crib khác.").classes(
                            "text-xs text-amber-800 font-medium italic"
                        )

                    if notify_on_run:
                        ui.notify(f"Đã thám mã xong! Tìm thấy {n_cands} vị trí ứng viên.", type="positive")

            # Bấm nút này gọi hàm run_attack_ui() để tính toán thám mã và hiển thị kết quả ở atk_box
            ui.button("Thực hiện Thám mã Known-Plaintext", icon="bolt", on_click=lambda: run_attack_ui(notify_on_run=True)).props(
                "color=negative"
            )

            atk_p1.on("change", lambda: run_attack_ui(notify_on_run=True))
            atk_p2.on("change", lambda: run_attack_ui(notify_on_run=True))
            atk_key.on("change", lambda: run_attack_ui(notify_on_run=True))
            atk_crib.on("change", lambda: run_attack_ui(notify_on_run=True))
            atk_crib_in.on_value_change(lambda: run_attack_ui(notify_on_run=True))

            atk_box = ui.column().classes("w-full gap-3")
            # Tự động thực hiện thám mã ngay khi mở tab để hiển thị kết quả mẫu ban đầu
            run_attack_ui(notify_on_run=False)

        # ======================================================================
        # PHÂN HỆ 3: THIÊN LỆCH DÒNG KHÓA (MANTIN–SHAMIR BIAS)
        # ======================================================================
        with ui.card().classes("w-full p-6 space-y-4"):
            with ui.row().classes("w-full items-center justify-between pb-2 border-b border-slate-100"):
                with ui.row().classes("items-center gap-3"):
                    with ui.row().classes("w-9 h-9 rounded-lg bg-amber-50 text-amber-700 items-center justify-center border border-amber-200"):
                        ui.icon("analytics", size="xs")
                    with ui.column().classes("gap-0"):
                        ui.label("3. Thiên Lệch Dòng Khóa (Mantin–Shamir)").classes("text-base font-bold text-slate-800")
                        ui.label("Đo phân bố xác suất byte dòng khóa RC4 trên nhiều khóa ngẫu nhiên").classes("text-xs text-slate-500")
                ui.badge("Mantin & Shamir (FSE 2001)", color="warning").classes("text-xs")

            with ui.row().classes("w-full items-start gap-2.5 p-3.5 bg-amber-50/70 border border-amber-200/80 rounded-xl"):
                ui.icon("lightbulb", size="xs").classes("text-amber-600 mt-0.5 shrink-0")
                with ui.column().classes("gap-1"):
                    ui.label("Hiện tượng Thiên Lệch Dòng Khóa (Mantin & Shamir, FSE 2001):").classes("text-xs font-bold text-amber-950")
                    ui.label(
                        "Byte thứ 2 của dòng khóa RC4 bằng 0 với xác suất xấp xỉ 2/256 thay vì 1/256 (Mantin & Shamir, FSE 2001); "
                        "do đó byte mã hóa thứ 2 trùng byte bản rõ thứ 2 với xác suất gấp đôi mức ngẫu nhiên; "
                        "thử đổi vị trí byte sang 3 để thấy phân bố gần đều."
                    ).classes("text-xs text-amber-900/90 leading-relaxed")

            with ui.row().classes("w-full items-center gap-4 flex-wrap"):
                # Ô nhập số lượng khóa ngẫu nhiên cần thử nghiệm để tính xác suất thống kê
                num_keys_input = ui.number(
                    label="Số khóa thử",
                    value=20000,
                    min=1000,
                    max=100000,
                    step=1000,
                ).classes("w-44")

                # Ô nhập độ dài khóa tính bằng byte (mặc định 16 byte = 128 bit)
                key_len_input = ui.number(
                    label="Độ dài khóa (byte)",
                    value=16,
                    min=1,
                    max=256,
                    step=1,
                ).classes("w-44")

                # Ô nhập vị trí byte trong dòng khóa cần kiểm tra thiên lệch (byte thứ 2 là trọng tâm)
                byte_idx_input = ui.number(
                    label="Vị trí byte dòng khóa",
                    value=2,
                    min=1,
                    max=16,
                    step=1,
                ).classes("w-44")

                # Bấm nút này gọi run_bias_experiment() để sinh khóa và tính tần suất trong core
                btn_run_bias = ui.button(
                    "Chạy thực nghiệm",
                    icon="science",
                    on_click=lambda: run_bias_experiment(),
                ).props("color=primary").classes("mt-2")

            # ui.linear_progress: thanh tiến trình hiển thị phần trăm khối lượng khóa đã duyệt
            progress_bar = ui.linear_progress(value=0.0, show_value=False).props("instant-feedback stripe").classes("w-full")
            progress_bar.visible = False

            bias_result_box = ui.column().classes("w-full gap-4")

            async def run_bias_experiment() -> None:
                """
                Hàm callback bất đồng bộ gọi keystream_bias_counts trong core và cập nhật biểu đồ phân bố xác suất.

                Tham số: Không có (lấy từ các ô số trên giao diện).
                Trả về: None.
                """
                btn_run_bias.disable()
                progress_bar.visible = True
                progress_bar.set_value(0.0)
                bias_result_box.clear()

                try:
                    total_keys = int(num_keys_input.value or 0)
                    k_len = int(key_len_input.value or 0)
                    b_idx = int(byte_idx_input.value or 0)

                    if not (1000 <= total_keys <= 100000):
                        raise ValueError("Số khóa thử phải từ 1.000 đến 100.000")
                    if not (1 <= k_len <= 256):
                        raise ValueError("Độ dài khóa phải trong khoảng 1–256 byte")
                    if not (1 <= b_idx <= 16):
                        raise ValueError("Vị trí byte dòng khóa phải trong khoảng 1–16")

                    rng = random.Random(2026)
                    accumulated_counts = [0] * 256
                    batch_size = 2000
                    done_keys = 0

                    while done_keys < total_keys:
                        current_batch = min(batch_size, total_keys - done_keys)
                        batch_counts = keystream_bias_counts(
                            num_keys=current_batch,
                            key_len=k_len,
                            byte_index=b_idx,
                            rng=rng,
                        )
                        for i in range(256):
                            accumulated_counts[i] += batch_counts[i]

                        done_keys += current_batch
                        progress_bar.set_value(done_keys / total_keys)
                        await asyncio.sleep(0)

                    frequencies = [c / total_keys for c in accumulated_counts]
                    p0 = frequencies[0]
                    ratio = p0 * 256.0

                    with bias_result_box:
                        with ui.row().classes("w-full items-center justify-between gap-4 flex-wrap pt-2"):
                            with ui.card().classes("flex-1 min-w-[200px] p-3.5 bg-rose-50/70 border border-rose-200 rounded-xl space-y-0.5"):
                                ui.label("P(byte = 0)").classes("text-xs font-bold text-rose-900")
                                ui.label(f"{p0:.4f}").classes("text-xl font-mono font-bold text-rose-700")
                                ui.label(f"Tần suất tại giá trị 0x00 ({accumulated_counts[0]:,} / {total_keys:,})").classes("text-2xs text-rose-600")

                            with ui.card().classes("flex-1 min-w-[200px] p-3.5 bg-slate-50 border border-slate-200 rounded-xl space-y-0.5"):
                                ui.label("Mức đều lý thuyết = 1/256 = 0,0039").classes("text-xs font-bold text-slate-800")
                                ui.label("0.0039").classes("text-xl font-mono font-bold text-slate-700")
                                ui.label("Xác suất kỳ vọng phân bố đều 1/256").classes("text-2xs text-slate-500")

                            with ui.card().classes("flex-1 min-w-[200px] p-3.5 bg-amber-50/70 border border-amber-200 rounded-xl space-y-0.5"):
                                ui.label(f"Gấp {ratio:.2f} lần mức đều").classes("text-xs font-bold text-amber-900")
                                ui.label(f"{ratio:.2f}×").classes("text-xl font-mono font-bold text-amber-700")
                                ui.label(f"N = P × 256 (P = {p0:.4f})").classes("text-2xs text-amber-600")

                        chart_options = {
                            "title": {
                                "text": f"Phân bố tần suất byte dòng khóa thứ {b_idx} (N = {total_keys:,} khóa)",
                                "textStyle": {"fontSize": 13, "fontWeight": "bold", "color": "#1e293b"},
                                "left": "center",
                            },
                            "tooltip": {
                                "trigger": "axis",
                                "axisPointer": {"type": "shadow"},
                            },
                            "grid": {"top": 45, "right": 30, "bottom": 35, "left": 60},
                            "xAxis": {
                                "type": "category",
                                "data": [str(i) for i in range(256)],
                                "name": "Giá trị byte (0..255)",
                                "nameLocation": "middle",
                                "nameGap": 22,
                                "axisLabel": {"interval": 31},
                                "axisLine": {"lineStyle": {"color": "#94a3b8"}},
                            },
                            "yAxis": {
                                "type": "value",
                                "name": "Tần suất",
                                "axisLine": {"lineStyle": {"color": "#94a3b8"}},
                                "splitLine": {"lineStyle": {"color": "#f1f5f9"}},
                            },
                            "series": [
                                {
                                    "name": "Tần suất",
                                    "type": "bar",
                                    "data": [
                                        {
                                            "value": round(frequencies[i], 6),
                                            "itemStyle": {"color": "#ef4444" if i == 0 else "#6366f1"},
                                        }
                                        for i in range(256)
                                    ],
                                    "markLine": {
                                        "silent": True,
                                        "symbol": "none",
                                        "lineStyle": {
                                            "color": "#10b981",
                                            "type": "dashed",
                                            "width": 2,
                                         },
                                        "label": {
                                            "formatter": "1/256 ≈ 0.0039",
                                            "position": "end",
                                        },
                                        "data": [{"yAxis": 1.0 / 256.0}],
                                    },
                                }
                            ],
                        }
                        # ui.echart: vẽ biểu đồ cột thể hiện phân bố xác suất của 256 giá trị byte
                        ui.echart(chart_options).classes("w-full h-72")

                except ValueError as err:
                    ui.notify(str(err), type="negative")
                except Exception as err:
                    ui.notify(f"Đã xảy ra lỗi: {err}", type="negative")
                finally:
                    progress_bar.visible = False
                    btn_run_bias.enable()



