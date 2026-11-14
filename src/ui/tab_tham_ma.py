"""Tab 5: Tấn công khôi phục khóa FMS trên giao thức WEP."""

from __future__ import annotations
import asyncio
from typing import Optional
from nicegui import ui

from src.core import (
    fms_partial_ksa,
    fms_predict_first_output,
    simulate_fms_wep_attack,
    FMSAttackResult,
    FMSByteResult,
)


def dung_tab_tham_ma() -> None:
    """Khởi tạo giao diện mô phỏng tấn công khôi phục khóa FMS trên WEP."""
    with ui.column().classes("w-full gap-6 max-w-6xl mx-auto pb-8"):
        with ui.card().classes("w-full p-6 space-y-4"):
            with ui.row().classes("w-full items-center justify-between pb-2 border-b border-slate-100"):
                with ui.row().classes("items-center gap-3"):
                    with ui.row().classes("w-9 h-9 rounded-lg bg-red-50 text-red-700 items-center justify-center border border-red-200"):
                        ui.icon("lock_open", size="xs")
                    with ui.column().classes("gap-0"):
                        ui.label("Tấn công khôi phục khóa FMS trên WEP").classes("text-base font-bold text-slate-800")
                        ui.label("Phương pháp Fluhrer–Mantin–Shamir (2001) • Khôi phục khóa bí mật K").classes("text-xs text-slate-500")

            with ui.column().classes("w-full bg-red-50/70 border border-red-200/80 p-3.5 rounded-xl gap-2"):
                with ui.row().classes("w-full items-start gap-2"):
                    ui.icon("psychology", size="xs").classes("text-red-600 mt-0.5 shrink-0")
                    ui.label(
                        "Nguyên lý Tấn công FMS: Khôi phục Khóa bí mật K chứ không chỉ đọc bản rõ hay quan sát thiên lệch:"
                    ).classes("text-xs font-semibold text-red-950 leading-relaxed")
                ui.markdown(
                    r"* **Cơ chế ghép khóa WEP**: Khóa từng gói tin được ghép từ `IV || K` với `IV` (3 byte) truyền công khai."
                    "\n"
                    r"* **Suy luận tuần tự**: Bằng cách thu thập các gói tin chứa lớp IV yếu `(A + 3, 0xFF, X)` và biết byte đầu `P[0] = 0xAA` (tiêu đề SNAP/LLC), "
                    r"kẻ tấn công mô phỏng KSA đã biết để bỏ phiếu tìm từng byte `K[A]` qua xác suất bảo toàn trạng thái (e⁻³ ≈ 5%). "
                    r"Sau khi tìm đủ các byte, hệ thống kiểm chứng độc lập trên 50 gói để ngăn ngừa sai lệch dây chuyền."
                ).classes("text-xs text-red-900/90 leading-relaxed pl-6")

            with ui.row().classes("w-full items-center gap-3 flex-wrap"):
                fms_key_input = ui.input(
                    label="Khóa bí mật K (chuỗi hoặc 0xHex)",
                    value="KEY_1",
                ).classes("w-52")

                fms_p0_input = ui.input(
                    label="Byte bản rõ đầu P[0]",
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

            # Dùng layout tĩnh và mutate properties thay vì .clear() để tránh xung đột reactivity trong Vue Virtual DOM
            with ui.column().classes("w-full gap-4"):
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

                with ui.column().classes("w-full p-4 bg-slate-50 border border-slate-200/80 rounded-xl gap-2 text-xs text-slate-700"):
                    ui.label("Nhận xét Mật Mã Học & Đánh Giá An Toàn:").classes("font-bold text-slate-800 text-sm")
                    ui.markdown(
                        """
* **Tỷ lệ tín hiệu trên nhiễu**: Xác suất trạng thái KSA được bảo toàn để cho ra manh mối tin cậy chỉ khoảng `e⁻³ ≈ 0.05` (khoảng 20 gói tin mới có 1 gói hữu ích). Do đó, cần thu thập đủ lượng mẫu (ví dụ 600 gói/byte) thì giá trị đúng mới có số phiếu tách biệt khỏi mức nhiễu ngẫu nhiên.
* **Hiện tượng byte sít sao**: Byte cuối `K[4]` chỉ dẫn đầu với cách biệt nhỏ (17 phiếu so với 11 phiếu của giá trị đứng nhì). Vì vậy, việc chọn ứng viên nhiều phiếu nhất chưa thể khẳng định đúng nếu chưa qua bước kiểm chứng.
* **Tầm quan trọng của bước kiểm chứng**: Sau khi có khóa ứng viên, bắt buộc phải khởi tạo lại RC4 và đối chiếu đầu ra với dữ liệu bắt được trên 50 gói độc lập để ngăn chặn lỗi sai lệch dây chuyền.
* **4 Giới hạn mật mã**:
  1. *Phụ thuộc cơ chế tạo khóa*: FMS chỉ khai thác được khi giao thức ghép `IV || K`; nếu các khóa được sinh độc lập, quan hệ này biến mất.
  2. *Cần byte đầu P[0]*: Cần biết trước byte đầu `P[0]` (như SNAP/LLC header) để suy ra `Z[0]`.
  3. *Phụ thuộc chất lượng và lượng mẫu*: Cần đủ các gói mang IV yếu thuộc lớp `(A + 3, 0xFF, X)`.
  4. *Không suy rộng sang TLS*: Các tấn công trong TLS (AlFardan, NOMORE) khai thác sai lệch dòng khóa để khôi phục bản rõ, hoàn toàn khác với việc bẻ khóa bí mật `K` trong WEP.
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

                lbl_sec_key.text = f"{res.secret_key_bytes} (Hex: {res.secret_key_bytes.hex().upper()})"
                lbl_rec_key.text = f"{res.recovered_key_bytes} (Hex: {res.recovered_key_bytes.hex().upper()})"
                lbl_rec_key.style(f"color: {'#047857' if res.all_matched else '#be123c'}")

                badge_match.text = "Khớp hoàn toàn" if res.all_matched else "Chưa khớp hoàn toàn"
                badge_match.props(f"color={'positive' if res.all_matched else 'negative'}")

                pct = res.verified_packets / max(res.total_verified_packets, 1) * 100
                badge_verify.text = f"Kiểm chứng độc lập: {res.verified_packets}/{res.total_verified_packets} gói ({pct:.0f}%)"
                badge_verify.props(f"color={'positive' if res.verified_packets == res.total_verified_packets else 'warning'}")

                badge_time.text = f"Thời gian: {res.elapsed_ms:.1f} ms"
                badge_time.props("color=primary")

                lbl_packet_count.text = f"Tổng gói tin IV yếu đã xét: {res.collected_packets_count} gói"

                # id duy nhất theo từng lượt chạy để giao diện không dùng lại phần tử cũ làm lệch dòng chọn
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

                    # Chạy thuật toán thám mã trong executor để giải phóng async thread của NiceGUI
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

            initial_fms_res = simulate_fms_wep_attack("KEY_1", 600, 0xAA, 50, 42)
            render_fms_result(initial_fms_res)
