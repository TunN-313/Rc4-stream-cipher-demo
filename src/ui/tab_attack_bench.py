"""
Tab 4: Đo Hiệu Năng & Tấn Công Dòng Khóa (Two-Time Pad, Crib-dragging & Bias)
======================================================================
Tab này mô phỏng lỗ hổng dùng lại dòng khóa (Two-Time Pad), kỹ thuật thám mã Crib-dragging,
đo thông lượng mã hóa (1 KB - 1 MB) và phân tích thiên lệch xác suất byte dòng khóa (Mantin-Shamir).
Người dùng nhập bản rõ, từ đoán trước, số lượng khóa ngẫu nhiên và theo dõi kết quả trực quan.
Gọi các hàm phân tích từ src.core.analysis: simulate_keystream_reuse_attack, run_rc4_benchmark, keystream_bias_counts.
"""

from __future__ import annotations  # dùng để hỗ trợ chú thích kiểu dữ liệu hiện đại
import asyncio  # dùng để xử lý tác vụ bất đồng bộ, cập nhật giao diện mượt mà không bị treo
import html  # dùng để mã hóa an toàn các ký tự đặc biệt sang định dạng HTML
import random  # dùng để sinh số ngẫu nhiên phục vụ tạo khóa thử nghiệm
from typing import Optional  # dùng để định nghĩa kiểu dữ liệu có thể nhận giá trị None
from nicegui import ui  # dùng để xây dựng các thành phần giao diện web (nút, bảng, biểu đồ)

from src.core.analysis import (  # dùng để gọi các hàm phân tích bảo mật và hiệu năng từ tầng core
    keystream_bias_counts,
    run_rc4_benchmark,
    simulate_keystream_reuse_attack,
)

# Tabulator là thư viện bảng thông minh hỗ trợ thanh tiến trình trực quan và xuất dữ liệu CSV
try:
    from nicegui_tabulator import tabulator  # dùng để dựng bảng đo hiệu năng Tabulator
    HAS_TABULATOR = True
except ImportError:
    tabulator = None
    HAS_TABULATOR = False


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


def build_tab_attack_bench() -> None:
    """
    Xây dựng giao diện Tab 4: Tấn công Keystream Reuse, đo hiệu năng và thiên lệch Mantin-Shamir.

    Tham số: Không có.
    Trả về: None.
    """
    with ui.row().classes("w-full gap-6 items-start"):  # các lớp Tailwind căn chỉnh hàng ngang

        # ======================================================================
        # NỬA TRÁI: TẤN CÔNG DÙNG LẠI DÒNG KHÓA (FLAT CARD 1)
        # ======================================================================
        with ui.card().classes("flex-1 p-6 space-y-4"):  # khung card bo góc bên trái
            with ui.row().classes("w-full items-center justify-between pb-2 border-b border-slate-100"):
                with ui.row().classes("items-center gap-3"):
                    with ui.row().classes("w-9 h-9 rounded-lg bg-rose-50 text-rose-700 items-center justify-center border border-rose-200"):
                        ui.icon("gpp_bad", size="xs")
                    with ui.column().classes("gap-0"):
                        ui.label("1. Tấn Công Dùng Lại Dòng Khóa (Two-Time Pad)").classes("text-base font-bold text-slate-800")
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

            def run_attack_ui() -> None:
                """
                Hàm callback gọi simulate_keystream_reuse_attack trong core và cập nhật giao diện thám mã.

                Tham số: Không có (lấy trực tiếp từ các ô nhập giao diện).
                Trả về: None.
                """
                atk_box.clear()
                crib_in_val = (atk_crib_in.value or "P1").lower()
                crib_text = atk_crib.value or ""
                res = simulate_keystream_reuse_attack(
                    atk_p1.value,
                    atk_p2.value,
                    atk_key.value,
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
                            <q-tr :props="props" :class="props.row.matches_real ? 'bg-emerald-50 text-emerald-950 font-medium' : ''" @click="props.selected = !props.selected" class="cursor-pointer">
                                <q-td auto-width @click.stop>
                                    <q-checkbox v-model="props.selected" dense />
                                </q-td>
                                <q-td v-for="col in props.cols" :key="col.name" :props="props">
                                    {{ col.value }}
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

            # Bấm nút này gọi hàm run_attack_ui() để tính toán thám mã và hiển thị kết quả ở atk_box
            ui.button("Thực hiện Thám mã Known-Plaintext", icon="bolt", on_click=run_attack_ui).props(
                "color=negative"
            )
            atk_box = ui.column().classes("w-full gap-3")
            # Tự động thực hiện thám mã ngay khi mở tab để hiển thị kết quả mẫu ban đầu
            run_attack_ui()

        # ======================================================================
        # NỬA PHẢI: ĐO HIỆU NĂNG THEO KÍCH THƯỚC DỮ LIỆU (FLAT CARD 2)
        # ======================================================================
        with ui.card().classes("flex-1 p-6 space-y-4"):  # khung card bo góc bên phải
            with ui.row().classes("w-full items-center justify-between pb-2 border-b border-slate-100"):
                with ui.row().classes("items-center gap-3"):
                    with ui.row().classes("w-9 h-9 rounded-lg bg-indigo-50 text-indigo-700 items-center justify-center border border-indigo-200"):
                        ui.icon("speed", size="xs")
                    with ui.column().classes("gap-0"):
                        ui.label("2. Đo Hiệu Năng Thực Thi (Benchmark)").classes("text-base font-bold text-slate-800")
                        ui.label("Đo thời gian (ms) & thông lượng (MB/s) trên CPU từ 1 KB đến 1 MB").classes("text-xs text-slate-500")
                # Bấm nút này gọi run_bench_ui() để đo lại thời gian mã hóa trên nhiều kích cỡ file
                ui.button("Chạy Lại Đo Tốc Độ", icon="play_arrow", on_click=lambda: run_bench_ui()).props(
                    "color=primary size=sm"
                )

            bench_box = ui.column().classes("w-full gap-3")

            def run_bench_ui() -> None:
                """
                Hàm callback gọi run_rc4_benchmark trong core và vẽ biểu đồ tốc độ cùng bảng dữ liệu.

                Tham số: Không có.
                Trả về: None.
                """
                bench_box.clear()
                rows = run_rc4_benchmark([1, 10, 50, 100, 250, 500, 1024])
                with bench_box:
                    # ui.echart: thành phần vẽ biểu đồ Apache ECharts tương tác (rê chuột xem số liệu)
                    ui.echart(
                        {
                            "tooltip": {"trigger": "axis"},
                            "grid": {"top": 30, "right": 20, "bottom": 30, "left": 50},
                            "xAxis": {
                                "type": "category",
                                "data": [r["size_label"] for r in rows],
                                "axisLine": {"lineStyle": {"color": "#94a3b8"}},
                            },
                            "yAxis": {
                                "type": "value",
                                "name": "Thời gian (ms)",
                                "axisLine": {"lineStyle": {"color": "#94a3b8"}},
                                "splitLine": {"lineStyle": {"color": "#f1f5f9"}},
                            },
                            "series": [
                                {
                                    "name": "Thời gian mã hóa (ms)",
                                    "type": "line",
                                    "smooth": True,
                                    "data": [r["elapsed_ms"] for r in rows],
                                    "itemStyle": {"color": "#4f46e5"},
                                    "areaStyle": {
                                        "color": {
                                            "type": "linear",
                                            "x": 0, "y": 0, "x2": 0, "y2": 1,
                                             "colorStops": [
                                                {"offset": 0, "color": "rgba(79, 70, 229, 0.25)"},
                                                {"offset": 1, "color": "rgba(79, 70, 229, 0.0)"},
                                            ],
                                        }
                                    },
                                }
                            ],
                        }
                    ).classes("w-full h-52")

                    if HAS_TABULATOR:
                        max_speed = max([r["throughput_mb_s"] for r in rows], default=100.0)
                        bench_tab_rows = [
                            {
                                "id": idx + 1,
                                "size_label": r["size_label"],
                                "bytes": f"{r['bytes']:,} B",
                                "elapsed_ms": f"{r['elapsed_ms']:.2f} ms",
                                "throughput_mb_s": r["throughput_mb_s"],
                            }
                            for idx, r in enumerate(rows)
                        ]
                        bench_tab_cols = [
                            {"title": "#", "field": "id", "width": 50, "hozAlign": "center"},
                            {"title": "Kích thước", "field": "size_label", "width": 110},
                            {"title": "Số Bytes", "field": "bytes", "hozAlign": "right", "width": 120},
                            {"title": "Thời gian (ms)", "field": "elapsed_ms", "hozAlign": "right", "width": 130},
                            {
                                "title": "Thông lượng (MB/s)",
                                "field": "throughput_mb_s",
                                "formatter": "progress",
                                "formatterParams": {
                                    "color": ["#3b82f6", "#10b981"],
                                    "legend": True,
                                    "legendColor": "#0f172a",
                                    "legendAlign": "center",
                                    "max": max(round(max_speed * 1.15, 1), 10.0),
                                },
                            },
                        ]
                        bench_tbl = tabulator(
                            {
                                "data": bench_tab_rows,
                                "layout": "fitColumns",
                                "columns": bench_tab_cols,
                            },
                            row_key="id",
                        ).classes("w-full shadow-xs rounded-xl border border-slate-200")

                        with ui.row().classes("w-full items-center justify-between pt-1"):
                            ui.badge("Tabulator Progress Engine", color="primary").classes("text-xs")
                            # Bấm nút này để xuất bảng kết quả đo hiệu năng ra tệp CSV
                            ui.button(
                                "Xuất Bảng Đo CSV",
                                icon="download",
                                on_click=lambda: bench_tbl.run_table_method("download", "csv", "rc4_benchmark_measurements.csv"),
                            ).props("size=sm outline color=primary")
                    else:
                        cols = [
                            {"name": "size_label", "label": "Kích thước", "field": "size_label", "align": "left"},
                            {"name": "bytes", "label": "Số Bytes", "field": "bytes", "align": "right"},
                            {"name": "elapsed_ms", "label": "Thời gian (ms)", "field": "elapsed_ms", "align": "right"},
                            {"name": "throughput_mb_s", "label": "Tốc độ (MB/s)", "field": "throughput_mb_s", "align": "right"},
                        ]
                        ui.table(columns=cols, rows=rows, row_key="size_label").classes("w-full")

            # Tự động đo tốc độ lần đầu ngay khi mở giao diện
            run_bench_ui()

    # ======================================================================
    # THẺ 3: THIÊN LỆCH DÒNG KHÓA (MANTIN–SHAMIR BIAS)
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

