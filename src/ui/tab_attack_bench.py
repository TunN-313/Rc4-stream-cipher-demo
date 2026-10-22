"""
Tab 4: Đo Hiệu Năng & Tấn Công Dòng Khóa (Điểm Cộng Khuyến Khích)
================================================================
1. Tấn công dùng lại dòng khóa (Keystream Reuse / Two-Time Pad Attack) & Crib-dragging
2. Đo thời gian thực thi theo kích thước dữ liệu (1KB -> 1MB) và vẽ biểu đồ ui.echart
Tích hợp hiển thị công thức toán học KaTeX.
"""

from __future__ import annotations
from nicegui import ui

from src.core.attack_demo import simulate_keystream_reuse_attack
from src.core.benchmark import run_rc4_benchmark

try:
    from nicegui_tabulator import tabulator
    HAS_TABULATOR = True
except ImportError:
    tabulator = None
    HAS_TABULATOR = False


def build_tab_attack_bench() -> None:
    """Xây dựng giao diện Tab 4: Tấn công Keystream Reuse & Đo hiệu năng theo chuẩn Flat Cards Dashboard."""
    with ui.row().classes("w-full gap-6 items-start"):

        # ======================================================================
        # NỬA TRÁI: TẤN CÔNG DÙNG LẠI DÒNG KHÓA (FLAT CARD 1)
        # ======================================================================
        with ui.card().classes("flex-1 p-6 space-y-4"):
            with ui.row().classes("w-full items-center justify-between pb-2 border-b border-slate-100"):
                with ui.row().classes("items-center gap-3"):
                    with ui.row().classes("w-9 h-9 rounded-lg bg-rose-50 text-rose-700 items-center justify-center border border-rose-200"):
                        ui.icon("gpp_bad", size="xs")
                    with ui.column().classes("gap-0"):
                        ui.label("1. Tấn Công Dùng Lại Dòng Khóa (Two-Time Pad)").classes("text-base font-bold text-slate-800")
                        ui.label("Keystream Reuse & Kỹ thuật Crib-dragging thám mã không cần khóa K").classes("text-xs text-slate-500")
                ui.badge("Lỗ hổng WEP/WPA", color="negative").classes("text-xs")

            ui.markdown(
                r"""
Khi hai bản rõ $P_1, P_2$ bị mã hóa bằng **cùng một khóa $K$**, kẻ tấn công tính:
$$C_1 \oplus C_2 = (P_1 \oplus S) \oplus (P_2 \oplus S) = P_1 \oplus P_2$$
*(Dòng khóa $S$ bị triệt tiêu hoàn toàn! Kỹ thuật Crib-dragging cho phép giải mã $P_2$ khi đoán được một phần từ $P_1$).*
                """
            ).classes("text-xs text-slate-700 bg-rose-50/60 border border-rose-200/70 p-3 rounded-lg")

            atk_p1 = ui.input(
                label="Bản rõ P1",
                value="Kinh gui Quy khach: Mat khau OTP la 849201",
            ).classes("w-full")
            atk_p2 = ui.input(
                label="Bản rõ P2",
                value="Chuyen khoan ngay 50000000 VND vao TK 9988",
            ).classes("w-full")
            atk_key = ui.input(
                label="Khóa K dùng chung cho cả 2 bản rõ",
                value="WEP-Reused-Key-123",
            ).classes("w-full")
            atk_crib = ui.input(
                label="Từ đoán trước trong P1 (Crib Word)",
                value="Kinh gui Quy khach",
            ).classes("w-full")

            atk_box = ui.column().classes("w-full gap-2")

            def run_attack_ui() -> None:
                atk_box.clear()
                res = simulate_keystream_reuse_attack(
                    atk_p1.value, atk_p2.value, atk_key.value, atk_crib.value
                )
                with atk_box:
                    with ui.column().classes("w-full p-3 bg-slate-50 rounded-lg border border-slate-200/60 font-mono text-xs text-slate-700 gap-1"):
                        ui.label(f"Bản mã C1 (Hex): {res.c1_hex[:44]}...")
                        ui.label(f"Bản mã C2 (Hex): {res.c2_hex[:44]}...")
                        ui.label(f"C1 ⊕ C2 (Hex)  : {res.xor_c1_c2_hex[:44]}...").classes("text-rose-700 font-bold")

                    with ui.row().classes("items-center gap-2"):
                        ui.badge(
                            f"Kiểm chứng: C1 ⊕ C2 == P1 ⊕ P2 {'(Khóa S bị triệt tiêu hoàn toàn!)' if res.streams_equal else '(Lỗi)'}",
                            color="negative" if res.streams_equal else "warning",
                        ).classes("text-xs")

                    if res.crib_matches:
                        pos, crib, recovered_p2 = res.crib_matches[0]
                        with ui.card().classes("w-full bg-rose-50/70 border border-rose-200 p-3.5 space-y-1"):
                            ui.label(f"Khôi phục đoạn P2 tại vị trí byte {pos} với Crib '{crib}':").classes("text-xs font-bold text-rose-900")
                            ui.label(f"→ Nội dung giải mã được: \"{recovered_p2}\"").classes(
                                "text-sm font-mono font-bold text-rose-800"
                            )

            ui.button("Thực hiện Thám mã Known-Plaintext", icon="bolt", on_click=run_attack_ui).props(
                "color=negative"
            )
            run_attack_ui()

        # ======================================================================
        # NỬA PHẢI: ĐO HIỆU NĂNG THEO KÍCH THƯỚC DỮ LIỆU (FLAT CARD 2)
        # ======================================================================
        with ui.card().classes("flex-1 p-6 space-y-4"):
            with ui.row().classes("w-full items-center justify-between pb-2 border-b border-slate-100"):
                with ui.row().classes("items-center gap-3"):
                    with ui.row().classes("w-9 h-9 rounded-lg bg-indigo-50 text-indigo-700 items-center justify-center border border-indigo-200"):
                        ui.icon("speed", size="xs")
                    with ui.column().classes("gap-0"):
                        ui.label("2. Đo Hiệu Năng Thực Thi (Benchmark)").classes("text-base font-bold text-slate-800")
                        ui.label("Đo thời gian (ms) & thông lượng (MB/s) trên CPU từ 1 KB đến 1 MB").classes("text-xs text-slate-500")
                ui.button("Chạy Lại Đo Tốc Độ", icon="play_arrow", on_click=lambda: run_bench_ui()).props(
                    "color=primary size=sm"
                )

            bench_box = ui.column().classes("w-full gap-3")

            def run_bench_ui() -> None:
                bench_box.clear()
                rows = run_rc4_benchmark([1, 10, 50, 100, 250, 500, 1024])
                with bench_box:
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

            run_bench_ui()
