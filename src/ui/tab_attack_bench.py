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
    """Xây dựng giao diện Tab 4: Tấn công Keystream Reuse & Đo hiệu năng."""
    with ui.row().classes("w-full gap-6 items-start"):

        # ======================================================================
        # NỬA TRÁI: TẤN CÔNG DÙNG LẠI DÒNG KHÓA (TWO-TIME PAD ATTACK)
        # ======================================================================
        with ui.card().classes("flex-1 p-5 border-t-4 border-rose-600 shadow-sm"):
            ui.label("1. Minh họa Tấn công Dùng lại Dòng khóa (Keystream Reuse Attack)").classes(
                "text-lg font-bold text-slate-800"
            )
            ui.markdown(
                r"""
Khi hai bản rõ $P_1, P_2$ bị mã hóa bằng **cùng một khóa $K$** (lỗ hổng kinh điển trong WEP), kẻ tấn công tính:
$$C_1 \oplus C_2 = (P_1 \oplus S) \oplus (P_2 \oplus S) = P_1 \oplus P_2$$
*(Dòng khóa $S$ bị triệt tiêu hoàn toàn! Kẻ tấn công dùng kỹ thuật Crib-dragging để đọc trộm bản rõ mà không cần khóa $K$).*
                """
            ).classes("text-xs text-slate-700 bg-rose-50 border border-rose-100 p-3 rounded mb-2")

            atk_p1 = ui.input(
                label="Bản rõ P1",
                value="Kinh gui Quy khach: Mat khau OTP la 849201",
            ).classes("w-full")
            atk_p2 = ui.input(
                label="Bản rõ P2",
                value="Chuyen khoan ngay 50000000 VND vao TK 9988",
            ).classes("w-full")
            atk_key = ui.input(
                label="Khóa K bị dùng lại",
                value="WEP-Reused-Key-123",
            ).classes("w-full")
            atk_crib = ui.input(
                label="Từ đoán trước trong P1 (Crib-dragging, theo Slide 13)",
                value="Kinh gui Quy khach",
            ).classes("w-full")

            atk_box = ui.column().classes("w-full mt-3")

            def run_attack_ui() -> None:
                atk_box.clear()
                res = simulate_keystream_reuse_attack(
                    atk_p1.value, atk_p2.value, atk_key.value, atk_crib.value
                )
                with atk_box:
                    ui.label(f"Bản mã C1 (Hex): {res.c1_hex[:48]}...").classes("font-mono text-xs")
                    ui.label(f"Bản mã C2 (Hex): {res.c2_hex[:48]}...").classes("font-mono text-xs")
                    ui.label(f"C1 ⊕ C2 (Hex)  : {res.xor_c1_c2_hex[:48]}...").classes(
                        "font-mono text-xs text-rose-700 font-bold"
                    )
                    ui.badge(
                        f"Kiểm chứng C1 ⊕ C2 == P1 ⊕ P2: {'ĐÚNG (Khóa S đã bị triệt tiêu!)' if res.streams_equal else 'SAI'}",
                        color="negative",
                    ).classes("my-2")

                    if res.crib_matches:
                        pos, crib, recovered_p2 = res.crib_matches[0]
                        with ui.card().classes("w-full bg-rose-50 border border-rose-200 p-3"):
                            ui.label(
                                f"Khôi phục P2 tại vị trí byte {pos} khi biết P1 bắt đầu bằng '{crib}':"
                            ).classes("text-xs font-bold text-rose-900")
                            ui.label(f"→ Đoạn bản rõ P2 lộ ra: \"{recovered_p2}\"").classes(
                                "text-base font-mono font-bold text-rose-800"
                            )

            ui.button("Thực hiện Tấn công Thám mã (Known-Plaintext)", icon="gpp_bad", on_click=run_attack_ui).props(
                "color=negative"
            )
            run_attack_ui()

        # ======================================================================
        # NỬA PHẢI: ĐO HIỆU NĂNG THEO KÍCH THƯỚC DỮ LIỆU
        # ======================================================================
        with ui.card().classes("flex-1 p-5 border-t-4 border-indigo-600 shadow-sm"):
            ui.label("2. Đo Thời Gian Chạy Theo Kích Thước Dữ Liệu (Benchmark)").classes(
                "text-lg font-bold text-slate-800"
            )
            ui.label(
                "Đo thời gian mã hóa (ms) và thông lượng (MB/s) trên CPU với các kích thước từ 1 KB đến 1 MB."
            ).classes("text-xs text-slate-600 mb-2")

            bench_box = ui.column().classes("w-full mt-2")

            def run_bench_ui() -> None:
                bench_box.clear()
                rows = run_rc4_benchmark([1, 10, 50, 100, 250, 500, 1024])
                with bench_box:
                    ui.echart(
                        {
                            "tooltip": {"trigger": "axis"},
                            "xAxis": {"type": "category", "data": [r["size_label"] for r in rows]},
                            "yAxis": {"type": "value", "name": "Thời gian (ms)"},
                            "series": [
                                {
                                    "name": "Thời gian mã hóa (ms)",
                                    "type": "line",
                                    "smooth": True,
                                    "data": [r["elapsed_ms"] for r in rows],
                                    "itemStyle": {"color": "#4f46e5"},
                                }
                            ],
                        }
                    ).classes("w-full h-56")

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
                        ).classes("w-full shadow-sm rounded border border-slate-200 mt-2")

                        with ui.row().classes("w-full items-center justify-between mt-2"):
                            ui.badge("Interactive Tabulator Engine", color="primary").classes("text-xs px-2 py-0.5")
                            ui.button(
                                "Xuất dữ liệu đo đạc (CSV)",
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

            ui.button("Chạy Đo Hiệu Năng (1 KB → 1 MB)", icon="speed", on_click=run_bench_ui).props(
                "color=primary"
            )
            run_bench_ui()
