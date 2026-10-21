"""
Tab 4: Đo Hiệu Năng & Tấn Công Dòng Khóa (Điểm Cộng Khuyến Khích)
================================================================
1. Tấn công dùng lại dòng khóa (Keystream Reuse / Two-Time Pad Attack) & Crib-dragging
2. Đo thời gian thực thi theo kích thước dữ liệu (1KB -> 1MB) và vẽ biểu đồ ui.echart
"""

from __future__ import annotations
from nicegui import ui

from src.core.attack_demo import simulate_keystream_reuse_attack
from src.core.benchmark import run_rc4_benchmark


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
            ui.label(
                "Khi 2 bản rõ P1, P2 dùng chung một khóa K (lỗi bảo mật nổi tiếng trong WEP), "
                "kẻ tấn công tính C1 ⊕ C2 = (P1 ⊕ S) ⊕ (P2 ⊕ S) = P1 ⊕ P2 (triệt tiêu hoàn toàn khóa S!)."
            ).classes("text-xs text-slate-600 mb-2")

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
