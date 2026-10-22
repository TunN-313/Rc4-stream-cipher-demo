"""
Tạo Bộ Icon PWA Chuẩn Cho RC4 Lab
==================================
Tạo các biểu tượng chuẩn PWA:
- icon-192.png (192x192)
- icon-512.png (512x512)
- icon-maskable.png (512x512 với safe zone padding)
- favicon.ico (64x64)
Thiết kế: Nền gradient Slate-950, biểu tượng chiếc khiên bảo mật Neon Gradient Blue/Indigo
kết hợp biểu tượng khóa mật mã và chữ RC4.
"""

import math
import os
from PIL import Image, ImageDraw, ImageFont

OUTPUT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static", "pwa")
os.makedirs(OUTPUT_DIR, exist_ok=True)


def draw_pwa_icon(size: int, is_maskable: bool = False) -> Image.Image:
    """Vẽ icon chất lượng cao chuẩn PWA."""
    # Vẽ ở độ phân giải gấp đôi (supersampling) để khử răng cưa mượt mà
    scale = 2
    actual_size = size * scale
    img = Image.new("RGBA", (actual_size, actual_size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    # 1. Vẽ nền (Background)
    # Maskable cần safe zone (khoảng 80% vùng trung tâm)
    if is_maskable:
        # Nền bao trọn toàn bộ khung hình cho maskable
        for y in range(actual_size):
            r = int(15 + (y / actual_size) * 10)
            g = int(23 + (y / actual_size) * 15)
            b = int(42 + (y / actual_size) * 20)
            draw.line([(0, y), (actual_size, y)], fill=(r, g, b, 255))
        padding = actual_size * 0.15
    else:
        # Nền bo góc mềm mại cho icon thông thường
        padding = actual_size * 0.05
        corner_radius = actual_size * 0.22
        # Vẽ hình chữ nhật bo tròn nền Slate-950 / Slate-900 gradient
        bg_mask = Image.new("L", (actual_size, actual_size), 0)
        mask_draw = ImageDraw.Draw(bg_mask)
        mask_draw.rounded_rectangle(
            [(padding, padding), (actual_size - padding, actual_size - padding)],
            radius=corner_radius,
            fill=255
        )
        
        # Tạo gradient cho nền
        bg_layer = Image.new("RGBA", (actual_size, actual_size), (0, 0, 0, 0))
        bg_draw = ImageDraw.Draw(bg_layer)
        for y in range(actual_size):
            r = int(15 + (y / actual_size) * 8)
            g = int(23 + (y / actual_size) * 12)
            b = int(42 + (y / actual_size) * 18)
            bg_draw.line([(0, y), (actual_size, y)], fill=(r, g, b, 255))
        
        img.paste(bg_layer, (0, 0), bg_mask)

        # Viền neon tinh tế quanh khung
        draw.rounded_rectangle(
            [(padding, padding), (actual_size - padding, actual_size - padding)],
            radius=corner_radius,
            outline=(59, 130, 246, 90),
            width=int(2 * scale)
        )

    # 2. Vẽ Biểu Tượng Chiếc Khiên Bảo Mật (Shield)
    cx = actual_size / 2
    cy = actual_size / 2
    shield_w = (actual_size - 2 * padding) * 0.68
    shield_h = (actual_size - 2 * padding) * 0.78
    top_y = cy - shield_h * 0.48
    bottom_y = cy + shield_h * 0.50
    left_x = cx - shield_w / 2
    right_x = cx + shield_w / 2

    # Các điểm của chiếc khiên hình ngũ giác bo đáy
    shield_points = [
        (left_x, top_y),
        (right_x, top_y),
        (right_x, top_y + shield_h * 0.52),
        (cx, bottom_y),
        (left_x, top_y + shield_h * 0.52),
    ]

    # Tạo gradient cho chiếc khiên (Blue 600 -> Indigo 600)
    shield_mask = Image.new("L", (actual_size, actual_size), 0)
    s_draw = ImageDraw.Draw(shield_mask)
    s_draw.polygon(shield_points, fill=255)

    shield_img = Image.new("RGBA", (actual_size, actual_size), (0, 0, 0, 0))
    sh_draw = ImageDraw.Draw(shield_img)
    for y in range(int(top_y), int(bottom_y) + 1):
        ratio = (y - top_y) / max(1, (bottom_y - top_y))
        # Gradient từ Electric Blue sang Indigo
        sr = int(37 + ratio * 42)
        sg = int(99 + ratio * 20)
        sb = int(235 - ratio * 25)
        sh_draw.line([(0, y), (actual_size, y)], fill=(sr, sg, sb, 255))

    img.paste(shield_img, (0, 0), shield_mask)

    # Viền chiếc khiên sáng màu Cyan / Light Blue
    draw.polygon(shield_points, outline=(96, 165, 250, 230), width=int(3 * scale))

    # 3. Vẽ Chi Tiết Khóa / Mật Mã ở Trung Tâm Khiên
    # Vòng tròn ổ khóa
    lock_cx = cx
    lock_cy = cy - shield_h * 0.08
    shackle_r = shield_w * 0.18
    shackle_top = lock_cy - shackle_r * 1.5
    shackle_width = int(4 * scale)

    # Quai khóa (Shackle)
    draw.arc(
        [(lock_cx - shackle_r, shackle_top), (lock_cx + shackle_r, shackle_top + shackle_r * 2)],
        start=180, end=0,
        fill=(255, 255, 255, 240),
        width=shackle_width
    )
    draw.line(
        [(lock_cx - shackle_r, shackle_top + shackle_r), (lock_cx - shackle_r, lock_cy)],
        fill=(255, 255, 255, 240),
        width=shackle_width
    )
    draw.line(
        [(lock_cx + shackle_r, shackle_top + shackle_r), (lock_cx + shackle_r, lock_cy)],
        fill=(255, 255, 255, 240),
        width=shackle_width
    )

    # Thân ổ khóa
    body_w = shackle_r * 2.8
    body_h = shackle_r * 2.0
    body_x0 = lock_cx - body_w / 2
    body_y0 = lock_cy
    draw.rounded_rectangle(
        [(body_x0, body_y0), (body_x0 + body_w, body_y0 + body_h)],
        radius=int(4 * scale),
        fill=(15, 23, 42, 230),
        outline=(255, 255, 255, 230),
        width=int(2 * scale)
    )

    # Lỗ khóa (Keyhole)
    hole_r = shackle_r * 0.28
    hole_cy = body_y0 + body_h * 0.4
    draw.ellipse(
        [(lock_cx - hole_r, hole_cy - hole_r), (lock_cx + hole_r, hole_cy + hole_r)],
        fill=(56, 189, 248, 255)
    )
    draw.polygon(
        [
            (lock_cx - hole_r * 0.6, hole_cy),
            (lock_cx + hole_r * 0.6, hole_cy),
            (lock_cx + hole_r * 0.9, body_y0 + body_h * 0.78),
            (lock_cx - hole_r * 0.9, body_y0 + body_h * 0.78),
        ],
        fill=(56, 189, 248, 255)
    )

    # 4. Chữ "RC4" bên dưới chiếc khiên
    try:
        font_size = int(size * 0.16 * scale)
        font = ImageFont.truetype("arialbd.ttf", font_size)
    except Exception:
        font = ImageFont.load_default()

    text = "RC4"
    bbox = draw.textbbox((0, 0), text, font=font)
    tw = bbox[2] - bbox[0]
    th = bbox[3] - bbox[1]
    text_x = cx - tw / 2
    text_y = bottom_y - th * 1.5
    # Vẽ chữ màu trắng với viền nhẹ
    draw.text((text_x, text_y), text, fill=(255, 255, 255, 255), font=font)

    # 5. Thu nhỏ về kích thước thực tế với bộ lọc khử răng cưa LANCZOS
    final_img = img.resize((size, size), Image.Resampling.LANCZOS)
    return final_img


def main():
    print("Generating PWA icons for RC4 Lab...")
    
    # 1. icon-192.png
    icon192 = draw_pwa_icon(192)
    path192 = os.path.join(OUTPUT_DIR, "icon-192.png")
    icon192.save(path192, format="PNG")
    print(f" -> Created: {path192}")

    # 2. icon-512.png
    icon512 = draw_pwa_icon(512)
    path512 = os.path.join(OUTPUT_DIR, "icon-512.png")
    icon512.save(path512, format="PNG")
    print(f" -> Created: {path512}")

    # 3. icon-maskable.png
    icon_maskable = draw_pwa_icon(512, is_maskable=True)
    path_maskable = os.path.join(OUTPUT_DIR, "icon-maskable.png")
    icon_maskable.save(path_maskable, format="PNG")
    print(f" -> Created: {path_maskable}")

    # 4. favicon.ico
    icon64 = draw_pwa_icon(64)
    path_favicon = os.path.join(OUTPUT_DIR, "favicon.ico")
    icon64.save(path_favicon, format="ICO")
    print(f" -> Created: {path_favicon}")

    print("PWA icons generated successfully!")


if __name__ == "__main__":
    main()
