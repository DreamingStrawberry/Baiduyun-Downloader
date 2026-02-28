"""구름 + 다운로드 화살표 아이콘 생성 (Baidu Blue)"""
from PIL import Image, ImageDraw
import math

def draw_icon(size):
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    s = size  # shorthand

    # 둥근 사각형 배경 (바이두 블루 그라데이션 효과)
    pad = int(s * 0.06)
    radius = int(s * 0.18)
    # 배경
    d.rounded_rectangle(
        [pad, pad, s - pad, s - pad],
        radius=radius,
        fill=(33, 150, 243, 255),  # #2196F3
    )

    # 구름 (흰색)
    cx, cy = s * 0.5, s * 0.32
    # 메인 원
    r1 = s * 0.18
    d.ellipse([cx - r1, cy - r1, cx + r1, cy + r1], fill="white")
    # 좌측 작은 원
    r2 = s * 0.13
    lx = cx - s * 0.16
    ly = cy + s * 0.04
    d.ellipse([lx - r2, ly - r2, lx + r2, ly + r2], fill="white")
    # 우측 중간 원
    r3 = s * 0.15
    rx = cx + s * 0.17
    ry = cy + s * 0.02
    d.ellipse([rx - r3, ry - r3, rx + r3, ry + r3], fill="white")
    # 하단 직사각형 (구름 바닥 평탄화)
    bottom = cy + r1 * 0.4
    d.rectangle([lx - r2 * 0.3, bottom, rx + r3 * 0.3, cy + r1 * 0.95], fill="white")

    # 다운로드 화살표 (흰색)
    arrow_color = (255, 255, 255, 255)
    arrow_cx = s * 0.5
    arrow_top = s * 0.48
    arrow_bottom = s * 0.82
    shaft_w = s * 0.08  # 화살표 축 반폭
    head_w = s * 0.18   # 화살표 머리 반폭
    head_start = s * 0.64  # 머리 시작 Y

    # 축 (세로 막대)
    d.rectangle([
        arrow_cx - shaft_w, arrow_top,
        arrow_cx + shaft_w, head_start + s * 0.02
    ], fill=arrow_color)

    # 화살표 머리 (▼ 삼각형)
    d.polygon([
        (arrow_cx - head_w, head_start),
        (arrow_cx + head_w, head_start),
        (arrow_cx, arrow_bottom),
    ], fill=arrow_color)

    # 바닥 라인 (트레이)
    line_y = s * 0.86
    line_w = s * 0.04
    d.rounded_rectangle([
        arrow_cx - head_w * 1.1, line_y,
        arrow_cx + head_w * 1.1, line_y + line_w,
    ], radius=int(line_w / 2), fill="white")

    return img

# 여러 크기 생성
sizes = [16, 24, 32, 48, 64, 128, 256]
images = [draw_icon(s) for s in sizes]

# ICO 저장 (모든 크기 포함)
images[-1].save(
    "app_icon.ico",
    format="ICO",
    sizes=[(s, s) for s in sizes],
    append_images=images[:-1],
)

# PNG도 저장 (256px, 미리보기용)
images[-1].save("app_icon.png")

print(f"app_icon.ico 생성 완료 ({len(sizes)}개 크기: {sizes})")
