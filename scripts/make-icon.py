"""生成应用图标 assets/icon/port-scan-rs.ico

设计：靛蓝渐变圆角底板 + 白色网口（RJ45）+ 向右发散的扫描波纹，
配色与 GUI 主题（src/gui/theme.rs 的 accent 靛蓝）保持一致。

用法：
    python scripts/make-icon.py

图标按三个细节层级分别渲染（而不是从大图硬缩），保证 16/24/32px 也清晰：
  L2 (>=48px)  完整：网口带卡扣缺口 + 4 根针脚，3 道波纹
  L1 (32-40px) 中等：网口带缺口、无针脚，2 道波纹
  L0 (<32px)   极简：实心网口 + 1 道粗波纹（元素越少，小尺寸越可辨识）
"""
import io
import math
import os
import struct
from PIL import Image, ImageDraw

CANVAS = 1024
C1 = (110, 155, 255)     # 渐变起点 #6E9BFF（亮靛蓝）
C2 = (38, 70, 184)       # 渐变终点 #2646B8（深靛蓝）

# 每个细节层级的几何参数（基于 1024 画布）
SPECS = {
    2: dict(pad=36, radius=224, port=(132, 444, 552, 764), port_radius=46,
            notch=True, notch_w=184, notch_h=64, pins=True,
            arc_center=(590, 604), arc_radii=(140, 252, 364), arc_width=48),
    1: dict(pad=30, radius=208, port=(124, 436, 564, 772), port_radius=52,
            notch=True, notch_w=204, notch_h=74, pins=False,
            arc_center=(600, 604), arc_radii=(152, 296), arc_width=66),
    0: dict(pad=20, radius=192, port=(112, 404, 604, 800), port_radius=66,
            notch=False, notch_w=0, notch_h=0, pins=False,
            arc_center=(632, 602), arc_radii=(206,), arc_width=118),
}

PIN_W = 34
PIN_H = 124
PIN_COUNT = 4
PIN_BOTTOM_GAP = 44
ARC_SWEEP = 52           # 波纹单侧张角（度）

OUT_ICO = os.path.join('assets', 'icon', 'port-scan-rs.ico')
OUT_PNG = os.path.join('assets', 'icon', 'port-scan-rs-256.png')
SIZES = [16, 20, 24, 32, 40, 48, 64, 96, 128, 256]


def level_for(size):
    if size >= 48:
        return 2
    if size >= 32:
        return 1
    return 0


def lerp(a, b, t):
    return tuple(round(a[i] + (b[i] - a[i]) * t) for i in range(3))


def gradient(size):
    """对角线性渐变：在小画布上算好后放大，避免逐像素循环过慢。"""
    n = 256
    g = Image.new('RGB', (n, n))
    px = g.load()
    for y in range(n):
        for x in range(n):
            px[x, y] = lerp(C1, C2, (x + y) / (2 * (n - 1)))
    return g.resize((size, size), Image.BILINEAR)


def render(size, level=None):
    if level is None:
        level = level_for(size)
    spec = SPECS[level]
    k = size / CANVAS

    def s(v):
        return v * k

    # ---- 底板：圆角矩形裁剪渐变 ----
    mask_card = Image.new('L', (size, size), 0)
    pad = spec['pad']
    ImageDraw.Draw(mask_card).rounded_rectangle(
        [s(pad), s(pad), s(CANVAS - pad) - 1, s(CANVAS - pad) - 1],
        radius=s(spec['radius']), fill=255)

    img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
    img.paste(gradient(size).convert('RGBA'), (0, 0), mask_card)

    # ---- 符号 mask：白色=绘制符号，黑色=露出底板渐变 ----
    mask = Image.new('L', (size, size), 0)
    md = ImageDraw.Draw(mask)

    x0, y0, x1, y1 = spec['port']
    md.rounded_rectangle([s(x0), s(y0), s(x1), s(y1)],
                         radius=s(spec['port_radius']), fill=255)

    if spec['notch']:
        cx = (x0 + x1) / 2
        md.rounded_rectangle(
            [s(cx - spec['notch_w'] / 2), s(y0),
             s(cx + spec['notch_w'] / 2), s(y0 + spec['notch_h'])],
            radius=s(spec['notch_h'] * 0.34), fill=0)

    if spec['pins']:
        gap = (x1 - x0 - PIN_COUNT * PIN_W) / (PIN_COUNT + 1)
        px = x0 + gap
        pin_top = y1 - PIN_BOTTOM_GAP - PIN_H
        for i in range(PIN_COUNT):
            x = px + i * (PIN_W + gap)
            md.rounded_rectangle([s(x), s(pin_top), s(x + PIN_W), s(pin_top + PIN_H)],
                                 radius=s(PIN_W / 2), fill=0)

    # ---- 波纹：向右发散的同心弧（带圆头）----
    width = max(1.6, s(spec['arc_width']))
    cxc, cyc = spec['arc_center']
    for r in spec['arc_radii']:
        md.arc([s(cxc - r), s(cyc - r), s(cxc + r), s(cyc + r)],
               start=-ARC_SWEEP, end=ARC_SWEEP, fill=255, width=round(width))
        cap = width / 2
        for ang in (-ARC_SWEEP, ARC_SWEEP):
            ex = cxc + r * math.cos(math.radians(ang))
            ey = cyc + r * math.sin(math.radians(ang))
            md.ellipse([s(ex - cap), s(ey - cap), s(ex + cap), s(ey + cap)], fill=255)

    white = Image.new('RGBA', (size, size), (255, 255, 255, 255))
    return Image.composite(white, img, mask)


def write_ico(path, sizes):
    """手工拼 ICO：每帧独立渲染后用 PNG 编码（Vista+ 与 VS2015+ 的 rc.exe 均支持）。"""
    blobs = []
    for size in sizes:
        buf = io.BytesIO()
        render(size).save(buf, format='PNG')
        blobs.append(buf.getvalue())

    out = io.BytesIO()
    out.write(struct.pack('<HHH', 0, 1, len(blobs)))
    offset = 6 + 16 * len(blobs)
    for size, blob in zip(sizes, blobs):
        dim = 0 if size >= 256 else size
        out.write(struct.pack('<BBBBHHII', dim, dim, 0, 0, 1, 32, len(blob), offset))
        offset += len(blob)
    for blob in blobs:
        out.write(blob)

    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'wb') as fh:
        fh.write(out.getvalue())
    return len(out.getvalue())


def write_preview(path):
    """各尺寸并排，用深/浅两种底色各画一行，方便肉眼检查可辨识度。"""
    sizes = (16, 20, 24, 32, 40, 48, 64, 128, 256)
    items = [(s, render(s)) for s in sizes]
    gap = 26
    w = sum(im.width for _, im in items) + gap * (len(items) + 1)
    h = max(im.height for _, im in items) * 2 + gap * 3
    sheet = Image.new('RGB', (w, h), (250, 250, 252))
    ImageDraw.Draw(sheet).rectangle([0, h // 2, w, h], fill=(32, 34, 40))
    for row in (0, 1):
        base = 0 if row == 0 else h // 2
        x = gap
        for _, im in items:
            sheet.paste(im, (x, base + (h // 2 - im.height) // 2), im)
            x += im.width + gap
    sheet.save(path)


if __name__ == '__main__':
    size = write_ico(OUT_ICO, SIZES)
    render(256, level=2).save(OUT_PNG)
    write_preview('icon-preview.png')
    print(f'OK  {OUT_ICO} ({size} bytes, {len(SIZES)} frames)')
    print(f'OK  {OUT_PNG}')
    print('OK  icon-preview.png')
