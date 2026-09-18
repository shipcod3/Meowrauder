#!/usr/bin/env python3
"""PNG -> LVGL TRUE_COLOR_ALPHA C-array, matching the existing ui_img_ic_* files.

Pixel layout is 3 bytes: RGB565 little-endian + alpha. That is LV_COLOR_DEPTH 16
with LV_COLOR_16_SWAP 0 (see lib/lv_conf.h) — verified by decoding a shipped
icon: LE yields the brand charcoal, byte-swapped yields garbage.

Usage: tools/png_to_lvgl.py <in.png> <symbol> <out.c> [size]
"""
import sys
from PIL import Image

src, sym, dst = sys.argv[1], sys.argv[2], sys.argv[3]
size = int(sys.argv[4]) if len(sys.argv) > 4 else 70

im = Image.open(src).convert("RGBA")
if im.size != (size, size):
    im = im.resize((size, size), Image.LANCZOS)

data = bytearray()
for y in range(size):
    for x in range(size):
        r, g, b, a = im.getpixel((x, y))
        c = ((r >> 3) << 11) | ((g >> 2) << 5) | (b >> 3)
        data += bytes((c & 0xFF, (c >> 8) & 0xFF, a))

rows = []
for i in range(0, len(data), 18):
    rows.append("    " + ",".join(f"0x{v:02x}" for v in data[i:i + 18]) + ",")

with open(dst, "w") as f:
    f.write(f"// FeralCat app icon — {sym}, {size}x{size} "
            f"(from {src.split('/')[-1]})\n\n")
    f.write('#include "../ui.h"\n\n')
    f.write("#ifndef LV_ATTRIBUTE_MEM_ALIGN\n    #define LV_ATTRIBUTE_MEM_ALIGN\n#endif\n\n")
    f.write(f"const LV_ATTRIBUTE_MEM_ALIGN uint8_t {sym}_data[] = {{\n")
    f.write("\n".join(rows) + "\n};\n")
    f.write(f"const lv_img_dsc_t {sym} = {{\n"
            "    .header.always_zero = 0,\n"
            f"    .header.w = {size},\n"
            f"    .header.h = {size},\n"
            f"    .data_size = sizeof({sym}_data),\n"
            "    .header.cf = LV_IMG_CF_TRUE_COLOR_ALPHA,\n"
            f"    .data = {sym}_data\n"
            "};\n")
print(f"wrote {dst}: {len(data)} bytes ({size}x{size}x3)")
