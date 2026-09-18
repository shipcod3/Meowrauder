#!/usr/bin/env python3
"""Generate the Meowrauder app icon in the FeralCat brand style.

Original artwork (not a copy of any other project's mark): a cat skull with
802.11 broadcast arcs — "marauder" menace crossed with the FeralCat mascot.

Follows docs/branding/icon-pack.md: square, transparent ground, art inside the
centre ~85% (tiles are circular, corners clip), bold shapes that survive 70x70.
Palette: red #FF2A3D, deep red #8A0016, charcoal #1A1214, white #FFFFFF.

Draws at 4x then downsamples, which is our antialiasing.
"""
from PIL import Image, ImageDraw
import os

RED   = (0xFF, 0x2A, 0x3D, 255)
DARK  = (0x8A, 0x00, 0x16, 255)
CHAR  = (0x1A, 0x12, 0x14, 255)
WHITE = (0xFF, 0xFF, 0xFF, 255)

S = 4096                      # supersampled canvas
img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
d   = ImageDraw.Draw(img)
u   = S / 1024.0              # 1 unit == 1px at the 1024 master

def R(*a): return [x * u for x in a]

# ── charcoal rounded-square badge ────────────────────────────────────────
d.rounded_rectangle(R(28, 28, 996, 996), radius=200 * u, fill=CHAR)

# ── broadcast arcs above the skull ──────────────────────────────────────
cx, cy = 512 * u, 452 * u
for rad, col in ((322, DARK), (240, RED), (158, RED)):
    d.arc([cx - rad * u, cy - rad * u, cx + rad * u, cy + rad * u],
          start=206, end=334, fill=col, width=int(32 * u))

# ── head silhouette: cranium + ears as one red mass ─────────────────────
# Drawn in one pass so there is no seam where the ears meet the cranium.
d.rounded_rectangle(R(298, 506, 726, 872), radius=168 * u, fill=RED)
d.polygon(R(306, 604, 372, 396, 470, 580), fill=RED)     # left ear
d.polygon(R(718, 604, 652, 396, 554, 580), fill=RED)     # right ear
d.polygon(R(344, 566, 375, 470, 425, 556), fill=DARK)    # inner left
d.polygon(R(680, 566, 649, 470, 599, 556), fill=DARK)    # inner right

# ── lower jaw: darker red, kept strictly inside the silhouette ──────────
d.rounded_rectangle(R(336, 726, 688, 862), radius=118 * u, fill=DARK)

# ── eye sockets: angry slanted wedges ───────────────────────────────────
d.polygon(R(352, 592, 484, 644, 484, 706, 352, 692), fill=CHAR)
d.polygon(R(672, 592, 540, 644, 540, 706, 672, 692), fill=CHAR)
d.polygon(R(374, 612, 452, 644, 452, 666, 374, 658), fill=WHITE)
d.polygon(R(650, 612, 572, 644, 572, 666, 650, 658), fill=WHITE)

# ── nose + fangs (fangs hang inside the jaw, not below the skull) ───────
d.polygon(R(512, 700, 482, 742, 542, 742), fill=CHAR)
d.rounded_rectangle(R(448, 754, 576, 766), radius=6 * u, fill=CHAR)
d.polygon(R(428, 766, 480, 766, 454, 848), fill=WHITE)
d.polygon(R(596, 766, 544, 766, 570, 848), fill=WHITE)

out = os.path.join(os.path.dirname(__file__), "..", "docs", "branding", "icons")
out = os.path.abspath(out)
master = img.resize((1024, 1024), Image.LANCZOS)
master.save(os.path.join(out, "meowrauder.png"))
master.resize((70, 70), Image.LANCZOS).save(os.path.join(out, "meowrauder_70.png"))
print("wrote", os.path.join(out, "meowrauder.png"), "and meowrauder_70.png")
