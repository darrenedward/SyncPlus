#!/usr/bin/env python3
"""Compose Brand Kit SVGs from the packaged Brand Mark and rasterize public sizes."""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path

from fontTools.misc.transform import Transform
from fontTools.pens.svgPathPen import SVGPathPen
from fontTools.pens.transformPen import TransformPen
from fontTools.ttLib import TTFont

ROOT = Path(__file__).resolve().parents[2]
ICONS = ROOT / "packaging" / "icons"
BRAND = ROOT / "docs" / "brand"
PROMISE = "Review the plan. Confirm what changes. Uncertainty preserves the source."
WORDMARK = "SyncPlus"
COPPER = "#E08A3C"
STEEL = "#8AA0B8"
INK = "#141210"
PAPER = "#F7F0E4"
COPPER_LIGHT = "#B65E1C"
STEEL_LIGHT = "#3E5874"
MARK = 64.0
CLEAR = MARK / 8.0
GAP = CLEAR * 2.0
WORDMARK_SIZE = 40.0
FONT_CANDIDATES = (
    Path("/usr/share/fonts/opentype/urw-base35/NimbusSans-Bold.otf"),
    Path("/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf"),
)

DARK_MARK_INNER = f"""  <rect width="64" height="64" rx="14" fill="{INK}"/>
  <path d="M18 27a16 16 0 0 1 27-8l4 4" fill="none" stroke="{COPPER}" stroke-linecap="round" stroke-width="6"/>
  <path d="m45 13 4 10-11 1" fill="none" stroke="{COPPER}" stroke-linecap="round" stroke-linejoin="round" stroke-width="6"/>
  <path d="M46 37a16 16 0 0 1-27 8l-4-4" fill="none" stroke="{STEEL}" stroke-linecap="round" stroke-width="6"/>
  <path d="m19 51-4-10 11-1" fill="none" stroke="{STEEL}" stroke-linecap="round" stroke-linejoin="round" stroke-width="6"/>"""

LIGHT_MARK_INNER = f"""  <rect width="64" height="64" rx="14" fill="{PAPER}"/>
  <path d="M18 27a16 16 0 0 1 27-8l4 4" fill="none" stroke="{COPPER_LIGHT}" stroke-linecap="round" stroke-width="6"/>
  <path d="m45 13 4 10-11 1" fill="none" stroke="{COPPER_LIGHT}" stroke-linecap="round" stroke-linejoin="round" stroke-width="6"/>
  <path d="M46 37a16 16 0 0 1-27 8l-4-4" fill="none" stroke="{STEEL_LIGHT}" stroke-linecap="round" stroke-width="6"/>
  <path d="m19 51-4-10 11-1" fill="none" stroke="{STEEL_LIGHT}" stroke-linecap="round" stroke-linejoin="round" stroke-width="6"/>"""

MONO_MARK_INNER = """  <path d="M18 27a16 16 0 0 1 27-8l4 4" fill="none" stroke="currentColor" stroke-linecap="round" stroke-width="6"/>
  <path d="m45 13 4 10-11 1" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" stroke-width="6"/>
  <path d="M46 37a16 16 0 0 1-27 8l-4-4" fill="none" stroke="currentColor" stroke-linecap="round" stroke-width="6"/>
  <path d="m19 51-4-10 11-1" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" stroke-width="6"/>"""


def load_font():
    for path in FONT_CANDIDATES:
        if path.is_file():
            font = TTFont(path)
            return font, font.getGlyphSet(), font.getBestCmap(), font["head"].unitsPerEm, font[
                "hhea"
            ].ascent, font["hhea"].descent, getattr(font["OS/2"], "sCapHeight", 700)
    raise SystemExit("Nimbus Sans Bold or Liberation Sans Bold is required to outline the wordmark")


_FONT, GLYPHS, CMAP, UPEM, ASCENT, DESCENT, CAP_HEIGHT = load_font()


def text_path(text: str, size: float, origin_x: float, baseline_y: float) -> tuple[str, float]:
    scale = size / UPEM
    x = origin_x
    commands: list[str] = []
    for char in text:
        name = CMAP.get(ord(char))
        if name is None:
            x += size * 0.3
            continue
        glyph = GLYPHS[name]
        pen = SVGPathPen(GLYPHS)
        glyph.draw(TransformPen(pen, Transform(scale, 0, 0, -scale, x, baseline_y)))
        command = pen.getCommands()
        if command:
            commands.append(command)
        x += glyph.width * scale
    return round_path(" ".join(commands)), round(x - origin_x, 2)


def round_path(commands: str) -> str:
    def repl(match: re.Match[str]) -> str:
        value = f"{float(match.group(0)):.2f}"
        if value.endswith(".00"):
            return value[:-3]
        if value.endswith("0"):
            return value[:-1]
        return value

    return re.sub(r"-?\d+\.\d+", repl, commands)


def svg_document(view_width: float, view_height: float, title: str, desc: str, body: str) -> str:
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {view_width:.2f} {view_height:.2f}" '
        f'role="img" aria-labelledby="title desc">\n'
        f'  <title id="title">{title}</title>\n'
        f'  <desc id="desc">{desc}</desc>\n'
        f"{body}"
        f"</svg>\n"
    )


def write_svg(path: Path, contents: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(contents, encoding="utf-8")


def copy_marks() -> None:
    mapping = {
        "syncplus.svg": "mark/syncplus.svg",
        "syncplus-light.svg": "mark/syncplus-light.svg",
        "syncplus-symbolic.svg": "mark/syncplus-mono.svg",
    }
    for source_name, dest_name in mapping.items():
        dest = BRAND / dest_name
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ICONS / source_name, dest)


def wordmark_metrics(size: float = WORDMARK_SIZE) -> tuple[float, float, float, float]:
    scale = size / UPEM
    ascent = ASCENT * scale
    descent = abs(DESCENT) * scale
    _, width = text_path(WORDMARK, size, 0.0, ascent)
    return width, ascent, descent, CAP_HEIGHT * scale


def write_wordmarks() -> tuple[float, float, float]:
    width, ascent, descent, _cap = wordmark_metrics()
    view_width = CLEAR + width + CLEAR
    view_height = CLEAR + ascent + descent + CLEAR
    baseline = CLEAR + ascent
    path_d, _ = text_path(WORDMARK, WORDMARK_SIZE, CLEAR, baseline)
    variants = (
        ("wordmark/wordmark-dark.svg", COPPER, "SyncPlus wordmark in copper for Dark Appearance"),
        ("wordmark/wordmark-light.svg", INK, "SyncPlus wordmark in ink for Light Appearance"),
        (
            "wordmark/wordmark-mono.svg",
            "currentColor",
            "Monochrome SyncPlus wordmark for constrained backgrounds",
        ),
    )
    for relative, fill, desc in variants:
        body = f'  <path d="{path_d}" fill="{fill}"/>\n'
        write_svg(BRAND / relative, svg_document(view_width, view_height, WORDMARK, desc, body))
    return width, ascent, descent


def lockup_body(mark_inner: str, wordmark_d: str, wordmark_fill: str, wordmark_x: float) -> str:
    return (
        f'  <g transform="translate({CLEAR:.2f} {CLEAR:.2f})">\n'
        f"{mark_inner}\n"
        f"  </g>\n"
        f'  <path d="{wordmark_d}" fill="{wordmark_fill}" '
        f'transform="translate({wordmark_x:.2f} 0)"/>\n'
    )


def write_lockups(wordmark_width: float) -> tuple[float, float]:
    view_width = CLEAR + MARK + GAP + wordmark_width + CLEAR
    view_height = CLEAR + MARK + CLEAR
    mark_center = CLEAR + MARK / 2.0
    cap = CAP_HEIGHT * (WORDMARK_SIZE / UPEM)
    # Center the cap height on the mark; keep the wordmark path in untranslated
    # coordinates by baking the baseline into the path.
    baseline = mark_center + cap / 2.0
    wordmark_x = CLEAR + MARK + GAP
    path_d, _ = text_path(WORDMARK, WORDMARK_SIZE, 0.0, baseline)
    write_svg(
        BRAND / "lockup/lockup-dark.svg",
        svg_document(
            view_width,
            view_height,
            WORDMARK,
            PROMISE,
            lockup_body(DARK_MARK_INNER, path_d, COPPER, wordmark_x),
        ),
    )
    write_svg(
        BRAND / "lockup/lockup-light.svg",
        svg_document(
            view_width,
            view_height,
            WORDMARK,
            PROMISE,
            lockup_body(LIGHT_MARK_INNER, path_d, INK, wordmark_x),
        ),
    )
    write_svg(
        BRAND / "lockup/lockup-mono.svg",
        svg_document(
            view_width,
            view_height,
            WORDMARK,
            "Monochrome SyncPlus horizontal lockup for constrained backgrounds",
            lockup_body(MONO_MARK_INNER, path_d, "currentColor", wordmark_x),
        ),
    )
    return view_width, view_height


def write_social(width: int, height: int, dest: Path, lockup_view: tuple[float, float]) -> None:
    lockup_w, lockup_h = lockup_view
    target_lockup_w = width * 0.56
    scale = target_lockup_w / lockup_w
    lockup_draw_h = lockup_h * scale
    lockup_x = (width - target_lockup_w) / 2.0
    lockup_y = height * 0.28
    promise_size = 26.0 if width <= 1280 else 32.0
    promise_ascent = ASCENT * (promise_size / UPEM)
    promise_baseline = lockup_y + lockup_draw_h + height * 0.08 + promise_ascent
    promise_path, promise_width = text_path(PROMISE, promise_size, 0.0, promise_baseline)
    promise_x = (width - promise_width) / 2.0
    lockup_path = BRAND / "lockup/lockup-dark.svg"
    lockup_svg = lockup_path.read_text(encoding="utf-8")
    # Extract inner markup (everything after desc, before closing svg) for the dark lockup.
    inner_start = lockup_svg.find("</desc>") + len("</desc>")
    inner_end = lockup_svg.rfind("</svg>")
    lockup_inner = lockup_svg[inner_start:inner_end].strip("\n")
    body = (
        f'  <rect width="{width}" height="{height}" fill="{INK}"/>\n'
        f'  <g transform="translate({lockup_x:.2f} {lockup_y:.2f}) scale({scale:.4f})">\n'
        f"{lockup_inner}\n"
        f"  </g>\n"
        f'  <path d="{promise_path}" fill="{PAPER}" transform="translate({promise_x:.2f} 0)"/>\n'
    )
    write_svg(dest, svg_document(float(width), float(height), WORDMARK, PROMISE, body))


def rasterize(svg: Path, png: Path, width: int, height: int) -> None:
    png.parent.mkdir(parents=True, exist_ok=True)
    subprocess.check_call(
        ["resvg", "--width", str(width), "--height", str(height), str(svg), str(png)],
        stdout=subprocess.DEVNULL,
    )


def main() -> int:
    if not (ICONS / "syncplus.svg").is_file():
        print("packaging/icons/syncplus.svg is required", file=sys.stderr)
        return 1
    copy_marks()
    wordmark_width, _ascent, _descent = write_wordmarks()
    lockup_view = write_lockups(wordmark_width)
    write_social(1280, 640, BRAND / "github/social-preview-1280x640.svg", lockup_view)
    write_social(1640, 924, BRAND / "facebook/cover-1640x924.svg", lockup_view)
    write_social(1200, 630, BRAND / "facebook/post-1200x630.svg", lockup_view)
    rasterize(BRAND / "mark/syncplus.svg", BRAND / "github/avatar.png", 512, 512)
    rasterize(BRAND / "mark/syncplus.svg", BRAND / "facebook/profile.png", 512, 512)
    rasterize(
        BRAND / "github/social-preview-1280x640.svg",
        BRAND / "github/social-preview-1280x640.png",
        1280,
        640,
    )
    rasterize(
        BRAND / "facebook/cover-1640x924.svg",
        BRAND / "facebook/cover-1640x924.png",
        1640,
        924,
    )
    rasterize(
        BRAND / "facebook/post-1200x630.svg",
        BRAND / "facebook/post-1200x630.png",
        1200,
        630,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
