#!/usr/bin/env python3
# ============================================================
# Osza - icon build pipeline
#
# Reads the design system (tools/icons/osza_design.py) and the
# brand lockup source (design/icons/brand-lockup.json) and
# deterministically regenerates every derivative:
#
#   design/icons/**            master sources (checked in)
#   src/lib/data/osza-icons/   the bundled "osza" + "osza-dark"
#                              freedesktop icon themes
#   src/lib/data/icons/**      resource-path icons, html art
#   themes/<t>/images/**       per-theme chrome artwork
#   plugin/adblock/exe icon PNG raster derivatives
#   linux/hicolor, mac/, logo.png packaging art
#   docs/screenshots/refresh/  contact + pilot sheets
#
# Tool dependencies (development only - nothing here is a build
# or runtime dependency of the browser):
#   python3 >= 3.9, cairosvg, Pillow
#
# Usage:
#   python3 tools/icons/build.py                 # emit everything
#   python3 tools/icons/build.py --check-contrast# palette WCAG check
#   python3 tools/icons/build.py --masters-only  # refresh design/ only
#
# Copyright (C) 2026 Osza Tools contributors
# GPL-3.0-or-later
# ============================================================

from __future__ import annotations

import argparse
import json
import math
import shutil
import sys
from pathlib import Path
from typing import Dict, List, Optional

import cairosvg
from PIL import Image

sys.path.insert(0, str(Path(__file__).resolve().parent))
import osza_design as D  # noqa: E402

REPO = Path(__file__).resolve().parents[2]
DESIGN = REPO / "design/icons"
SVG_HEADER = ('<svg xmlns="http://www.w3.org/2000/svg" '
              'viewBox="0 0 {size} {size}">\n')


# ---------------------------------------------------------------------------
# SVG rendering
# ---------------------------------------------------------------------------

def gradient_defs(kind: str) -> str:
    stops = D.GRADIENTS["neon"] if kind == "gradient-neon" else D.GRADIENTS["lite"]
    return ('<defs><linearGradient id="g" x1="0.15" y1="0.9" x2="0.85" y2="0.1">'
            + "".join(
                f'<stop offset="{i / (len(stops) - 1):.3f}" stop-color="{c}"/>'
                for i, c in enumerate(stops))
            + "</linearGradient></defs>\n")


def render_svg(elements: List[dict], size: float, palette: Dict[str, str],
               with_gradient: bool = True) -> str:
    """Render design elements to a standalone SVG string."""
    stroke_w = {24: 2.0, 16: 1.6, 20: 1.8, 48: 3.0, 32: 2.4}.get(size, 2.0 * size / 24.0)
    out = [SVG_HEADER.format(size=_n(size))]
    needs_gradient = any(str(e.get("c", "")).startswith("gradient") for e in elements)
    if with_gradient and needs_gradient:
        out.append(gradient_defs(palette.get("gradient_kind", "lite")))

    def color(token: str) -> str:
        if token == "gradient" or token.startswith("gradient-"):
            return "url(#g)"
        return palette.get(token, token)

    for e in elements:
        c = color(e["c"])
        if e["t"] == "path":
            attrs = (f'fill="none" stroke="{c}" stroke-width="{_n(e.get("w", stroke_w))}"'
                     ' stroke-linecap="round" stroke-linejoin="round"')
            if e.get("dash"):
                attrs += f' stroke-dasharray="{e["dash"]}"'
            out.append(f'<path d="{e["d"]}" {attrs}/>')
        elif e["t"] == "fill":
            attrs = f'fill="{c}"'
            if e.get("opacity") is not None:
                attrs += f' fill-opacity="{_n(e["opacity"])}"'
            out.append(f'<path d="{e["d"]}" {attrs}/>')
        elif e["t"] == "circle":
            if e.get("fill"):
                out.append(f'<circle cx="{_n(e["cx"])}" cy="{_n(e["cy"])}" '
                           f'r="{_n(e["r"])}" fill="{c}"/>')
            else:
                out.append(f'<circle cx="{_n(e["cx"])}" cy="{_n(e["cy"])}" '
                           f'r="{_n(e["r"])}" fill="none" stroke="{c}" '
                           f'stroke-width="{_n(stroke_w)}" stroke-linecap="round"/>')
        elif e["t"] == "rect":
            out.append(f'<rect x="{_n(e["x"])}" y="{_n(e["y"])}" width="{_n(e["w"])}" '
                       f'height="{_n(e["h"])}" rx="{_n(e.get("rx", 2))}" fill="none" '
                       f'stroke="{c}" stroke-width="{_n(stroke_w)}" '
                       'stroke-linejoin="round"/>')
    out.append("</svg>\n")
    return "".join(out)


def _n(v: float) -> str:
    s = f"{float(v):.2f}".rstrip("0").rstrip(".")
    return s if s else "0"


def write_svg(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def svg_to_png(svg: str, w: int, h: Optional[int] = None) -> Image.Image:
    data = cairosvg.svg2png(bytestring=svg.encode("utf-8"),
                            output_width=w, output_height=h or w)
    import io
    return Image.open(io.BytesIO(data)).convert("RGBA")


# ---------------------------------------------------------------------------
# Masters: design/icons (light palette values, render standalone)
# ---------------------------------------------------------------------------

def emit_masters() -> None:
    # 24 px masters for every themed name
    for name, els in D.ICONS_24.items():
        write_svg(DESIGN / f"theme-24/{name}.svg", render_svg(els, 24, D.PALETTES["light"]))
    # hand-tuned 16 px masters
    for name, els in D.ICONS_16.items():
        write_svg(DESIGN / f"theme-16/{name}.svg", render_svg(els, 16, D.PALETTES["light"]))
    # 48 px feature icons (duotone, light-safe gradient)
    for name, els in D.FEATURE_48.items():
        write_svg(DESIGN / f"feature-48/{name}.svg",
                  render_svg(els, 48, D.PALETTES["light"]))
    # misc artwork masters
    for key, (size, els) in D.MISC_SVG.items():
        sub, _, leaf = key.partition("/")
        write_svg(DESIGN / f"misc/{sub}/{leaf}.svg", render_svg(els, size, D._MENU_DUAL))


# ---------------------------------------------------------------------------
# Bundled icon theme: src/lib/data/osza-icons/{osza,osza-dark}
# ---------------------------------------------------------------------------

INDEX_THEME = """[Icon Theme]
Name=Osza
Name[osza]=Osza
Comment=Osza browser icon theme (bundled)
Comment{suffix}=Osza browser icon theme, light variant for dark surfaces

Directories=scalable,16x16,22x22,32x32

[scalable]
Size=24
MaxSize=256
Type=Scalable

[16x16]
Size=16
Type=Fixed

[22x22]
Size=22
Type=Fixed

[32x32]
Size=32
Type=Fixed
"""


def emit_bundled_theme() -> None:
    base = REPO / "src/lib/data/osza-icons"
    for variant, palette in (("osza", D.PALETTES["light"]),
                             ("osza-dark", D.PALETTES["dark"])):
        theme_dir = base / variant
        if theme_dir.exists():
            shutil.rmtree(theme_dir)
        (theme_dir / "scalable").mkdir(parents=True)
        for name, els in D.ICONS_24.items():
            write_svg(theme_dir / f"scalable/{name}.svg", render_svg(els, 24, palette))
        for size_dir in ("16x16", "22x22", "32x32"):
            (theme_dir / size_dir).mkdir()
        # hand-tuned 16 px overrides
        for name, els in D.ICONS_16.items():
            write_svg(theme_dir / f"16x16/{name}.svg", render_svg(els, 16, palette))
        # the 22 and 32 px dirs are also served from the masters so fixed-size
        # lookups never miss (identical vectors, Qt renders them at request size)
        for name, els in D.ICONS_24.items():
            content = render_svg(els, 24, palette)
            for d in ("22x22", "32x32"):
                write_svg(theme_dir / f"{d}/{name}.svg", content)
        suffix = "-dark" if variant.endswith("-dark") else ""
        (theme_dir / "index.theme").write_text(
            INDEX_THEME.format(suffix=suffix), encoding="utf-8")

    # the qrc for both variants
    entries = []
    for variant in ("osza", "osza-dark"):
        entries.append(f"osza-icons/{variant}/index.theme")
        for d in ("scalable", "16x16", "22x22", "32x32"):
            for f in sorted((base / variant / d).glob("*.svg")):
                entries.append(f"osza-icons/{variant}/{d}/{f.name}")
    qrc = ('<RCC>\n    <qresource prefix="/icons">\n'
           + "".join(f"        <file>{e}</file>\n" for e in entries)
           + "    </qresource>\n</RCC>\n")
    (REPO / "src/lib/data/osza-icons.qrc").write_text(qrc, encoding="utf-8")


# ---------------------------------------------------------------------------
# Resource-path icons: src/lib/data/icons (menu + other + preferences)
# ---------------------------------------------------------------------------

RESOURCE_MAP = {
    # design key -> (target file under src/lib/data/icons, palette)
    "menu/history": ("icons/menu/history.svg", "menu"),
    "menu/history_entry": ("icons/menu/history_entry.svg", "menu"),
    "menu/tab-new": ("icons/menu/tab-new.svg", "menu"),
    "menu/window-new": ("icons/menu/window-new.svg", "menu"),
    "menu/tab": ("icons/menu/tab.svg", "menu"),
    "menu/settings": ("icons/menu/settings.svg", "menu"),
    "menu/download": ("icons/menu/download.svg", "menu"),
    "menu/search-icon": ("icons/menu/search-icon.svg", "menu"),
    "menu/privatebrowsing": ("icons/menu/privatebrowsing.svg", "menu"),
    "menu/speeddial": ("icons/menu/speeddial.svg", "menu"),
    "other/webpage": ("icons/other/webpage.svg", "menu"),
    "other/audioplaying": ("icons/other/audioplaying.svg", "dark"),
    "other/audiomuted": ("icons/other/audiomuted.svg", "dark"),
    "other/login": ("icons/other/login.svg", "menu"),
    "locationbar/safe": ("icons/locationbar/safe.svg", "menu"),
    "locationbar/unsafe": ("icons/locationbar/unsafe.svg", "menu"),
    "locationbar/visit1": ("icons/locationbar/visit1.svg", "menu"),
    "locationbar/visit2": ("icons/locationbar/visit2.svg", "menu"),
    "locationbar/visit3": ("icons/locationbar/visit3.svg", "menu"),
}

FEATURE_MAP = {
    # design/icons/feature-48/<key> -> src/lib/data/icons/<target>
    "general": "icons/preferences/general.svg",
    "appearance": "icons/preferences/appearance.svg",
    "browsing": "icons/preferences/browsing.svg",
    "tabs": "icons/preferences/tabs.svg",
    "downloads": "icons/preferences/downloads.svg",
    "extensions": "icons/preferences/extensions.svg",
    "fonts": "icons/preferences/fonts.svg",
    "passwords": "icons/preferences/passwords.svg",
    "privacy": "icons/preferences/privacy.svg",
    "notifications": "icons/preferences/notifications.svg",
    "shortcuts": "icons/preferences/shortcuts.svg",
    "spellcheck": "icons/preferences/spellcheck.svg",
    "other": "icons/preferences/other.svg",
    "document-properties": "icons/preferences/document-properties.svg",
    "applications-graphics": "icons/preferences/applications-graphics.svg",
    "download": "icons/other/download.svg",
    "bigstar": "icons/other/bigstar.svg",
    "bigstar-selected": "icons/other/bigstar-selected.svg",
    "bighistory": "icons/other/bighistory.svg",
    "bighistory-selected": "icons/other/bighistory-selected.svg",
}


def emit_resource_icons() -> None:
    data = REPO / "src/lib/data"
    for key, (target, pal) in RESOURCE_MAP.items():
        size, els = D.MISC_SVG[key]
        palette = {"menu": D._MENU_DUAL, "dark": D.PALETTES["dark"]}[pal]
        write_svg(data / target, render_svg(els, size, palette))
    for key, target in FEATURE_MAP.items():
        els = D.FEATURE_48[key]
        write_svg(data / target, render_svg(els, 48, D._MENU_DUAL))

    # html internal-page art (dark pages, page palette)
    html = REPO / "src/lib/data/html"
    for key, (size, els) in D.MISC_SVG.items():
        if key.startswith("html/"):
            write_svg(html / f"{key.split('/', 1)[1]}.svg",
                      render_svg(els, size, D._PAGE_DUAL))


# ---------------------------------------------------------------------------
# Per-theme chrome artwork: themes/<t>/images
# ---------------------------------------------------------------------------

THEME_INKS = {
    # theme -> ink token set used for its artwork
    "linux": "dual",
    "windows": "dual",
    "mac": "dual",
    "osza-cyber": "dark",
}

# 24-grid stroke-path element bound to the theme palette.
def P2(d: str) -> dict:
    return {"t": "path", "d": d, "c": "ink"}


# Which images each theme ships (kept aligned with each theme's CSS).
THEME_IMAGES = {
    "linux": ["arrow-down", "exit-fullscreen", "goto", "menu", "star", "star-a",
              "tab-close", "tab-close-h", "tab-close-a", "tab-left-arrow",
              "tab-right-arrow", "tools", "tools-rtl", "user"],
    "windows": ["exit-fullscreen", "goto", "menu", "star", "star-a",
                "tab-close", "tab-close-h", "tab-close-a", "tab-left-arrow",
                "tab-right-arrow", "tools", "tools-rtl", "user"],
    "mac": ["arrow-down", "exit-fullscreen", "goto", "menu", "star", "star-a",
            "tab-close", "tab-close-h", "tab-close-a", "tab-left-arrow",
            "tab-right-arrow", "tools", "tools-rtl", "user"],
    "osza-cyber": ["addtab", "arrow-down", "back", "downloads", "exit-fullscreen",
                   "forward", "goto", "home", "menu", "reload", "search", "star",
                   "star-a", "stop", "tab-close", "tab-close-h", "tab-close-a",
                   "tab-left-arrow", "tab-right-arrow", "tools", "tools-rtl", "user"],
}

# 24-grid glyph per image name (some reuse themed masters).
THEME_GLYPHS: Dict[str, List[dict]] = {
    "arrow-down": D.ICONS_24["arrow-down"],
    "back": D.ICONS_24["go-previous"],
    "forward": D.ICONS_24["go-next"],
    "home": D.ICONS_24["go-home"],
    "reload": D.ICONS_24["view-refresh"],
    "stop": D.ICONS_24["process-stop"],
    "search": [e for e in D.ICONS_24["edit-find"]],
    "downloads": D.ICONS_24["download"],
    "addtab": D.ICONS_24["list-add"],
    "exit-fullscreen": [P2("M8 4v4H4"), P2("M16 4v4h4"), P2("M8 20v-4H4"), P2("M16 20v-4h4")],
    "goto": D.ICONS_24["go-jump-locationbar"],
    "menu": D.ICONS_24["application-menu"],
    "tools": D.ICONS_24["arrow-right-double"],
    "tools-rtl": D.ICONS_24["arrow-left-double"],
    "user": D.ICONS_24["user-identity"],
    "star": D.ICONS_24["rating-unrated"],
    "star-a": D.ICONS_24["rating"],
    "tab-left-arrow": [P2("M14.5 6 8.5 12l6 6")],
    "tab-right-arrow": [P2("M9.5 6l6 6-6 6")],
    "tab-close": [P2("M6.5 6.5l11 11"), P2("M17.5 6.5l-11 11")],
    "tab-close-h": [P2("M6.5 6.5l11 11"), P2("M17.5 6.5l-11 11")],
    "tab-close-a": [P2("M6.5 6.5l11 11"), P2("M17.5 6.5l-11 11")],
}


def emit_theme_images() -> None:
    for theme, names in THEME_IMAGES.items():
        pal = (D.PALETTES["dark"] if THEME_INKS[theme] == "dark"
               else dict(D._MENU_DUAL))
        # tab close trio gets its dedicated dual-safe state colors
        for name in names:
            els = [dict(e) for e in THEME_GLYPHS[name]]
            p = dict(pal)
            if name == "tab-close":
                p["ink"] = D.DUAL_SAFE["tab_close"]
            elif name == "tab-close-h":
                p["ink"] = D.DUAL_SAFE["tab_close_hover"]
            elif name == "tab-close-a":
                p["ink"] = D.DUAL_SAFE["tab_close_pressed"]
            write_svg(REPO / f"themes/{theme}/images/{name}.svg",
                      render_svg(els, 24, p))


# ---------------------------------------------------------------------------
# Tab loading animation strip (frame format expected by tabicon.cpp:
# N square frames stacked horizontally; 288x16 = 18 frames of 16 px)
# ---------------------------------------------------------------------------

FRAMES = 18
STRIP_H = 16


def spinner_frame(i: int, size: int) -> str:
    c = size / 2.0
    r = size * 0.345
    w = size * 0.125
    a0 = i * 360.0 / FRAMES
    els = [D.arc(c, c, r, a0, a0 + 250, c="accent", w=w)]
    return render_svg(els, size, D.PALETTES["dark"], with_gradient=False)


def emit_loading_strip() -> None:
    other = REPO / "src/lib/data/icons/other"
    for scale, name in ((1, "loading.png"), (2, "loading@2x.png")):
        frame_px = STRIP_H * scale
        strip = Image.new("RGBA", (frame_px * FRAMES, frame_px), (0, 0, 0, 0))
        for i in range(FRAMES):
            png = svg_to_png(spinner_frame(i, frame_px), frame_px, frame_px)
            strip.paste(png, (i * frame_px, 0))
        strip.save(other / name)


# ---------------------------------------------------------------------------
# Brand lockups (ring + comet dot + wordmark) from the extracted source
# ---------------------------------------------------------------------------

def load_brand() -> dict:
    return json.loads((DESIGN / "brand-lockup.json").read_text(encoding="utf-8"))


def lockup_svg(brand: dict, wordmark_color: str, gradient: List[str],
               width: int = 494, height: int = 132, pad: int = 16) -> str:
    gid = "zg"
    stops = "".join(
        f'<stop offset="{i / (len(gradient) - 1):.3f}" stop-color="{c}"/>'
        for i, c in enumerate(gradient))
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}">\n',
        f'<defs><linearGradient id="{gid}" x1="0.12" y1="0.92" x2="0.88" y2="0.08">'
        f'{stops}</linearGradient></defs>\n',
        f'<g transform="translate({pad},{height - pad})">\n',
        f'<path d="{brand["ring"]}" fill="none" stroke="url(#{gid})" '
        'stroke-width="23.9" stroke-linecap="round"/>\n',
        f'<circle cx="{brand["dot"][0]}" cy="{brand["dot"][1]}" r="{brand["dot"][2]}" '
        f'fill="url(#{gid})"/>\n',
    ]
    for d in brand["wordmarks"]:
        parts.append(f'<path d="{d}" fill="{wordmark_color}"/>\n')
    parts.append("</g>\n</svg>\n")
    return "".join(parts)


def startpage_svg(brand: dict, wordmark_color: str, gradient: List[str]) -> str:
    """Hero art for the start page: large ring + wordmark beneath."""
    gid = "zg"
    stops = "".join(
        f'<stop offset="{i / (len(gradient) - 1):.3f}" stop-color="{c}"/>'
        for i, c in enumerate(gradient))
    # scale the 494x132 lockup to fit a 256x200 canvas, centered
    scale = 208 / 494.0
    w, h = 494 * scale, 132 * scale
    x, y = (256 - w) / 2, 118
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="256" height="200" '
        f'viewBox="0 0 256 200">\n'
        f'<defs><linearGradient id="{gid}" x1="0.12" y1="0.92" x2="0.88" y2="0.08">'
        f'{stops}</linearGradient></defs>\n'
        # orbit hint: two dim arcs echoing the ring
        f'<path d="M42 44a124 124 0 0 1 42-24" fill="none" stroke="{wordmark_color}" '
        'stroke-opacity="0.22" stroke-width="4" stroke-linecap="round"/>\n'
        f'<path d="M214 156a124 124 0 0 1-42 24" fill="none" stroke="{wordmark_color}" '
        'stroke-opacity="0.22" stroke-width="4" stroke-linecap="round"/>\n'
        f'<g transform="translate({x:.1f},{y:.1f}) scale({scale:.4f})">\n'
        f'<g transform="translate(16,116)">\n'
        f'<path d="{brand["ring"]}" fill="none" stroke="url(#{gid})" '
        'stroke-width="23.9" stroke-linecap="round"/>\n'
        f'<circle cx="{brand["dot"][0]}" cy="{brand["dot"][1]}" r="{brand["dot"][2]}" '
        f'fill="url(#{gid})"/>\n'
        + "".join(f'<path d="{d}" fill="{wordmark_color}"/>\n' for d in brand["wordmarks"])
        + "</g>\n</g>\n</svg>\n"
    )


def emit_brand_art() -> None:
    brand = load_brand()
    other = REPO / "src/lib/data/icons/other"
    neon, lite = D.GRADIENTS["neon"], D.GRADIENTS["lite"]
    ink_light, ink_dark = "#171C28", "#E9EDF5"
    # osza:about and osza:config pages are dark
    write_svg(other / "logo.svg", lockup_svg(brand, ink_light, lite))
    write_svg(other / "logo-dark.svg", lockup_svg(brand, ink_dark, neon))
    write_svg(other / "about.svg", lockup_svg(brand, ink_light, lite))
    write_svg(other / "about-dark.svg", lockup_svg(brand, ink_dark, neon))
    # start page hero (page background is dark navy)
    write_svg(other / "startpage.svg", startpage_svg(brand, ink_light, lite))
    write_svg(other / "startpage-dark.svg", startpage_svg(brand, ink_dark, neon))


# ---------------------------------------------------------------------------
# Raster derivatives (PNG where Qt or the platform requires it)
# ---------------------------------------------------------------------------

def rasters_for_plugin(name: str, out_size: int, palette_name: str = "menu") -> Image.Image:
    grid, els = D.MISC_SVG[f"plugin/{name}"]
    pal = {"menu": D._MENU_DUAL, "dark": D.PALETTES["dark"]}[palette_name]
    return svg_to_png(render_svg(els, grid, pal), out_size)


def emit_plugin_rasters() -> None:
    p = REPO / "src/plugins"

    # AutoScroll overlays (33 px, matching autoscroller.cpp's pixmap(33);
    # rendered over arbitrary pages: dual-safe ink with a light halo)
    for base, glyph in (("scroll_all", "autoscroll"),
                        ("scroll_horizontal", "autoscroll-h"),
                        ("scroll_vertical", "autoscroll-v")):
        grid, els = D.MISC_SVG[f"plugin/{glyph}"]
        for scale in (1, 2):
            size = 33 * scale
            png = svg_to_png(render_svg(els, grid, D._MENU_DUAL), size)
            _with_halo(png).save(
                p / f"AutoScroll/data/{base}{'' if scale == 1 else '@2x'}.png")

    # FlashCookieManager, PIM, StatusBarIcons, MouseGestures
    rasters_for_plugin("flashcookies", 128).save(
        p / "FlashCookieManager/data/flash-cookie-manager.png")
    rasters_for_plugin("pim", 32).save(p / "PIM/data/PIM.png")
    rasters_for_plugin("mousegestures", 32).save(p / "MouseGestures/data/icon.png")
    rasters_for_plugin("statusbaricons", 32).save(p / "StatusBarIcons/data/icon.png")

    # StatusBarIcons individual glyphs (16 px)
    sbi = p / "StatusBarIcons/data"
    for fname, glyph in (("add.png", "plus"), ("remove.png", "minus"),
                         ("images.png", "image"), ("javascript.png", "script"),
                         ("preferences-network.png", "network"),
                         ("network-online.png", "net-online"),
                         ("network-offline.png", "net-offline"),
                         ("network-unknown.png", "net-unknown")):
        els = _sbi_glyph(glyph)
        svg = render_svg(els, 16, D._MENU_DUAL, with_gradient=False)
        svg_to_png(svg, 16).save(sbi / fname)

    # TabManager glyph set (16 px actions + 32 px tab badges + 128 px icon)
    tm = p / "TabManager/data"
    for fname, els in (("addtab.png", D.ICONS_16["list-add"]),
                       ("closetab.png", D.ICONS_16["window-close"])):
        svg = render_svg(els, 16, D._MENU_DUAL, with_gradient=False)
        svg_to_png(svg, 16).save(tm / fname)
    tm_32 = {
        "tab-close.png": D.ICONS_24["window-close"],
        "tab-bookmark.png": D.ICONS_24["bookmark-new"],
        "tab-detach.png": D.ICONS_24["go-next"],
        "tab-pinned.png": [P2("M12 3.5v5"), P2("M12 8.5l-3-3"), P2("M12 8.5l3-3"),
                           P2("M8 12.5h8v4H8z")],
        "tab-loading.png": [D.arc(12, 12, 7.8, 20, 270, c="accent", w=2.4)],
        "side-by-side.png": [P2("M4 6h8v6H4z"), P2("M12 12h8v6h-8z")],
    }
    for fname, els in tm_32.items():
        svg = render_svg(els, 24, D._MENU_DUAL, with_gradient=False)
        svg_to_png(svg, 32).save(tm / fname)
    rasters_for_plugin("verticaltabs-icon", 128).save(tm / "tabmanager.png")

    # GreaseMonkey icon (SVG, dormant-safe colors)
    size, els = D.MISC_SVG["plugin/greasemonkey"]
    write_svg(p / "GreaseMonkey/data/icon.svg", render_svg(els, size, D._MENU_DUAL))
    size, els = D.MISC_SVG["plugin/verticaltabs-icon"]
    write_svg(p / "VerticalTabs/data/icon.svg", render_svg(els, size, D._MENU_DUAL))
    size, els = D.MISC_SVG["plugin/verticaltabs-group"]
    write_svg(p / "VerticalTabs/data/group.svg", render_svg(els, size, D._MENU_DUAL))

    # AdBlock
    ab = REPO / "src/lib/adblock/data"
    size, els = D.MISC_SVG["plugin/adblock"]
    svg = render_svg(els, size, D._MENU_DUAL)
    svg_to_png(svg, 32).save(ab / "adblock.png")
    svg_to_png(svg, 48).save(ab / "adblock_big.png")

    # RunAction scripts (generic glyphs - no third-party marks)
    ra = REPO / "src/scripts/runaction/actions"
    for fname, glyph in (("google.png", "search"), ("tineye.png", "image-search"),
                         ("translate.png", "translate"),
                         ("w3.png", "encyclopedia"), ("yandex.png", "search")):
        size, els = D.MISC_SVG[f"runaction/{glyph}"]
        svg_to_png(render_svg(els, size, D._MENU_DUAL), 32).save(ra / fname)


def _sbi_glyph(glyph: str) -> List[dict]:
    G = {
        "plus": [P2("M8 2.8v10.4M2.8 8h10.4")],
        "minus": [P2("M2.8 8h10.4")],
        "image": [P2("M2.8 4h10.4v8H2.8zM2.8 10l3-3 2.2 2.2 2-2 3.2 2.8"),
                  {"t": "circle", "cx": 5.6, "cy": 6.4, "r": 1, "c": "ink", "fill": True}],
        "script": [P2("M4 2.8h5l3 3v7.4H4V2.8z"), P2("M9 2.8V6h3"),
                   P2("M6.2 8l1.6 2.4-1.6 2.4"), P2("M9.8 8l-1.6 2.4L9.8 12.8")],
        "network": [P2("M8 2.8a5.2 5.2 0 1 0 0.01 0zM8 2.8c-2.1 1.5-2.1 8.9 0 10.4"
                       "M8 2.8c2.1 1.5 2.1 8.9 0 10.4M2.8 8h10.4")],
        "net-online": [P2("M8 2.8a5.2 5.2 0 1 0 0.01 0z")],
        "net-offline": [P2("M8 2.8a5.2 5.2 0 1 0 0.01 0z"), P2("M4.3 4.3l7.4 7.4")],
        "net-unknown": [P2("M8 2.8a5.2 5.2 0 1 0 0.01 0z"), P2("M6.4 6.6c0-1 0.7-1.6 1.6-1.6"
                                                              "s1.6 0.6 1.6 1.4c0 1.1-1.4 1.2-1.4 2.3"),
                        {"t": "circle", "cx": 8, "cy": 10.9, "r": 0.8, "c": "ink", "fill": True}],
    }
    return G[glyph]


def _with_halo(img: Image.Image, radius: float = 2.5) -> Image.Image:
    """Composite a soft light halo behind overlay art so it stays
    readable over any web page background."""
    from PIL import ImageFilter
    alpha = img.split()[3]
    halo = Image.new("RGBA", img.size, (255, 255, 255, 0))
    solid = Image.new("RGBA", img.size, (255, 255, 255, 190))
    halo.paste(solid, (0, 0), alpha)
    halo = halo.filter(ImageFilter.GaussianBlur(radius))
    out = Image.alpha_composite(halo, img)
    return out


# ---------------------------------------------------------------------------
# Mouse gesture preview GIFs
# ---------------------------------------------------------------------------

GESTURES = {
    "up": [(0, 1)], "down": [(0, -1)], "left": [(-1, 0)], "right": [(1, 0)],
    "up-down": [(0, 1), (0, -1)], "down-up": [(0, -1), (0, 1)],
    "up-left": [(0, 1), (-1, 0)], "up-right": [(0, 1), (1, 0)],
    "down-left": [(0, -1), (-1, 0)], "down-right": [(0, -1), (1, 0)],
}


def emit_gesture_gifs() -> None:
    import io
    gd = REPO / "src/plugins/MouseGestures/data"
    W = H = 46
    seg = 13
    cx, cy = W / 2, H / 2
    for name, dirs in GESTURES.items():
        # build the polyline: first segment starts at center
        pts = [(cx, cy)]
        x, y = cx, cy
        for dx, dy in dirs:
            x += dx * seg
            y += dy * seg
            pts.append((x, y))
        frames = []
        n = 6
        for step in range(1, n + 1):
            img = Image.new("RGBA", (W, H), (0, 0, 0, 0))
            from PIL import ImageDraw
            dr = ImageDraw.Draw(img)
            total = len(pts) - 1
            frac = step / n
            upto = frac * total
            full = int(upto)
            for i in range(full):
                dr.line([pts[i], pts[i + 1]], fill=(0, 229, 200, 255), width=4)
                dr.ellipse([pts[i][0] - 2, pts[i][1] - 2, pts[i][0] + 2, pts[i][1] + 2],
                           fill=(0, 229, 200, 255))
            if full < total:
                t = upto - full
                p0, p1 = pts[full], pts[full + 1]
                pe = (p0[0] + (p1[0] - p0[0]) * t, p0[1] + (p1[1] - p0[1]) * t)
                dr.line([p0, pe], fill=(0, 229, 200, 255), width=4)
            else:
                pe = pts[-1]
                # arrow head at the end
                dx, dy = pts[-1][0] - pts[-2][0], pts[-1][1] - pts[-2][1]
                L = math.hypot(dx, dy) or 1
                ux, uy = dx / L, dy / L
                hx, hy = pe[0] - ux * 7, pe[1] - uy * 7
                dr.polygon([(pe[0] + 0.5, pe[1] + 0.5),
                            (hx - uy * 3.5, hy + ux * 3.5),
                            (hx + uy * 3.5, hy - ux * 3.5)], fill=(0, 229, 200, 255))
            frames.append(img.convert("P", palette=Image.ADAPTIVE))
        buf = io.BytesIO()
        frames[0].save(buf, format="GIF", save_all=True, append_images=frames[1:],
                       duration=90, loop=0, transparency=0, disposal=2)
        (gd / f"{name}.gif").write_bytes(buf.getvalue())


# ---------------------------------------------------------------------------
# html loading.gif (restore page spinner)
# ---------------------------------------------------------------------------

def emit_loading_gif() -> None:
    import io
    frames = []
    for i in range(12):
        els = [D.arc(10, 10, 7, i * 30, i * 30 + 240, c="accent", w=2.4)]
        png = svg_to_png(render_svg(els, 20, D._PAGE_DUAL, with_gradient=False), 20)
        frames.append(png.convert("P", palette=Image.ADAPTIVE))
    buf = io.BytesIO()
    frames[0].save(buf, format="GIF", save_all=True, append_images=frames[1:],
                   duration=80, loop=0, transparency=0, disposal=2)
    (REPO / "src/lib/data/html/loading.gif").write_bytes(buf.getvalue())


# ---------------------------------------------------------------------------
# App + packaging icons
# ---------------------------------------------------------------------------

def app_icon_svg(simplified: bool = False, size: int = 1024) -> str:
    """The Osza app mark: open ring + comet dot on a navy tile.
    Refines the existing logo geometry; the mark itself is unchanged."""
    import random  # noqa: F401  (deterministic - not actually used)
    ring_r = 0.4525 * size
    sw = 0.1094 * size if not simplified else 0.16 * size
    cx = cy = size / 2
    gap = 56.0
    stroke_cx = cx + ring_r * math.cos(math.radians(-45))
    stroke_cy = cy + ring_r * math.sin(math.radians(-45))
    dot_r = sw * 0.535 if not simplified else sw * 0.72
    ring_start, ring_end = -45 + gap / 2, -45 - gap / 2 + 360
    p0x = cx + ring_r * math.cos(math.radians(ring_start))
    p0y = cy + ring_r * math.sin(math.radians(ring_start))
    p1x = cx + ring_r * math.cos(math.radians(ring_end))
    p1y = cy + ring_r * math.sin(math.radians(ring_end))
    r = f"{ring_r:.1f}"
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{size}" height="{size}" '
        f'viewBox="0 0 {size} {size}">\n'
        '<defs><linearGradient id="ozg" x1="0.12" y1="0.92" x2="0.88" y2="0.08">'
        '<stop offset="0" stop-color="#00FFD1"/><stop offset="0.5" stop-color="#2FD9F2"/>'
        '<stop offset="1" stop-color="#7C8CF8"/></linearGradient>'
        '<radialGradient id="ozbg" cx="0.38" cy="0.30" r="1.05">'
        '<stop offset="0" stop-color="#182236"/><stop offset="0.55" stop-color="#0C1220"/>'
        '<stop offset="1" stop-color="#070A12"/></radialGradient></defs>\n'
        f'<rect width="{size}" height="{size}" rx="{int(size * 0.2246)}" fill="url(#ozbg)"/>\n'
        f'<path d="M{p0x:.1f} {p0y:.1f}A{r} {r} 0 1 1 {p1x:.1f} {p1y:.1f}" '
        f'fill="none" stroke="url(#ozg)" stroke-width="{sw:.1f}" stroke-linecap="round"/>\n'
        f'<circle cx="{stroke_cx:.1f}" cy="{stroke_cy:.1f}" r="{dot_r:.1f}" fill="url(#ozg)"/>\n'
        '</svg>\n'
    )


def page_icon_svg(size: int) -> str:
    """Document-type icon: page with folded corner + small ring mark."""
    s = 48
    fold = 13
    mark_r = 7.2
    mcx, mcy = 30.5, 30
    p0x = mcx + mark_r * math.cos(math.radians(-17))
    p0y = mcy + mark_r * math.sin(math.radians(-17))
    p1x = mcx + mark_r * math.cos(math.radians(337))
    p1y = mcy + mark_r * math.sin(math.radians(337))
    dx = mcx + mark_r * math.cos(math.radians(-45))
    dy = mcy + mark_r * math.sin(math.radians(-45))
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{size}" height="{size}" '
        f'viewBox="0 0 {s} {s}">\n'
        '<defs><linearGradient id="g" x1="0.15" y1="0.9" x2="0.85" y2="0.1">'
        '<stop offset="0" stop-color="#009E7C"/><stop offset="0.5" stop-color="#2FA8C9"/>'
        '<stop offset="1" stop-color="#7C8CF8"/></linearGradient></defs>\n'
        f'<path d="M8 4h20l12 12v28H8V4z" fill="#FFFFFF" stroke="#4B5566" '
        'stroke-width="2" stroke-linejoin="round"/>\n'
        f'<path d="M28 4v12h12" fill="#E9EDF5" stroke="#4B5566" stroke-width="2" '
        'stroke-linejoin="round"/>\n'
        f'<path d="M{p0x:.1f} {p0y:.1f}A{mark_r} {mark_r} 0 1 1 {p1x:.1f} {p1y:.1f}" '
        'fill="none" stroke="url(#g)" stroke-width="3.2" stroke-linecap="round"/>\n'
        f'<circle cx="{dx:.1f}" cy="{dy:.1f}" r="3.4" fill="url(#g)"/>\n'
        '</svg>\n'
    )


def save_ico(sizes_imgs: Dict[int, Image.Image], path: Path) -> None:
    path.write_bytes(_ico_bytes(sizes_imgs))


def _ico_bytes(sizes_imgs: Dict[int, Image.Image]) -> bytes:
    import struct
    sizes = sorted(sizes_imgs)
    header = struct.pack("<HHH", 0, 1, len(sizes))
    entries = b""
    offset = 6 + 16 * len(sizes)
    blobs = []
    for s in sizes:
        buf = io_bytes_png(sizes_imgs[s])
        w = 0 if s >= 256 else s
        entries += struct.pack("<BBBBHHII", w, w, 0, 0, 1, 32, len(buf), offset)
        blobs.append(buf)
        offset += len(buf)
    return header + entries + b"".join(blobs)


def io_bytes_png(img: Image.Image) -> bytes:
    import io
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


# pixel size -> ICNS 4-byte type code (PNG payloads)
ICNS_TYPES = {16: "icp4", 32: "ic11", 64: "ic12", 128: "ic07",
              256: "ic08", 512: "ic09", 1024: "ic10"}


def save_icns(sizes_imgs: Dict[int, Image.Image], path: Path) -> None:
    """Write an ICNS container: "icns" magic + big-endian total file
    length, then one PNG chunk per size (type + chunk length + payload)."""
    import struct
    chunks = b""
    for s in sorted(sizes_imgs):
        code = ICNS_TYPES[s].encode("ascii")
        blob = io_bytes_png(sizes_imgs[s])
        chunks += code + struct.pack(">I", len(blob) + 8) + blob
    path.write_bytes(b"icns" + struct.pack(">I", 8 + len(chunks)) + chunks)


def emit_packaging() -> None:
    exe = REPO / "src/lib/data/icons/exeicons"
    # PNG renders: small sizes use the simplified mark
    renders: Dict[int, Image.Image] = {}
    for s in (16, 24, 32, 48, 64, 128, 256, 512, 1024):
        svg = app_icon_svg(simplified=(s <= 32), size=1024)
        renders[s] = svg_to_png(svg, s)

    # linux hicolor
    for s in (16, 32, 48, 64, 128, 256):
        renders[s].save(REPO / f"linux/hicolor/{s}-apps-osza.png")
    write_svg(REPO / "linux/hicolor/sc-apps-osza.svg", app_icon_svg())

    # osza.ico / osza.icns
    save_ico({s: renders[s] for s in (16, 24, 32, 48, 64, 128, 256)}, exe / "osza.ico")
    save_icns({s: renders[s] for s in (16, 32, 128, 256, 512, 1024)}, exe / "osza.icns")

    # document-type icons
    page_renders = {s: svg_to_png(page_icon_svg(s), s) for s in (16, 32, 48, 256)}
    page_renders[16].save(exe / "page16.png")
    page_renders[32].save(exe / "page32.png")
    page_renders[48].save(exe / "page48.png")
    page_renders[256].save(exe / "page256.png")
    save_ico({s: page_renders[s] for s in (16, 32, 48, 256)}, exe / "page.ico")

    # DMG art
    renders[512].save(REPO / "mac/dmg-icon.png")
    _dmg_background().save(REPO / "mac/dmg-background.png")

    # monochrome app icon variants for chrome that needs them
    write_svg(REPO / "src/lib/data/icons/osza.svg", app_icon_svg())
    _mono_app_icon("#171C28", REPO / "src/lib/data/icons/osza-black.svg")
    _mono_app_icon("#E9EDF5", REPO / "src/lib/data/icons/osza-white.svg")

    # README logo banner 1280x640
    _readme_logo().save(REPO / "logo.png")


def _mono_app_icon(color: str, path: Path) -> None:
    size = 1024
    r = 0.4525 * size
    sw = 0.1094 * size
    cx = cy = size / 2
    p0 = (cx + r * math.cos(math.radians(-17)), cy + r * math.sin(math.radians(-17)))
    p1 = (cx + r * math.cos(math.radians(337)), cy + r * math.sin(math.radians(337)))
    dot = (cx + r * math.cos(math.radians(-45)), cy + r * math.sin(math.radians(-45)))
    svg = (f'<svg xmlns="http://www.w3.org/2000/svg" width="{size}" height="{size}" '
           f'viewBox="0 0 {size} {size}">\n'
           f'<path d="M{p0[0]:.1f} {p0[1]:.1f}A{r:.1f} {r:.1f} 0 1 1 {p1[0]:.1f} {p1[1]:.1f}" '
           f'fill="none" stroke="{color}" stroke-width="{sw:.1f}" stroke-linecap="round"/>\n'
           f'<circle cx="{dot[0]:.1f}" cy="{dot[1]:.1f}" r="{sw * 0.535:.1f}" fill="{color}"/>\n'
           '</svg>\n')
    write_svg(path, svg)


def _dmg_background() -> Image.Image:
    from PIL import ImageDraw
    W, H = 500, 460
    img = Image.new("RGBA", (W, H), (12, 18, 32, 255))
    dr = ImageDraw.Draw(img)
    # vertical navy wash
    for y in range(H):
        t = y / H
        dr.line([(0, y), (W, y)], fill=(int(24 - 12 * t), int(34 - 16 * t),
                                        int(54 - 22 * t), 255))
    # dim brand ring, right side
    ring = svg_to_png(
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 200 200">'
        '<path d="M60 30A72 72 0 1 1 35 95" fill="none" stroke="#00E5C8" '
        'stroke-opacity="0.16" stroke-width="14" stroke-linecap="round"/>'
        '<circle cx="148" cy="47" r="9" fill="#00E5C8" fill-opacity="0.22"/></svg>', 300)
    img.alpha_composite(ring, (W - 260, 30))
    # wordmark bottom-left
    brand = load_brand()
    lock = lockup_svg(brand, "#E9EDF5", D.GRADIENTS["neon"], width=494, height=132)
    mark = svg_to_png(lock, 300)
    img.alpha_composite(mark, (40, H - 140))
    return img


def _readme_logo() -> Image.Image:
    W, H = 1280, 640
    img = Image.new("RGBA", (W, H), (12, 18, 32, 255))
    tile = svg_to_png(app_icon_svg(), 256)
    img.alpha_composite(tile, ((W - 256) // 2, 96))
    brand = load_brand()
    lock = lockup_svg(brand, "#E9EDF5", D.GRADIENTS["neon"])
    mark = svg_to_png(lock, 560)
    img.alpha_composite(mark, ((W - 560) // 2, 400))
    return img


# ---------------------------------------------------------------------------
# Verification sheets: docs/screenshots/refresh
# ---------------------------------------------------------------------------

SHEET_NAMES_24 = list(D.ICONS_24.keys())


def _sheet(names: List[str], glyphs: Dict[str, List[dict]], grid: int, cell: int,
           palette: Dict[str, str], bg: str, title: str) -> Image.Image:
    import io
    from PIL import ImageDraw, ImageFont
    font = ImageFont.load_default()
    label = lambda n: n[:20]
    # column wide enough for both the glyph and its label
    colw = max([cell] + [6 * len(label(n)) + 12 for n in names])
    rowh = cell + 26
    cols = min(12, max(1, (1400 - 24) // colw))
    rows = math.ceil(len(names) / cols)
    pad = 24
    W = pad + cols * colw + 8
    H = pad + rows * rowh + 30
    img = Image.new("RGBA", (W, H), bg)
    dr = ImageDraw.Draw(img)
    dr.text((pad, 8), title, fill=palette["ink_strong"])
    for i, name in enumerate(names):
        cx_ = pad + (i % cols) * colw
        cy_ = pad + 18 + (i // cols) * rowh
        svg = render_svg(glyphs[name], grid, palette)
        png = svg_to_png(svg, cell)
        img.alpha_composite(png, (cx_ + (colw - cell) // 2, cy_))
        dr.text((cx_ + (colw - cell) // 2, cy_ + cell + 3), label(name),
                fill=palette["ink"], font=font)
    return img


def emit_sheets() -> None:
    out = REPO / "docs/screenshots/refresh"

    # full family at 24 on light and dark
    _sheet(SHEET_NAMES_24, D.ICONS_24, 24, 44, D.PALETTES["light"], "#FFFFFF",
           "Osza icon family - 24 px masters (light set)").convert("RGB").save(
        out / "icons-family-light.png")
    _sheet(SHEET_NAMES_24, D.ICONS_24, 24, 44, D.PALETTES["dark"], "#182236",
           "Osza icon family - 24 px masters (dark set)").convert("RGB").save(
        out / "icons-family-dark.png")

    # 16 px tuned set, rendered at 2x
    names16 = list(D.ICONS_16.keys())
    _sheet(names16, D.ICONS_16, 16, 32, D.PALETTES["light"], "#FFFFFF",
           "Hand-tuned 16 px set (light, rendered 2x)").convert("RGB").save(
        out / "icons-16-light.png")
    _sheet(names16, D.ICONS_16, 16, 32, D.PALETTES["dark"], "#182236",
           "Hand-tuned 16 px set (dark, rendered 2x)").convert("RGB").save(
        out / "icons-16-dark.png")

    # feature icons
    feat = list(D.FEATURE_48.keys())
    _sheet(feat, D.FEATURE_48, 48, 72, D._MENU_DUAL, "#FFFFFF",
           "48 px duotone feature icons").convert("RGB").save(
        out / "icons-feature-48.png")

    # per-theme preview chips (honest composites - the browser itself could
    # not be run headless in this environment, see the PR description)
    for theme in ("linux", "windows", "mac", "osza-cyber"):
        chip = _theme_chip(theme)
        chip.save(out / f"preview-theme-{theme}.png")
        # regenerate each theme's picker preview (themes/<t>/theme.png) from
        # the same composite; real screenshots should replace these once the
        # browser can be run headless
        chip.crop((0, 0, 640, 52)).save(REPO / f"themes/{theme}/theme.png")


def _theme_chip(theme: str) -> Image.Image:
    from PIL import ImageDraw
    dark = theme == "osza-cyber"
    bg = "#12141D" if dark else "#F7F8FA"
    strip = "#1B1E2B" if dark else "#E6E9F0"
    ink = "#9AA3B5" if dark else "#4B5566"
    W, H = 640, 96
    img = Image.new("RGBA", (W, H), bg)
    dr = ImageDraw.Draw(img)
    dr.rounded_rectangle([8, 8, 200, 44], radius=6, fill=strip)
    pal = D.PALETTES["dark"] if dark else D.PALETTES["light"]
    order = ["go-previous", "go-next", "view-refresh", "go-home", "list-add",
             "edit-find", "window-close", "application-menu"]
    x = 220
    for name in order:
        els = D.ICONS_16.get(name) or D.ICONS_24[name]
        svg = render_svg(els, 16, pal, with_gradient=False)
        png = svg_to_png(svg, 32)
        img.alpha_composite(png, (x, 12))
        x += 44
    dr.text((16, 58), f"theme: {theme}", fill=ink)
    return img


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description="Osza icon build pipeline")
    ap.add_argument("--check-contrast", action="store_true",
                    help="verify palette tokens against WCAG 3:1 and exit")
    ap.add_argument("--masters-only", action="store_true")
    args = ap.parse_args()

    if args.check_contrast:
        problems = D.check_contrast()
        print("Osza palette contrast check (WCAG 2.1 non-text, >= 3:1)")
        if problems:
            for p in problems:
                print("  FAIL", p)
            return 1
        print("  all tokens pass on their declared surfaces")
        return 0

    emit_masters()
    if args.masters_only:
        return 0

    emit_bundled_theme()
    emit_resource_icons()
    emit_theme_images()
    emit_loading_strip()
    emit_brand_art()
    emit_plugin_rasters()
    emit_gesture_gifs()
    emit_loading_gif()
    emit_packaging()
    emit_sheets()
    print("Osza icon build: all derivatives regenerated")
    return 0


if __name__ == "__main__":
    sys.exit(main())
