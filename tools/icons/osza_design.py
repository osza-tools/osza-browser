#!/usr/bin/env python3
# ============================================================
# Osza - icon design system
#
# Single source of truth for the Osza icon language:
#
#   * palette tokens (light set, dark set, dual-safe neutrals)
#      - run `python3 tools/icons/build.py --check-contrast` to
#        verify every token against the WCAG 3:1 non-text rule
#   * drawing helpers (arcs, stars, gears, arrowheads)
#   * the full glyph catalogue:
#        ICONS_24    - 24 px masters for every themed icon name
#        ICONS_16    - hand-tuned 16 px versions of the
#                      high-traffic glyphs
#        FEATURE_48  - 48 px duotone feature icons
#        MISC_SVG    - menu / html / plugin / theme artwork
#
# Grid:      24 x 24 with a 20 x 20 live area (2 px margin)
#            16 x 16 with a ~13 px live area
#            48 x 48 with a 40 x 40 live area
# Stroke:    2 px on the 24 grid (1.6 at 16, 3 at 48),
#            round caps and joins, no fills except where a
#            filled state carries meaning.
# Colors:    everything is expressed as a palette token string;
#            tools/icons/build.py resolves tokens per target
#            (light theme, dark theme, per-theme images, ...).
# Qt subset: paths, basic shapes, linear/radial gradients,
#            clip paths and opacity only - no filters, masks
#            or <text>.
#
# Copyright (C) 2026 Osza Tools contributors
# GPL-3.0-or-later
# ============================================================

from __future__ import annotations

import math
from typing import Dict, List, Tuple

# ---------------------------------------------------------------------------
# Palette
# ---------------------------------------------------------------------------

BRAND = {
    "mint": "#00FFD1",
    "mint_deep": "#00E5C8",
    "cyan": "#2FD9F2",
    "periwinkle": "#7C8CF8",
    "accent_light": "#009E7C",   # brand accent legible on light surfaces
    "navy_900": "#070A12",
    "navy_800": "#0C1220",
    "navy_700": "#182236",
}

# Surfaces every token is verified against (see check_contrast()).
SURFACES_LIGHT = ["#FFFFFF", "#E9EDF5"]       # light chrome range
SURFACES_DARK = ["#0C1220", "#182236"]        # dark chrome range

# Tokens for the bundled light-surface icon set ("osza").
LIGHT_SET = {
    "ink": "#4B5566",
    "ink_strong": "#171C28",
    # one half-step darker than the #009E7C focus ring used by the CSS
    # themes so accent icons also hold 3:1 on light *grey* surfaces
    "accent": "#008F72",
    "danger": "#C13A2E",
    "warning": "#8F6400",
    "success": "#008F72",
}

# Tokens for the bundled dark-surface icon set ("osza-dark").
DARK_SET = {
    "ink": "#9AA3B5",
    "ink_strong": "#E9EDF5",
    "accent": "#3DDEC0",
    "danger": "#FF8377",
    "warning": "#FFC46B",
    "success": "#3DDEC0",
}

# Neutral tokens that keep >= 3:1 on both light and dark chrome.
# Used for artwork that exists as a single file for both modes
# (tab close buttons, dormant fallbacks, overlay art).
DUAL_SAFE = {
    "neutral": "#6E788C",
    "tab_close": "#757F93",
    "tab_close_hover": "#667084",
    "tab_close_pressed": "#E5484D",
}

# Brand gradients. "neon" for dark surfaces (internal pages, osza-cyber),
# "lite" for light surfaces (feature icons on the preferences dialog).
GRADIENTS = {
    # neon ramp: dark surfaces only (internal pages, osza-cyber chrome)
    "neon": [BRAND["mint"], BRAND["cyan"], BRAND["periwinkle"]],
    # light ramp: every stop holds 3:1 on white and light grey as well
    # as on the navy chrome, so feature icons work in light and dark
    "lite": ["#008F72", "#0077A8", "#5A6BE8"],
}

# The palette variants build.py knows how to emit. "gradient_kind" picks
# which brand gradient ramp goes with a palette (see GRADIENTS).
PALETTES: Dict[str, Dict[str, str]] = {
    "light": dict(LIGHT_SET, gradient_kind="lite"),
    "dark": dict(DARK_SET, gradient_kind="neon"),
}


def _rel_lum(hex_color: str) -> float:
    h = hex_color.lstrip("#")
    r, g, b = (int(h[i:i + 2], 16) / 255.0 for i in (0, 2, 4))

    def lin(c: float) -> float:
        return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4

    return 0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b)


def contrast_ratio(a: str, b: str) -> float:
    la, lb = _rel_lum(a), _rel_lum(b)
    hi, lo = max(la, lb), min(la, lb)
    return (hi + 0.05) / (lo + 0.05)


def check_contrast() -> List[str]:
    """Verify every palette token keeps >= 3:1 on its surfaces."""
    problems = []

    def check(token: str, color: str, surfaces: List[str]) -> None:
        for s in surfaces:
            ratio = contrast_ratio(color, s)
            if ratio < 3.0:
                problems.append(
                    f"{token} {color} on {s}: {ratio:.2f}:1 (< 3:1)"
                )

    for token, color in LIGHT_SET.items():
        check(f"light.{token}", color, SURFACES_LIGHT)
    for token, color in DARK_SET.items():
        check(f"dark.{token}", color, SURFACES_DARK)
    for token, color in DUAL_SAFE.items():
        check(f"dual.{token}", color, SURFACES_LIGHT + SURFACES_DARK)
    for i, color in enumerate(GRADIENTS["lite"]):
        check(f"gradient.lite[{i}]", color, SURFACES_LIGHT + SURFACES_DARK)
    return problems


# ---------------------------------------------------------------------------
# Drawing helpers. Elements are plain dicts; build.py renders them.
#   {"t": "path", "d": ..., "c": token, "w": stroke width override}
#   {"t": "fill", "d": ..., "c": token}                     filled path
#   {"t": "circle", ... , "fill": True}                     filled circle
#   {"t": "rect", "x","y","w","h", "rx"}                    stroked rect
# ---------------------------------------------------------------------------

def P(d: str, c: str = "ink", w: float = None, dash=None) -> dict:
    el = {"t": "path", "d": d, "c": c}
    if w is not None:
        el["w"] = w
    if dash:
        el["dash"] = dash
    return el


def F(d: str, c: str = "ink", opacity: float = None) -> dict:
    el = {"t": "fill", "d": d, "c": c}
    if opacity is not None:
        el["opacity"] = opacity
    return el


def C(cx: float, cy: float, r: float, c: str = "ink", fill: bool = False) -> dict:
    return {"t": "circle", "cx": cx, "cy": cy, "r": r, "c": c, "fill": fill}


def R(x: float, y: float, w: float, h: float, c: str = "ink", rx: float = 2.0) -> dict:
    return {"t": "rect", "x": x, "y": y, "w": w, "h": h, "c": c, "rx": rx}


def _fmt(v: float) -> str:
    s = f"{v:.2f}".rstrip("0").rstrip(".")
    return s if s else "0"


def pt(x: float, y: float) -> str:
    return f"{_fmt(x)} {_fmt(y)}"


def arc(cx: float, cy: float, r: float, a0: float, a1: float,
        c: str = "ink", w: float = None, sweep: int = 1, large: int = None) -> dict:
    """Arc path element. Angles in degrees, screen coordinates
    (0 = east, 90 = south), sweep=1 draws clockwise from a0 to a1."""
    p0 = (cx + r * math.cos(math.radians(a0)), cy + r * math.sin(math.radians(a0)))
    p1 = (cx + r * math.cos(math.radians(a1)), cy + r * math.sin(math.radians(a1)))
    if large is None:
        large = 1 if abs(a1 - a0) > 180 else 0
    d = f"M{pt(*p0)}A{_fmt(r)} {_fmt(r)} 0 {large} {sweep} {pt(*p1)}"
    return P(d, c, w)


def arrowhead(x: float, y: float, angle_deg: float, size: float = 3.4,
              c: str = "ink") -> dict:
    """Chevron arrowhead with its tip at (x, y) pointing along angle_deg."""
    back = math.radians(angle_deg + 180.0)
    d = (
        f"M{pt(x + size * math.cos(back + math.radians(38)), y + size * math.sin(back + math.radians(38)))}"
        f"L{pt(x, y)}"
        f"L{pt(x + size * math.cos(back - math.radians(38)), y + size * math.sin(back - math.radians(38)))}"
    )
    return P(d, c)


def star_d(cx: float, cy: float, r_out: float, r_in: float = None,
           points: int = 5, rot: float = -90.0) -> str:
    if r_in is None:
        r_in = r_out * 0.45
    verts = []
    for i in range(points * 2):
        r = r_out if i % 2 == 0 else r_in
        a = math.radians(rot + 180.0 * i / points)
        verts.append(pt(cx + r * math.cos(a), cy + r * math.sin(a)))
    return "M" + "L".join(verts) + "Z"


def gear_d(cx: float, cy: float, r_tip: float, r_root: float,
           teeth: int = 8, hole: float = 0.0) -> List[dict]:
    """Gear as stroke elements: toothed outline plus (optionally) a hole."""
    verts = []
    for i in range(teeth):
        a = 2.0 * math.pi * i / teeth
        span = math.pi / teeth
        for r, da in ((r_root, -0.62 * span), (r_tip, -0.30 * span),
                      (r_tip, 0.30 * span), (r_root, 0.62 * span)):
            verts.append(pt(cx + r * math.cos(a + da), cy + r * math.sin(a + da)))
    els = [P("M" + "L".join(verts) + "Z")]
    if hole:
        els.append(C(cx, cy, hole))
    return els


def ring_d(cx: float, cy: float, r: float, w: float, gap_deg: float = 56.0,
           c: str = "ink") -> List[dict]:
    """The Osza 'o': an open ring with the gap (and comet dot) at
    the north-east, 45 degrees up-right."""
    a_gap = -45.0
    start = a_gap + gap_deg / 2.0          # e.g. -17
    end = a_gap - gap_deg / 2.0 + 360.0    # e.g. 337, drawn the long way
    els = [arc(cx, cy, r, start, end, c=c, w=w, sweep=1, large=1)]
    dot_r = w * 1.05
    dot_a = math.radians(a_gap)
    els.append(C(cx + r * math.cos(dot_a), cy + r * math.sin(dot_a),
                 dot_r, c="accent", fill=True))
    return els


# ---------------------------------------------------------------------------
# ICONS_24 - master glyphs for every themed icon name
# (24 x 24 grid, 20 x 20 live area, 2 px stroke)
# ---------------------------------------------------------------------------

_SPEAKER = "M4 9.5v5h3.2l5.3 4.3V5.2L7.2 9.5H4z"
_DOC = "M6 3.5h7.5l4.5 4.5V20.5H6V3.5z"
_DOC_FOLD = "M13.5 3.5V8H18"
_FOLDER = "M3 19V6.5h5.5l2 2H21V19H3z"
_LENS = (C(10.3, 10.3, 6.3), P("M15 15l5.2 5.2"))

ICONS_24: Dict[str, List[dict]] = {
    # --- navigation and arrows ---
    "arrow-down": [P("M12 4.5v15"), P("M5.5 13 12 19.5 18.5 13")],
    "arrow-left": [P("M19.5 12H4.5"), P("M11 5.5 4.5 12 11 18.5")],
    "arrow-left-double": [P("M11.5 6.5 6 12l5.5 5.5"), P("M18.5 6.5 13 12l5.5 5.5")],
    "arrow-right": [P("M4.5 12h15"), P("M13 5.5 19.5 12 13 18.5")],
    "arrow-right-double": [P("M12.5 6.5 18 12l-5.5 5.5"), P("M5.5 6.5 11 12l-5.5 5.5")],
    "go-down": [P("M12 4.5v15"), P("M5.5 13 12 19.5 18.5 13")],
    "go-up": [P("M12 19.5v-15"), P("M5.5 11 12 4.5 18.5 11")],
    "go-next": [P("M4 12h13.5"), P("M11.5 5.5 18.5 12 11.5 18.5")],
    "go-previous": [P("M20 12H6.5"), P("M12.5 5.5 5.5 12l7 6.5")],
    "go-home": [P("M3.5 11.5 12 4l8.5 7.5"), P("M6 9.8V20h12V9.8"), P("M10 20v-5.5h4V20")],
    "go-jump-locationbar": [P("M4.5 6v6.5a4 4 0 0 0 4 4h9.5"),
                            P("M15.5 13.5 18.5 16.5l-3 3")],
    "view-refresh": [arc(12, 12, 8.5, 135, -45), P("M15.5 3.5 18 6l-2.5 2.5")],
    "process-stop": [P("M6 6l12 12"), P("M18 6 6 18")],
    "view-restore": [P("M4 14V4h10"), P("M10 10h10v10H10V10z")],
    "view-fullscreen": [P("M4 9V4h5"), P("M20 9V4h-5"), P("M4 15v5h5"), P("M20 15v5h-5")],

    # --- tabs and windows ---
    "tab-new": [P("M3 18V8.5L7.5 4H21v14H3z"), P("M14 9.2v5.6"), P("M11.2 12h5.6")],
    "tab-detach": [P("M3 18.5V9l4-4h8.5"), P("M12.5 10.5 19.5 3.5"), P("M13.5 3.5h6v6")],
    "tab-duplicate": [P("M3 18V8.5L7.5 4H18v14H3z"), P("M9 8.5V6l3.5-2.5H21v12")],
    "window-new": [P("M3 5h18v14H3V5z"), P("M3 9h18"), P("M13.5 11.8v4.4"), P("M11.3 14h4.4")],
    "window-close": [P("M3 5h18v14H3V5z"), P("M3 9h18"), P("M11 12.2l5 5"), P("M16 12.2l-5 5")],
    "application-exit": [P("M9.5 4H5v16h4.5"), P("M13 12h8"),
                         P("M17.5 8.5 21 12l-3.5 3.5")],
    "application-menu": [P("M4 7h16"), P("M4 12h16"), P("M4 17h16")],
    "list-add": [P("M12 5v14"), P("M5 12h14")],
    "list-remove": [P("M5 12h14")],
    "dialog-close": [P("M6 6l12 12"), P("M18 6 6 18")],

    # --- bookmarks, history, identity ---
    "bookmark-new": [P(star_d(12, 12.3, 8.1, 3.6)), P("M18.5 3.5v4"), P("M16.5 5.5h4")],
    "bookmarks": [F(star_d(12, 12.3, 8.4, 3.8))],
    "bookmarks-organize": [P(_FOLDER), F(star_d(14.5, 13.2, 4.3, 2.0))],
    "rating": [F(star_d(12, 12.5, 8.5, 3.9), c="accent")],
    "rating-unrated": [P(star_d(12, 12.5, 8.5, 3.9))],
    "deep-history": [arc(12, 12, 8.5, 100, 350),
                     arrowhead(12 + 8.5 * math.cos(math.radians(350)),
                               12 + 8.5 * math.sin(math.radians(350)), 80),
                     P("M12 7.8V12l3.2 2.2")],
    "view-calendar": [P("M4 6.5h16V20.5H4V6.5z"), P("M4 10.5h16"),
                      P("M8 3.5v4"), P("M16 3.5v4")],
    "user-identity": [P("M3 5h18v14H3V5z"), C(12, 10.4, 2.7),
                      P("M7.3 17.3c0.9-2.5 2.6-3.7 4.7-3.7s3.8 1.2 4.7 3.7")],
    "user-trash": [P("M4.5 6.5h15"), P("M9.5 6.5V4.2h5v2.3"),
                   P("M7 6.5 8 20h8l1-13.5"), P("M10.3 10v6.3"), P("M13.7 10v6.3")],
    "user-trash-full": [P("M4.5 4.5h15"), P("M7 6.5 8 20h8l1-13.5"),
                        P("M10.3 10v6.3"), P("M13.7 10v6.3"),
                        P("M8.6 6.5V3.9"), P("M12 6.5V3.2"), P("M15.4 6.5V3.9")],
    "view-private-symbolic": [C(7.3, 13, 3.6), C(16.7, 13, 3.6), P("M10.9 13h2.2"),
                              P("M3.7 11.2 2.2 9.7"), P("M20.3 11.2l1.5-1.5")],

    # --- files, downloads, sharing ---
    "download": [P("M12 3.5V15"), P("M7 10.5l5 5 5-5"), P("M4.5 16v3.5h15V16")],
    "edit-download": [P("M5.5 3.5v9"), P("M2.8 10.2l2.7 2.7 2.7-2.7"),
                      P("M12.8 13.6l5.6-5.6 2 2-5.6 5.6-2.8 0.8 0.8-2.8z")],
    "document-new": [P(_DOC), P(_DOC_FOLD), P("M12 11.5v6"), P("M9 14.5h6")],
    "document-open": [P("M3 19V6.5h5.5l2 2h7"), P("M3 19l2.8-4.8H21L18.2 19H3z")],
    "document-open-remote": [P("M3 6.5h5.5l2 2h6"),
                             C(15.5, 13.5, 4.6), P("M10.9 13.5h9.2"),
                             P("M15.5 8.9c-2.4 2.2-2.4 7.9 0 10.1"),
                             P("M15.5 8.9c2.4 2.2 2.4 7.9 0 10.1")],
    "document-save": [P("M4 4h13l3 3v13H4V4z"), P("M8 20v-6.5h8V20"), P("M8 4v4.5h7V4")],
    "document-print": [P("M7 8.5V4h10v4.5"), P("M4 8.5h16v6.5H4V8.5z"),
                       P("M7.5 15h9v5h-9z")],
    "document-share": [C(6.5, 6, 2.7), C(6.5, 18, 2.7), C(17.5, 12, 2.7),
                       P("M8.9 7.2 15.1 10.8"), P("M8.9 16.8 15.1 13.2")],
    "document-properties": [P("M6 20.5V3.5h7.5l4.5 4.5v4"),
                            P(_DOC_FOLD)] + gear_d(15, 15.8, 4.6, 3.5, 7, 1.7),
    "document-encrypted": [P(_DOC), P(_DOC_FOLD), P("M12 13v-1.4a2.25 2.25 0 0 1 4.5 0V13"),
                           P("M10.5 13h7.5v6h-7.5z", c="accent")],
    "folder-new": [P(_FOLDER), P("M16 10.5v7"), P("M12.5 14h7")],
    "image-x-generic": [R(4, 5, 16, 14), P("M4 16l4.7-4.7 3.4 3.4 3-3 4.9 4.3"),
                        C(8.6, 9, 1.6)],
    "text-html": [P(_DOC), P(_DOC_FOLD), P("M10 11.5 7.5 14l2.5 2.5"),
                  P("M14 11.5 16.5 14 14 16.5")],
    "application-x-javascript": [P(_DOC), P(_DOC_FOLD),
                                 F("M14.8 10 10.9 15.7h2.8L12.4 20l4-5.7h-2.8l1.2-4.3z")],
    "applications-graphics": [C(12, 12, 8.5), C(15.2, 14.2, 2.3),
                              C(9, 9.5, 1.5, fill=True), C(12.5, 8.2, 1.5, fill=True)],

    # --- editing ---
    "edit-clear": [P("M3.8 16.2l8.4-8.4 5.9 5.9-8.4 8.4H6.2l-2.4-2.4z"),
                   P("M10.9 9.1l5.9 5.9"), P("M14 20.5h6.5")],
    "edit-copy": [P("M9 8V4h11v12h-4"), P("M4 8h11v12H4V8z")],
    "edit-cut": [C(6.3, 6.6, 2.6), C(6.3, 17.4, 2.6), P("M8.5 8.2 19.5 18.6"),
                 P("M8.5 15.8 19.5 5.4")],
    "edit-delete": [P("M4.5 6.5h15"), P("M9.5 6.5V4.2h5v2.3"),
                    P("M7 6.5 8 20h8l1-13.5"), P("M10.3 10v6.3"), P("M13.7 10v6.3")],
    "edit-paste": [P("M5 5h14v15.5H5V5z"),
                   P("M9 6V4.2c0-0.6 0.5-1.2 1.2-1.2h3.6c0.7 0 1.2 0.6 1.2 1.2V6"),
                   P("M8.5 11h7"), P("M8.5 14.5h7"), P("M8.5 18h4.5")],
    "edit-redo": [P("M4.5 16c0-5 3.9-9 8.9-9h5.6"), P("M16.5 4.2 19.9 7l-3.4 2.8")],
    "edit-undo": [P("M19.5 16c0-5-3.9-9-8.9-9H5"), P("M7.5 4.2 4.1 7l3.4 2.8")],
    "edit-select-all": [P("M4.5 6.5h15v11h-15z", dash="3 2.6"),
                        P("M8.5 10h7"), P("M8.5 13.5h7"), P("M8.5 17h4")],
    "edit-find": list(_LENS),

    # --- zoom and media ---
    "zoom-in": list(_LENS) + [P("M10.3 7.6v5.4"), P("M7.6 10.3h5.4")],
    "zoom-out": list(_LENS) + [P("M7.6 10.3h5.4")],
    "zoom-original": list(_LENS) + [P("M8.6 8.4v4.2"), C(10.7, 10.0, 0.75, fill=True),
                                    C(10.7, 12.2, 0.75, fill=True), P("M12.8 8.4v4.2")],
    "audio-volume-high": [P(_SPEAKER), P("M15.8 9.6a3.6 3.6 0 0 1 0 4.8"),
                          P("M18.3 7.5a7 7 0 0 1 0 9")],
    "audio-volume-muted": [P(_SPEAKER), P("M16 9.5l5 5"), P("M21 9.5l-5 5")],
    "media-playback-pause": [P("M8.7 5.5v13"), P("M15.3 5.5v13")],
    "media-playback-start": [F("M8 5.2v13.6L19.5 12 8 5.2z")],

    # --- status and dialogs ---
    "dialog-error": [C(12, 12, 8.5, c="danger"), P("M8.8 8.8l6.4 6.4", c="danger"),
                     P("M15.2 8.8l-6.4 6.4", c="danger")],
    "dialog-information": [C(12, 12, 8.5), C(12, 8.2, 1.3, fill=True), P("M12 11.2v5.4")],
    "dialog-question": [C(12, 12, 8.5),
                        P("M9.7 9.4c0-1.7 1.3-3 2.9-3 1.6 0 2.9 1.1 2.9 2.7 0 2-2.6 2.3-2.6 4.2"),
                        C(12.6, 16.8, 1.3, fill=True)],
    "dialog-warning": [P("M12 3.8 21.2 19.6H2.8L12 3.8z", c="warning"),
                       P("M12 9.8v4.6", c="warning"), C(12, 17.4, 1.3, c="warning", fill=True)],

    # --- security ---
    "security-low": [R(6.5, 11, 11, 9.5, c="danger", rx=1.6),
                     P("M9 11V8a3.2 3.2 0 0 1 6.4 0", c="danger")],
    "security-medium": [R(6.5, 11, 11, 9.5, c="warning", rx=1.6),
                        P("M9 11V7.8a3.2 3.2 0 0 1 6.4 0V11", c="warning")],

    # --- other ---
    "configure": gear_d(12, 12, 8.2, 6.3, 8, 3.1),
    "help-about": [C(12, 12, 8.5), C(12, 8.2, 1.3, fill=True), P("M12 11.2v5.4")],
    "help-contents": [P("M4 5.5c2.6-1.4 5.4-1.4 8 0.2 2.6-1.6 5.4-1.6 8-0.2v13.4"
                        "c-2.6-1.4-5.4-1.4-8 0.2-2.6-1.6-5.4-1.6-8-0.2V5.5z"),
                      P("M12 5.7v13.4")],
    "mail-message-new": [P("M3.5 7h17v11h-17V7z"), P("M3.5 7 12 13.5 20.5 7"),
                         P("M18.5 2.5v4"), P("M16.5 4.5h4")],
    "preferences-system-network": [C(12, 12, 8.5), P("M3.5 12h17"),
                                   P("M12 3.5c-3.2 2.3-3.2 14.7 0 17"),
                                   P("M12 3.5c3.2 2.3 3.2 14.7 0 17")],
    "go-down-search": list(_LENS) + [P("M10.3 7v6.6"), P("M7.4 11.2l2.9 2.9 2.9-2.9")],
    "go-up-search": list(_LENS) + [P("M10.3 13.6V7"), P("M7.4 9.4l2.9-2.9 2.9 2.9")],

    # --- brand ---
    "osza": ring_d(12, 12, 8.0, 2.2),
}

# ---------------------------------------------------------------------------
# ICONS_16 - hand-tuned 16 px versions of the high-traffic glyphs
# (16 x 16 grid, ~13 px live area, 1.6 px stroke)
# ---------------------------------------------------------------------------

_SPEAKER16 = "M2.6 6.4v3.2h2L8.4 12V4L4.6 6.4h-2z"
_LENS16 = (C(7, 7, 4.2), P("M10.2 10.2l3.6 3.6"))

ICONS_16: Dict[str, List[dict]] = {
    "go-previous": [P("M13.4 8H4"), P("M7.6 3.6 3.2 8l4.4 4.4")],
    "go-next": [P("M2.6 8H12"), P("M8.4 3.6 12.8 8l-4.4 4.4")],
    "view-refresh": [arc(8, 8, 5.6, 135, -45), P("M10.2 2.3 12 4.04l-1.8 1.74")],
    "process-stop": [P("M4 4l8 8"), P("M12 4 4 12")],
    "go-home": [P("M2.2 8 8 2.6l5.8 5.4"), P("M4 6.9V13.5h8V6.9"),
                P("M6.6 13.5V9.9h2.8v3.6")],
    "list-add": [P("M8 2.8v10.4"), P("M2.8 8h10.4")],
    "tab-new": [P("M2.5 13.5V6l2.6-2.6h8.4v10.1H2.5z"), P("M9.5 6.8v4.4"),
                P("M7.3 9h4.4")],
    "window-close": [P("M2.5 3.5h11v9h-11v-9z"), P("M2.5 6h11"),
                     P("M7.4 7.8l3.2 3.2"), P("M10.6 7.8l-3.2 3.2")],
    "bookmark-new": [P(star_d(7.6, 8.2, 5.2, 2.4)), P("M12.6 2.4v2.8"),
                     P("M11.2 3.8h2.8")],
    "edit-find": list(_LENS16),
    "application-menu": [P("M2.8 4.5h10.4"), P("M2.8 8h10.4"), P("M2.8 11.5h10.4")],
    "download": [P("M8 2.6v8"), P("M4.8 7.4 8 10.6l3.2-3.2"), P("M3 12.6h10")],
    "document-encrypted": [P("M4 2.8h5l3 3v7.4H4V2.8z"), P("M9 2.8V6h3"),
                           P("M6.9 8.8V8a1.3 1.3 0 0 1 2.6 0v0.8"),
                           P("M5.8 8.8h4.4v3.7H5.8z", c="accent")],
    "audio-volume-high": [P(_SPEAKER16), P("M10.4 6.3a2.4 2.4 0 0 1 0 3.4"),
                          P("M12.1 4.9a4.7 4.7 0 0 1 0 6.2")],
    "audio-volume-muted": [P(_SPEAKER16), P("M10.6 6.4l3.4 3.4"),
                           P("M14 6.4l-3.4 3.4")],
}

# ---------------------------------------------------------------------------
# FEATURE_48 - 48 px duotone feature icons
# (48 x 48 grid, 40 x 40 live area, 3 px stroke, ink + brand gradient)
# ---------------------------------------------------------------------------

def _g(shape: dict) -> dict:
    """Recolor an element to the brand gradient token."""
    shape = dict(shape)
    shape["c"] = "gradient"
    return shape


FEATURE_48: Dict[str, List[dict]] = {
    "general": gear_d(24, 24, 16.5, 12.6, 8) + [_g(C(24, 24, 5.6))],
    "appearance": [C(24, 24, 16.5), C(30, 28.5, 4.6),
                   _g(C(17.5, 18.5, 3.1, fill=True)), _g(C(23.5, 15, 3.1, fill=True)),
                   _g(C(29.5, 20, 3.1, fill=True))],
    "browsing": [C(24, 24, 16.5), _g(P("M7.5 24h33")),
                 _g(P("M24 7.5c-6.2 4.4-6.2 28.6 0 33")),
                 _g(P("M24 7.5c6.2 4.4 6.2 28.6 0 33"))],
    "tabs": [P("M6 40V16l5-5h18v29H6z"), _g(P("M16 16v-3l5-5h18v25"))],
    "downloads": [P("M24 6v22"), _g(P("M13 17l11 11 11-11")),
                  P("M7 33v7h34v-7")],
    "extensions": [P("M11 11h10v3c0 2.7 4 2.7 4 0v-3h10v10h3c2.7 0 2.7 4 0 4h-3v10H25v3"
                     "c0 2.7-4 2.7-4 0v-3H11V11z"), _g(C(24, 24, 5, fill=True))],
    "fonts": [_g(P("M14 37 23 10l9 27")), _g(P("M17.5 28.5h11")),
              P("M10 41h28")],
    "passwords": [_g(C(16.5, 16.5, 6.8)), P("M21.5 21.5 39 39"),
                  P("M31.5 31.5l4-4"), P("M35 35l4-4")],
    "privacy": [P("M24 5 41 10.5V22c0 10.5-7 17.8-17 21-10-3.2-17-10.5-17-21V10.5L24 5z"),
                _g(P("M16.5 23.5 22 29l9.5-11"))],
    "notifications": [P("M24 6a10.5 10.5 0 0 1 10.5 10.5c0 6 2 8.5 3.5 10H10"
                        "c1.5-1.5 3.5-4 3.5-10A10.5 10.5 0 0 1 24 6z"),
                       _g(P("M20.5 30.5a3.5 3.5 0 0 0 7 0"))],
    "shortcuts": [P("M5 14h38v20H5V14z"),
                  C(12, 20, 1.4, fill=True), C(17.5, 20, 1.4, fill=True),
                  C(23, 20, 1.4, fill=True), C(28.5, 20, 1.4, fill=True),
                  C(34, 20, 1.4, fill=True),
                  _g(P("M17 27.5h14"))],
    "spellcheck": [P("M10 6h17l7 7v29H10V6z"), P("M27 6v7h7"),
                   _g(P("M15.5 28l5 5 10-12"))],
    "other": [P("M8 15h32"), P("M8 24h32"), P("M8 33h32"),
              _g(C(30, 15, 3.6, fill=True)), _g(C(16, 24, 3.6, fill=True)),
              _g(C(24, 33, 3.6, fill=True))],
    # site info dialog
    "document-properties": [P("M10 6h17l7 7v29H10V6z"), P("M27 6v7h7")]
                           + [_g(e) for e in gear_d(31.5, 31.5, 7.2, 5.5, 7, 3.2)],
    "applications-graphics": [C(24, 24, 16.5), C(30.5, 28, 4.6),
                              _g(C(16.5, 18, 3.1, fill=True)),
                              _g(C(23, 15.5, 3.1, fill=True)),
                              _g(C(29, 21.5, 3.1, fill=True))],
}

# Feature icons that also exist as the "selected" browsing-library pair.
FEATURE_48["bigstar"] = [P(star_d(24, 25, 17.5, 7.9))]
FEATURE_48["bigstar-selected"] = [_g(F(star_d(24, 25, 17.5, 7.9)))]
FEATURE_48["bighistory"] = [C(24, 24, 16.5), P("M24 14.5V24l7 4.5")]
FEATURE_48["bighistory-selected"] = [_g(C(24, 24, 16.5)), _g(P("M24 14.5V24l7 4.5"))]
FEATURE_48["download"] = [P("M24 6v22"), _g(P("M13 17l11 11 11-11")), P("M7 33v7h34v-7")]

# ---------------------------------------------------------------------------
# MISC_SVG - dormant fallbacks, menu icons, html page buttons, plugin art.
# Each entry: name -> (size, elements); colors use the "dual" palette
# (dual-safe neutrals) unless noted.
# ---------------------------------------------------------------------------

_MENU_DUAL = {"ink": DUAL_SAFE["neutral"], "accent": GRADIENTS["lite"][0],
              "accent2": GRADIENTS["lite"][2],
              "gradient": "gradient-lite", "danger": DUAL_SAFE["tab_close_pressed"],
              "warning": DUAL_SAFE["neutral"], "success": GRADIENTS["lite"][0],
              "ink_strong": DUAL_SAFE["neutral"], "gradient_kind": "lite"}

# Internal pages are always dark navy - the "page" set uses their tokens.
_PAGE_DUAL = {"ink": "#E9EDF5", "accent": "#00FFD1", "gradient": "gradient-neon",
              "danger": "#FF8377", "warning": "#FFC46B", "success": "#00FFD1",
              "ink_strong": "#FFFFFF", "gradient_kind": "neon"}

MISC_SVG: Dict[str, Tuple[float, List[dict]]] = {
    # menu fallbacks (dormant once the bundled theme is complete,
    # drawn dual-safe so they stay legible if ever shown)
    "menu/history": (24, [C(12, 12, 8.5), P("M12 7.5V12l3.4 2.3")]),
    "menu/history_entry": (24, [C(12, 12, 8.5), P("M12 7.5V12l3.4 2.3"), C(12, 12, 3.4, fill=True)]),
    "menu/tab-new": (24, ICONS_24["tab-new"]),
    "menu/window-new": (24, ICONS_24["window-new"]),
    "menu/tab": (24, [P("M3 18V8.5L7.5 4H21v14H3z")]),
    "menu/settings": (24, ICONS_24["configure"]),
    "menu/download": (24, ICONS_24["download"]),
    "menu/search-icon": (24, list(_LENS)),
    "menu/privatebrowsing": (24, ICONS_24["view-private-symbolic"]),
    "menu/speeddial": (24, [R(3.5, 4.5, 17, 15, rx=2), C(9, 10, 1.4, fill=True),
                            C(15, 10, 1.4, fill=True), C(9, 15, 1.4, fill=True),
                            C(15, 15, 1.4, fill=True)]),

    # site-info dialog glyphs (32 grid). Colors chosen to hold >= 3:1 on
    # both light and dark palettes (single files for both modes).
    "locationbar/safe": (32, [R(8, 13.5, 16, 13.5, rx=2.4),
                              P("M11.5 13.5v-4a4.5 4.5 0 0 1 9 0v4", c="ink")]),
    "locationbar/unsafe": (32, [R(8, 13.5, 16, 13.5, rx=2.4, c="danger"),
                               P("M11.5 13.5v-4a4.5 4.5 0 0 1 9 0", c="danger")]),
    "locationbar/visit1": (32, [P(star_d(16, 17, 12.5, 5.6))]),
    "locationbar/visit2": (32, [P(star_d(16, 17, 12.5, 5.6)),
                                F(star_d(16, 17, 12.5, 5.6), opacity=0.45)]),
    "locationbar/visit3": (32, [F(star_d(16, 17, 12.5, 5.6), c="accent2")]),

    # web page fallback glyphs
    "other/webpage": (24, [C(12, 12, 8.5), P("M3.5 12h17"),
                           P("M12 3.5c-3.2 2.3-3.2 14.7 0 17"),
                           P("M12 3.5c3.2 2.3 3.2 14.7 0 17")]),
    "other/audioplaying": (24, ICONS_24["audio-volume-high"]),
    "other/audiomuted": (24, ICONS_24["audio-volume-muted"]),
    "other/login": (24, [C(7.5, 8.5, 3.5), P("M10.1 11.1 19.5 20.5"),
                          P("M16.5 17.5l2.6-2.6"), P("M13.9 14.9l1.8-1.8")]),

    # html internal-page art (dark pages, page palette)
    "html/broken-page": (48, [P("M10 6h17l7 7v29H10V6z"), P("M27 6v7h7"),
                              _g(P("M22 20l-4.5 6h7L19 33l2 6"))]),

    # html internal-page buttons (dark pages)
    "html/close": (20, [P("M5 5l10 10"), P("M15 5 5 15")]),
    "html/close_active": (20, [C(10, 10, 8.5), P("M6.2 6.2l7.6 7.6", c="accent"),
                               P("M13.8 6.2l-7.6 7.6", c="accent")]),
    "html/edit": (20, [P("M6.5 5h9"), P("M6.5 10h9"), P("M6.5 15h9"),
                       C(3.6, 5, 0.9, fill=True), C(3.6, 10, 0.9, fill=True),
                       C(3.6, 15, 0.9, fill=True)]),
    "html/edit_active": (20, [P("M6.5 5h9", c="accent"), P("M6.5 10h9", c="accent"),
                              P("M6.5 15h9", c="accent"),
                              C(3.6, 5, 0.9, c="accent", fill=True),
                              C(3.6, 10, 0.9, c="accent", fill=True),
                              C(3.6, 15, 0.9, c="accent", fill=True)]),
    "html/plus": (20, [P("M10 4v12"), P("M4 10h12")]),
    "html/reload": (20, [arc(10, 10, 7, 135, -45), P("M13.4 2.5 15.5 4.6l-2.1 2.1")]),
    "html/reload_active": (20, [arc(10, 10, 7, 135, -45, c="accent"),
                                P("M13.4 2.5 15.5 4.6l-2.1 2.1", c="accent")]),
    "html/configure": (24, gear_d(12, 12, 8.2, 6.3, 8, 3.1)),

    # plugin glyphs
    "plugin/greasemonkey": (32, [P("M8 4h13l6 6v18H8V4z"), P("M21 4v6h6"),
                                 F("M17.5 12.5 12.9 19h3.7L14.6 26l5.4-7.6h-3.7l1.2-5.9z")]),
    "plugin/verticaltabs-icon": (24, [P("M3 18V8.5L7.5 4H21v14H3z"), P("M3 21.5h18")]),
    "plugin/verticaltabs-group": (24, [P("M4 6h16"), P("M4 12h16"), P("M4 18h16"),
                                       C(8.5, 6, 1.2, fill=True),
                                       C(8.5, 12, 1.2, fill=True),
                                       C(8.5, 18, 1.2, fill=True)]),
    "plugin/adblock": (24, [P("M12 3.5 20 7v6c0 4.7-3.2 8-8 9.5C7.8 21 4.6 17.7 4.6 13V7L12 3.5z"),
                            C(12, 13, 4.6, c="danger"),
                            P("M8.8 9.8l6.4 6.4", c="danger"),
                            P("M15.2 9.8l-6.4 6.4", c="danger")]),
    "plugin/pim": (24, [P("M3 5h18v14H3V5z"), C(9, 10.2, 2.2),
                        P("M5.6 16.2c0.7-2 2-3 3.4-3s2.7 1 3.4 3"),
                        P("M15 9h4"), P("M15 12.5h4"), P("M15 16h3")]),
    "plugin/mousegestures": (24, [R(7, 4, 10, 16, rx=5), P("M12 4v5"),
                                  P("M5 13H2.5"), P("M19 13h2.5"),
                                  P("M12 20v2.5")]),
    "plugin/statusbaricons": (24, [C(12, 13, 4.6), P("M12 8.5V4"),
                                   P("M6 13H2.5"), P("M18 13h3.5"),
                                   P("M9.5 20.5 12 18l2.5 2.5")]),
    "plugin/flashcookies": (24, [C(12, 12, 8.2), C(9.6, 10.2, 1.7, fill=True),
                                 C(14.4, 10.2, 1.7, fill=True),
                                 P("M8.2 14.5c1 1.4 2.3 2.1 3.8 2.1s2.8-0.7 3.8-2.1")]),
    "plugin/autoscroll": (32, [C(16, 16, 8.5), C(16, 16, 2.2, c="accent", fill=True),
                               P("M16 2.5v4"), arrowhead(16, 7.5, -90, 3.0),
                               P("M16 25.5v4"), arrowhead(16, 25.5, 90, 3.0),
                               P("M2.5 16h4"), arrowhead(7.5, 16, 0, 3.0),
                               P("M25.5 16h4"), arrowhead(25.5, 16, 180, 3.0)]),
    "plugin/autoscroll-h": (32, [C(16, 16, 8.5), C(16, 16, 2.2, c="accent", fill=True),
                                  P("M2.5 16h4"), arrowhead(7.5, 16, 0, 3.0),
                                  P("M25.5 16h4"), arrowhead(25.5, 16, 180, 3.0)]),
    "plugin/autoscroll-v": (32, [C(16, 16, 8.5), C(16, 16, 2.2, c="accent", fill=True),
                                  P("M16 2.5v4"), arrowhead(16, 7.5, -90, 3.0),
                                  P("M16 25.5v4"), arrowhead(16, 25.5, 90, 3.0)]),

    # RunAction glyphs (generic - no third-party marks)
    "runaction/search": (24, list(_LENS)),
    "runaction/image-search": (24, list(_LENS) + [C(10.3, 10.3, 1.8, fill=True)]),
    "runaction/translate": (24, [P("M4 6.5h9v7H7.5l-2 2v-2H4v-7z"),
                                 P("M15.5 11.5H20V19h-5l-2 2v-2h-1.5v-5")]),
    "runaction/encyclopedia": (24, [P("M5 4.5c1.9-1 4-1 6 0.15 2-1.15 4.1-1.15 6-0.15"
                                      "v10c-1.9-1-4-1-6 0.15-2-1.15-4.1-1.15-6-0.15v-10z"),
                                    P("M11 4.65v10.15")]),
}
