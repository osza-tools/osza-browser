# Osza icon system

This document describes the Osza icon language, how the artwork is produced
and how to add a new icon. Everything in this file applies to the product
artwork; the third-party marks under `src/lib/data/icons/browsers/` and
`sites/` are deliberately excluded and must not be redrawn.

All artwork is original and drawn from scratch for this project. The only
reused geometry is the Osza brand mark (open ring + comet dot + lowercase
wordmark), which is this project's own art and is kept as-is; its source
paths live in `design/icons/brand-lockup.json`.

---

## 1. Where things live

| Path | Content |
| --- | --- |
| `tools/icons/osza_design.py` | the design system: palette tokens, drawing helpers and the geometry of every glyph |
| `tools/icons/build.py` | the pipeline: renders masters and regenerates every derivative deterministically |
| `tools/icons/audit.py` | static audit of themed names, resources and orphaned files |
| `design/icons/` | checked-in master sources (24 px theme masters, 16 px tuned set, 48 px feature icons, misc artwork) |
| `src/lib/data/osza-icons/` | the bundled `osza` (light) and `osza-dark` freedesktop icon themes |
| `src/lib/data/icons/` | resource-path icons (`menu/`, `other/`, `locationbar/`, `preferences/`, `exeicons/`) |
| `themes/<name>/images/` | per-theme chrome artwork (CSS `url()` and `qproperty-icon` targets) |
| `src/lib/data/html/` | internal-page artwork and buttons |
| `src/plugins/*/data/` | plugin glyphs |

The pipeline needs **python3 (>= 3.9), cairosvg and Pillow**. These are
development tools only — nothing in `tools/icons/` is a build or runtime
dependency of the browser, and the committed derivatives are what ships.

```
python3 tools/icons/build.py              # regenerate everything
python3 tools/icons/build.py --masters-only
python3 tools/icons/build.py --check-contrast
python3 tools/icons/audit.py --strict      # used by CI-minded checks
```

## 2. Grid and stroke

* **Masters**: 24 × 24 grid with a 20 × 20 live area (2 px margin on every
  side), 2 px strokes, round caps and joins. No fills except where the fill
  *is* the meaning (bookmarked star, active download, play triangle).
* **High-traffic 16 px glyphs**: hand-tuned on a 16 × 16 grid with 1.6 px
  strokes — scaled-down 24 px masters go soft, so the toolbar set
  (back, forward, reload, stop, home, new tab, tab close, star, lock,
  search, menu, download, speaker on/muted, list-add) is drawn twice.
* **Feature icons** (preferences pages, site-info fallbacks, browsing
  library): 48 × 48 with 40 × 40 live area, 3 px strokes, duotone — ink
  strokes plus the brand gradient on a secondary element.
* **App mark**: the ring + comet dot is unchanged. Sizes ≤ 32 px use a
  simplified variant (thicker ring, larger dot) so it stays readable.
* SVG hygiene: paths, basic shapes, linear/radial gradients and opacity
  only. No `<text>` (letterforms are paths), no filters, no masks, no
  editor metadata — Qt's SVG renderer supports only a subset and every
  asset must render there, not just in a browser.

## 3. Palette

The tokens live in `tools/icons/osza_design.py` and every one is verified
against WCAG 2.1 non-text contrast (≥ 3:1) on its declared surfaces by
`build.py --check-contrast`.

| Token | Light set (`osza`) | Dark set (`osza-dark`) |
| --- | --- | --- |
| ink (default glyph) | `#4B5566` | `#9AA3B5` |
| ink strong (hover-weight) | `#171C28` | `#E9EDF5` |
| accent / success ("on" states) | `#008F72` | `#3DDEC0` |
| danger | `#C13A2E` | `#FF8377` |
| warning | `#8F6400` | `#FFC46B` |

* The light accent is a half-step darker than the `#009E7C` focus ring
  used by the CSS themes so accent glyphs also hold 3:1 on light *grey*
  surfaces, not only on white.
* **Dual-safe neutrals** exist for artwork that is a single file for both
  modes: `#6E788C` (neutral ink) and the tab-close ladder `#757F93` /
  `#667084` (hover) / `#E5484D` (pressed, danger). All of them pass 3:1 on
  white, light grey and both navy chrome colors.
* **Brand gradients**: the neon ramp (`#00FFD1 → #2FD9F2 → #7C8CF8`) is
  for dark surfaces only (internal pages, osza-cyber). The light ramp
  (`#008F72 → #0077A8 → #5A6BE8`) has every stop — including interpolated
  ones — at ≥ 3:1 on light and dark surfaces, which is what feature icons
  use.
* Status colors are the danger/warning/success rows above; they were chosen
  specifically to clear 3:1 on both light and dark toolbars.

## 4. Light and dark strategy

Qt's SVG renderer cannot resolve `currentColor`, so palette-following
icons cannot live in a single SVG. The chosen mechanism (§4.4 of the task
brief, option (a) realized at the asset level):

* One master geometry per glyph; the pipeline emits it **twice** with the
  light-set and dark-set token values — the two bundled themes `osza` and
  `osza-dark`.
* `OszaIcons::activateTheme()` (`src/lib/tools/oszaicons.cpp`) picks the
  variant once at startup from the color-scheme preference or the palette,
  and keeps the previously active system theme as a fallback for names we
  do not ship. No call site changes, no runtime recoloring cost, and the
  two variants can never drift because they are generated from one source.
* Because a Qt icon theme cannot be hot-swapped for already-created
  `QIcon` objects, the selection happens at startup; a palette or scheme
  change takes effect after a restart — exactly like the chrome themes.
* Artwork that exists as a **single file for both modes** (CSS `image:`
  targets such as the tab-close trio, dormant fallbacks, overlays drawn
  over arbitrary web content) uses the dual-safe neutrals so it is
  legible under any palette.

## 5. States

* default / hover / pressed: handled by the chrome CSS. Hover overlays are
  10% *neutral* grey (`rgba(128,128,128,26)`), which shades light chrome
  and tints dark chrome alike; the old black-alpha overlays were invisible
  on dark palettes.
* disabled: leave to Qt (40% opacity), do not ship state art.
* accent color is for "on" states only: bookmarked star, secure lock,
  active download.
* Tab close: quiet neutral X, darker neutral on hover, danger red on
  press — deliberately no longer a saturated red by default.

## 6. Naming

* Themed names follow the freedesktop spec and are exactly the names the
  code requests (the audit is the authority: 81 names).
* Resource-path icons keep their existing file names; renames are avoided
  unless a format changes (`png → svg`), and every rename updates all
  reference sites in the same commit.
* Design masters mirror the shipped name: `design/icons/theme-24/<name>.svg`,
  `theme-16/`, `feature-48/` and `misc/<area>/<name>.svg`.

## 7. How to add an icon

1. Add the geometry to `ICONS_24` (or `ICONS_16` / `FEATURE_48` /
   `MISC_SVG`) in `tools/icons/osza_design.py`. Express colors as palette
   tokens, never literal hex.
2. If the name is looked up through `QIcon::fromTheme`, nothing else is
   needed — the pipeline ships it in both theme variants.
3. If it is loaded by resource path, add it to `RESOURCE_MAP` or
   `FEATURE_MAP` in `build.py`, register it in the right `.qrc`, and
   reference it from code/CSS.
4. `python3 tools/icons/build.py`, then `python3 tools/icons/audit.py
   --strict` — the audit must stay at zero missing names and zero
   unresolved references.

## 8. Platform behavior (deliberate change)

The bundled theme is active on **all** platforms, Linux included. Osza's
own UI icons no longer follow the desktop icon theme; the system theme is
only a fallback for names we do not ship (MIME types and friends). This is
a conscious product decision (§4.3 of the task brief) so the browser looks
the same everywhere; it is recorded in the CHANGELOG and there is no new
setting for it.

## 9. What the audit checks

`tools/icons/audit.py` reports: themed names requested by code/CSS but not
provided by a bundled theme; `.qrc` entries whose files are missing;
resource references that no `.qrc` resolves; theme CSS `url()` images
missing on disk; asset files referenced nowhere; and SVGs that fail to
render (cairosvg stands in for Qt's renderer here — the generated subset
is deliberately Qt-safe). `--strict` exits non-zero on any finding.
