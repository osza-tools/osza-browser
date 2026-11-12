#!/usr/bin/env python3
# ============================================================
# Osza - Speed Dial entrance-motion verifier
#
# Standalone verification of the start-page/speed-dial motion pass
# (the choreographed entrance), without a Qt build, in the spirit
# of verify_theme.py and verify_load_progress.py:
#
#   1. The fill-mode contract. Every entrance ends exactly at the
#      element's resting style and leaves nothing behind: the
#      animations declare fill-mode backwards (never both/forwards,
#      which would pin their last keyframe over the resting style
#      forever - and animations outrank normal declarations, so the
#      tile hover lift, the drag tilt and every later transform
#      state would never show again), the keyframes carry no
#      to-frame, and the states the fix frees really exist in the
#      stylesheet.
#
#   2. The stagger wiring. The page's script reads the Motion tokens
#      from the stylesheet (with fallbacks equal to the token
#      values, the same contract alignPage keeps with the grid gap),
#      writes --sd-delay per tile with the ramp flattened at the
#      cap, and nothing else writes a delay - a tile added from the
#      FAB after the page has settled takes the 0ms default and
#      rises immediately.
#
#   3. The budget. base + cap * stagger + duration stays inside
#      1300 ms, so even a capped dial finishes its whole entrance
#      inside one perceptual gesture.
#
#   4. The choreography. The world surfaces first (mesh fades in,
#      wallpaper a beat later, the base floor never animates - it
#      is the color the page opens on), the header's furniture
#      drops in 80 ms apart, the FAB pops with the overshoot curve,
#      the empty state's ghost card fades in where the grid would
#      have settled, and both dialogs (the served settings panel
#      and the edit dialog jQuery builds at run time) rise when
#      they render.
#
#   5. The compositor contract. Every osza-* keyframe animates only
#      opacity and transform - no filter, backdrop-filter or
#      layout property ever animates, so 24 glass tiles can rise
#      without forcing repaints of their blurred layers.
#
#   6. The thumbnail settle. A thumbnail landing over the skeleton
#      eases in, and the class replay (remove, force a reflow, add)
#      restarts the animation for every later delivery.
#
#   7. Reduced motion. The kill switch now zeroes the delays as
#      well as the durations - zeroed durations alone would leave
#      the stagger holding tiles at their invisible from-state for
#      up to a second with nothing playing.
#
#   8. The serving contract. The stylesheet stays free of
#      percent-wrapped tokens (it is served verbatim from the
#      resources; the dynamic values live in the page's inline
#      block), the inline block keeps its placeholders, the user
#      script keeps its %JQUERY% placeholders for scripts.cpp, and
#      the resource bundle still lists every file the page needs.
#
#   9. The README and the CHANGELOG tell the user about it.
#
# Usage:
#   python3 tools/ui/verify_speeddial_motion.py
#
# Copyright (C) 2026 Osza Tools contributors
# GPL-3.0-or-later
# ============================================================

import os
import re

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                    os.pardir, os.pardir)

SPEEDDIAL_CSS = os.path.join(ROOT, "src", "lib", "data", "html", "speeddial.css")
SPEEDDIAL_HTML = os.path.join(ROOT, "src", "lib", "data", "html", "speeddial.html")
SPEEDDIAL_JS = os.path.join(ROOT, "src", "lib", "data", "html", "speeddial.user.js")
HTML_QRC = os.path.join(ROOT, "src", "lib", "data", "html.qrc")
SCRIPTS_CPP = os.path.join(ROOT, "src", "lib", "tools", "scripts.cpp")
README = os.path.join(ROOT, "README.md")
CHANGELOG = os.path.join(ROOT, "CHANGELOG")


def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


css = read(SPEEDDIAL_CSS)
html = read(SPEEDDIAL_HTML)
js = read(SPEEDDIAL_JS)
qrc = read(HTML_QRC)
scripts_cpp = read(SCRIPTS_CPP)
readme = read(README)
changelog = read(CHANGELOG)

failures = 0
checks = 0


def check(label, ok):
    global failures, checks
    checks += 1
    print(("  PASS " if ok else "  FAIL ") + label)
    if not ok:
        failures += 1


def keyframe_block(text, name):
    """The declarations of one @keyframes rule, brace-matched, with
    comments stripped - the same whole-construct cut the other
    verifiers take before reasoning about rules."""
    m = re.search(r"@keyframes\s+" + re.escape(name) + r"\s*\{", text)
    if m is None:
        return None
    depth = 1
    i = m.end()
    while i < len(text) and depth > 0:
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
        i += 1
    body = text[m.end():i - 1]
    return re.sub(r"/\*.*?\*/", "", body, flags=re.S)


def rules(text, selector):
    """The declaration blocks of every rule whose selector is exactly
    this one - '.a::before' never answers for '.a' - brace-matched so
    nested blocks stay whole."""
    out = []
    for m in re.finditer(re.escape(selector) + r"\s*\{", text):
        if m.start() > 0 and text[m.start() - 1] not in "}\n":
            continue
        start = m.end()
        depth, i = 1, start
        while i < len(text) and depth > 0:
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
            i += 1
        out.append(text[start:i - 1])
    return out


def rule(text, selector):
    """All the declarations this selector ever declares, joined - for
    checks that only want to know what the selector says, across all
    its rules."""
    return "\n".join(rules(text, selector))


def token_value(name):
    m = re.search(r"--" + name + r":\s*([^;]+);", css)
    return m.group(1).strip() if m else None


# ------------------------------------------------------------------
# 1. The fill-mode contract
# ------------------------------------------------------------------
print("1. the fill-mode contract")

entry_rule = rule(css, ".entry")
check("the tile rise is declared on .entry",
      entry_rule is not None and "animation: osza-dial-in" in entry_rule)
check("the rise lasts the entrance-duration token",
      entry_rule is not None and "var(--osza-enter-duration)" in entry_rule)
check("the rise's delay rides --sd-delay with a 0ms default (the FAB-added tile pops immediately)",
      entry_rule is not None and "var(--sd-delay, 0ms)" in entry_rule)
check("the rise fills backwards only",
      entry_rule is not None and entry_rule.split("animation:")[1].split(";")[0].strip().endswith("backwards"))

animation_decls = [d.strip() for d in re.findall(r"animation\s*:\s*([^;}]+)", css)]
check("every animation in the sheet exists",
      len(animation_decls) >= 7)
check("no animation pins its last keyframe forever (no both/forwards fill anywhere)",
      all(("both" not in d and "forwards" not in d) for d in animation_decls))

dial_in = keyframe_block(css, "osza-dial-in")
check("osza-dial-in carries no to-frame (the rise ends exactly at rest)",
      dial_in is not None and not re.search(r"\bto\b\s*\{", dial_in))
check("osza-dial-in starts invisible, low and slightly small",
      dial_in is not None and "opacity: 0" in dial_in
      and re.search(r"transform:\s*translateY\(14px\)\s*scale\(0\.96\)", dial_in))

check("the hover lift the fix frees still exists",
      ".entry:hover" in css and "transform: translateY(-4px)" in rule(css, ".entry:hover"))
check("the drag tilt the fix frees still exists",
      ".entry.ui-sortable-helper" in css and "transform: rotate" in rule(css, ".entry.ui-sortable-helper"))

# ------------------------------------------------------------------
# 2. The stagger wiring
# ------------------------------------------------------------------
print("2. the stagger wiring")

check("the script reads the three Motion tokens from the stylesheet",
      js.count("getPropertyValue('--osza-enter-") == 3)

css_base = int(re.search(r"(\d+)", token_value("osza-enter-base")).group(1))
css_stagger = int(re.search(r"(\d+)", token_value("osza-enter-stagger")).group(1))
css_duration = int(re.search(r"(\d+)", token_value("osza-enter-duration")).group(1))
css_cap = int(re.search(r"(\d+)", token_value("osza-enter-cap")).group(1))

js_fallbacks = dict((m.group(1), int(m.group(2))) for m in re.finditer(
    r"getPropertyValue\('--osza-enter-(base|stagger|cap)'\), 10\) \|\| (\d+)", js))
check("the script's fallbacks equal the token values (JS and CSS never disagree)",
      js_fallbacks == {"base": css_base, "stagger": css_stagger, "cap": css_cap})
check("the cap is a positive integer",
      css_cap >= 1 and token_value("osza-enter-cap").isdigit())

check("the boot loop flattens the ramp at the cap",
      re.search(r"--sd-delay',\s*\(enterBase \+ Math\.min\(i, enterCap\) \* enterStagger\) \+ 'ms'\)", js) is not None)

addbox_body = js[js.find("function addBox("):js.find("function setBoxImage(")]
check("only the boot loop writes a delay (addBox never does - a FAB tile takes the 0ms default)",
      "--sd-delay" not in addbox_body)

init_body = js[js.find("function init() {"):js.find("%JQUERY%")]
check("the delay write sits inside init's page-building loop",
      "box.style.setProperty('--sd-delay'" in init_body)

# ------------------------------------------------------------------
# 3. The budget
# ------------------------------------------------------------------
print("3. the budget")

budget = css_base + css_cap * css_stagger + css_duration
check("the capped dial finishes its whole entrance inside 1300ms (%dms)" % budget,
      budget <= 1300)
check("each beat of the stagger is a perceptible but quick 30-50ms",
      30 <= css_stagger <= 50)

# ------------------------------------------------------------------
# 4. The choreography
# ------------------------------------------------------------------
print("4. the choreography")

check("the mesh fades in over the floor",
      "osza-layer-in" in rule(css, ".background-layer--mesh"))
check("the wallpaper settles a beat later",
      "osza-layer-in" in rule(css, ".background-layer--wallpaper")
      and "80ms" in rule(css, ".background-layer--wallpaper").split("animation:")[1])
check("the base floor never animates (it is the color the page opens on)",
      "animation" not in rule(css, ".background-layer--base"))

check("the header's furniture drops in",
      "osza-drop-in" in rule(css, ".sd-header__inner > *"))
check("brand, pill and settings each follow 80ms apart",
      rule(css, ".sd-header__inner > *:nth-child(2)").strip().endswith("80ms;")
      and rule(css, ".sd-header__inner > *:nth-child(3)").strip().endswith("160ms;"))

fab_rule = rule(css, ".fab")
check("the FAB pops in with the overshoot curve",
      fab_rule is not None and "osza-pop-in" in fab_rule
      and "var(--osza-ease-out-back)" in fab_rule)

check("the empty state's ghost card fades in",
      "osza-ghost-in" in rule(css, ".speeddial-grid:empty::after"))
check("both dialogs rise when they render",
      "osza-panel-in" in rule(css, ".overlay .sd-panel"))
check("the served settings panel and the runtime edit dialog both match that rule",
      'id="fadeOverlay2" class="overlay"' in html and 'id="settingsBox" class="sd-panel"' in html
      and '<div id="fadeOverlay" class="overlay"' in js and '<div id="overlay-edit" class="sd-panel">' in js)

check("the overshoot token is defined with the other Motion tokens",
      token_value("osza-ease-out-back") == "cubic-bezier(0.34, 1.56, 0.64, 1)")

# ------------------------------------------------------------------
# 5. The compositor contract
# ------------------------------------------------------------------
print("5. the compositor contract")

kf_names = set(re.findall(r"@keyframes\s+(osza-[\w-]+)", css))
expected = {"osza-dial-in", "osza-drop-in", "osza-pop-in", "osza-layer-in",
            "osza-ghost-in", "osza-panel-in", "osza-thumb-settle", "osza-pulse"}
check("every keyframe the rules reference is defined",
      expected <= kf_names)

animated_props = set()
for name in kf_names:
    block = keyframe_block(css, name)
    animated_props |= set(re.findall(r"([a-zA-Z-]{2,})\s*:", block or ""))
check("only opacity and transform ever animate (%s)" % ", ".join(sorted(animated_props)),
      animated_props <= {"opacity", "transform"})

# ------------------------------------------------------------------
# 6. The thumbnail settle
# ------------------------------------------------------------------
print("6. the thumbnail settle")

check("a thumbnail landing over the skeleton settles in place",
      "osza-thumb-settle" in rule(css, ".entry.thumb-arrived .dial-preview"))
settle_block = keyframe_block(css, "osza-thumb-settle")
check("the settle eases in at a slightly larger scale",
      settle_block is not None and "opacity: 0" in settle_block
      and "scale(1.05)" in settle_block)

setimg_body = js[js.find("function setImageToUrl("):js.find("function setBoxUrl(")]
check("every delivery replays the settle (remove, reflow, add)",
      "classList.remove('thumb-arrived')" in setimg_body
      and "void entry.offsetWidth;" in setimg_body
      and "classList.add('thumb-arrived')" in setimg_body)
check("the swap still writes the src plain (no cache-buster query)",
      "$(imgElement).attr('src', img_source/* + '?' + new Date()*/);" in setimg_body)

# ------------------------------------------------------------------
# 7. Reduced motion
# ------------------------------------------------------------------
print("7. reduced motion")

rm = re.search(r"@media\s*\(prefers-reduced-motion:\s*reduce\)\s*\{(.*?)\n\}", css, re.S)
check("the kill switch still collapses durations and iterations",
      rm is not None and "animation-duration: 0.01ms !important;" in rm.group(1)
      and "animation-iteration-count: 1 !important;" in rm.group(1))
check("the kill switch zeroes animation delays too (no invisible stagger waits)",
      rm is not None and "animation-delay: 0s !important;" in rm.group(1))
check("the kill switch zeroes transition delays too",
      rm is not None and "transition-delay: 0s !important;" in rm.group(1))

# ------------------------------------------------------------------
# 8. The serving contract
# ------------------------------------------------------------------
print("8. the serving contract")

check("the stylesheet carries no percent-wrapped tokens (it is served verbatim)",
      re.search(r"%[A-Z][A-Z0-9-]*%", css) is None)
check("the page's inline block keeps the dynamic placeholders",
      "%IMG_BACKGROUND%" in html and "%LOADING-IMG%" in html and "%DIRECTION%" in html)
check("the page still links the stylesheet from the resources",
      'href="qrc:html/speeddial.css"' in html)

check("the user script keeps both jQuery placeholders for scripts.cpp",
      js.count("%JQUERY%\n") == 1 and js.count("%JQUERY-UI%") == 1)
check("scripts.cpp still substitutes them from the bundled libraries",
      'QSL(":html/speeddial.user.js")' in scripts_cpp
      and '%JQUERY%' in scripts_cpp and 'QSL(":html/jquery.js")' in scripts_cpp
      and '%JQUERY-UI%' in scripts_cpp and 'QSL(":html/jquery-ui.js")' in scripts_cpp)

for res in ("html/speeddial.html", "html/speeddial.css", "html/speeddial.user.js",
            "html/jquery.js", "html/jquery-ui.js"):
    check("the resource bundle still lists %s" % res,
          "<file>%s</file>" % res in qrc)

# ------------------------------------------------------------------
# 9. The user-facing notes
# ------------------------------------------------------------------
print("9. the docs")

check("the README mentions the entrance and its verifier",
      "choreographed entrance" in readme
      and "tools/ui/verify_speeddial_motion.py" in readme)
check("the CHANGELOG has an entry",
      "choreographed entrance" in changelog)

print()
if failures:
    print("FAILED: %d of %d checks failed" % (failures, checks))
    raise SystemExit(1)
print("OK: all %d checks passed" % checks)
