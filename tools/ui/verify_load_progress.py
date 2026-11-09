#!/usr/bin/env python3
# ============================================================
# Osza - address-bar load-progress verifier
#
# Standalone verification of the eased load-progress treatment in
# the location bar (the animated accent line and its classic
# siblings), without a Qt build, in the spirit of
# verify_theme.py and verify_locationbar_badge.py:
#
#   1. One display value, one writer. The engine reports progress
#      in bursts; the paint follows only m_displayProgress, and
#      nothing but the glide animation's value-changed slot (plus
#      the loadStarted reset) ever writes it. A direct paint of
#      m_loadProgress, or an update() on the raw report, is a
#      regression to the jumpy bar.
#
#   2. The animations exist, are wired once each, and carry the
#      easing contract: the glide (OutCubic, 320 ms, retargeted
#      from the displayed value so a burst redirects the same
#      motion) and the fade (OutCubic, 300 ms, started only by
#      the dwell timer's slot, retiring the bar through
#      progressFadeFinished instead of dropping it).
#
#   3. The lifecycle tells one story: loadStarted resets from
#      zero (stopping everything), loadProgress and loadFinished
#      only ever retarget, and hideProgress never sets
#      m_progressVisible directly - only the fade's finished
#      slot does.
#
#   4. Four styles, all painted, in a stable index order
#      (Filled=0, Bottom=1, Top=2, AccentLine=3) so stored
#      settings keep their meaning across versions.
#
#   5. The showcase treatment is really drawn: the field-spanning
#      line inside the border, the caps kept clear of the pill's
#      curvature by the horizontal inset, the whisper fill
#      clipped to the pill shape, the glow rising off the line,
#      the brighter leading tip with its bloom.
#
#   6. The accent follows the theme with no code of its own: the
#      custom color wins, otherwise the palette's Highlight - the
#      role the cyber theme's #locationbar selection-background-
#      color already paints mint (violet in the private variant),
#      the system accent everywhere else. The Filled style keeps
#      its calm text-mid tone, because it paints over the text.
#
#   7. Right-to-left layouts read the bar anchored to the edge
#      the text grows from: every painted branch mirrors.
#
#   8. The out-of-the-box experience: progress shows by default
#      and defaults to the accent line, in all three settings
#      readers (qzsettings, the bar's loadSettings, Preferences),
#      and the Preferences selector offers exactly the four
#      styles in the enum's order - while the save path still
#      writes both keys so an explicit choice survives.
#
#   9. Qt keyword discipline in the touched header (Q_SLOTS,
#      never bare slots: - the tree builds with -DQT_NO_KEYWORDS).
#
#  10. The README and the CHANGELOG tell the user about it.
#
# Usage:
#   python3 tools/ui/verify_load_progress.py
#
# Copyright (C) 2026 Osza Tools contributors
# GPL-3.0-or-later
# ============================================================

import os
import re

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                    os.pardir, os.pardir)

LOCATIONBAR_H = os.path.join(ROOT, "src", "lib", "navigation", "locationbar.h")
LOCATIONBAR_CPP = os.path.join(ROOT, "src", "lib", "navigation", "locationbar.cpp")
QZSETTINGS_CPP = os.path.join(ROOT, "src", "lib", "other", "qzsettings.cpp")
PREFERENCES_CPP = os.path.join(ROOT, "src", "lib", "preferences", "preferences.cpp")
PREFERENCES_UI = os.path.join(ROOT, "src", "lib", "preferences", "preferences.ui")
README = os.path.join(ROOT, "README.md")
CHANGELOG = os.path.join(ROOT, "CHANGELOG")


def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


locationbar_h = read(LOCATIONBAR_H)
locationbar_cpp = read(LOCATIONBAR_CPP)
qzsettings_cpp = read(QZSETTINGS_CPP)
preferences_cpp = read(PREFERENCES_CPP)
preferences_ui = read(PREFERENCES_UI)
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


def body(text, signature):
    """The source of one function, from its signature to the next
    function definition at the same level - a small structural cut
    so the checks below reason about whole functions, not lines.
    Same boundary shape as the other verifiers (a plain ')' and a
    ') const')."""
    start = text.find(signature)
    if start == -1:
        return None
    rest = text[start:]
    next_def = re.search(r"\n[A-Za-z].*\)(?:\s+const)?\s*\n?\{", rest[len(signature):])
    end = len(signature) + next_def.start() if next_def else len(rest)
    return rest[:end]


paint = body(locationbar_cpp, "void LocationBar::paintEvent(QPaintEvent* event)")
load_started = body(locationbar_cpp, "void LocationBar::loadStarted()")
load_progress = body(locationbar_cpp, "void LocationBar::loadProgress(int progress)")
load_finished = body(locationbar_cpp, "void LocationBar::loadFinished()")
hide_progress = body(locationbar_cpp, "void LocationBar::hideProgress()")
glide_advanced = body(locationbar_cpp, "void LocationBar::progressGlideAdvanced(const QVariant &value)")
fade_advanced = body(locationbar_cpp, "void LocationBar::progressFadeAdvanced(const QVariant &value)")
fade_finished = body(locationbar_cpp, "void LocationBar::progressFadeFinished()")
retarget = body(locationbar_cpp, "void LocationBar::retargetProgressGlide(int target)")
accent_color = body(locationbar_cpp, "QColor LocationBar::progressAccentColor() const")
load_settings = body(locationbar_cpp, "void LocationBar::loadSettings()")

# ------------------------------------------------------------------
# 1. One display value, one writer
# ------------------------------------------------------------------
print("1. the eased display value")

check("the paint follows the eased value, never the raw report",
      paint is not None and "m_displayProgress" in paint and "m_loadProgress" not in paint)

writers = re.findall(r"m_displayProgress\s*=[^=]", locationbar_cpp)
check("the eased value is written exactly twice in the .cpp (reset + glide slot)",
      len(writers) == 2)

check("the glide slot is the runtime writer",
      glide_advanced is not None and "m_displayProgress = value.toInt();" in glide_advanced)
check("a raw engine report never calls update() directly",
      load_progress is not None and "update();" not in load_progress)

# ------------------------------------------------------------------
# 2. The animations and their easing contract
# ------------------------------------------------------------------
print("2. the glide and the fade")

ctor = body(locationbar_cpp, "LocationBar::LocationBar(QWidget *parent)")
check("the glide is built once, OutCubic, 320 ms",
      ctor is not None
      and ctor.count("m_progressGlide = new QVariantAnimation(this);") == 1
      and "m_progressGlide->setEasingCurve(QEasingCurve::OutCubic);" in ctor
      and "m_progressGlide->setDuration(320);" in ctor)
check("the glide's value changes reach the slot",
      "connect(m_progressGlide, &QVariantAnimation::valueChanged, this, &LocationBar::progressGlideAdvanced);"
      in locationbar_cpp)
check("the fade is built once, OutCubic, 300 ms, full to gone",
      ctor is not None
      and ctor.count("m_progressFade = new QVariantAnimation(this);") == 1
      and "m_progressFade->setEasingCurve(QEasingCurve::OutCubic);" in ctor
      and "m_progressFade->setDuration(300);" in ctor
      and "m_progressFade->setStartValue(1.0);" in ctor
      and "m_progressFade->setEndValue(0.0);" in ctor)
check("the fade's value changes and finish reach their slots",
      "connect(m_progressFade, &QVariantAnimation::valueChanged, this, &LocationBar::progressFadeAdvanced);"
      in locationbar_cpp
      and "connect(m_progressFade, &QVariantAnimation::finished, this, &LocationBar::progressFadeFinished);"
      in locationbar_cpp)
check("retargeting starts from the displayed value, so a burst redirects the same motion",
      retarget is not None
      and "m_progressGlide->setStartValue(m_displayProgress);" in retarget
      and retarget.count("m_progressGlide->start();") == 1)
check("a retarget to where the display already stands just stops",
      "if (target == m_displayProgress) {" in retarget)

# ------------------------------------------------------------------
# 3. The lifecycle
# ------------------------------------------------------------------
print("3. one story from started to gone")

check("loadStarted stops all three timers and resets from zero",
      load_started is not None
      and "m_progressTimer->stop();" in load_started
      and "m_progressGlide->stop();" in load_started
      and "m_progressFade->stop();" in load_started
      and "m_displayProgress = 0;" in load_started
      and "m_progressOpacity = 1.0;" in load_started)
check("loadProgress only retargets",
      load_progress is not None
      and "retargetProgressGlide(progress);" in load_progress
      and "m_progressGlide->start();" not in load_progress)
check("loadFinished sweeps to 100 and dwells",
      load_finished is not None
      and "retargetProgressGlide(100);" in load_finished
      and "m_progressTimer->start();" in load_finished)
check("the dwell's end eases out instead of dropping",
      hide_progress is not None
      and "m_progressFade->start();" in hide_progress
      and "m_progressVisible" not in hide_progress)
check("only the fade's finish retires the bar",
      fade_finished is not None and "m_progressVisible = false;" in fade_finished
      and locationbar_cpp.count("m_progressVisible = false;") == 1)

# ------------------------------------------------------------------
# 4. Four styles, stable order
# ------------------------------------------------------------------
print("4. the four styles")

enum_block = locationbar_h.split("enum ProgressStyle {", 1)[1].split("};", 1)[0]
names = [n.strip().rstrip(",") for n in enum_block.splitlines()
         if n.strip() and not n.strip().startswith("//")]
check("the enum reads Filled, Bottom, Top, AccentLine in that order",
      names == ["ProgressFilled", "ProgressBottom", "ProgressTop", "ProgressAccentLine"])
for case in ("ProgressFilled", "ProgressBottom", "ProgressTop", "ProgressAccentLine"):
    check("paintEvent handles %s" % case, paint is not None and "case %s" % case in paint)
check("an unknown style paints nothing (default: break)",
      paint is not None and "default:" in paint)

# ------------------------------------------------------------------
# 5. The showcase treatment is really drawn
# ------------------------------------------------------------------
print("5. the accent line, drawn as designed")

line_case = paint.split("case ProgressAccentLine:", 1)[1].split("default:", 1)[0] if paint else ""
check("the line spans the widget's field, inside the border",
      "rect().adjusted(1, 1, -1, -1)" in line_case)
check("the caps stay clear of the pill's curvature (horizontal inset)",
      "const int inset = 10;" in line_case
      and "field.width() - 2 * inset" in line_case)
check("the whisper fill is clipped to the pill shape",
      "QPainterPath pillShape;" in line_case
      and "p.setClipPath(pillShape);" in line_case)
check("the glow rises off the line",
      "QLinearGradient glow(" in line_case
      and "lineY - 14" in line_case)
check("the line itself is the accent, rounded",
      "p.setBrush(accent);" in line_case
      and "p.drawRoundedRect(line, 1.5, 1.5);" in line_case)
check("the leading tip is brighter and blooms",
      "accent.lighter(160)" in line_case
      and "QRadialGradient bloom(" in line_case)
check("the treatment starts at the first reported progress, not before",
      "if (loadedWidth <= 0) {" in line_case
      and "break;" in line_case)

# ------------------------------------------------------------------
# 6. The accent follows the theme
# ------------------------------------------------------------------
print("6. the accent, without theme-specific code")

check("one accent resolver, custom color first",
      accent_color is not None
      and "m_progressColor.isValid() && m_progressColor.alpha() > 0" in accent_color
      and "return m_progressColor;" in accent_color)
check("the resolver falls back to the palette's Highlight - the role the themes already paint",
      "return palette().color(QPalette::Highlight);" in accent_color)
check("the accent line and the thin lines ride the resolver",
      line_case.count("progressAccentColor()") == 1
      and paint.split("case ProgressBottom:", 1)[1].split("case ProgressAccentLine:", 1)[0].count("progressAccentColor()") == 1)
check("the Filled style keeps its calm text-mid tone (it paints over text)",
      "Colors::mid(" in paint.split("case ProgressFilled:", 1)[1].split("case ProgressBottom:", 1)[0])
check("the fade composes with the style's own opacity, not replaces it",
      "p.setOpacity(m_progressOpacity);" in paint
      and "0.5 * m_progressOpacity" in paint)

# ------------------------------------------------------------------
# 7. Right-to-left reads anchored to the text's edge
# ------------------------------------------------------------------
print("7. right-to-left")

check("the direction is read once for all branches",
      paint is not None
      and "layoutDirection() == Qt::RightToLeft" in paint)
check("every painted branch mirrors",
      paint is not None and paint.count("if (rtl)") >= 3
      and "moveRight(" in paint)

# ------------------------------------------------------------------
# 8. The out-of-the-box experience
# ------------------------------------------------------------------
print("8. defaults and Preferences")

check("progress shows by default (qzsettings)",
      'settings.value(QSL("ShowLoadingProgress"), true).toBool()' in qzsettings_cpp)
check("the bar defaults to the accent line",
      'settings.value(QSL("ProgressStyle"), ProgressAccentLine).toInt()' in load_settings)
check("Preferences defaults to the accent line too",
      'settings.value(QSL("ProgressStyle"), 3).toInt()' in preferences_cpp)
check("Preferences defaults the checkbox to on",
      'settings.value(QSL("ShowLoadingProgress"), true).toBool()' in preferences_cpp)
check("the save path still writes both keys",
      'settings.setValue(QSL("ShowLoadingProgress"), ui->showLoadingInAddressBar->isChecked());' in preferences_cpp
      and 'settings.setValue(QSL("ProgressStyle"), ui->progressStyleSelector->currentIndex());' in preferences_cpp)

combo = preferences_ui.split('name="progressStyleSelector"', 1)[1].split("</widget>", 1)[0]
combo_items = re.findall(r"<string>([^<]+)</string>", combo)
check("the selector offers exactly the four styles, in the enum's order",
      combo_items == ["Fill", "Bottom", "Top", "Accent line"])

# ------------------------------------------------------------------
# 9. Qt keyword discipline
# ------------------------------------------------------------------
print("9. keyword discipline")

check("the touched header uses Q_SLOTS, never bare slots:",
      "private Q_SLOTS:" in locationbar_h
      and not re.search(r"^\s*(private|public|protected)\s+slots:", locationbar_h, re.M))
check("no bare signals: either",
      not re.search(r"^\s*(private|public|protected)\s+signals:", locationbar_h, re.M))

# ------------------------------------------------------------------
# 10. The user-facing notes
# ------------------------------------------------------------------
print("10. the docs")

check("the README mentions the load line",
      "load line" in readme.lower() or "accent line" in readme.lower())
check("the CHANGELOG has an entry",
      "load line" in changelog.lower() or "accent line" in changelog.lower())

print()
if failures:
    print("FAILED: %d of %d checks failed" % (failures, checks))
    raise SystemExit(1)
print("OK: all %d checks passed" % checks)
