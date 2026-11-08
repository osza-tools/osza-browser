#!/usr/bin/env python3
# ============================================================
# Osza - theme completeness verifier
#
# A theme in this browser is applied as an application-wide
# stylesheet and nothing else: the application palette still
# follows the system. Two families of themes live in themes/:
#
#   * palette-following themes (linux, windows, mac, chrome) -
#     their surfaces read palette(...) colors, so any widget the
#     stylesheet does not mention still matches the system look;
#
#   * self-contained designs (osza-cyber) - they hardcode their
#     surfaces, so EVERY widget class the browser instantiates
#     must carry a rule, or the widget renders in the system
#     look: a light Preferences dialog inside a dark browser.
#
# This tool keeps the second family honest without building Qt:
#
#   1. QSS sanity for every bundled theme: balanced blocks,
#      terminated declarations, known properties / pseudo-states /
#      subcontrols, url() artwork present on disk, no constructs
#      Qt style sheets do not support.
#   2. Widget-coverage for self-contained themes: every widget
#      class instantiated in the tree's .ui files (custom classes
#      resolved to their Qt base) that paints a visible surface
#      must be mentioned by the theme's selectors, and the custom
#      class selectors the theme uses must name real classes.
#   3. Ordering invariants the coverage relies on: rules that win
#      by cascade order (the QFrame[frameShape] card vs the item
#      views carrying the same attribute) are checked to keep
#      their order, and the WebView page background rule must
#      exist.
#
# Usage:
#   python3 tools/themes/verify_theme.py            # human report
#   python3 tools/themes/verify_theme.py --json     # machine report
#   python3 tools/themes/verify_theme.py --strict   # exit 1 on any finding
#
# Copyright (C) 2026 Osza Tools contributors
# GPL-3.0-or-later
# ============================================================

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Set

REPO = Path(__file__).resolve().parents[2]
THEMES_DIR = REPO / "themes"

# Themes that hardcode their surfaces and therefore must cover the
# whole widget inventory. Palette-following themes are exempt from
# the coverage check (their unstyled widgets follow the system
# palette by design); they still get the QSS sanity checks.
FULL_COVERAGE_THEMES = {"osza-cyber"}

# Qt widget classes that paint a visible surface and therefore
# must be addressed by a self-contained theme. Classes not listed
# here either paint nothing (QStackedWidget) or are containers
# whose look is owned by their children.
REQUIRED_PAINTERS = {
    "QDialog", "QMessageBox", "QLabel", "QPushButton", "QToolButton",
    "QCommandLinkButton", "QLineEdit", "QTextEdit", "QPlainTextEdit",
    "QTextBrowser", "QComboBox", "QCheckBox", "QRadioButton", "QSpinBox",
    "QDoubleSpinBox", "QSlider", "QProgressBar", "QListView", "QListWidget",
    "QTreeView", "QTreeWidget", "QTableView", "QTableWidget", "QTabWidget",
    "QGroupBox", "QMenu", "QMenuBar", "QStatusBar", "QSplitter", "QScrollArea",
    "QGraphicsView", "QToolTip", "QHeaderView", "QScrollBar", "QTabBar",
    "QFrame",
}

# uic's <widget class="Line"> maps to a QFrame with a line shape.
UI_CLASS_ALIASES = {"Line": "QFrame"}

# Properties understood by Qt style sheets (the subset this tree
# uses, plus common neighbors). qproperty-* is dynamic and skipped.
KNOWN_PROPERTIES = {
    "background", "background-color", "background-image", "background-repeat",
    "background-position", "background-attachment", "background-clip",
    "background-origin", "color", "border", "border-top", "border-bottom",
    "border-left", "border-right", "border-color", "border-top-color",
    "border-bottom-color", "border-left-color", "border-right-color",
    "border-width", "border-style", "border-radius", "border-top-left-radius",
    "border-top-right-radius", "border-bottom-left-radius",
    "border-bottom-right-radius", "border-image", "padding", "padding-top",
    "padding-bottom", "padding-left", "padding-right", "margin", "margin-top",
    "margin-bottom", "margin-left", "margin-right", "min-width", "min-height",
    "max-width", "max-height", "width", "height", "font", "font-family",
    "font-size", "font-style", "font-weight", "text-align", "text-decoration",
    "selection-background-color", "selection-color", "alternate-background-color",
    "gridline-color", "image", "spacing", "outline", "subcontrol-origin",
    "subcontrol-position", "position", "left", "right", "top", "bottom",
}

# Pseudo-states documented for Qt style sheets.
KNOWN_PSEUDO_STATES = {
    "active", "adjoins-item", "alternate", "bottom", "checked", "closable",
    "closed", "default", "disabled", "editable", "edit-focus", "enabled",
    "exclusive", "first", "flat", "focus", "has-children", "has-focus",
    "has-siblings", "horizontal", "hover", "indeterminate", "last", "left",
    "maximized", "middle", "minimized", "movable", "next-selected",
    "no-frame", "non-exclusive", "off", "on", "only-one", "open", "pressed",
    "previous-selected", "read-only", "right", "selected", "top", "unchecked",
    "vertical", "window",
}

# Sub-controls documented for Qt style sheets.
KNOWN_SUBCONTROLS = {
    "add-line", "add-page", "branch", "chunk", "close-button",
    "corner", "down-arrow", "down-button", "drop-down", "float-button",
    "groove", "handle", "indicator", "icon", "item", "menu-arrow",
    "menu-indicator", "menu-button", "pane", "scroller", "section",
    "separator", "sub-line", "sub-page", "tab", "tear", "tearoff", "text",
    "title", "up-arrow", "up-button",
}

# Constructs Qt style sheets do not support; using them silently
# drops the whole rule, so they must not appear at all.
FORBIDDEN_CONSTRUCTS = {
    ":not(": "Qt style sheets have no :not(); use attribute or ID selectors",
    "box-shadow": "Qt style sheets do not implement box-shadow; simulate with borders",
    "!important": "Qt style sheets do not implement !important",
}


# ---------------------------------------------------------------------------
# widget inventory
# ---------------------------------------------------------------------------

def scan_class_bases() -> Dict[str, str]:
    """class name -> direct public base, for every C++ class in src/."""
    bases: Dict[str, str] = {}
    pattern = re.compile(r"class\s+(?:OSZA_EXPORT\s+)?(\w+)\s*:\s*public\s+(\w+)")
    for header in list(REPO.rglob("*.h")):
        s = str(header)
        if "/po/" in s or "/poqm/" in s or "/.git/" in s or "3rdparty" in s:
            continue
        try:
            text = header.read_text(errors="ignore")
        except OSError:
            continue
        for match in pattern.finditer(text):
            bases.setdefault(match.group(1), match.group(2))
    return bases


def resolve_qt_base(cls: str, bases: Dict[str, str]) -> Optional[str]:
    """Walk the base chain until a Qt class is reached."""
    seen: Set[str] = set()
    current = UI_CLASS_ALIASES.get(cls, cls)
    while current in bases and current not in seen:
        seen.add(current)
        current = bases[current]
    return current if current.startswith("Q") else None


def scan_ui_widget_classes() -> Set[str]:
    """Widget classes instantiated by every .ui file in the tree."""
    found: Set[str] = set()
    for ui in REPO.rglob("*.ui"):
        s = str(ui)
        if "/po/" in s or "/.git/" in s:
            continue
        text = ui.read_text(errors="ignore")
        for match in re.finditer(r'<widget class="([^"]+)"', text):
            found.add(match.group(1))
        for match in re.finditer(r"<extends>([^<]+)</extends>", text):
            found.add(match.group(1))
    return found


def required_widget_inventory(bases: Dict[str, str]) -> Set[str]:
    """REQUIRED_PAINTERS actually instantiated in this tree."""
    instantiated = scan_ui_widget_classes()
    resolved: Set[str] = set()
    for cls in instantiated:
        qt_base = resolve_qt_base(cls, bases)
        if qt_base in REQUIRED_PAINTERS:
            resolved.add(qt_base)
    # QToolTip is never declared in a .ui file but every tooltip
    # in the browser is one; QTabBar is reached through QTabWidget.
    resolved.add("QToolTip")
    if "QTabWidget" in resolved:
        resolved.add("QTabBar")
    # Views bring their headers.
    if resolved & {"QTreeView", "QTreeWidget", "QTableView", "QTableWidget"}:
        resolved.add("QHeaderView")
    return resolved


# ---------------------------------------------------------------------------
# QSS parsing
# ---------------------------------------------------------------------------

class Block:
    def __init__(self, selector: str, line: int) -> None:
        self.selector = selector
        self.line = line


def strip_comments(css: str) -> str:
    return re.sub(r"/\*.*?\*/", "", css, flags=re.S)


def parse_blocks(css: str) -> List[Block]:
    """Selector heads in file order (Qt style sheets have no @rules)."""
    blocks: List[Block] = []
    depth = 0
    head: List[str] = []
    line = 1
    for ch in css:
        if ch == "\n":
            line += 1
        if ch == "{":
            if depth == 0:
                selector = " ".join("".join(head).split())
                if selector:
                    blocks.append(Block(selector, line))
            depth += 1
            head = []
        elif ch == "}":
            depth = max(0, depth - 1)
            head = []
        elif depth == 0:
            head.append(ch)
    return blocks


def theme_selectors(blocks: List[Block]) -> Set[str]:
    selectors: Set[str] = set()
    for block in blocks:
        for part in block.selector.split(","):
            part = " ".join(part.split())
            if part:
                selectors.add(part)
    return selectors


def selector_class_tokens(selectors: Set[str]) -> Set[str]:
    """Class names (Qt or custom) any selector mentions."""
    tokens: Set[str] = set()
    for selector in selectors:
        for token in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", selector):
            if token[0].isupper():
                tokens.add(token)
    return tokens


def check_qss_sanity(name: str, css: str, theme_dir: Path) -> List[str]:
    findings: List[str] = []

    if css.count("{") != css.count("}"):
        findings.append(
            f"{name}: unbalanced braces ({css.count('{')} '{{' vs {css.count('}')} '}}')")

    stripped = strip_comments(css)

    for construct, why in FORBIDDEN_CONSTRUCTS.items():
        if construct in stripped:
            findings.append(f"{name}: '{construct}' used - {why}")

    # url() artwork must exist
    for match in re.finditer(r"url\(\s*([^)\s]+)\s*\)", stripped):
        target = match.group(1).strip("\"'")
        if target.startswith("data:") or target.startswith(":"):
            continue
        if not (theme_dir / target).exists():
            findings.append(f"{name}: url() target missing on disk: {target}")

    # pseudo-states, subcontrols
    for block in parse_blocks(stripped):
        sel = block.selector
        without_subcontrols = re.sub(r"::[a-z-]+", "", sel)
        for state in re.findall(r":([a-z-]+)", without_subcontrols):
            if state not in KNOWN_PSEUDO_STATES:
                findings.append(
                    f"{name}:{block.line}: unknown pseudo-state ':{state}' in '{sel}'")
        for sub in re.findall(r"::([a-z-]+)", sel):
            if sub not in KNOWN_SUBCONTROLS:
                findings.append(
                    f"{name}:{block.line}: unknown subcontrol '::{sub}' in '{sel}'")

    # every declaration must be 'known-property: value;'
    for body in re.findall(r"\{([^{}]*)\}", stripped):
        for declaration in body.split(";"):
            declaration = declaration.strip()
            if not declaration:
                continue
            if ":" not in declaration:
                findings.append(f"{name}: declaration without a value: '{declaration}'")
                continue
            prop = declaration.split(":", 1)[0].strip()
            if prop.startswith("qproperty-") or prop.startswith("*"):
                continue
            if prop not in KNOWN_PROPERTIES:
                findings.append(f"{name}: unknown property '{prop}' in '{declaration[:60]}'")

    return findings


# ---------------------------------------------------------------------------
# coverage + invariants
# ---------------------------------------------------------------------------

def check_coverage(name: str, blocks: List[Block],
                   bases: Dict[str, str]) -> List[str]:
    findings: List[str] = []
    selectors = theme_selectors(blocks)
    mentioned = selector_class_tokens(selectors)
    inventory = required_widget_inventory(bases)

    for required in sorted(inventory):
        if required not in mentioned:
            findings.append(
                f"{name}: widget class {required} is instantiated in the tree "
                f"but no selector mentions it - it renders in the system look")

    # custom class selectors must name real classes
    for token in sorted(mentioned):
        if token.startswith("Q") or token in (
                # pseudo-element-ish and known chrome names
                "ToolButton", "TabBarTabMetrics", "IconProvider", "WebView",
                "SearchToolBar", "AboutDialog", "DesktopNotification"):
            continue
        if token not in bases and token not in UI_CLASS_ALIASES.values():
            findings.append(
                f"{name}: selector names '{token}' but no such class exists in src/")

    return findings


def check_ordering(name: str, css: str) -> List[str]:
    """Invariants the theme's cascade relies on."""
    findings: List[str] = []
    blocks = parse_blocks(strip_comments(css))

    # the item-view rules carrying [frameShape="6"] must come after
    # the QFrame[frameShape="6"] rule they override by cascade order
    frame_card_lines = [b.line for b in blocks
                        if b.selector == 'QFrame[frameShape="6"]']
    view_lines = [b.line for b in blocks
                  if "frameShape" in b.selector
                  and b.selector != 'QFrame[frameShape="6"]'
                  and not b.selector.startswith("QScrollArea")
                  and not b.selector.startswith("QGraphicsView")]
    if frame_card_lines and view_lines:
        if min(view_lines) < frame_card_lines[0]:
            findings.append(
                f"{name}: item-view [frameShape] rules appear before the "
                f"QFrame[frameShape=\"6\"] card rule - the views lose the "
                f"cascade tie and render as cards")

    # the WebView page background must exist
    if not any(b.selector == "WebView" for b in blocks):
        findings.append(
            f"{name}: no WebView background rule - page surfaces can go dark")

    return findings


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description="Osza theme completeness verifier")
    ap.add_argument("--theme", help="verify a single theme by directory name")
    ap.add_argument("--json", action="store_true", help="machine report")
    ap.add_argument("--strict", action="store_true",
                    help="exit 1 when any finding is reported")
    args = ap.parse_args()

    theme_names = sorted(
        d.name for d in THEMES_DIR.iterdir()
        if d.is_dir() and (d / "main.css").exists())
    if args.theme:
        if args.theme not in theme_names:
            print(f"no such theme: {args.theme}")
            return 2
        theme_names = [args.theme]

    bases = scan_class_bases()
    report: Dict[str, List[str]] = {}
    total = 0

    for name in theme_names:
        theme_dir = THEMES_DIR / name
        findings: List[str] = []
        for css_name in ("main.css", "private.css", "rtl.css"):
            css_file = theme_dir / css_name
            if not css_file.exists():
                continue
            css = css_file.read_text(errors="ignore")
            findings.extend(check_qss_sanity(f"{name}/{css_name}", css, theme_dir))
            if css_name == "main.css":
                blocks = parse_blocks(strip_comments(css))
                if name in FULL_COVERAGE_THEMES:
                    findings.extend(check_coverage(name, blocks, bases))
                findings.extend(check_ordering(name, css))
        report[name] = findings
        total += len(findings)

    if args.json:
        print(json.dumps({"themes": report, "findings": total}, indent=2))
    else:
        print("Osza theme verification")
        for name in theme_names:
            findings = report[name]
            status = "clean" if not findings else f"{len(findings)} finding(s)"
            coverage = "full coverage" if name in FULL_COVERAGE_THEMES \
                else "palette-following"
            print(f"  {name} ({coverage}): {status}")
            for finding in findings:
                print(f"    - {finding}")
        print(f"  total findings: {total}")

    if total and args.strict:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
