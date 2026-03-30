#!/usr/bin/env python3
"""Font Awesome Icon Subset Audit Tool.

Scans all Go templates for fa-* icon usage, cross-references against
the WOFF2 font subset and CSS, reports any missing glyphs.

Usage:
    python3 go-server/scripts/audit_icons.py

Exit code 0 = all icons present, 1 = missing icons found.

Root Cause Context:
    Icons keep disappearing because the project uses a WOFF2 font SUBSET
    (not the full Font Awesome). When templates add new fa-* classes,
    the glyph must exist in BOTH:
      1. static/css/fontawesome-subset.min.css  (CSS :before rule)
      2. static/webfonts/fa-solid-900.woff2     (actual glyph in font)
    If either is missing, the icon renders as a blank space.
"""

import os
import re
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATE_DIR = os.path.join(SCRIPT_DIR, "..", "templates")
CSS_FILE = os.path.join(SCRIPT_DIR, "..", "..", "static", "css", "fontawesome-subset.min.css")
FONT_FILE = os.path.join(SCRIPT_DIR, "..", "..", "static", "webfonts", "fa-solid-900.woff2")

MODIFIER_CLASSES = {"fa-lg", "fa-2x", "fa-3x", "fa-4x", "fa-5x", "fa-fw",
                     "fa-spin", "fa-pulse", "fa-xs", "fa-sm", "fa-xl", "fa-2xl",
                     "fa-beat", "fa-bounce", "fa-fade", "fa-flip", "fa-shake"}

FA6_CODEPOINTS = {
    "angle-right": 0xf105, "archive": 0xf187, "arrow-right": 0xf061,
    "arrows-rotate": 0xf021, "asterisk": 0x2a, "balance-scale": 0xf24e,
    "ban": 0xf05e, "biohazard": 0xf780, "bolt": 0xf0e7, "book": 0xf02a,
    "briefcase": 0xf0b1, "building": 0xf1ad, "bullhorn": 0xf0a1,
    "calendar": 0xf133, "calendar-alt": 0xf073, "calendar-days": 0xf073,
    "certificate": 0xf0a3, "chart-bar": 0xf080, "chart-line": 0xf201,
    "check": 0xf00c, "check-circle": 0xf058, "check-double": 0xf560,
    "check-square": 0xf14a, "chevron-down": 0xf078, "chevron-left": 0xf053,
    "chevron-right": 0xf054, "circle-check": 0xf058, "circle-info": 0xf05a,
    "circle-minus": 0xf056, "circle-notch": 0xf1ce, "circle-question": 0xf059,
    "circle-xmark": 0xf057, "clipboard-list": 0xf46d, "clock": 0xf017,
    "clock-rotate-left": 0xf1da, "cloud": 0xf0c2, "code-compare": 0xe13a,
    "cogs": 0xf085, "compress": 0xf066, "compress-arrows-alt": 0xf78c,
    "copy": 0xf0c5,
    "crosshairs": 0xf05b, "database": 0xf1c0, "diagram-project": 0xf542,
    "directions": 0xf5eb, "envelope": 0xf0e0, "equals": 0x3d,
    "exchange-alt": 0xf362, "expand": 0xf065, "exclamation-circle": 0xf06a,
    "exclamation-triangle": 0xf071, "external-link-alt": 0xf35d,
    "eye": 0xf06e, "eye-slash": 0xf070, "file": 0xf15b,
    "file-alt": 0xf15c, "file-code": 0xf1c9, "file-lines": 0xf15c,
    "filter": 0xf0b0, "fish": 0xf578, "flask": 0xf0c3, "gavel": 0xf0e3,
    "gears": 0xf085, "globe": 0xf0ac, "globe-americas": 0xf57d,
    "handshake": 0xf2b5, "heart": 0xf004, "history": 0xf1da,
    "house": 0xf015, "id-card": 0xf2c2, "image": 0xf03e,
    "info-circle": 0xf05a, "key": 0xf084, "landmark": 0xf66f,
    "language": 0xf1ab, "laptop-code": 0xf5fc, "lightbulb": 0xf0eb,
    "link": 0xf0c1, "link-slash": 0xf127, "list": 0xf03a,
    "lock": 0xf023, "long-arrow-alt-right": 0xf30b,
    "map-marker-alt": 0xf3c5, "map-pin": 0xf276, "microchip": 0xf2db,
    "microscope": 0xf610, "minus": 0xf068, "minus-circle": 0xf056,
    "network-wired": 0xf6ff, "paper-plane": 0xf1d8, "percentage": 0x25,
    "plus": 0x2b, "plus-circle": 0xf055, "print": 0xf02f,
    "project-diagram": 0xf542, "puzzle-piece": 0xf12e,
    "question-circle": 0xf059, "robot": 0xf544, "route": 0xf4d7,
    "search": 0xf002, "search-plus": 0xf00e, "server": 0xf233,
    "shield": 0xf132, "shield-alt": 0xf3ed, "shield-halved": 0xf3ed,
    "shield-virus": 0xe06c, "signature": 0xf5b7, "sitemap": 0xf0e8,
    "sliders-h": 0xf1de, "spinner": 0xf110, "square": 0xf0c8,
    "stopwatch": 0xf2f2, "sync": 0xf021, "sync-alt": 0xf2f1,
    "tag": 0xf02b, "terminal": 0xf120, "times": 0xf00d,
    "times-circle": 0xf057, "tools": 0xf7d9,
    "triangle-exclamation": 0xf071, "trophy": 0xf091, "unlink": 0xf127,
    "user": 0xf007, "users": 0xf0c0, "user-shield": 0xf505,
    "wrench": 0xf0ad,
}


def scan_templates():
    icons = set()
    for fname in os.listdir(TEMPLATE_DIR):
        if not fname.endswith(".html"):
            continue
        with open(os.path.join(TEMPLATE_DIR, fname)) as f:
            content = f.read()
        for match in re.findall(r'fa-([a-z][a-z0-9-]*)', content):
            cls = f"fa-{match}"
            if cls not in MODIFIER_CLASSES:
                icons.add(match)
    return icons


def scan_css():
    with open(CSS_FILE) as f:
        css = f.read()
    return set(re.findall(r'\.fa-([a-z][a-z0-9-]*):before', css))


def scan_font():
    try:
        from fontTools.ttLib import TTFont
        font = TTFont(FONT_FILE)
        return font.getBestCmap()
    except ImportError:
        print("WARNING: fonttools not installed, skipping font glyph audit")
        return None


def classify_icons(template_icons, css_icons, font_cmap):
    missing_css = []
    missing_font = []
    unknown = []
    for icon in sorted(template_icons):
        if icon not in FA6_CODEPOINTS:
            unknown.append(icon)
            continue
        if icon not in css_icons:
            missing_css.append(icon)
        if font_cmap is not None and FA6_CODEPOINTS[icon] not in font_cmap:
            missing_font.append(icon)
    return missing_css, missing_font, unknown


def report_missing(label, items):
    if not items:
        return True
    print(f"\n{label} ({len(items)}):")
    for i in items:
        print(f"  fa-{i}")
    return False


def main():
    template_icons = scan_templates()
    css_icons = scan_css()
    font_cmap = scan_font()

    missing_css, missing_font, unknown = classify_icons(template_icons, css_icons, font_cmap)

    print(f"Template icons found: {len(template_icons)}")
    print(f"CSS rules present: {len(css_icons)}")
    if font_cmap:
        print(f"Font glyphs present: {len(font_cmap)}")

    ok = report_missing("MISSING FROM CSS", missing_css)
    ok = report_missing("MISSING FROM FONT", missing_font) and ok
    if unknown:
        report_missing("UNKNOWN — not in codepoint map, cannot verify", unknown)
        print("  Add these to FA6_CODEPOINTS dict to track them.")
        ok = False

    if ok:
        print("\nAll icons present in both CSS and font.")
        return 0
    print("\nFAILED: Missing icons detected.")
    return 1

if __name__ == "__main__":
    sys.exit(main())
