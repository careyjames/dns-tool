#!/usr/bin/env python3
"""Generate OG social card images for DNS Tool.

Layout: 1200x630, vertically balanced composition.
The content block (owl + text + footer) is measured first,
then vertically centered in the canvas so nothing clusters
at the top or leaves dead space at the bottom.
"""

import os
from PIL import Image, ImageDraw, ImageFont

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "static", "images")
OWL_PATH = os.path.join(STATIC_DIR, "owl-signature.png")

W, H = 1200, 630
BG_COLOR = (13, 17, 23)
TEXT_PRIMARY = (230, 237, 243)
TEXT_SECONDARY = (139, 148, 158)
TEXT_MUTED = (110, 118, 129)
TEXT_DIM = (72, 79, 88)
ACCENT_GREEN = (126, 231, 135)
ACCENT_PURPLE = (201, 160, 255)
ACCENT_GOLD = (200, 168, 120)

FONT_BOLD = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
FONT_REGULAR = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"

OWL_SIZE = 160
TITLE_SIZE = 52
SUBTITLE_SIZE = 22
TAGS_SIZE = 16
HIGHLIGHT_SIZE = 18
DETAIL_SIZE = 15
FOOTER_SIZE = 13

GAP_OWL_TITLE = 20
GAP_TITLE_SUBTITLE = 12
GAP_SUBTITLE_TAGS = 16
GAP_TAGS_HIGHLIGHT = 12
GAP_HIGHLIGHT_DETAIL = 12
GAP_DETAIL_FOOTER = 28
GAP_LINE_COMPANY = 12
GAP_COMPANY_URL = 4


def load_font(path, size):
    try:
        return ImageFont.truetype(path, size)
    except (OSError, IOError):
        return ImageFont.load_default()


def text_width(draw, text, font):
    bbox = draw.textbbox((0, 0), text, font=font)
    return bbox[2] - bbox[0]


def text_height(draw, text, font):
    bbox = draw.textbbox((0, 0), text, font=font)
    return bbox[3] - bbox[1]


def center_x(draw, text, font):
    return (W - text_width(draw, text, font)) // 2


def generate(filename, title, subtitle, tags, highlight, detail):
    img = Image.new("RGBA", (W, H), BG_COLOR)
    draw = ImageDraw.Draw(img)

    font_title = load_font(FONT_BOLD, TITLE_SIZE)
    font_subtitle = load_font(FONT_REGULAR, SUBTITLE_SIZE)
    font_tags = load_font(FONT_REGULAR, TAGS_SIZE)
    font_highlight = load_font(FONT_BOLD, HIGHLIGHT_SIZE)
    font_detail = load_font(FONT_REGULAR, DETAIL_SIZE)
    font_footer = load_font(FONT_REGULAR, FOOTER_SIZE)

    company = "IT Help San Diego Inc."
    url = "dnstool.it-help.tech"

    h_owl = OWL_SIZE
    h_title = text_height(draw, title, font_title)
    h_subtitle = text_height(draw, subtitle, font_subtitle)
    h_tags = text_height(draw, tags, font_tags)
    h_highlight = text_height(draw, highlight, font_highlight)
    h_detail = text_height(draw, detail, font_detail)
    h_company = text_height(draw, company, font_footer)
    h_url = text_height(draw, url, font_footer)
    line_h = 2

    total = (h_owl + GAP_OWL_TITLE +
             h_title + GAP_TITLE_SUBTITLE +
             h_subtitle + GAP_SUBTITLE_TAGS +
             h_tags + GAP_TAGS_HIGHLIGHT +
             h_highlight + GAP_HIGHLIGHT_DETAIL +
             h_detail + GAP_DETAIL_FOOTER +
             line_h + GAP_LINE_COMPANY +
             h_company + GAP_COMPANY_URL +
             h_url)

    y = (H - total) // 2

    owl = Image.open(OWL_PATH).convert("RGBA")
    owl = owl.resize((OWL_SIZE, OWL_SIZE), Image.LANCZOS)
    img.paste(owl, ((W - OWL_SIZE) // 2, y), owl)
    y += h_owl + GAP_OWL_TITLE

    draw.text((center_x(draw, title, font_title), y), title,
              fill=TEXT_PRIMARY, font=font_title)
    y += h_title + GAP_TITLE_SUBTITLE

    draw.text((center_x(draw, subtitle, font_subtitle), y), subtitle,
              fill=TEXT_SECONDARY, font=font_subtitle)
    y += h_subtitle + GAP_SUBTITLE_TAGS

    draw.text((center_x(draw, tags, font_tags), y), tags,
              fill=ACCENT_GREEN, font=font_tags)
    y += h_tags + GAP_TAGS_HIGHLIGHT

    draw.text((center_x(draw, highlight, font_highlight), y), highlight,
              fill=ACCENT_PURPLE, font=font_highlight)
    y += h_highlight + GAP_HIGHLIGHT_DETAIL

    draw.text((center_x(draw, detail, font_detail), y), detail,
              fill=TEXT_MUTED, font=font_detail)
    y += h_detail + GAP_DETAIL_FOOTER

    line_w = 140
    draw.line([((W - line_w) // 2, y), ((W + line_w) // 2, y)],
              fill=ACCENT_GOLD + (120,), width=2)
    y += line_h + GAP_LINE_COMPANY

    draw.text((center_x(draw, company, font_footer), y), company,
              fill=TEXT_DIM, font=font_footer)
    y += h_company + GAP_COMPANY_URL

    draw.text((center_x(draw, url, font_footer), y), url,
              fill=TEXT_DIM, font=font_footer)

    out_path = os.path.join(STATIC_DIR, filename)
    img_rgb = Image.new("RGB", (W, H), BG_COLOR)
    img_rgb.paste(img, mask=img.split()[3] if img.mode == "RGBA" else None)
    img_rgb.save(out_path, "PNG", optimize=True)
    size_kb = os.path.getsize(out_path) // 1024
    print(f"Generated {filename} ({size_kb} KB)")


cards = [
    ("og-image.png",
     "DNS Tool",
     "Domain Security Intelligence",
     "SPF \u00b7 DKIM \u00b7 DMARC \u00b7 DANE \u00b7 DNSSEC \u00b7 BIMI \u00b7 MTA-STS \u00b7 TLS-RPT \u00b7 CAA",
     "9 Protocols \u00b7 RFC-Verified \u00b7 Open-Core",
     "Intelligence Confidence Audit Engine (ICAE)"),
    ("og-toolkit.png",
     "Field Tech Toolkit",
     "Guided Network Troubleshooting for Everyone",
     "What's My IP \u00b7 Port Check \u00b7 DNS Test \u00b7 Traceroute \u00b7 Network Chain",
     "Step-by-Step Diagnostics \u00b7 Educational",
     "Wizard-Style Flow with RFC Citations"),
    ("og-investigate.png",
     "IP Intelligence",
     "Is This IP Part of Your Infrastructure?",
     "ASN \u00b7 Geolocation \u00b7 Reverse DNS \u00b7 RDAP \u00b7 SPF Authorization",
     "Evidence-Based Attribution \u00b7 Multi-Source",
     "Certificate Transparency \u00b7 Subdomain Discovery"),
    ("og-email-header.png",
     "Email Intelligence",
     "Did This Email Actually Come from Who It Claims?",
     "SPF \u00b7 DKIM \u00b7 DMARC \u00b7 Delivery Routing \u00b7 Spam Vendor Detection",
     "Authentication Assessment \u00b7 RFC-Compliant",
     "OpenPhish Integration \u00b7 Brand Mismatch Detection"),
    ("og-ttl-tuner.png",
     "TTL Tuner",
     "Tune Your DNS for Speed, Reliability, and Control",
     "A \u00b7 AAAA \u00b7 MX \u00b7 NS \u00b7 SOA \u00b7 TXT \u00b7 CNAME \u00b7 SRV \u00b7 CAA",
     "Provider-Aware \u00b7 RFC-Cited \u00b7 Copy-Paste Instructions",
     "Cloudflare \u00b7 Route 53 \u00b7 BIND \u00b7 GoDaddy \u00b7 All Providers"),
    ("og-forgotten-domain.png",
     "Forgotten Domain",
     "Silence Is Not Protection",
     "SPF: v=spf1 -all    DMARC: p=reject    MX: 0 .",
     "Three Records Separate Protection from Impersonation",
     "If a domain sends no mail, publish the policy."),
]

if __name__ == "__main__":
    for args in cards:
        generate(*args)
