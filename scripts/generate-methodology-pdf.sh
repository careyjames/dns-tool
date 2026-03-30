#!/bin/bash
# Generate the methodology PDF from the HTML source using WeasyPrint.
# Usage: bash scripts/generate-methodology-pdf.sh [VERSION]
#
# If VERSION is provided, updates the version in both .md and .html before
# generating the PDF. If omitted, generates from current content.
#
# Prerequisites: weasyprint (listed in pyproject.toml)
# Logo asset: static/images/owl-signature.png (Owl of Athena — dark background, premium version)
#
# This MUST be run after every version bump that touches
# docs/dns-tool-methodology.html or docs/dns-tool-methodology.md

set -euo pipefail
cd "$(dirname "$0")/.."

VERSION="${1:-}"

if [ -n "$VERSION" ]; then
  echo "Updating methodology version to ${VERSION}..."

  sed -i -E "s/Version [0-9]+\.[0-9]+\.[0-9]+/Version ${VERSION}/" docs/dns-tool-methodology.md
  sed -i -E "s/version      = \{[0-9]+\.[0-9]+\.[0-9]+\}/version      = {${VERSION}}/" docs/dns-tool-methodology.md
  sed -i -E "s/DNS Tool v[0-9]+\.[0-9]+\.[0-9]+/DNS Tool v${VERSION}/" docs/dns-tool-methodology.md

  sed -i -E "s/Version<\/span>\&ensp;[0-9]+\.[0-9]+\.[0-9]+/Version<\/span>\&ensp;${VERSION}/" docs/dns-tool-methodology.html
  sed -i -E "s/version\&nbsp;\&nbsp;\&nbsp;\&nbsp;\&nbsp;\&nbsp;= \{[0-9]+\.[0-9]+\.[0-9]+\}/version\&nbsp;\&nbsp;\&nbsp;\&nbsp;\&nbsp;\&nbsp;= {${VERSION}}/" docs/dns-tool-methodology.html
  sed -i -E "s/DNS Tool v[0-9]+\.[0-9]+\.[0-9]+/DNS Tool v${VERSION}/" docs/dns-tool-methodology.html

  echo "Version updated in .md and .html"
fi

echo "Generating methodology PDF..."
python -c "
import weasyprint
html = weasyprint.HTML(filename='docs/dns-tool-methodology.html', base_url='docs/')
html.write_pdf('docs/dns-tool-methodology.pdf')
"

cp docs/dns-tool-methodology.pdf static/docs/dns-tool-methodology.pdf

SIZE=$(stat -f%z docs/dns-tool-methodology.pdf 2>/dev/null || stat -c%s docs/dns-tool-methodology.pdf 2>/dev/null)
echo "PDF generated: docs/dns-tool-methodology.pdf (${SIZE} bytes)"
echo "Copied to:     static/docs/dns-tool-methodology.pdf"

if [ ! -s docs/dns-tool-methodology.pdf ]; then
  echo "ERROR: docs/dns-tool-methodology.pdf is empty or missing"
  exit 1
fi
if [ ! -s static/docs/dns-tool-methodology.pdf ]; then
  echo "ERROR: static/docs/dns-tool-methodology.pdf is empty or missing"
  exit 1
fi

echo "Done."
