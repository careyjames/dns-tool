#!/bin/bash
# Generate the philosophical foundations PDF from the HTML source using WeasyPrint.
# Usage: bash scripts/generate-foundations-pdf.sh [VERSION]
#
# If VERSION is provided, updates the version in both .html and .md before
# generating the PDF. If omitted, generates from current content.
#
# Prerequisites: weasyprint (listed in pyproject.toml)
# Logo asset: static/images/owl-signature.png (Owl of Athena — dark background, premium version)
#
# This MUST be run after every edit to docs/philosophical-foundations.html

set -euo pipefail
cd "$(dirname "$0")/.."

VERSION="${1:-}"

if [ -n "$VERSION" ]; then
  echo "Updating foundations version to ${VERSION}..."

  sed -i -E "s/Version<\/span>\&ensp;[0-9]+\.[0-9]+\.[0-9]+/Version<\/span>\&ensp;${VERSION}/" docs/philosophical-foundations.html
  sed -i -E "s/Version [0-9]+\.[0-9]+\.[0-9]+/Version ${VERSION}/" docs/philosophical-foundations.md

  echo "Version updated in .html and .md"
fi

echo "Generating philosophical foundations PDF..."
python -c "
import weasyprint
html = weasyprint.HTML(filename='docs/philosophical-foundations.html', base_url='docs/')
html.write_pdf('docs/philosophical-foundations.pdf')
"

cp docs/philosophical-foundations.pdf static/docs/philosophical-foundations.pdf

SIZE=$(stat -f%z docs/philosophical-foundations.pdf 2>/dev/null || stat -c%s docs/philosophical-foundations.pdf 2>/dev/null)
echo "PDF generated: docs/philosophical-foundations.pdf (${SIZE} bytes)"
echo "Copied to:     static/docs/philosophical-foundations.pdf"

if [ ! -s docs/philosophical-foundations.pdf ]; then
  echo "ERROR: docs/philosophical-foundations.pdf is empty or missing"
  exit 1
fi
if [ ! -s static/docs/philosophical-foundations.pdf ]; then
  echo "ERROR: static/docs/philosophical-foundations.pdf is empty or missing"
  exit 1
fi

echo "Done."
