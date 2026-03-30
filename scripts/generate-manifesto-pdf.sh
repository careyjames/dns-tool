#!/bin/bash
# Generate the Founder's Manifesto PDF from the HTML source using WeasyPrint.
# Usage: bash scripts/generate-manifesto-pdf.sh [VERSION]
#
# If VERSION is provided, updates the version in the HTML before
# generating the PDF. If omitted, generates from current content.
#
# Prerequisites: weasyprint (listed in pyproject.toml)
# Logo asset: static/images/owl-signature.png (Owl of Athena)
#
# This MUST be run after every edit to docs/founders-manifesto.html

set -euo pipefail
cd "$(dirname "$0")/.."

VERSION="${1:-}"

if [ -n "$VERSION" ]; then
  echo "Updating manifesto version to ${VERSION}..."

  sed -i -E "s/Version<\/span>\&ensp;[0-9]+\.[0-9]+\.[0-9]+/Version<\/span>\&ensp;${VERSION}/" docs/founders-manifesto.html
  sed -i -E "s/Version [0-9]+\.[0-9]+\.[0-9]+/Version ${VERSION}/" docs/FOUNDERS_MANIFESTO.md

  echo "Version updated in .html and .md"
fi

echo "Generating Founder's Manifesto PDF..."
python -c "
import weasyprint
html = weasyprint.HTML(filename='docs/founders-manifesto.html', base_url='docs/')
html.write_pdf('docs/founders-manifesto.pdf')
"

cp docs/founders-manifesto.pdf static/docs/founders-manifesto.pdf
cp docs/founders-manifesto.pdf go-server/static/docs/founders-manifesto.pdf

SIZE=$(stat -f%z docs/founders-manifesto.pdf 2>/dev/null || stat -c%s docs/founders-manifesto.pdf 2>/dev/null)
echo "PDF generated: docs/founders-manifesto.pdf (${SIZE} bytes)"
echo "Copied to:     static/docs/founders-manifesto.pdf"
echo "Copied to:     go-server/static/docs/founders-manifesto.pdf"

if [ ! -s docs/founders-manifesto.pdf ]; then
  echo "ERROR: docs/founders-manifesto.pdf is empty or missing"
  exit 1
fi
if [ ! -s static/docs/founders-manifesto.pdf ]; then
  echo "ERROR: static/docs/founders-manifesto.pdf is empty or missing"
  exit 1
fi
if [ ! -s go-server/static/docs/founders-manifesto.pdf ]; then
  echo "ERROR: go-server/static/docs/founders-manifesto.pdf is empty or missing"
  exit 1
fi

echo "Done."
