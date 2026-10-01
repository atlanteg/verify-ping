#!/usr/bin/env bash
# Build docs/verify-ping-manual.pdf from README.md.
# Needs python3 (a venv with python-markdown is created on first run) and
# Google Chrome or Chromium for the PDF step.
set -euo pipefail
cd "$(dirname "$0")/.."

VENV=docs/.venv
if [ ! -x "$VENV/bin/python" ]; then
  python3 -m venv "$VENV"
  "$VENV/bin/pip" install --quiet markdown
fi

VERSION=$(sed -n 's/^__version__ = "\(.*\)"/\1/p' verify_ping.py)
"$VENV/bin/python" - "$VERSION" <<'EOF' > docs/manual.html
import sys, datetime, markdown
version = sys.argv[1]
body = markdown.markdown(open("README.md", encoding="utf-8").read(),
                         extensions=["tables", "fenced_code", "toc"])
css = """
@page { size: A4; margin: 18mm 16mm 18mm 16mm; }
body { font: 10.5pt/1.45 -apple-system, "Segoe UI", Helvetica, Arial, sans-serif; color: #111; max-width: 100%; }
h1 { font-size: 22pt; margin: 0 0 4pt 0; }
h1 + p { color: #444; }
h2 { font-size: 15pt; margin-top: 22pt; border-bottom: 1px solid #bbb; padding-bottom: 3pt; page-break-after: avoid; }
h3 { font-size: 12pt; margin-top: 14pt; page-break-after: avoid; }
code, pre { font-family: "SF Mono", Menlo, Consolas, monospace; font-size: 8.6pt; }
pre { background: #f4f4f4; border: 1px solid #ddd; padding: 6pt 8pt; white-space: pre-wrap; word-break: break-all; page-break-inside: avoid; }
code { background: #f1f1f1; padding: 0 2pt; border-radius: 2pt; }
pre code { background: none; padding: 0; }
table { border-collapse: collapse; width: 100%; margin: 6pt 0 10pt 0; font-size: 9.3pt; page-break-inside: avoid; }
th, td { border: 1px solid #ccc; padding: 3pt 5pt; vertical-align: top; text-align: left; }
th { background: #eee; }
hr { border: 0; border-top: 1px solid #bbb; margin: 14pt 0; }
.cover { text-align: center; margin-top: 150pt; page-break-after: always; }
.cover h1 { font-size: 30pt; }
.cover p { font-size: 13pt; color: #333; }
"""
today = datetime.date.today().isoformat()
cover = (f'<div class="cover"><h1>verify-ping</h1><p>User manual</p>'
         f'<p>Version {version} &middot; {today}</p>'
         f'<p><code>https://github.com/atlanteg/verify-ping</code></p></div>')
print(f"<!doctype html><html><head><meta charset='utf-8'><title>verify-ping manual</title>"
      f"<style>{css}</style></head><body>{cover}{body}</body></html>")
EOF

CHROME=""
for c in "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
         "/Applications/Chromium.app/Contents/MacOS/Chromium" \
         google-chrome chromium chromium-browser; do
  if command -v "$c" >/dev/null 2>&1 || [ -x "$c" ]; then CHROME="$c"; break; fi
done
[ -n "$CHROME" ] || { echo "no Chrome/Chromium found for the PDF step; docs/manual.html is ready" >&2; exit 1; }

"$CHROME" --headless --disable-gpu --no-pdf-header-footer \
  --print-to-pdf="$PWD/docs/verify-ping-manual.pdf" "file://$PWD/docs/manual.html" 2>/dev/null
rm -f docs/manual.html
ls -l docs/verify-ping-manual.pdf
