#!/bin/bash
# Extrae el texto de un PDF (pdftotext si existe; si no, pypdf).
f="$1"
if command -v pdftotext >/dev/null 2>&1; then
  pdftotext -layout "$f" -
else
  python3 - "$f" <<'PY'
import sys
try:
    import pypdf
except ImportError:
    print("SIN pdftotext NI pypdf"); sys.exit(1)
r = pypdf.PdfReader(sys.argv[1])
for i, p in enumerate(r.pages, 1):
    print(f"===== página {i} =====")
    print(p.extract_text())
PY
fi
