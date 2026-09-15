#!/bin/bash
# Texto visible de una página web (sin scripts ni estilos). Uso: leer_web.sh URL [max_chars]
python3 - "$1" "${2:-8000}" <<'PY'
import sys, re, html, urllib.request
url, n = sys.argv[1], int(sys.argv[2])
t = urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "x39-lector"}), timeout=30).read().decode("utf-8", "replace")
t = re.sub(r"<(script|style)[^>]*>.*?</\1>", " ", t, flags=re.S | re.I)
t = re.sub(r"<(br|p|div|li|h[1-6]|tr)[^>]*>", "\n", t, flags=re.I)
t = html.unescape(re.sub(r"<[^>]+>", " ", t))
t = re.sub(r"[ \t]+", " ", t)
t = re.sub(r"\n\s*\n+", "\n", t)
print(t[:n])
PY
