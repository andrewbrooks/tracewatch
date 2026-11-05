#!/bin/bash
# Regression: a RELATIVE --out must still give the target an absolute, working CA path even after it changes directory.
set -u
HERE=$(cd "$(dirname "$0")/../.." && pwd); cd "$HERE"; OUT=out/relpath
rm -rf "$OUT"
res=$(.venv/bin/tracewatch record --quiet --out "$OUT" --name r -- bash -c '
  cd / || exit 90
  for v in SSL_CERT_FILE CURL_CA_BUNDLE REQUESTS_CA_BUNDLE NODE_EXTRA_CA_CERTS GIT_SSL_CAINFO; do
    eval "p=\$$v"; case "$p" in /*) ;; *) echo "RELATIVE:$v=$p"; exit 91;; esac
    [ -s "$p" ] || { echo "MISSING:$v=$p"; exit 92; }
  done
  python3 -c "import ssl; c = ssl.create_default_context(); print(\"PY_CA_LOADED\" if c.cert_store_stats()[\"x509_ca\"] >= 1 else \"PY_NO_CA\")"
  echo CA_OK' 2>&1); rc=$?
echo "$res" | tail -3
if [ $rc = 0 ] && echo "$res" | grep -q CA_OK && echo "$res" | grep -q PY_CA_LOADED; then echo "PASS relative --out: every CA variable is absolute and resolves after the target changes directory"; exit 0; fi
echo "FAIL relative --out (exit $rc)"; exit 1
