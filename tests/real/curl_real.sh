#!/bin/bash
# curl recorded against REAL servers (needs internet). Slice 1e. Not part of the default regression.
set -u
HERE=$(cd "$(dirname "$0")/../.." && pwd); OUT=$HERE/out/curl_real
TW="$HERE/.venv/bin/tracewatch"; PY="$HERE/.venv/bin/python"
rm -rf "$OUT"; mkdir -p "$OUT"
probe() { curl -s -o /dev/null -m 15 -w '%{http_code}' "$1" 2>/dev/null; }
have() { [ "$(probe "$1")" = "$2" ] && echo 1 || { echo "SKIP: $1 did not answer $2 directly; checks that need it are skipped" >&2; echo 0; }; }
export HAVE_HTTPBIN=$(have https://httpbin.org/get 200)
export HAVE_CFBR=$(have https://developers.cloudflare.com/ 200)
export HAVE_OVH=$(have https://proof.ovh.net/files/10Mb.dat 200)
BAD=$(probe https://expired.badssl.com/); [ "$BAD" = 000 ] && export HAVE_BADSSL=1 || { echo "SKIP: badssl not behaving as expected"; export HAVE_BADSSL=0; }
[ "$(probe https://example.com/)" = 200 ] || { echo "FAIL: example.com unreachable; no real-target test possible"; exit 1; }
# direct (unrecorded) references
mkdir -p "$OUT/direct"
[ "$HAVE_OVH" = 1 ] && curl -s -m 60 -o "$OUT/direct/big.bin" https://proof.ovh.net/files/10Mb.dat
[ "$HAVE_HTTPBIN" = 1 ] && curl -s -o /dev/null -m 30 -w '%{json}' "https://httpbin.org/drip?duration=3&numbytes=6&code=200&delay=0" > "$OUT/direct/drip.meta"
echo "{\"httpbin\":$HAVE_HTTPBIN,\"cfbr\":$HAVE_CFBR,\"ovh\":$HAVE_OVH,\"badssl\":$HAVE_BADSSL}" > "$OUT/have.json"
echo "=== run A: everything through the proxy"
"$TW" record --out "$OUT/runs" --name A -- "$HERE/tests/real/curl_workload.sh" "$OUT/results" 2>&1 | tail -2
echo "=== run B: one request bypasses the proxy via NO_PROXY"
NO_PROXY=example.com no_proxy=example.com "$TW" record --quiet --out "$OUT/runs" --name B -- sh -c \
  'curl -sS -o /dev/null https://example.com/; curl -sS -o /dev/null https://api.github.com/zen' 2>&1 | tail -2
"$PY" tests/real/curl_real_check.py "$OUT"
