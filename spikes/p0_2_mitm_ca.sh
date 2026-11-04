#!/bin/bash
# Phase 0 spike 2: mitmproxy decrypts HTTPS from a client that trusts ONLY a per-run CA given
# via env var. Loopback only (local HTTPS server signed by a separate test CA).
#  positive : client with the run CA env succeeds; proxy records decrypted path/auth/body
#  negative : client without the CA env fails TLS; no decrypted flow recorded
#  negative : upstream with an untrusted cert is still rejected (upstream verification on)
#  negative : a client trusting run A's CA is rejected by run B's proxy (CA is per-run)
#  negative : system trust store unchanged and does not contain the run CA
set -u
HERE=$(cd "$(dirname "$0")/.." && pwd)
OUT=$HERE/out/p0_2; rm -rf "$OUT"; mkdir -p "$OUT"/{up,confA,confB}
PA=18091; PB=18092; UP=18443; BAD=18444
pass=0; fail=0
check() { if [ "$2" = 1 ]; then echo "PASS $1"; pass=$((pass+1)); else echo "FAIL $1"; fail=$((fail+1)); fi; }
cleanup() { pkill -f "mitmdump --listen-host 127.0.0.1 --listen-port $PA" ; pkill -f "mitmdump --listen-host 127.0.0.1 --listen-port $PB"; kill $S1 $S2 2>/dev/null; }
trap cleanup EXIT

# --- upstream test PKI: UPCA signs the good server; BAD server is self-signed (unknown to UPCA)
cd "$OUT/up"
openssl req -x509 -newkey rsa:2048 -nodes -keyout upca.key -out upca.pem -days 2 -subj "/CN=tw-upstream-test-ca" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -keyout srv.key -out srv.csr -subj "/CN=localhost" 2>/dev/null
printf 'subjectAltName=DNS:localhost,IP:127.0.0.1\n' > san.ext
openssl x509 -req -in srv.csr -CA upca.pem -CAkey upca.key -CAcreateserial -out srv.pem -days 2 -extfile san.ext 2>/dev/null
openssl req -x509 -newkey rsa:2048 -nodes -keyout bad.key -out bad.pem -days 2 -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null
cat > srv.py <<'P'
import http.server, ssl, sys
port, crt, key = int(sys.argv[1]), sys.argv[2], sys.argv[3]
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(s):
        b = b"upstream-secret-body"; s.send_response(200); s.send_header("Content-Length", str(len(b))); s.end_headers(); s.wfile.write(b)
    def log_message(s, *a): pass
srv = http.server.HTTPServer(("127.0.0.1", port), H)
c = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); c.load_cert_chain(crt, key); srv.socket = c.wrap_socket(srv.socket, server_side=True)
srv.serve_forever()
P
python3 srv.py $UP srv.pem srv.key & S1=$!
python3 srv.py $BAD bad.pem bad.key & S2=$!
cd "$HERE"

start_proxy() {  # name port confdir flows   (native via uvx: Docker Desktop's loopback is not ours)
  TW_FLOWS="$OUT/$4" uvx --from mitmproxy mitmdump --listen-host 127.0.0.1 --listen-port "$2" \
    --set confdir="$OUT/$3" --set ssl_verify_upstream_trusted_ca="$OUT/up/upca.pem" \
    -s "$HERE/spikes/p0_2_addon.py" >"$OUT/$1.log" 2>&1 &
  eval "$1_PID=$!"
  for i in $(seq 120); do (exec 3<>/dev/tcp/127.0.0.1/$2) 2>/dev/null && return 0; sleep 0.5; done
  echo "proxy $1 did not come up"; tail -5 "$OUT/$1.log"; return 1
}
start_proxy mitmA $PA confA flowsA.jsonl || exit 1
start_proxy mitmB $PB confB flowsB.jsonl || exit 1
CAA=$OUT/confA/mitmproxy-ca-cert.pem; CAB=$OUT/confB/mitmproxy-ca-cert.pem
SYS_BEFORE=$(sha256sum /etc/ssl/certs/ca-certificates.crt 2>/dev/null | cut -d' ' -f1)

URL="https://localhost:$UP/secret?x=1"

# positive
code=$(env HTTPS_PROXY=http://127.0.0.1:$PA CURL_CA_BUNDLE=$CAA curl -sS -o "$OUT/body" -w '%{http_code}' --max-time 15 -H 'Authorization: Bearer TESTTOKEN' "$URL" 2>"$OUT/err"); rc=$?
check "positive: client with run CA gets 200 and upstream body" $([ "$rc" = 0 ] && [ "$code" = 200 ] && grep -q upstream-secret-body "$OUT/body" && echo 1 || echo 0)
check "positive: proxy recorded decrypted path, Authorization header and body" \
  $(python3 - "$OUT/flowsA.jsonl" <<'P'
import json,sys
r=[json.loads(l) for l in open(sys.argv[1])]
print(1 if any(x["kind"]=="flow" and x["path"]=="/secret?x=1" and x["req_auth"]=="Bearer TESTTOKEN" and x["resp_body"]=="upstream-secret-body" and x["scheme"]=="https" for x in r) else 0)
P
)

# negative: no CA env -> client rejects the proxy's cert
n0=$(grep -c '"kind": "flow"' "$OUT/flowsA.jsonl")
env HTTPS_PROXY=http://127.0.0.1:$PA curl -sS -o /dev/null --max-time 15 "$URL" 2>"$OUT/err2"; rc=$?
sleep 1
check "negative: client without CA env fails TLS (curl exit 60)" $([ "$rc" = 60 ] && echo 1 || echo 0)
check "negative: no new decrypted flow recorded for that attempt" $([ "$(grep -c '"kind": "flow"' "$OUT/flowsA.jsonl")" = "$n0" ] && echo 1 || echo 0)

# negative: upstream cert untrusted -> mitmproxy must refuse, not pass through
code=$(env HTTPS_PROXY=http://127.0.0.1:$PA CURL_CA_BUNDLE=$CAA curl -sS -o "$OUT/body2" -w '%{http_code}' --max-time 15 "https://localhost:$BAD/x" 2>/dev/null)
check "negative: untrusted upstream cert is rejected (502, upstream body not delivered)" $([ "$code" = 502 ] && ! grep -q upstream-secret-body "$OUT/body2" && echo 1 || echo 0)

# negative: per-run CA, client trusting A used against proxy B
env HTTPS_PROXY=http://127.0.0.1:$PB CURL_CA_BUNDLE=$CAA curl -sS -o /dev/null --max-time 15 "$URL" 2>/dev/null; rc=$?
check "negative: CA of run A is rejected by run B's proxy (exit 60)" $([ "$rc" = 60 ] && echo 1 || echo 0)
fa=$(openssl x509 -in "$CAA" -noout -fingerprint -sha256); fb=$(openssl x509 -in "$CAB" -noout -fingerprint -sha256)
check "negative: run A and run B CAs have different fingerprints" $([ "$fa" != "$fb" ] && echo 1 || echo 0)
env HTTPS_PROXY=http://127.0.0.1:$PB CURL_CA_BUNDLE=$CAB curl -sS -o /dev/null --max-time 15 "$URL" 2>/dev/null; rc=$?
check "positive: run B's own CA works against run B's proxy" $([ "$rc" = 0 ] && echo 1 || echo 0)

# system trust store untouched
SYS_AFTER=$(sha256sum /etc/ssl/certs/ca-certificates.crt 2>/dev/null | cut -d' ' -f1)
# contains_ca <ca.pem> <bundle>: exit 0 iff the CA's base64 body appears in the bundle (newlines stripped)
contains_ca() { python3 - "$1" "$2" <<'P'
import sys
body = lambda f: "".join(l.strip() for l in open(f) if "-----" not in l)
sys.exit(0 if body(sys.argv[1]) in body(sys.argv[2]) else 1)
P
}
# the detector must be able to say yes: positive control with a bundle that does contain the CA
cat "$CAA" > "$OUT/fake_bundle.pem"
check "control: CA-containment detector finds the CA in a bundle that has it" $(contains_ca "$CAA" "$OUT/fake_bundle.pem" && echo 1 || echo 0)
check "negative: system trust store unchanged and lacks the run CA" \
  $([ -n "$SYS_BEFORE" ] && [ "$SYS_BEFORE" = "$SYS_AFTER" ] && ! contains_ca "$CAA" /etc/ssl/certs/ca-certificates.crt && echo 1 || echo 0)
echo "pass=$pass fail=$fail"; [ $fail = 0 ]
