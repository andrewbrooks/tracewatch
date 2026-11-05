#!/bin/bash
# A recording well past a minute (~100 s): steady traffic, a 30 s idle gap, then a burst. usage: long_run.sh [flags...]
set -u
HERE=$(cd "$(dirname "$0")/../.." && pwd); OUT=$HERE/out/long; UPPORT=18471
TW="$HERE/.venv/bin/tracewatch"; PY="$HERE/.venv/bin/python"
rm -rf "$OUT"; mkdir -p "$OUT/up" "$OUT/runs"; cd "$OUT/up"
openssl req -x509 -newkey rsa:2048 -nodes -keyout upca.key -out upca.pem -days 2 -subj "/CN=tw-upstream-test-ca" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -keyout srv.key -out srv.csr -subj "/CN=localhost" 2>/dev/null
printf 'subjectAltName=DNS:localhost,IP:127.0.0.1\n' > san.ext
openssl x509 -req -in srv.csr -CA upca.pem -CAkey upca.key -CAcreateserial -out srv.pem -days 2 -extfile san.ext 2>/dev/null
cat > srv.py <<'P'
import http.server, ssl, sys
port, crt, key = int(sys.argv[1]), sys.argv[2], sys.argv[3]
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(s):
        s.send_response(200); s.send_header("Content-Length", "2"); s.end_headers(); s.wfile.write(b"ok")
    def log_message(s, *a): pass
srv = http.server.ThreadingHTTPServer(("127.0.0.1", port), H)
c = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); c.load_cert_chain(crt, key); srv.socket = c.wrap_socket(srv.socket, server_side=True)
srv.serve_forever()
P
"$PY" srv.py $UPPORT srv.pem srv.key & S1=$!
cat > "$OUT/workload.sh" <<'W'
#!/bin/sh
# phase 1 (0-30 s): one request a second. phase 2 (30-60 s): idle. phase 3 (60-100 s): 4 requests a second
ok=0; sent=0; t0=$(date +%s)
req() { sent=$((sent+1)); code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "https://localhost:$UPPORT/$1"); [ "$code" = 200 ] && ok=$((ok+1)); }
while [ $(( $(date +%s) - t0 )) -lt 30 ]; do req "a$sent"; sleep 1; done
sleep 30
while [ $(( $(date +%s) - t0 )) -lt 100 ]; do req "c$sent"; sleep 0.25; done
echo "$ok $sent $(( $(date +%s) - t0 ))" > "$OUT/result"
W
chmod +x "$OUT/workload.sh"; cd "$HERE"
cleanup() { kill $S1 2>/dev/null; docker ps -aq --filter label=tracewatch.run | xargs -r docker rm -f >/dev/null 2>&1; pkill -9 -f "confdir=$OUT/runs/" 2>/dev/null; }
trap cleanup EXIT
UPPORT=$UPPORT OUT=$OUT "$TW" record --out "$OUT/runs" --name long --upstream-ca "$OUT/up/upca.pem" "$@" -- "$OUT/workload.sh" 2>&1 | tail -3
"$PY" tests/integration/long_check.py "$OUT/runs/long" "$OUT/result"
