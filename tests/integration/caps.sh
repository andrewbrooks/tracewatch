#!/bin/bash
# Size caps through the real recorder, with deliberately tiny limits.
set -u
HERE=$(cd "$(dirname "$0")/../.." && pwd); OUT=$HERE/out/caps; UPPORT=18449
TW="$HERE/.venv/bin/tracewatch"; PY="$HERE/.venv/bin/python"
rm -rf "$OUT"; mkdir -p "$OUT/up" "$OUT/runs"; cd "$OUT/up"
openssl req -x509 -newkey rsa:2048 -nodes -keyout upca.key -out upca.pem -days 2 -subj "/CN=tw-upstream-test-ca" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -keyout srv.key -out srv.csr -subj "/CN=localhost" 2>/dev/null
printf 'subjectAltName=DNS:localhost,IP:127.0.0.1\n' > san.ext
openssl x509 -req -in srv.csr -CA upca.pem -CAkey upca.key -CAcreateserial -out srv.pem -days 2 -extfile san.ext 2>/dev/null
cat > srv.py <<'P'
import http.server, json, ssl, sys
port, crt, key = int(sys.argv[1]), sys.argv[2], sys.argv[3]
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(s):
        n = int(s.headers.get("Content-Length") or 0); s.rfile.read(n)
        out = json.dumps({"note": "VISMARKresp " + "r" * 500}).encode()
        s.send_response(200); s.send_header("Content-Type", "application/json"); s.send_header("Content-Length", str(len(out))); s.end_headers(); s.wfile.write(out)
    def log_message(s, *a): pass
srv = http.server.ThreadingHTTPServer(("127.0.0.1", port), H)
c = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); c.load_cert_chain(crt, key); srv.socket = c.wrap_socket(srv.socket, server_side=True)
srv.serve_forever()
P
python3 srv.py $UPPORT srv.pem srv.key & S1=$!
cat > "$OUT/workload.sh" <<'W'
#!/bin/sh
i=0; ok=0
while [ $i -lt 60 ]; do i=$((i+1))
  code=$(curl -s -o /dev/null -w '%{http_code}' -H 'Content-Type: text/plain' --data-binary "VISMARKreq$i $(printf 'q%.0s' $(seq 1 400))" "https://localhost:$UPPORT/p$i")
  [ "$code" = 200 ] && ok=$((ok+1))
  sleep 0.2   # outlast the caps and several heartbeats: the recorder must keep supervising after a cap
done
echo "$ok" > "$OUT/ok_count"
W
chmod +x "$OUT/workload.sh"; cd "$HERE"
cleanup() { kill $S1 2>/dev/null; docker ps -aq --filter label=tracewatch.run | xargs -r docker rm -f >/dev/null 2>&1; pkill -9 -f "confdir=$OUT/runs/" 2>/dev/null; }
trap cleanup EXIT
UPPORT=$UPPORT OUT=$OUT "$TW" record --out "$OUT/runs" --name caps --upstream-ca "$OUT/up/upca.pem" \
  --max-flows-mb 0.0625 --soft-flows-mb 0.015625 --max-tracee-mb 0.04 -- "$OUT/workload.sh" 2>&1 | tail -6
"$PY" tests/integration/caps_check.py "$OUT/runs/caps" "$OUT/ok_count"
