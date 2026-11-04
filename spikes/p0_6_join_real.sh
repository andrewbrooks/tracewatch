#!/bin/bash
# Phase 0 spike 6: join hardening against a real traced run (uses the p0_4 prototype recorder).
set -u
HERE=$(cd "$(dirname "$0")/.." && pwd); OUT=$HERE/out/p0_6; PP=18107; UPPORT=18447; HP=18083
rm -rf "$OUT"; mkdir -p "$OUT/up"; cd "$OUT/up"
openssl req -x509 -newkey rsa:2048 -nodes -keyout upca.key -out upca.pem -days 2 -subj "/CN=tw-upstream-test-ca" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -keyout srv.key -out srv.csr -subj "/CN=localhost" 2>/dev/null
printf 'subjectAltName=DNS:localhost,IP:127.0.0.1\n' > san.ext
openssl x509 -req -in srv.csr -CA upca.pem -CAkey upca.key -CAcreateserial -out srv.pem -days 2 -extfile san.ext 2>/dev/null
cat > srv.py <<'P'
import http.server, ssl, sys, time
port, crt, key = int(sys.argv[1]), sys.argv[2], sys.argv[3]
class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def do_GET(s):
        if s.path.startswith("/slow"): time.sleep(1.5)
        s.send_response(200); s.send_header("Content-Length", "2"); s.end_headers(); s.wfile.write(b"ok")
    def log_message(s, *a): pass
srv = http.server.ThreadingHTTPServer(("127.0.0.1", port), H)
if len(sys.argv) > 2:
    c = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); c.load_cert_chain(crt, key); srv.socket = c.wrap_socket(srv.socket, server_side=True)
srv.serve_forever()
P
python3 srv.py $UPPORT srv.pem srv.key & S1=$!
python3 - $HP <<'P' & S2=$!
import http.server, sys
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(s): s.send_response(200); s.send_header("Content-Length", "2"); s.end_headers(); s.wfile.write(b"ok")
    def log_message(s, *a): pass
http.server.ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
P
cd "$HERE"
cleanup() { kill $S1 $S2 2>/dev/null; docker ps -aq --filter label=tracewatch.run | xargs -r docker rm -f >/dev/null 2>&1; pkill -9 -f "confdir=$OUT/run/" 2>/dev/null; }
trap cleanup EXIT
python3 spikes/p0_6_join_test.py || { echo "synthetic tests failed"; exit 1; }
echo "=== real run"
RUN=$OUT/run
python3 spikes/p0_4_supervisor.py run --run-dir "$RUN" --port $PP --upstream-ca "$OUT/up/upca.pem" --addon "$HERE/spikes/p0_6_addon.py" -- \
  python3 "$HERE/spikes/p0_6_workload.py" "$RUN" $PP $UPPORT $HP >"$OUT/sup.out" 2>&1 &
SUP=$!
for i in $(seq 240); do [ -f "$RUN/truth.json" ] && break; kill -0 $SUP 2>/dev/null || break; sleep 0.5; done
CA=$RUN/ca/mitmproxy-ca-cert.pem
sh -c 'echo $$ > "'"$OUT"'/ctrl_pid"; exec env HTTPS_PROXY=http://127.0.0.1:'$PP' CURL_CA_BUNDLE='"$CA"' curl -s -o /dev/null --max-time 20 "https://localhost:'$UPPORT'/slowctrl"' &
wait $SUP; echo "supervisor exit=$? manifest=$(python3 -c "import json;m=json.load(open('$RUN/manifest.json'));print(m['status'],m['degraded'])")"
python3 spikes/p0_6_check.py "$RUN" $PP "$(cat "$OUT/ctrl_pid")"
