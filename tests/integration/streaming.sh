#!/bin/bash
# Streaming / large-body behavior through the real recorder.
set -u
HERE=$(cd "$(dirname "$0")/../.." && pwd); OUT=$HERE/out/streaming; UPPORT=18448
TW="$HERE/.venv/bin/tracewatch"; PY="$HERE/.venv/bin/python"
rm -rf "$OUT"; mkdir -p "$OUT/up" "$OUT/runs"; cd "$OUT/up"
openssl req -x509 -newkey rsa:2048 -nodes -keyout upca.key -out upca.pem -days 2 -subj "/CN=tw-upstream-test-ca" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -keyout srv.key -out srv.csr -subj "/CN=localhost" 2>/dev/null
printf 'subjectAltName=DNS:localhost,IP:127.0.0.1\n' > san.ext
openssl x509 -req -in srv.csr -CA upca.pem -CAkey upca.key -CAcreateserial -out srv.pem -days 2 -extfile san.ext 2>/dev/null
cat > srv.py <<'P'
import gzip, hashlib, http.server, json, ssl, sys, time
port, crt, key = int(sys.argv[1]), sys.argv[2], sys.argv[3]
BIG = (b"abcdefghij" * 400000)[: 3 * 1024 * 1024]
class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def chunk(s, b): s.wfile.write(b"%x\r\n" % len(b) + b + b"\r\n"); s.wfile.flush()
    def do_GET(s):
        if s.path == "/sse":
            s.send_response(200); s.send_header("Content-Type", "text/event-stream"); s.send_header("Transfer-Encoding", "chunked"); s.end_headers()
            for i in range(6):
                s.chunk(('data: {"n":%d,"note":"VISMARKsse","access_token":"CANARYssetoken0123456789"}\n\n' % i).encode()); time.sleep(0.5)
            s.wfile.write(b"0\r\n\r\n"); s.wfile.flush()
        elif s.path == "/big":
            s.send_response(200); s.send_header("Content-Type", "text/plain"); s.send_header("Content-Length", str(len(BIG)))
            s.send_header("X-Sha256", hashlib.sha256(BIG).hexdigest()); s.end_headers(); s.wfile.write(BIG)
        elif s.path == "/gz":
            b = gzip.compress(b"VISMARKgzip hello compressed world password=CANARYgzpw0123456789")
            s.send_response(200); s.send_header("Content-Type", "text/plain"); s.send_header("Content-Encoding", "gzip"); s.send_header("Content-Length", str(len(b))); s.end_headers(); s.wfile.write(b)
        elif s.path == "/nd":
            s.send_response(200); s.send_header("Content-Type", "application/x-ndjson"); s.send_header("Transfer-Encoding", "chunked"); s.end_headers()
            for i in range(4):
                s.chunk(('{"k":%d,"mark":"VISMARKnd","password":"CANARYndpw0123456789"}\n' % i).encode()); time.sleep(0.3)
            s.wfile.write(b"0\r\n\r\n"); s.wfile.flush()
        else:
            s.send_response(404); s.send_header("Content-Length", "0"); s.end_headers()
    def do_POST(s):
        n = int(s.headers.get("Content-Length") or 0); body = s.rfile.read(n); out = json.dumps({"sha256": hashlib.sha256(body).hexdigest(), "len": len(body)}).encode()
        s.send_response(200); s.send_header("Content-Type", "application/json"); s.send_header("Content-Length", str(len(out))); s.end_headers(); s.wfile.write(out)
    def log_message(s, *a): pass
srv = http.server.ThreadingHTTPServer(("127.0.0.1", port), H)
c = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); c.load_cert_chain(crt, key); srv.socket = c.wrap_socket(srv.socket, server_side=True)
srv.serve_forever()
P
python3 srv.py $UPPORT srv.pem srv.key & S1=$!
cd "$HERE"
cleanup() { kill $S1 2>/dev/null; docker ps -aq --filter label=tracewatch.run | xargs -r docker rm -f >/dev/null 2>&1; pkill -9 -f "confdir=$OUT/runs/" 2>/dev/null; }
trap cleanup EXIT
"$TW" record --out "$OUT/runs" --name streaming --upstream-ca "$OUT/up/upca.pem" -- "$PY" tests/integration/streaming_client.py $UPPORT "$OUT/results.json" 2>&1 | tail -3
"$PY" tests/integration/streaming_check.py "$OUT/runs/streaming" "$OUT/results.json"
