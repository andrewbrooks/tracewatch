#!/bin/bash
# One TCP connection held by several processes, through the real recorder. usage: shared_socket.sh [record flags...]
set -u
HERE=$(cd "$(dirname "$0")/../.." && pwd); OUT=$HERE/out/shared_socket; PORT=18470
TW="$HERE/.venv/bin/tracewatch"; PY="$HERE/.venv/bin/python"
rm -rf "$OUT"; mkdir -p "$OUT/runs"
cat > "$OUT/server.py" <<'P'
import http.server, sys
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        b = b'{"ok":true}'
        self.send_response(200); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def log_message(self, *a): pass
http.server.ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
P
"$PY" "$OUT/server.py" $PORT & S1=$!
sleep 1; cd "$HERE"
cleanup() { kill $S1 2>/dev/null; docker ps -aq --filter label=tracewatch.run | xargs -r docker rm -f >/dev/null 2>&1; pkill -9 -f "confdir=$OUT/runs/" 2>/dev/null; }
trap cleanup EXIT
"$TW" record --out "$OUT/runs" --name shared "$@" -- "$PY" tests/integration/shared_client.py $PORT "$OUT/results.json" 2>&1 | tail -3
"$PY" tests/integration/shared_check.py "$OUT/runs/shared" "$OUT/results.json"
