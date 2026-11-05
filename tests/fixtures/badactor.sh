#!/bin/bash
# Record the simulated intruder session (badactor_workload.sh) and check which rules fired.
# usage: badactor.sh [OUT_DIR]          Leaves the run in OUT_DIR/runs/badactor (default out/simulation).
set -u
HERE=$(cd "$(dirname "$0")/../.." && pwd); OUT=${1:-$HERE/out/simulation}
TW="$HERE/.venv/bin/tracewatch"; PY="$HERE/.venv/bin/python"
HPORT=18481; LPORT=18482; STAGE=/dev/shm/tw_sim_stage
rm -rf "$OUT"; mkdir -p "$OUT/runs" "$OUT/fakehome/.ssh" "$OUT/fakehome/.aws"
printf -- '-----BEGIN OPENSSH PRIVATE KEY-----\nDECOY-NOT-A-REAL-KEY-DECOY-NOT-A-REAL-KEY\n-----END OPENSSH PRIVATE KEY-----\n' > "$OUT/fakehome/.ssh/id_rsa"
printf '[default]\naws_access_key_id = DECOYDECOYDECOYDECOY\naws_secret_access_key = decoydecoydecoydecoydecoydecoydecoydecoy\n' > "$OUT/fakehome/.aws/credentials"
cat > "$OUT/server.py" <<'P'
import http.server, sys
class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def _send(self, body):
        b = body.encode()
        self.send_response(200); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def do_GET(self):
        self._send('echo "[sim] installer ran"\n' if self.path.startswith(("/install", "/payload")) else "ok\n")
    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length") or 0)); self._send("ok\n")
    def log_message(self, *a): pass
http.server.ThreadingHTTPServer(("0.0.0.0", int(sys.argv[1])), H).serve_forever()
P
"$PY" "$OUT/server.py" $HPORT & S1=$!
# the "attacker's listener": accepts ONE connection and sends two harmless commands to whatever shell connects
( printf 'echo simulated-attacker-session\nexit\n' | nc -l 127.0.0.1 $LPORT >/dev/null 2>&1 ) & S2=$!
sleep 1
LANIP=$(hostname -I | awk '{print $1}')
cleanup() { kill $S1 $S2 2>/dev/null; rm -rf "$STAGE"; docker ps -aq --filter label=tracewatch.run | xargs -r docker rm -f >/dev/null 2>&1; pkill -9 -f "confdir=$OUT/runs/" 2>/dev/null; }
trap cleanup EXIT
HPORT=$HPORT LPORT=$LPORT FAKEHOME="$OUT/fakehome" LANIP=$LANIP STAGE=$STAGE \
  "$TW" record --out "$OUT/runs" --name badactor -- bash "$HERE/tests/fixtures/badactor_workload.sh" 2>&1 | tail -4
"$PY" - "$OUT/runs/badactor" <<'P'
import sys
from pathlib import Path
from tracewatch.model import build
m = build(Path(sys.argv[1]))
from collections import Counter
c = Counter((f["rule"], f["severity"]) for f in m["findings"])
for (rule, sev), n in sorted(c.items(), key=lambda kv: (["high", "medium", "low", "info"].index(kv[0][1]), kv[0][0])):
    print(f"  {sev:7} {rule:26} x{n}")
print("verdict:", m["integrity"]["verdict"], "| processes:", m["stats"]["processes"], "| findings:", len(m["findings"]))
fired = {f["rule"] for f in m["findings"]}
want = {"reverse-shell-shape", "encoded-payload", "masquerade", "pipe-to-shell", "scanner-or-tunnel-tool", "privilege-change",
        "drop-and-execute", "credential-file-access", "cleartext-credentials", "unproxied-connection"}
bad = 0
for r in sorted(want - fired):
    print("FAIL expected rule did not fire:", r); bad += 1
run = Path(sys.argv[1])
for name in ("flows.jsonl", "tracee.jsonl"):
    if "DECOY-NOT-A-REAL-KEY" in (run / name).read_text():
        print("FAIL decoy key material leaked into", name); bad += 1
print("PASS all expected rules fired and no decoy key material was recorded" if not bad else f"{bad} problem(s)")
sys.exit(1 if bad else 0)
P
