#!/bin/bash
# Phase 0 spike 4+5: durability and lifecycle. Runs the prototype recorder against a finite proxied
# workload and injects faults; checks what survives on disk and that every loss is recorded.
# Scenarios: control | kill_tracee | kill_mitm | kill_root | sigterm | kill_supervisor
# usage: p0_4_durability.sh [scenario ...]   (default: all)
set -u
HERE=$(cd "$(dirname "$0")/.." && pwd); OUT=$HERE/out/p0_4; UPPORT=18446
SCN=("$@"); [ ${#SCN[@]} = 0 ] && SCN=(control kill_tracee kill_mitm kill_root sigterm kill_supervisor)
mkdir -p "$OUT/up" "$OUT/runs"
cd "$OUT/up"
if [ ! -s srv.pem ]; then
openssl req -x509 -newkey rsa:2048 -nodes -keyout upca.key -out upca.pem -days 2 -subj "/CN=tw-upstream-test-ca" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -keyout srv.key -out srv.csr -subj "/CN=localhost" 2>/dev/null
printf 'subjectAltName=DNS:localhost,IP:127.0.0.1\n' > san.ext
openssl x509 -req -in srv.csr -CA upca.pem -CAkey upca.key -CAcreateserial -out srv.pem -days 2 -extfile san.ext 2>/dev/null
fi
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
python3 srv.py $UPPORT srv.pem srv.key & S1=$!
cat > "$OUT/workload.sh" <<'W'
#!/bin/sh
LOG=$1; URL=$2; N=$3; i=0
while [ $i -lt $N ]; do i=$((i+1)); code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "$URL/req$i"); echo "$i rc=$? code=$code" >> "$LOG"; sleep 0.5; done
W
cd "$HERE"
cleanup() { kill $S1 2>/dev/null; docker ps -aq --filter label=tracewatch.run | xargs -r docker rm -f >/dev/null 2>&1; pkill -9 -f "confdir=$OUT/runs/" 2>/dev/null; }
trap cleanup EXIT
leaks_now() { # echo "clean" or a description
  local n=$1 port=$2 out=""
  c=$(docker ps -aq --filter label=tracewatch.run=$n | wc -l); [ "$c" != 0 ] && out+="containers=$c "
  p=$(pgrep -f "confdir=$OUT/runs/$n/ca" | wc -l); [ "$p" != 0 ] && out+="proxy_procs=$p "
  k=$(pgrep -f "docker logs -f tw-$n" | wc -l); [ "$k" != 0 ] && out+="collector_procs=$k "
  echo "${out:-clean}"
}
fails=0
for s in "${SCN[@]}"; do
  case $s in control) port=18101;; kill_tracee) port=18102;; kill_mitm) port=18103;; kill_root) port=18104;; sigterm) port=18105;; kill_supervisor) port=18106;; esac
  RUN=$OUT/runs/$s; rm -rf "$RUN" "$OUT/runs/$s.sup.out" "$OUT/runs/$s.leaks"; docker rm -f tw-$s >/dev/null 2>&1
  echo "=== $s"
  python3 spikes/p0_4_supervisor.py run --run-dir "$RUN" --port $port --upstream-ca "$OUT/up/upca.pem" -- \
    sh "$OUT/workload.sh" "$RUN/workload.log" "https://localhost:$UPPORT" 24 >"$OUT/runs/$s.sup.out" 2>&1 &
  SUP=$!
  if [ $s != control ]; then   # wait for 6 completed requests, then inject
    for i in $(seq 240); do [ -f "$RUN/workload.log" ] && [ "$(wc -l < "$RUN/workload.log")" -ge 6 ] && break; kill -0 $SUP 2>/dev/null || break; sleep 0.5; done
    case $s in
      kill_tracee) docker kill tw-$s >/dev/null;;
      kill_mitm) pkill -9 -f "listen-port $port";;
      kill_root) kill -9 "$(python3 -c "import json;print(json.load(open('$RUN/manifest.json'))['root_pid'])")";;
      sigterm) kill -TERM $SUP;;
      kill_supervisor) kill -9 $SUP;;
    esac
  fi
  for i in $(seq 240); do kill -0 $SUP 2>/dev/null || break; sleep 0.5; done
  kill -0 $SUP 2>/dev/null && { echo "supervisor still running after timeout"; kill -9 $SUP; }
  if [ $s = kill_supervisor ]; then
    sleep 2; before=$(leaks_now $s $port)
    python3 spikes/p0_4_supervisor.py sweep --runs-root "$OUT/runs"; sleep 8   # let the workload finish on its own
    echo "before=$before" > "$OUT/runs/$s.leaks"; echo "after=$(leaks_now $s $port)" >> "$OUT/runs/$s.leaks"
  else
    echo "after=$(leaks_now $s $port)" > "$OUT/runs/$s.leaks"
  fi
  python3 spikes/p0_4_check.py $s "$RUN" $port "$OUT/runs/$s.leaks" || fails=$((fails+1))
done
echo "scenarios failed: $fails"; [ $fails = 0 ]
