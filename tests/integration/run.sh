#!/bin/bash
# Integration/fault tests for the real recorder (needs Docker + Tracee image; ~1 min per scenario).
# usage: tests/integration/run.sh [scenario ...]
# Scenarios: control kill_tracee kill_mitm kill_root sigterm kill_supervisor
set -u
HERE=$(cd "$(dirname "$0")/../.." && pwd); OUT=$HERE/out/it; UPPORT=18446
TW="$HERE/.venv/bin/tracewatch"; PY="$HERE/.venv/bin/python"
SCN=("$@"); [ ${#SCN[@]} = 0 ] && SCN=(control kill_tracee kill_mitm kill_root sigterm kill_supervisor recorder_death_continue component_stop component_stop_stubborn)
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
python3 srv.py $UPPORT srv.pem srv.key & S1=$!
cat > "$OUT/workload.sh" <<'W'
#!/bin/sh
LOG=$1; URL=$2; N=$3; i=0
while [ $i -lt $N ]; do i=$((i+1)); code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "$URL/req$i"); echo "$i rc=$? code=$code" >> "$LOG"; sleep 0.5; done
W
cat > "$OUT/stubborn.sh" <<'W'
#!/bin/sh
trap '' TERM
LOG=$1; URL=$2; N=$3; i=0
while [ $i -lt 40 ]; do i=$((i+1)); code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "$URL/req$i"); echo "$i rc=$? code=$code" >> "$LOG"; sleep 0.5; done
W
cd "$HERE"
cleanup() { kill $S1 2>/dev/null; docker ps -aq --filter label=tracewatch.run | xargs -r docker rm -f >/dev/null 2>&1; pkill -9 -f "confdir=$OUT/runs/" 2>/dev/null; }
trap cleanup EXIT
leaks_now() {
  local n=$1 out=""
  c=$(docker ps -aq --filter label=tracewatch.run=$n | wc -l); [ "$c" != 0 ] && out+="containers=$c "
  p=$(pgrep -f "confdir=$OUT/runs/$n/ca" | wc -l); [ "$p" != 0 ] && out+="proxy_procs=$p "
  k=$(pgrep -f "tracewatch.run=$n" | wc -l); [ "$k" != 0 ] && out+="collector_procs=$k "
  rp=$("$PY" -c "import json;print(json.load(open('$OUT/runs/$n/manifest.json')).get('root_pid',0))" 2>/dev/null)
  [ -n "$rp" ] && [ "$rp" != 0 ] && [ -d "/proc/$rp" ] && out+="target_alive=1 "
  echo "${out:-clean}"
}
fails=0
for s in "${SCN[@]}"; do
  case $s in control) port=18101;; kill_tracee) port=18102;; kill_mitm) port=18103;; kill_root) port=18104;; sigterm) port=18105;; kill_supervisor) port=18106;; recorder_death_continue) port=18107;; component_stop) port=18108;; component_stop_stubborn) port=18109;; esac
  RUN=$OUT/runs/$s; echo "=== $s"
  FLAGS=""; WL="$OUT/workload.sh"
  case $s in
    recorder_death_continue) FLAGS="--on-recorder-death continue";;
    component_stop) FLAGS="--on-component-loss stop";;
    component_stop_stubborn) FLAGS="--on-component-loss stop --kill-grace-s 3"; WL="$OUT/stubborn.sh";;
  esac
  "$TW" record --out "$OUT/runs" --name $s --port $port --upstream-ca "$OUT/up/upca.pem" --quiet $FLAGS -- \
    sh "$WL" "$RUN/workload.log" "https://localhost:$UPPORT" 24 >"$OUT/runs/$s.out" 2>&1 &
  SUP=$!
  if [ $s != control ]; then
    for i in $(seq 240); do [ -f "$RUN/workload.log" ] && [ "$(wc -l < "$RUN/workload.log")" -ge 6 ] && break; kill -0 $SUP 2>/dev/null || break; sleep 0.5; done
    case $s in
      kill_tracee) docker kill tw-$s >/dev/null;;
      kill_mitm) pkill -9 -f "listen-port $port";;
      kill_root) kill -9 "$("$PY" -c "import json;print(json.load(open('$RUN/manifest.json'))['root_pid'])")";;
      sigterm) kill -TERM $SUP;;
      kill_supervisor|recorder_death_continue) echo "at_kill=$(wc -l < "$RUN/workload.log")" > "$OUT/runs/$s.atkill"; kill -9 $SUP;;
      component_stop|component_stop_stubborn) pkill -9 -f "listen-port $port"; date +%s > "$OUT/runs/$s.faultat";;
    esac
  fi
  if [ $s = recorder_death_continue ]; then   # recorder is dead; sweep NOW while the target still runs
    sleep 1; "$TW" sweep --out "$OUT/runs" > "$OUT/runs/$s.sweep" 2>&1
    sleep 14   # let the (now unrecorded, proxy-less) target finish by itself
  fi
  for i in $(seq 240); do kill -0 $SUP 2>/dev/null || break; sleep 0.5; done
  kill -0 $SUP 2>/dev/null && { echo "recorder still running after timeout"; kill -9 $SUP; }
  if [ $s = kill_supervisor ]; then
    sleep 2; before=$(leaks_now $s)
    "$TW" record --out "$OUT/runs" --name sweeper --quiet -- true >/dev/null 2>&1   # its startup sweep must clean up
    sleep 8
    echo "before=$before" > "$OUT/runs/$s.leaks"; echo "after=$(leaks_now $s)" >> "$OUT/runs/$s.leaks"
  else
    echo "after=$(leaks_now $s)" > "$OUT/runs/$s.leaks"
  fi
  "$PY" tests/integration/check.py $s "$RUN" $port "$OUT/runs/$s.leaks" || fails=$((fails+1))
done
echo "scenarios failed: $fails"; [ $fails = 0 ]
