#!/bin/bash
# Record the demo workload against local servers. usage: demo.sh [OUT_DIR] [extra tracewatch record flags]
# Leaves the run in OUT_DIR/runs/demo (default out/demo).
set -u
HERE=$(cd "$(dirname "$0")/../.." && pwd); OUT=${1:-$HERE/out/demo}; shift || true
TW="$HERE/.venv/bin/tracewatch"; PY="$HERE/.venv/bin/python"
UPPORT=18460; HPORT=18461; WSPORT=18462
rm -rf "$OUT"; mkdir -p "$OUT/up" "$OUT/runs" "$OUT/fakehome/.ssh"; cd "$OUT/up"
openssl req -x509 -newkey rsa:2048 -nodes -keyout upca.key -out upca.pem -days 2 -subj "/CN=tw-upstream-test-ca" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -keyout srv.key -out srv.csr -subj "/CN=localhost" 2>/dev/null
printf 'subjectAltName=DNS:localhost,IP:127.0.0.1\n' > san.ext
openssl x509 -req -in srv.csr -CA upca.pem -CAkey upca.key -CAcreateserial -out srv.pem -days 2 -extfile san.ext 2>/dev/null
echo "DECOY-NOT-A-REAL-KEY" > "$OUT/fakehome/.ssh/id_rsa"
"$PY" "$HERE/tests/fixtures/demo_servers.py" $UPPORT $HPORT srv.pem srv.key & S1=$!
"$PY" "$HERE/tests/integration/ws_server.py" $WSPORT srv.pem srv.key & S2=$!
sleep 1; cd "$HERE"
LANIP=$(hostname -I | awk '{print $1}')
cleanup() { kill $S1 $S2 2>/dev/null; docker ps -aq --filter label=tracewatch.run | xargs -r docker rm -f >/dev/null 2>&1; pkill -9 -f "confdir=$OUT/runs/" 2>/dev/null; rm -rf /tmp/tw_demo; }
trap cleanup EXIT
UPPORT=$UPPORT HPORT=$HPORT WSPORT=$WSPORT LANIP=$LANIP FAKEHOME="$OUT/fakehome" PY="$PY" ROOT="$HERE" \
  "$TW" record --out "$OUT/runs" --name demo --upstream-ca "$OUT/up/upca.pem" "$@" -- "$HERE/tests/fixtures/demo_workload.sh" 2>&1 | tail -4
