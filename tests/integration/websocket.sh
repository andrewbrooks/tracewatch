#!/bin/bash
# Websockets through the real recorder. usage: websocket.sh [extra tracewatch record flags...]
set -u
HERE=$(cd "$(dirname "$0")/../.." && pwd); OUT=$HERE/out/websocket; UPPORT=18450
TW="$HERE/.venv/bin/tracewatch"; PY="$HERE/.venv/bin/python"
rm -rf "$OUT"; mkdir -p "$OUT/up" "$OUT/runs"; cd "$OUT/up"
openssl req -x509 -newkey rsa:2048 -nodes -keyout upca.key -out upca.pem -days 2 -subj "/CN=tw-upstream-test-ca" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -keyout srv.key -out srv.csr -subj "/CN=localhost" 2>/dev/null
printf 'subjectAltName=DNS:localhost,IP:127.0.0.1\n' > san.ext
openssl x509 -req -in srv.csr -CA upca.pem -CAkey upca.key -CAcreateserial -out srv.pem -days 2 -extfile san.ext 2>/dev/null
"$PY" "$HERE/tests/integration/ws_server.py" $UPPORT srv.pem srv.key & S1=$!
sleep 1; cd "$HERE"
cleanup() { kill $S1 2>/dev/null; docker ps -aq --filter label=tracewatch.run | xargs -r docker rm -f >/dev/null 2>&1; pkill -9 -f "confdir=$OUT/runs/" 2>/dev/null; }
trap cleanup EXIT
"$TW" record --out "$OUT/runs" --name ws --upstream-ca "$OUT/up/upca.pem" "$@" -- \
  "$PY" tests/integration/ws_client.py $UPPORT "$OUT/results.json" 2>&1 | tail -3
"$PY" tests/integration/ws_check.py "$OUT/runs/ws" "$OUT/results.json" "$*"
