#!/bin/bash
# A harmless but busy workload for the report: process chains, temp-dir execution, a decoy credential read,
# cleartext credentials, a connection that bypasses the proxy, a signal death, pipelines, websockets, DNS.
# env: UPPORT HPORT WSPORT LANIP FAKEHOME PY ROOT
set -u
D=/tmp/tw_demo; rm -rf "$D"; mkdir -p "$D"
U="https://localhost:$UPPORT"
echo "[demo] stage 1: fetch and stage a payload"
bash -c '
  cd /tmp/tw_demo
  curl -s -o payload.bin "'"$U"'/download"
  curl -s -o /dev/null -H "Authorization: Bearer DEMObearertoken0123456789" "'"$U"'/api/json"
  cp /bin/true /tmp/tw_demo/updater && /tmp/tw_demo/updater --check
  sha256sum payload.bin | head -c 16 > /dev/null
'
echo "[demo] stage 2: python helper spawning tools"
"$PY" -c "
import subprocess
subprocess.run(['curl','-s','-o','/dev/null','-X','POST','-d','user=demo&password=DEMOformpassword0123456789','$U/submit'])
subprocess.run(['getent','hosts','example.com'], capture_output=True)
subprocess.run(['curl','-s','-o','/dev/null','$U/missing'])
"
echo "[demo] stage 3: credential file access (decoy)"
HOME="$FAKEHOME" cat "$FAKEHOME/.ssh/id_rsa" > /dev/null
echo "[demo] stage 4: cleartext credentials over HTTP"
curl -s -o /dev/null -u demo:DEMObasicpassword0123456789 "http://localhost:$HPORT/basic"
echo "[demo] stage 5: a connection that bypasses the proxy"
NO_PROXY="$LANIP" no_proxy="$LANIP" curl -s -o /dev/null "http://$LANIP:$HPORT/direct"
echo "[demo] stage 6: crashes, failures, pipelines, background jobs"
sh -c 'kill -SEGV $$' 2>/dev/null
/bin/false
sh -c 'exit 3'
ls / | grep etc | wc -l > /dev/null
for i in 1 2 3; do (sleep 0.3; echo bg$i > /dev/null) & done; wait
echo "[demo] stage 7: websockets"
"$PY" "$ROOT/tests/integration/ws_client.py" "$WSPORT" "$D/ws_results.json" > /dev/null 2>&1
curl -s -o /dev/null "$U/slow"
echo "[demo] done"
