#!/bin/bash
# HTTP keep-alive, HTTP/2 (sequential and multiplexed), compressed bodies, certificate pinning, and a client that
# ignores the proxy - through the real recorder. usage: protocols.sh [record flags...]
set -u
HERE=$(cd "$(dirname "$0")/../.." && pwd); OUT=$HERE/out/protocols; UPPORT=18472
TW="$HERE/.venv/bin/tracewatch"; PY="$HERE/.venv/bin/python"
rm -rf "$OUT"; mkdir -p "$OUT/up" "$OUT/runs"; cd "$OUT/up"
openssl req -x509 -newkey rsa:2048 -nodes -keyout upca.key -out upca.pem -days 2 -subj "/CN=tw-upstream-test-ca" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -keyout srv.key -out srv.csr -subj "/CN=localhost" 2>/dev/null
LANIP=$(hostname -I | awk '{print $1}')
printf 'subjectAltName=DNS:localhost,IP:127.0.0.1,IP:%s\n' "$LANIP" > san.ext
openssl x509 -req -in srv.csr -CA upca.pem -CAkey upca.key -CAcreateserial -out srv.pem -days 2 -extfile san.ext 2>/dev/null
"$PY" "$HERE/tests/integration/protocols_server.py" $UPPORT srv.pem srv.key & S1=$!
sleep 1; cd "$HERE"
cleanup() { kill $S1 2>/dev/null; docker ps -aq --filter label=tracewatch.run | xargs -r docker rm -f >/dev/null 2>&1; pkill -9 -f "confdir=$OUT/runs/" 2>/dev/null; }
trap cleanup EXIT
cat > "$OUT/workload.sh" <<'W'
#!/bin/sh
B=https://localhost:$UPPORT; B2=https://localhost:$((UPPORT+1))
rc() { echo "$1 $2" >> "$OUT/rc"; }
curl -s --http1.1 -o /dev/null -o /dev/null -o /dev/null $B/k1 $B/k2 $B/k3; rc keepalive $?
curl -s --http2 -o /dev/null -o /dev/null -o /dev/null $B2/h2a $B2/h2b $B2/h2c; rc h2seq $?
cfg=$OUT/par.cfg; : > $cfg; for i in 1 2 3 4 5 6; do printf 'url = "%s/m%s"\noutput = "/dev/null"\n' $B2 $i >> $cfg; done
curl -s --http2 --parallel --parallel-max 6 -K $cfg; rc h2par $?
for p in gz deflate br zst; do curl -s --compressed -o /dev/null $B/$p; rc $p $?; done
curl -s -o /dev/null --pinnedpubkey 'sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=' $B/pin; rc pin $?
curl -s -o /dev/null --cacert "$OUT/up/upca.pem" $B/untrusted; rc untrusted $?
curl -s -o /dev/null -k --noproxy '*' https://$LANIP:$UPPORT/direct; rc direct $?
W
chmod +x "$OUT/workload.sh"
UPPORT=$UPPORT OUT=$OUT LANIP=$LANIP "$TW" record --out "$OUT/runs" --name p --upstream-ca "$OUT/up/upca.pem" "$@" -- "$OUT/workload.sh" 2>&1 | tail -3
"$PY" tests/integration/protocols_check.py "$OUT/runs/p" "$OUT/rc" $UPPORT "$LANIP"
