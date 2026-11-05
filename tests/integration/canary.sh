#!/bin/bash
# Redaction canary: plant secrets everywhere through a real recorded run, then scan the whole run dir.
set -u
HERE=$(cd "$(dirname "$0")/../.." && pwd); OUT=$HERE/out/canary; UPPORT=18447
TW="$HERE/.venv/bin/tracewatch"; PY="$HERE/.venv/bin/python"
rm -rf "$OUT"; mkdir -p "$OUT/up" "$OUT/runs"
cat > "$OUT/canaries.env" <<'C'
C_BEARER=CANARYbearer0123456789abcdef
C_COOKIE=CANARYcookie0123456789
C_XAPIKEY=CANARYxapikey0123456789
C_QUERY=CANARYquery0123456789
C_BASIC_PW=CANARYbasicpw0123456789
C_URLPW=CANARYurlpw0123456789
C_JSON_PW=CANARYjsonpw0123456789
C_FORM_PW=CANARYformpw0123456789
C_SK=sk-ant-CANARYshape0123456789abcdef
C_AWS=AKIACANARYKEY0123456
C_JWT=eyJhbGciOiJIUzI1NiJ9.eyJjYW5hcnkiOiJDQU5BUllKV1QifQ.CANARYsig0123456789abc
C_ERRQ=CANARYerrq0123456789
C_ARGV=CANARYargv0123456789
C_ENVASSIGN=CANARYenvassign0123456789
C_RESPTOKEN=CANARYresptoken0123456789
C_SETCOOKIE=CANARYsetcookie0123456789
VIS_QUERY=VISMARKquery
VIS_HDR=VISMARKhdr
VIS_BODY=VISMARKbody
VIS_FORM=VISMARKform
VIS_TEXT=VISMARKtext
VIS_RESP=VISMARKresp
C
set -a; . "$OUT/canaries.env"; set +a
cd "$OUT/up"
openssl req -x509 -newkey rsa:2048 -nodes -keyout upca.key -out upca.pem -days 2 -subj "/CN=tw-upstream-test-ca" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -keyout srv.key -out srv.csr -subj "/CN=localhost" 2>/dev/null
printf 'subjectAltName=DNS:localhost,IP:127.0.0.1\n' > san.ext
openssl x509 -req -in srv.csr -CA upca.pem -CAkey upca.key -CAcreateserial -out srv.pem -days 2 -extfile san.ext 2>/dev/null
cat > srv.py <<'P'
import http.server, json, os, ssl, sys
port, crt, key, seen = int(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4]
class H(http.server.BaseHTTPRequestHandler):
    def _do(s):
        n = int(s.headers.get("Content-Length") or 0); body = s.rfile.read(n).decode("utf-8", "replace") if n else ""
        with open(seen, "a") as f: f.write(json.dumps({"path": s.path, "headers": dict(s.headers), "body": body}) + "\n")
        out = json.dumps({"access_token": os.environ["C_RESPTOKEN"], "note": os.environ["VIS_RESP"], "usage": {"input_tokens": 7}}).encode()
        s.send_response(200); s.send_header("Content-Type", "application/json"); s.send_header("Content-Length", str(len(out)))
        s.send_header("Set-Cookie", "sess=%s; Path=/; HttpOnly" % os.environ["C_SETCOOKIE"]); s.end_headers(); s.wfile.write(out)
    do_GET = do_POST = _do
    def log_message(s, *a): pass
srv = http.server.ThreadingHTTPServer(("127.0.0.1", port), H)
c = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); c.load_cert_chain(crt, key); srv.socket = c.wrap_socket(srv.socket, server_side=True)
srv.serve_forever()
P
python3 srv.py $UPPORT srv.pem srv.key "$OUT/server_seen.log" & S1=$!
cat > "$OUT/canary_workload.sh" <<'W'
#!/bin/sh
U="https://localhost:$UPPORT"
curl -s -o /dev/null "$U/a?api_key=$C_QUERY&q=$VIS_QUERY" -H "Authorization: Bearer $C_BEARER" -H "Cookie: sid=$C_COOKIE; theme=dark" -H "X-Api-Key: $C_XAPIKEY" -H "X-Visible: $VIS_HDR"
curl -s -o /dev/null "$U/b" -H 'Content-Type: application/json' -d "{\"user\":\"bob\",\"password\":\"$C_JSON_PW\",\"note\":\"$VIS_BODY\",\"max_tokens\":5}"
curl -s -o /dev/null "$U/c" -d "user=bob&password=$C_FORM_PW&q=$VIS_FORM"
curl -s -o /dev/null "$U/d" -H 'Content-Type: text/plain' --data-binary "here is $C_SK and $C_AWS and $C_JWT and $VIS_TEXT"
curl -s -o /dev/null -u "bob:$C_BASIC_PW" "$U/e"
curl -s -o /dev/null "https://alice:$C_URLPW@localhost:$UPPORT/f"
curl -s -o /dev/null --max-time 5 "https://localhost:1/zz?api_key=$C_ERRQ"
env FOO_API_KEY="$C_ENVASSIGN" true --token "$C_ARGV"
W
chmod +x "$OUT/canary_workload.sh"; cd "$HERE"
cleanup() { kill $S1 2>/dev/null; docker ps -aq --filter label=tracewatch.run | xargs -r docker rm -f >/dev/null 2>&1; pkill -9 -f "confdir=$OUT/runs/" 2>/dev/null; }
trap cleanup EXIT
# while the run is live: does Docker keep a (raw, unredacted) copy of the Tracee output?
( for i in $(seq 400); do
    t=$(docker inspect -f '{{.HostConfig.LogConfig.Type}}' tw-canary 2>/dev/null)
    if [ -n "$t" ] && [ "$t" != "<no value>" ]; then
      echo "$t" > "$OUT/logdriver.txt"; docker logs tw-canary > "$OUT/dockerlogs.txt" 2>&1; break
    fi
    sleep 0.25
  done ) &
SAMPLER=$!
UPPORT=$UPPORT "$TW" record --out "$OUT/runs" --name canary --upstream-ca "$OUT/up/upca.pem" -- "$OUT/canary_workload.sh" 2>&1 | tail -3
wait $SAMPLER 2>/dev/null
CANARY_FILE="$OUT/canaries.env" "$PY" tests/integration/canary_check.py "$OUT/runs/canary" "$OUT/server_seen.log" $UPPORT
