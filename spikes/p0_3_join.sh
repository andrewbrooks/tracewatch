#!/bin/bash
# Phase 0 spike 3: join a proxied flow to the pid that made it, using only data recorded at capture
# time (proxy-side client-port->pid resolution + Tracee events), joined AFTER the run.
#  positive : 3 concurrent traced curls each map to exactly their own pid; Tracee confirms each
#             pid's connect to the proxy and its exec
#  negative : an outside-the-tree curl through the same proxy is attributed to its own pid, which
#             Tracee did NOT see, so the join labels it "outside tree" instead of misattributing it
set -u
HERE=$(cd "$(dirname "$0")/.." && pwd)
OUT=$HERE/out/p0_3; rm -rf "$OUT"; mkdir -p "$OUT"/{up,conf,flags}
PP=18093; UP=18445
RUN=(docker run -d --pid=host --cgroupns=host --privileged
     -v /etc/os-release:/etc/os-release-host:ro -v /sys/kernel/debug:/sys/kernel/debug
     -e LIBBPFGO_OSRELEASE_FILE=/etc/os-release-host)
cleanup() { docker rm -f tw-boot tw-spike >/dev/null 2>&1; pkill -f "mitmdump --listen-host 127.0.0.1 --listen-port $PP"; kill $S1 2>/dev/null; }
trap cleanup EXIT; docker rm -f tw-boot tw-spike >/dev/null 2>&1

cd "$OUT/up"
openssl req -x509 -newkey rsa:2048 -nodes -keyout upca.key -out upca.pem -days 2 -subj "/CN=tw-upstream-test-ca" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -keyout srv.key -out srv.csr -subj "/CN=localhost" 2>/dev/null
printf 'subjectAltName=DNS:localhost,IP:127.0.0.1\n' > san.ext
openssl x509 -req -in srv.csr -CA upca.pem -CAkey upca.key -CAcreateserial -out srv.pem -days 2 -extfile san.ext 2>/dev/null
cat > srv.py <<'P'
import http.server, ssl, sys, time
port, crt, key = int(sys.argv[1]), sys.argv[2], sys.argv[3]
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(s):
        if s.path.startswith("/slow"): time.sleep(1.5)   # keep connections overlapping
        b = b"ok"; s.send_response(200); s.send_header("Content-Length", "2"); s.end_headers(); s.wfile.write(b)
    def log_message(s, *a): pass
srv = http.server.ThreadingHTTPServer(("127.0.0.1", port), H)
c = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); c.load_cert_chain(crt, key); srv.socket = c.wrap_socket(srv.socket, server_side=True)
srv.serve_forever()
P
python3 srv.py $UP srv.pem srv.key & S1=$!
cd "$HERE"

TW_FLOWS="$OUT/flows.jsonl" uvx --from mitmproxy mitmdump --listen-host 127.0.0.1 --listen-port $PP \
  --set confdir="$OUT/conf" --set ssl_verify_upstream_trusted_ca="$OUT/up/upca.pem" \
  -s "$HERE/spikes/p0_3_addon.py" >"$OUT/mitm.log" 2>&1 &
for i in $(seq 120); do (exec 3<>/dev/tcp/127.0.0.1/$PP) 2>/dev/null && break; sleep 0.5; done
CA=$OUT/conf/mitmproxy-ca-cert.pem; [ -s "$CA" ] || { echo "FAIL: proxy/CA not up"; tail -5 "$OUT/mitm.log"; exit 1; }

cp /bin/true "$OUT/twprobe"; mkfifo "$OUT/go"
cat > "$OUT/workload.sh" <<'W'
#!/bin/sh
OUT=$1; UP=$2
for n in 1 2 3; do
  sh -c 'echo $$ > "$1/pid_$2"; exec curl -s -o /dev/null --max-time 20 "https://localhost:$3/slow$2"' _ "$OUT" $n $UP &
done
wait
W
# traced root: env gives its children the proxy + per-run CA (and only them)
HTTPS_PROXY=http://127.0.0.1:$PP CURL_CA_BUNDLE=$CA bash -c '
  while [ ! -e "$1/flags/p1" ]; do "$1/twprobe"; sleep 0.3; done
  while [ ! -e "$1/flags/p2" ]; do "$1/twprobe"; sleep 0.3; done
  read _ < "$1/go"
  exec sh "$1/workload.sh" "$1" "$2"
' _ "$OUT" $UP &
TREE=$!

"${RUN[@]}" --name tw-boot aquasec/tracee:latest --events sched_process_exec --scope comm=twprobe --output json >/dev/null
HP=
for i in $(seq 80); do
  HP=$(docker logs tw-boot 2>/dev/null | grep -m1 eventName | python3 -c "import sys,json; print(json.loads(sys.stdin.readline())['hostParentProcessId'])" 2>/dev/null) && [ -n "$HP" ] && break
  sleep 0.5
done
[ -n "$HP" ] || { echo "FAIL: bootstrap tracee never reported the probe"; exit 1; }
touch "$OUT/flags/p1"; docker rm -f tw-boot >/dev/null
"${RUN[@]}" --name tw-spike aquasec/tracee:latest --events sched_process_exec,net_tcp_connect --scope tree=$HP --output json >/dev/null
for i in $(seq 80); do docker logs tw-spike 2>/dev/null | grep -q eventName && break; sleep 0.5; done
touch "$OUT/flags/p2"; sleep 1

# outside-the-tree control through the same proxy, overlapping the traced curls
sh -c 'echo $$ > "'"$OUT"'/pid_ctrl"; exec env HTTPS_PROXY=http://127.0.0.1:'$PP' CURL_CA_BUNDLE='"$CA"' curl -s -o /dev/null --max-time 20 "https://localhost:'$UP'/slowctrl"' &
CTRL=$!
echo go > "$OUT/go"
wait $CTRL; sleep 5
docker logs tw-spike >"$OUT/tracee.json" 2>"$OUT/tracee.err"
echo "$TREE" > "$OUT/tree_pid"; echo "$HP" > "$OUT/tree_host_pid"

# ---- post-facto reconstruction: uses ONLY the files in $OUT (plus ground-truth pid_* for checking)
python3 - "$OUT" $PP <<'P'
import json, sys
out, pp = sys.argv[1], int(sys.argv[2])
rd = lambda f: [json.loads(l) for l in open(f"{out}/{f}") if l.startswith("{")]
fl = rd("flows.jsonl"); tr = [e for e in rd("tracee.json") if "eventName" in e and e["processName"] != "twprobe"]
conn = {r["client_port"]: r for r in fl if r["kind"] == "conn"}
flows = [r for r in fl if r["kind"] == "flow"]
tree_pids = {e["processId"] for e in tr}
connects = {(e["processId"], a["value"]) for e in tr if e["eventName"] == "net_tcp_connect"
            for a in e["args"] if a["name"] == "dst_port"}
execs = {e["processId"] for e in tr if e["eventName"] == "sched_process_exec" and e["processName"] == "curl"}
truth = {n: int(open(f"{out}/pid_{n}").read()) for n in ("1", "2", "3", "ctrl")}

def join(f):   # the reconstruction step
    c = conn.get(f["client_port"]); h = c["holder_pids"] if c else []
    if len(h) != 1: return ("ambiguous" if h else "unresolved", h)
    return ("in-tree" if h[0] in tree_pids else "outside-tree", h)

ok = True
def check(name, cond):
    global ok; ok &= bool(cond); print(("PASS " if cond else "FAIL ") + name)
print("flows:")
res = {}
for f in flows:
    label, h = join(f); n = f["path"].replace("/slow", ""); res[n] = (label, h)
    print(f"  {f['path']:<10} client_port={f['client_port']} -> {label} pid={h}")
check("4 flows recorded, 4 distinct client ports", len(flows) == 4 and len({f['client_port'] for f in flows}) == 4)
for n in ("1", "2", "3"):
    check(f"positive: /slow{n} -> exactly its own pid {truth[n]}, in-tree", res.get(n) == ("in-tree", [truth[n]]))
    check(f"positive: Tracee saw pid {truth[n]} exec curl and connect to proxy :{pp}", truth[n] in execs and (truth[n], pp) in connects)
check(f"negative: control /slowctrl -> its own pid {truth['ctrl']}, labelled outside-tree", res.get("ctrl") == ("outside-tree", [truth["ctrl"]]))
check("negative: Tracee has no events for the control pid", truth["ctrl"] not in tree_pids)
t = sorted(r["t_wall_ns"] for r in fl if r["kind"] == "conn"); rt = sorted(r["t_wall_ns"] for r in flows)
check("flows genuinely overlapped (all connects before first response)", t[-1] < rt[0])
sys.exit(0 if ok else 1)
P
