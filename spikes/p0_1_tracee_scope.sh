#!/bin/bash
# Phase 0 spike 1: does `--scope tree=<pid>` capture a launched tree, which pid does it expect,
# and what do the events report for pid fields?
#
# Established by hand first: tree= takes the HOST-namespace pid (hostProcessId),
# not the pid /proc shows in this WSL2 distro. This script automates that and checks:
#   positive: exec of both curls and both tcp connects to the loopback server are captured
#   negative: an unrelated concurrent curl (CONTROL) is NOT captured
#   pid kinds: reports processId vs hostProcessId for the same events
# Usage: p0_1_tracee_scope.sh [with-proctree]   (default: no --proctree; pass arg to add it)
set -u
HERE=$(cd "$(dirname "$0")/.." && pwd)
OUT=$HERE/out/p0_1; rm -rf "$OUT"; mkdir -p "$OUT"
PROCTREE=(); [ "${1:-}" = with-proctree ] && PROCTREE=(--proctree source=both)
IMG=aquasec/tracee:latest
RUN=(docker run -d --pid=host --cgroupns=host --privileged
     -v /etc/os-release:/etc/os-release-host:ro -v /sys/kernel/debug:/sys/kernel/debug
     -e LIBBPFGO_OSRELEASE_FILE=/etc/os-release-host)
cleanup() { docker rm -f tw-boot tw-spike >/dev/null 2>&1; kill $SRV 2>/dev/null; }
trap cleanup EXIT
docker rm -f tw-boot tw-spike >/dev/null 2>&1

python3 -m http.server 18080 --bind 127.0.0.1 >"$OUT/server.log" 2>&1 & SRV=$!
cp /bin/true "$OUT/twprobe"; mkfifo "$OUT/go"; mkdir "$OUT/flags"

# Held tree root. Phase 1: runs twprobe until /flags/p1 exists (lets a bootstrap tracee read this
# process's host pid and prove it is ready). Phase 2: probes until /flags/p2 (main tracee ready),
# then waits for `go`, then execs the real workload tree (sh -> curl, curl).
bash -c '
  while [ ! -e "$1/flags/p1" ]; do "$1/twprobe"; sleep 0.3; done
  while [ ! -e "$1/flags/p2" ]; do "$1/twprobe"; sleep 0.3; done
  read _ < "$1/go"
  exec sh -c "curl -s -o /dev/null http://127.0.0.1:18080/a; curl -s -o /dev/null http://127.0.0.1:18080/b"
' _ "$OUT" &
TREE=$!
echo "held tree root, distro pid (what /proc shows): $TREE"

# bootstrap: tracee scoped to the probe binary, only to learn the root's host pid
"${RUN[@]}" --name tw-boot $IMG --events sched_process_exec --scope comm=twprobe --output json >/dev/null
HP=
for i in $(seq 80); do
  HP=$(docker logs tw-boot 2>/dev/null | grep -m1 eventName |
       python3 -c "import sys,json; print(json.loads(sys.stdin.readline())['hostParentProcessId'])" 2>/dev/null) && [ -n "$HP" ] && break
  sleep 0.5
done
[ -n "$HP" ] || { echo "FAIL: bootstrap tracee never reported the probe"; exit 1; }
touch "$OUT/flags/p1"; docker rm -f tw-boot >/dev/null
echo "root host pid (hostProcessId): $HP"

# main tracee, scoped to the host pid
"${RUN[@]}" --name tw-spike $IMG \
  --events sched_process_exec,net_tcp_connect,net_flow_tcp_begin,net_flow_tcp_end \
  "${PROCTREE[@]}" --scope tree=$HP --output json >/dev/null
for i in $(seq 80); do docker logs tw-spike 2>/dev/null | grep -q eventName && break; sleep 0.5; done
touch "$OUT/flags/p2"   # twprobe execs in the tree now guarantee at least one event; ready
sleep 1

# negative control: unrelated process that talks to the same server; record its distro pid
sh -c 'echo $$ > "'"$OUT"'/control_pid"; exec curl -s -o /dev/null http://127.0.0.1:18080/CONTROL'
echo go > "$OUT/go"
sleep 4
docker logs tw-spike >"$OUT/tracee.json" 2>"$OUT/tracee.err"
echo "$TREE" > "$OUT/tree_pid"; echo "$HP" > "$OUT/tree_host_pid"

python3 - "$OUT" <<'E'
import json, sys
out = sys.argv[1]
ctrl = int(open(f"{out}/control_pid").read())
ev = [json.loads(l) for l in open(f"{out}/tracee.json") if l.startswith("{") and '"eventName"' in l]
real = [e for e in ev if e["processName"] != "twprobe"]
by = lambda n: [e for e in real if e["eventName"] == n]
arg = lambda e, k: next((a["value"] for a in e["args"] if a["name"] == k), None)
curls = [e for e in by("sched_process_exec") if e["processName"] == "curl"]
conns = [e for e in by("net_tcp_connect") if "18080" in json.dumps(e["args"])]
print(f"events total={len(ev)} (probe={len(ev)-len(real)})  by type:",
      {n: len(by(n)) for n in sorted({e['eventName'] for e in real})})
for e in curls[:3]:
    print("  curl exec  processId=%s hostProcessId=%s ppid=%s" % (e["processId"], e["hostProcessId"], e["parentProcessId"]))
ok = True
def check(name, cond):
    global ok; ok &= bool(cond); print(("PASS " if cond else "FAIL ") + name)
check("positive: 2 curl execs captured", len(curls) == 2)
check("positive: 2 tcp connects to :18080 captured", len(conns) == 2)
check("negative: CONTROL curl (distro pid %d) absent" % ctrl, all(e["processId"] != ctrl and e["hostProcessId"] != ctrl for e in ev))
check("pid kinds differ (processId != hostProcessId)", all(e["processId"] != e["hostProcessId"] for e in curls) and bool(curls))
sys.exit(0 if ok else 1)
E
