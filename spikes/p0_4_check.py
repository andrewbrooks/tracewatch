"""Post-run checks for spike p0_4. usage: p0_4_check.py <scenario> <run-dir> <proxy-port> <leaks-file>"""
import json, os, sys
scn, d, port, leakf = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
ok = True
def check(name, cond):
    global ok; ok &= bool(cond); print(("PASS " if cond else "FAIL ") + name)
def info(msg): print("INFO " + msg)

def jsonl(fn):
    """-> (records, n_bad_complete_lines, last_line_truncated)"""
    p = f"{d}/{fn}"
    if not os.path.exists(p): return [], 0, False
    raw = open(p, "rb").read(); lines = raw.split(b"\n"); trunc = bool(lines[-1])  # no trailing newline
    recs, bad = [], 0
    for i, l in enumerate(lines):
        if not l: continue
        try: recs.append(json.loads(l))
        except ValueError:
            if i == len(lines) - 1: trunc = True
            else: bad += 1
    return recs, bad, trunc

man = json.load(open(f"{d}/manifest.json"))
ev, evbad, _ = jsonl("events.jsonl")
fl, flbad, fltrunc = jsonl("flows.jsonl")
tr_all, trbad, trtrunc = [r for r in jsonl("tracee.jsonl")[0] if "eventName" in r], *jsonl("tracee.jsonl")[1:]
tr = [e for e in tr_all if e["processName"] != "twprobe"]
connects = [e for e in tr if e["eventName"] == "net_tcp_connect" and any(a["name"] == "dst_port" and a["value"] == port for a in e["args"])]
flows = [r for r in fl if r["kind"] == "flow"]
wl = [l.split() for l in open(f"{d}/workload.log")] if os.path.exists(f"{d}/workload.log") else []
wl_ok = [w for w in wl if w[1] == "rc=0" and w[2] == "code=200"]
kinds = [e["kind"] for e in ev]
died = [e for e in ev if e["kind"] == "component_died"]
leaks = dict(l.strip().split("=", 1) for l in open(leakf) if "=" in l)
print(f"[{scn}] workload ok={len(wl_ok)}/{len(wl)} flows={len(flows)} tracee_connects={len(connects)} "
      f"tracee_lines_trunc={trtrunc} manifest={man['status']} lost={man['lost_components']}")

check("no corrupt complete lines in events/flows/tracee files", evbad == flbad == trbad == 0)
N = 24
if scn == "control":
    check("manifest finished, not degraded, root exit 0", man["status"] == "finished" and not man["degraded"] and man["root_returncode"] == 0)
    check("no component_died event", not died)
    check(f"all {N} requests succeeded", len(wl_ok) == N)
    check(f"all {N} flows recorded with decrypted path", len(flows) == N and {f"/req{i}" for i in range(1, N + 1)} == {f["path"] for f in flows})
    check(f"Tracee recorded {N} connects to the proxy", len(connects) == N)
    check("run_finished comes after root_exited", kinds.index("root_exited") < kinds.index("run_finished"))
elif scn == "kill_tracee":
    check("component_died(tracee) recorded", [e["component"] for e in died] == ["tracee"])
    check("manifest finished, degraded, lost=[tracee]", man["status"] == "finished" and man["degraded"] and man["lost_components"] == ["tracee"])
    check("workload unaffected (all requests succeeded)", len(wl_ok) == N)
    check("proxy kept recording after Tracee died (all flows present)", len(flows) == N)
    check("Tracee pre-death events survived on disk", 0 < len(connects) < N)
    last_t = max(e["timestamp"] for e in tr_all); dt = died[0]["t_wall_ns"]
    check("gap is visible: no Tracee event after the recorded death time", last_t <= dt)
elif scn == "kill_mitm":
    check("component_died(mitm) recorded", [e["component"] for e in died] == ["mitm"])
    check("manifest finished, degraded, lost=[mitm]", man["status"] == "finished" and man["degraded"] and man["lost_components"] == ["mitm"])
    check("pre-death flows survived on disk", 0 < len(flows) < N)
    check("workload requests failed after the proxy died (visible, not hidden)", len(wl_ok) < N and len(wl) == N)
    check("Tracee kept recording and shows the failed attempts too", len(connects) == N)
    last_t = max(f["t_wall_ns"] for f in fl); dt = died[0]["t_wall_ns"]
    check("gap is visible: no proxy record after the recorded death time", last_t <= dt)
elif scn == "kill_root":
    check("manifest finished with root killed by signal 9 (returncode -9)", man["status"] == "finished" and man["root_returncode"] == -9)
    rx = [e for e in ev if e["kind"] == "root_exited"][0]
    check("root_exited event records signal 9", rx["signal"] == 9)
    check("recording ended promptly after the kill (run_finished within 15s)", (ev[-1]["t_wall_ns"] - rx["t_wall_ns"]) / 1e9 < 15)
    check("workload stopped early (fewer than all requests)", 0 < len(wl) < N)
    check("Tracee saw the connects that happened", 0 < len(connects) <= len(wl))
    check("not degraded: both components survived", not man["degraded"])
elif scn == "sigterm":
    check("manifest status interrupted, finalized", man["status"] == "interrupted" and "ended_ns" in man)
    check("interrupted event recorded before root_exited", "interrupted" in kinds and kinds.index("interrupted") < kinds.index("root_exited"))
    check("workload stopped early", 0 < len(wl) < N)
    check("not degraded", not man["degraded"])
elif scn == "kill_supervisor":
    info(f"after kill -9, before sweep: {leaks.get('before')}")
    check("sweep marked the run aborted (was left 'running' by the dead supervisor)", man["status"] == "aborted")
    check("sweep event recorded", "swept" in kinds)
    check("no run_finished (nothing pretends the run finished cleanly)", "run_finished" not in kinds)
    check("data written before the kill survived", len(flows) > 0 and len(connects) > 0)
    check("no leaked containers/proxy/collector after sweep", leaks.get("after") == "clean")
if scn != "kill_supervisor":
    check("no leaked containers/proxy/collector afterwards", leaks.get("after") == "clean")
sys.exit(0 if ok else 1)
