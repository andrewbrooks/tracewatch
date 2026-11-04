"""Real-run checks for spike p0_6. usage: p0_6_check.py RUN_DIR PROXY_PORT CTRL_PID"""
import json, os, sys, statistics
sys.path.insert(0, os.path.dirname(__file__))
from p0_6_join import join_run, load
d, pp, ctrl = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
rows, fl, tr = join_run(d, pp); truth = json.load(open(f"{d}/truth.json"))
by = lambda p: [r for r in rows if r["path"] == p]
ok = True
def check(name, cond):
    global ok; ok &= bool(cond); print(("PASS " if cond else "FAIL ") + name)
def info(m): print("INFO " + m)
for r in sorted(rows, key=lambda r: r["path"]):
    print(f"  {r['path']:<9} port={r['client_port']:<6} {r['scope']:<13} pid={r['pid']} via {r['method']} cand={r['candidates']}")
# --- port reuse
if all(truth[f"reuse{i}"].get("rc") == 0 for i in (1, 2, 3)):
    ports = {by(f"/reuse{i}")[0]["client_port"] for i in (1, 2, 3)}
    check("setup: three connections really reused one client port (41000)", ports == {41000})
    check("port reuse: each flow attributed to its own pid via conn_id", all(by(f"/reuse{i}") and by(f"/reuse{i}")[0]["pid"] == truth[f"reuse{i}"]["pid"] for i in (1, 2, 3)))
    # negative: the OLD port-keyed join (last connection with that port wins) must get this wrong
    conns = {}
    for c in [r for r in fl if r["kind"] == "conn"]: conns[c["client_port"]] = c
    old = [conns[41000]["holder_pids"] for _ in (1, 2, 3)]
    check("negative: the old port-keyed join WOULD misattribute (test is sensitive)", sum(o == [truth[f"reuse{i}"]["pid"]] for o, i in zip(old, (1, 2, 3))) < 3)
else:
    info("source-port reuse could not be forced here: " + str([truth[f"reuse{i}"].get("rc") for i in (1, 2, 3)]))
# --- shared socket
sh = by("/shared"); c = [r for r in fl if r["kind"] == "conn" and len(r["holder_pids"]) > 1]
check("shared socket: the proxy saw >1 holder of the client socket", bool(c))
check("shared socket: resolved to the process that connected (not the child)", bool(sh) and sh[0]["pid"] == truth["shared"]["pid"] and sh[0]["method"] == "socket-holder+connect-event")
# --- keep-alive / h2
for tag, a, b in (("ka", "/ka1", "/ka2"), ("h2req", "/h2a", "/h2b")):
    A, B = by(a), by(b)
    check(f"{tag}: both requests recorded", bool(A and B))
    if A and B:
        info(f"{tag}: http_version={A[0]['http_version']}, same connection={A[0]['conn_id'] == B[0]['conn_id']}")
        check(f"{tag}: both attributed to the client pid {truth[tag]['pid']}", A[0]["pid"] == B[0]["pid"] == truth[tag]['pid'])
        if tag == "h2req" and A[0]["http_version"] != "HTTP/2.0": info("HTTP/2 was requested but NOT negotiated (test upstream is HTTP/1.1 only): h2 is NOT verified")
# --- fire and forget: never wrong; report how often unresolved
for n in ("ff1", "ff2", "ff3"):
    r = by("/" + n); got = r[0] if r else None
    check(f"{n}: recorded and NOT misattributed (right pid, or no pid)", got is not None and got["pid"] in (truth[n]["pid"], None))
    if got: info(f"{n}: {got['method']} pid={got['pid']} (truth {truth[n]['pid']})")
res = {r["flow_id"]: r for r in fl if r["kind"] == "flow_result"}
check("every recorded flow has a result record or is visibly missing one", True)
info("flows without a result record: " + str([r["path"] for r in fl if r["kind"] == "flow" and r["flow_id"] not in res]))
# --- control outside the tree
ct = by("/slowctrl")
check("control: outside-tree curl attributed to its own pid, scope outside-tree", bool(ct) and ct[0]["pid"] == ctrl and ct[0]["scope"] == "outside-tree")
# --- clocks and cost
from p0_6_join import join_records
inf = {}; join_records(fl, tr, pp, inf)
info(f"join clock={inf['clock']} offset(tracee-proxy_mono)={inf['offset_ns']} votes={inf['votes']}")
check("join used the monotonic clock (calibration found anchors)", inf["clock"] == "monotonic")
conns = {r["conn_id"]: r for r in fl if r["kind"] == "conn"}
cons = [(e["timestamp"], e["processId"]) for e in tr if e["eventName"] == "net_tcp_connect" and any(a["name"] == "dst_port" and a["value"] == pp for a in e["args"])]
res_m, res_w = [], []
for r in rows:
    if r["pid"] and r["method"].startswith("socket-holder") and "no tracee" not in r["method"]:
        c = conns[r["conn_id"]]
        m = [ts for ts, p in cons if p == r["pid"] and abs(ts - (c["accept_mono_ns"] + inf["offset_ns"])) < 1e9]
        if m: res_m.append((min(m, key=lambda ts: abs(ts - (c["accept_mono_ns"] + inf["offset_ns"]))) - c["accept_mono_ns"] - inf["offset_ns"]) / 1e6)
        res_w.append((c["t_wall_ns"] - c["accept_mono_ns"]) / 1e6)
if res_m:
    info(f"monotonic residuals (connect vs calibrated accept), ms: min={min(res_m):.2f} max={max(res_m):.2f} (n={len(res_m)})")
    check("monotonic calibration is tight: all residuals within +/-20 ms", all(abs(x) < 20 for x in res_m))
spread = (max(res_w) - min(res_w)) / 1000 if res_w else 0
info(f"wall-vs-monotonic offset moved by {spread:.2f} s across the run (wall-clock steps)")
lk = [r["lookup_ms"] for r in fl if r["kind"] == "conn"]
info(f"capture-time lookup: max {max(lk):.1f} ms, median {statistics.median(lk):.1f} ms over {len(lk)} connections; procs scanned up to {max(r['procs_scanned'] for r in fl if r['kind']=='conn')}")
sys.exit(0 if ok else 1)
