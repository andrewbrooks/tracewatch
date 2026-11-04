"""Synthetic edge-case tests for spikes/p0_6_join.py (deterministic; the real run is not)."""
import os, sys
sys.path.insert(0, os.path.dirname(__file__))
from p0_6_join import join_records, WINDOW_NS
PP, S = 18107, 1_000_000_000
ok = True
def check(name, cond):
    global ok; ok &= bool(cond); print(("PASS " if cond else "FAIL ") + name)
def conn(cid, port, holders, t): return dict(kind="conn", conn_id=cid, client_port=port, holder_pids=holders, t_wall_ns=t)
def flow(cid, path, port=1, t=0): return dict(kind="flow", conn_id=cid, client_port=port, path=path, t_wall_ns=t)
def connect(pid, t, port=PP): return dict(eventName="net_tcp_connect", processId=pid, timestamp=t, processName="x", args=[dict(name="dst_port", value=port)])
def exe(pid, t=0): return dict(eventName="sched_process_exec", processId=pid, timestamp=t, processName="x", args=[])
by = lambda rows: {r["path"]: r for r in rows}

# S1 port reuse: same client_port, different conns/pids; must not cross-attribute
r = by(join_records([conn("a", 5000, [10], 10*S), flow("a", "/1", 5000), conn("b", 5000, [11], 20*S), flow("b", "/2", 5000)],
                    [exe(10), exe(11), connect(10, 10*S), connect(11, 20*S)], PP))
check("port reuse: each flow gets its own pid via conn_id", r["/1"]["pid"] == 10 and r["/2"]["pid"] == 11)
# S2 shared socket: two holders, only one issued the connect -> resolved to the connecter
r = by(join_records([conn("a", 5000, [10, 12], 10*S), flow("a", "/s")], [exe(10), exe(12), connect(10, 10*S - 5)], PP))
check("shared socket: connecting holder wins", r["/s"]["pid"] == 10 and r["/s"]["method"] == "socket-holder+connect-event")
# S3 shared socket, no connect evidence -> ambiguous, not guessed
r = by(join_records([conn("a", 5000, [10, 12], 10*S), flow("a", "/s")], [exe(10), exe(12)], PP))
check("shared socket w/o evidence: ambiguous, pid None, both candidates", r["/s"]["pid"] is None and r["/s"]["candidates"] == [10, 12] and r["/s"]["scope"] == "unknown")
# S4 shared socket, both holders connected within window -> ambiguous
r = by(join_records([conn("a", 5000, [10, 12], 10*S), flow("a", "/s")], [exe(10), exe(12), connect(10, 10*S - 5), connect(12, 10*S - 9)], PP))
check("shared socket, both connected: ambiguous (not guessed)", r["/s"]["pid"] is None and r["/s"]["method"] == "ambiguous-holders")
# S5 client gone before lookup, one unclaimed connect in window -> inferred
r = by(join_records([conn("a", 5000, [], 10*S), flow("a", "/g")], [exe(10), connect(10, 10*S - 1000)], PP))
check("gone client, single candidate connect: inferred in-tree", r["/g"]["pid"] == 10 and r["/g"]["method"] == "inferred-connect-window" and r["/g"]["scope"] == "in-tree")
# S6 two gone clients, two candidate connects -> unresolved (no guess)
r = by(join_records([conn("a", 5000, [], 10*S), flow("a", "/g1"), conn("b", 5001, [], 10*S + 1000), flow("b", "/g2")],
                    [exe(10), exe(11), connect(10, 10*S - 1000), connect(11, 10*S - 500)], PP))
check("two gone clients: both unresolved, candidates listed, nothing guessed", all(r[p]["pid"] is None and r[p]["method"] == "unresolved" and r[p]["candidates"] == [10, 11] for p in ("/g1", "/g2")))
# S7 gone client but the only connect in window was already claimed by a resolved conn -> unresolved
r = by(join_records([conn("a", 5000, [10], 10*S), flow("a", "/k"), conn("b", 5001, [], 10*S + 5000), flow("b", "/g")],
                    [exe(10), connect(10, 10*S - 1000)], PP))
check("claimed connect is not reused for inference", r["/k"]["pid"] == 10 and r["/g"]["pid"] is None)
# S8 connect outside the window is ignored
r = by(join_records([conn("a", 5000, [], 100*S), flow("a", "/g")], [exe(10), connect(10, 10*S)], PP))
check("stale connect outside window is not used", r["/g"]["pid"] is None)
# S9 holder not in Tracee tree -> outside-tree
r = by(join_records([conn("a", 5000, [99], 10*S), flow("a", "/o")], [exe(10), connect(10, 5*S)], PP))
check("holder unseen by Tracee: outside-tree, still attributed", r["/o"]["pid"] == 99 and r["/o"]["scope"] == "outside-tree")
# S10 keep-alive: two flows on one connection share the attribution
r = by(join_records([conn("a", 5000, [10], 10*S), flow("a", "/k1"), flow("a", "/k2")], [exe(10), connect(10, 10*S - 5)], PP))
check("keep-alive: both flows on one connection map to the same pid", r["/k1"]["pid"] == r["/k2"]["pid"] == 10)
# S11 flow without a connection record
r = by(join_records([flow("zzz", "/n")], [exe(10)], PP))
check("flow with no connection record: unknown, not guessed", r["/n"]["pid"] is None and r["/n"]["method"] == "no-connection-record")

# --- monotonic calibration: wall clock stepped +5s mid-run (bigger than the 2s window)
OFF = 5_000_000_000_000   # tracee clock = proxy monotonic + OFF
def mconn(cid, m, holders, wall_step=0): return dict(kind="conn", conn_id=cid, client_port=1, holder_pids=holders, accept_mono_ns=m, t_mono_ns=m, t_wall_ns=m + wall_step)
def tconnect(pid, m): return connect(pid, m + OFF)
fl = [mconn("a", 10*S, [10]), flow("a", "/a"), mconn("b", 20*S, [11]), flow("b", "/b"),
      mconn("g", 30*S, [], wall_step=5*S), flow("g", "/g")]       # g: client gone, wall stepped +5s before it
tr = [exe(10), exe(11), exe(12), tconnect(10, 10*S - 3_000_000), tconnect(11, 20*S - 3_000_000), tconnect(12, 30*S - 3_000_000)]
info = {}; r = by(join_records(fl, tr, PP, info))
check("calibration: offset recovered from unambiguous pairs, clock=monotonic", info["clock"] == "monotonic" and abs(info["offset_ns"] - (OFF - 3_000_000)) < 1000)
check("wall step +5s: gone client still inferred correctly on the monotonic clock", r["/g"]["pid"] == 12 and r["/g"]["method"] == "inferred-connect-window")
# negative control: same data without monotonic stamps -> wall fallback cannot cope with the step
fl2 = [{k: v for k, v in x.items() if k not in ("accept_mono_ns", "t_mono_ns")} for x in fl]
fl2 = [dict(x, t_wall_ns=x["t_wall_ns"] + OFF) if x["kind"] == "conn" else x for x in fl2]   # wall clock expressed on the tracee clock
info2 = {}; r2 = by(join_records(fl2, tr, PP, info2))
check("negative: wall-clock fallback is flagged and fails on the stepped clock (test is sensitive)", info2["clock"] == "wall-fallback" and r2["/g"]["pid"] != 12)
# one process, many connections (agent-like): calibration must not need unique connects
fl3 = []; tr3 = [exe(20)]
for i in range(6):
    fl3 += [mconn(f"c{i}", (10 + 7*i)*S, [20]), flow(f"c{i}", f"/m{i}")]; tr3.append(tconnect(20, (10 + 7*i)*S - 2_000_000))
info3 = {}; r3 = by(join_records(fl3, tr3, PP, info3))
check("agent-like: one pid, 6 connections -> offset still recovered by voting", info3["clock"] == "monotonic" and abs(info3["offset_ns"] - (OFF - 2_000_000)) < 1000 and info3["votes"] >= 6)
check("agent-like: all 6 flows attributed to pid 20", all(r3[f"/m{i}"]["pid"] == 20 for i in range(6)))
sys.exit(0 if ok else 1)
