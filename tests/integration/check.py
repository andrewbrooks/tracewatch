"""Post-run checks for tests/integration/run.sh.  usage: check.py SCENARIO RUN_DIR PROXY_PORT LEAKS_FILE"""

import json
import os
import stat
import sys
from pathlib import Path

from tracewatch.integrity import assess
from tracewatch.join import join_records

scn, d, port, leakf = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
N = 24
ok = True


def check(name, cond):
    global ok
    ok &= bool(cond)
    print(("PASS " if cond else "FAIL ") + name)


def info(msg):
    print("INFO " + msg)


def jsonl(fn):
    """-> (records, n_corrupt_complete_lines, last_line_truncated)"""
    p = f"{d}/{fn}"
    if not os.path.exists(p):
        return [], 0, False
    raw = open(p, "rb").read()
    lines = raw.split(b"\n")
    trunc = bool(lines[-1])
    recs, bad = [], 0
    for i, line in enumerate(lines):
        if not line:
            continue
        try:
            recs.append(json.loads(line))
        except ValueError:
            if i == len(lines) - 1:
                trunc = True
            else:
                bad += 1
    return recs, bad, trunc


man = json.load(open(f"{d}/manifest.json"))
ev, evbad, _ = jsonl("events.jsonl")
fl, flbad, _ = jsonl("flows.jsonl")
tr_raw, trbad, trtrunc = jsonl("tracee.jsonl")
tr_all = [r for r in tr_raw if "eventName" in r]
tr = [e for e in tr_all if e["processName"] != "twprobe"]
flows = [r for r in fl if r["kind"] == "flow"]
results = {r["flow_id"]: r for r in fl if r["kind"] == "flow_result"}
connects = [
    e
    for e in tr
    if e["eventName"] == "net_tcp_connect" and any(a["name"] == "dst_port" and a["value"] == port for a in e["args"])
]
wl = [ln.split() for ln in open(f"{d}/workload.log")] if os.path.exists(f"{d}/workload.log") else []
wl_ok = [w for w in wl if w[1] == "rc=0" and w[2] == "code=200"]
kinds = [e["kind"] for e in ev]
died = [e for e in ev if e["kind"] == "component_died"]
leaks = dict(ln.strip().split("=", 1) for ln in open(leakf) if "=" in ln)
inf = {}
join_records(fl, tr, port, inf)
print(
    f"[{scn}] workload ok={len(wl_ok)}/{len(wl)} flows={len(flows)} connects={len(connects)} "
    f"manifest={man['status']} lost={man['lost_components']} clock={inf.get('clock')}"
)

check("no corrupt complete lines in events/flows/tracee", evbad == flbad == trbad == 0)
hb = [e for e in ev if e["kind"] == "heartbeat"]
check(
    "heartbeats carry both clocks and are monotonic",
    all("t_wall_ns" in h and "t_mono_ns" in h for h in hb)
    and [h["t_mono_ns"] for h in hb] == sorted(h["t_mono_ns"] for h in hb),
)


def tracee_ts_to_mono(ts):
    return ts - inf["offset_ns"]


A = assess(Path(d))
atkill = int(open(f"{d}/../{scn}.atkill").read().split("=")[1]) if os.path.exists(f"{d}/../{scn}.atkill") else None
if scn == "control":
    check("verify: complete", A["verdict"] == "complete")
    check(
        "manifest finished, not degraded, root exit 0",
        man["status"] == "finished" and not man["degraded"] and man["root_returncode"] == 0,
    )
    check("no component_died", not died)
    check(f"all {N} requests succeeded", len(wl_ok) == N)
    check(
        f"{N} flow records at request time with the right paths",
        sorted(f["path"] for f in flows) == sorted(f"/req{i}" for i in range(1, N + 1)),
    )
    check(
        f"{N} flow_result records, all status 200",
        len(results) == N and all(r.get("status") == 200 for r in results.values()),
    )
    check(f"Tracee recorded {N} connects to the proxy", len(connects) == N)
    check("run_finished comes after root_exited", kinds.index("root_exited") < kinds.index("run_finished"))
    check("at least 3 heartbeats in a ~12 s run", len(hb) >= 3)
    check(
        "manifest records tool versions (tracee version + digest, mitmproxy)",
        str(man["versions"]["tracee"]["version"]).startswith("Tracee version")
        and "sha256" in str(man["versions"]["tracee"]["digest"])
        and man["versions"]["mitmproxy"],
    )
    # end to end: the real join over the recorded files
    rows = join_records(fl, tr, port)
    curl_pids = {e["processId"] for e in tr if e["eventName"] == "sched_process_exec" and e["processName"] == "curl"}
    check(
        f"end-to-end join: all {N} flows attributed in-tree to a curl pid Tracee saw exec",
        len(rows) == N and all(r["scope"] == "in-tree" and r["pid"] in curl_pids for r in rows),
    )
    check("end-to-end join used the monotonic clock", inf["clock"] == "monotonic")
    check(
        "no private key material left anywhere in the run dir",
        not any(b"PRIVATE KEY" in open(os.path.join(root, f), "rb").read() for root, _, fs in os.walk(d) for f in fs),
    )
    check(
        "CA private files were removed, public cert kept",
        not any(
            os.path.exists(f"{d}/ca/{n}") for n in ("mitmproxy-ca.pem", "mitmproxy-ca.p12", "mitmproxy-dhparam.pem")
        )
        and os.path.exists(f"{d}/ca/mitmproxy-ca-cert.pem"),
    )
    modes = {
        f: stat.S_IMODE(os.stat(f"{d}/{f}").st_mode)
        for f in ("manifest.json", "events.jsonl", "flows.jsonl", "tracee.jsonl", "mitm.log", "tracee.err")
    }
    check(f"all capture files are 0600 ({modes})", all(m == 0o600 for m in modes.values()))
elif scn == "kill_tracee":
    check(
        "verify: complete-with-losses, with a tracee gap",
        A["verdict"] == "complete-with-losses" and [g["source"] for g in A["gaps"]] == ["tracee"],
    )
    check("component_died(tracee) recorded", [e["component"] for e in died] == ["tracee"])
    check(
        "manifest finished, degraded, lost=[tracee]",
        man["status"] == "finished" and man["degraded"] and man["lost_components"] == ["tracee"],
    )
    check("workload unaffected", len(wl_ok) == N)
    check("proxy kept recording after Tracee died", len(flows) == N)
    check("Tracee pre-death events survived", 0 < len(connects) < N)
    check(
        "gap visible: no Tracee event after the recorded death (monotonic clock)",
        inf["clock"] == "monotonic"
        and max(tracee_ts_to_mono(e["timestamp"]) for e in tr_all) <= died[0]["t_mono_ns"] + 200_000_000,
    )
elif scn == "kill_mitm":
    check(
        "verify: complete-with-losses, with a proxy gap",
        A["verdict"] == "complete-with-losses" and [g["source"] for g in A["gaps"]] == ["proxy"],
    )
    check("component_died(mitm) recorded", [e["component"] for e in died] == ["mitm"])
    check(
        "manifest finished, degraded, lost=[mitm]",
        man["status"] == "finished" and man["degraded"] and man["lost_components"] == ["mitm"],
    )
    check("pre-death flows survived", 0 < len(flows) < N)
    check("later requests fail visibly", len(wl_ok) < N and len(wl) == N)
    check("Tracee shows all attempts", len(connects) == N)
    check(
        "gap visible: no proxy record after the recorded death", max(r["t_mono_ns"] for r in fl) <= died[0]["t_mono_ns"]
    )
elif scn == "kill_root":
    check("verify: complete (a killed target is still a complete recording)", A["verdict"] == "complete")
    check("finished with root killed by signal 9", man["status"] == "finished" and man["root_returncode"] == -9)
    rx = [e for e in ev if e["kind"] == "root_exited"][0]
    check("root_exited records signal 9", rx["signal"] == 9)
    check("run finalized within 15 s of the kill", (ev[-1]["t_mono_ns"] - rx["t_mono_ns"]) / 1e9 < 15)
    check("workload stopped early", 0 < len(wl) < N)
    check("not degraded", not man["degraded"])
elif scn == "sigterm":
    check("verify: complete", A["verdict"] == "complete")
    check("manifest interrupted and finalized", man["status"] == "interrupted" and "ended" in man)
    check(
        "signal_received recorded before root_exited",
        "signal_received" in kinds and kinds.index("signal_received") < kinds.index("root_exited"),
    )
    check("workload stopped early", 0 < len(wl) < N)
    check("not degraded", not man["degraded"])
elif scn == "kill_supervisor":
    check(
        "verify: incomplete, with an untrusted tail after the last heartbeat",
        A["verdict"] == "incomplete" and A.get("untrusted_after_mono") is not None,
    )
    check(
        "POLICY on-recorder-death=stop (default): the kernel stopped the target; it is not left running",
        "target_alive" not in leaks.get("before", "") and man["policy"]["on_recorder_death"] == "stop",
    )
    check(
        "POLICY: the workload stopped when the recorder died (no more than 1 line after the kill)",
        atkill is not None and len(wl) <= atkill + 1,
    )
    check("sweep did not report a running target", man.get("target_still_running") is False)
    info(f"after kill -9, before sweep: {leaks.get('before')}")
    check(
        "REGRESSION FIX: the proxy is no longer orphaned by a recorder crash",
        "proxy_procs" not in leaks.get("before", ""),
    )
    check("the collector is not orphaned either", "collector_procs" not in leaks.get("before", ""))
    check("the Tracee container does leak until swept (documented limit)", "containers=1" in leaks.get("before", ""))
    check("the next recorder's startup sweep marked the run aborted", man["status"] == "aborted" and "swept" in man)
    check("sweep event recorded; no run_finished", "swept" in kinds and "run_finished" not in kinds)
    check("heartbeats exist, bounding the last known-good time", len(hb) >= 1)
    check("data written before the kill survived", len(flows) > 0 and len(connects) > 0)
    check("sweep removed the CA private key of the dead run", not os.path.exists(f"{d}/ca/mitmproxy-ca.pem"))
    check("nothing leaked after the sweep", leaks.get("after") == "clean")
elif scn == "recorder_death_continue":
    sweep_out = open(f"{d}/../{scn}.sweep").read()
    check(
        "POLICY on-recorder-death=continue recorded in the manifest", man["policy"]["on_recorder_death"] == "continue"
    )
    check("the target kept running after the recorder died", atkill is not None and len(wl) > atkill + 3)
    check("...unrecorded, with a dead proxy: its later requests fail", any(w[1] != "rc=0" for w in wl[atkill:]))
    check(
        "the sweep warned that the target is STILL RUNNING and marked the manifest",
        "STILL RUNNING" in sweep_out and man.get("target_still_running") is True,
    )
    check(
        "verify: incomplete, mentions the running target",
        A["verdict"] == "incomplete" and any("still running" in r for r in A["reasons"]),
    )
    check("no run_finished (nothing pretends the run completed)", "run_finished" not in kinds)
elif scn == "component_stop":
    check("POLICY on-component-loss=stop recorded", man["policy"]["on_component_loss"] == "stop")
    check(
        "events: component_died, then target_stopped, then root_exited",
        [k for k in kinds if k in ("component_died", "target_stopped", "root_exited")]
        == ["component_died", "target_stopped", "root_exited"],
    )
    rx = next(e for e in ev if e["kind"] == "root_exited")
    check(
        "the target got SIGTERM (exit signal 15) and the run still finalized properly",
        rx["signal"] == 15 and man["status"] == "finished" and man["root_returncode"] == -15 and man["degraded"],
    )
    check("manifest says who stopped the target and why", "mitm" in man["target_stopped"]["reason"])
    check("the workload was stopped early", 0 < len(wl) < N)
    check(
        "verify: complete-with-losses with a proxy gap, target_stopped surfaced",
        A["verdict"] == "complete-with-losses"
        and "target_stopped" in A
        and [g["source"] for g in A["gaps"]] == ["proxy"],
    )
elif scn == "component_stop_stubborn":
    ts = next(e for e in ev if e["kind"] == "target_stopped")
    tk = [e for e in ev if e["kind"] == "target_killed"]
    check(
        "a target that ignores SIGTERM is SIGKILLed after the grace period",
        len(tk) == 1 and man["root_returncode"] == -9,
    )
    check(
        f"...and not before it ({(tk[0]['t_mono_ns'] - ts['t_mono_ns']) / 1e9:.1f} s, grace 3 s)"
        if tk
        else "...timing",
        bool(tk) and 2.5 <= (tk[0]["t_mono_ns"] - ts["t_mono_ns"]) / 1e9 <= 8,
    )
    check("the run finalized after the kill", man["status"] == "finished" and "run_finished" in kinds)
if scn not in ("kill_supervisor",):
    check("nothing leaked afterwards", leaks.get("after") == "clean")
sys.exit(0 if ok else 1)
