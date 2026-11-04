"""Post-facto flow->pid join. Pure function over the recorded files.
Inputs: flow/conn records written by the proxy addon, Tracee events (non-probe).
Per flow it returns: pid (or None), method, scope (in-tree/outside-tree/unknown), candidates."""

import json
import sys

WINDOW_NS = 2_000_000_000  # a connect this long before the proxy accepted still counts
SLACK_NS = 100_000_000  # tolerated clock skew (connect timestamped slightly after accept)


def load(path):
    """Read a JSONL file, skipping lines that do not parse (a kill can truncate the last one)."""
    out = []
    with open(path, "rb") as f:
        for line in f:
            try:
                out.append(json.loads(line))
            except ValueError:
                pass
    return out


def calibrate(conns, connects, bucket_ns=20_000_000):
    """Estimate offset = tracee_ts - proxy_mono. Tracee timestamps are a fixed offset from CLOCK_MONOTONIC,
    so this is constant for a run even when the wall clock steps. Candidates pair each single-holder
    connection with every connect by that pid; the true offset recurs, spurious pairs scatter."""
    cands = []
    for c in conns.values():
        h = c["holder_pids"]
        if len(h) != 1 or "accept_mono_ns" not in c:
            continue
        for ts, p in connects:
            if p == h[0]:
                cands.append(ts - c["accept_mono_ns"])
    if not cands:
        return None, 0
    from collections import Counter

    votes = Counter(round(x / bucket_ns) for x in cands)
    top = max(votes.values())
    best = [b for b, v in votes.items() if v == top]
    b = min(best)  # deterministic tie-break
    near = sorted(x for x in cands if abs(round(x / bucket_ns) - b) <= 1)
    return near[len(near) // 2], top


def join_records(fl, tr, proxy_port, info=None):
    conns = {r["conn_id"]: r for r in fl if r["kind"] == "conn"}
    flows = [r for r in fl if r["kind"] == "flow"]
    tree = {e["processId"] for e in tr}
    connects = sorted(
        (e["timestamp"], e["processId"])
        for e in tr
        if e["eventName"] == "net_tcp_connect"
        and any(a["name"] == "dst_port" and a["value"] == proxy_port for a in e["args"])
    )
    claimed = set()
    offset, votes = calibrate(conns, connects)
    if info is not None:
        info.update(offset_ns=offset, votes=votes, clock="monotonic" if offset is not None else "wall-fallback")
    # time of a connection on the Tracee clock
    when = (lambda c: c["accept_mono_ns"] + offset) if offset is not None else (lambda c: c["t_wall_ns"])

    def match(pid, t):
        best = None
        for i, (ts, p) in enumerate(connects):
            if p == pid and i not in claimed and t - WINDOW_NS <= ts <= t + SLACK_NS:
                if best is None or ts > connects[best][0]:
                    best = i
        return best

    res = {}
    ordered = sorted(conns.values(), key=when)
    for c in ordered:  # pass 1: connections with socket holders
        h, t = c["holder_pids"], when(c)
        if len(h) == 1:
            i = match(h[0], t)
            if i is not None:
                claimed.add(i)
            res[c["conn_id"]] = dict(
                pid=h[0], method="socket-holder" + ("" if i is not None else " (no tracee connect)"), candidates=h
            )
        elif len(h) > 1:
            cr = [(p, match(p, t)) for p in h]
            cr = [x for x in cr if x[1] is not None]
            if len(cr) == 1:
                claimed.add(cr[0][1])
                res[c["conn_id"]] = dict(pid=cr[0][0], method="socket-holder+connect-event", candidates=h)
            else:
                res[c["conn_id"]] = dict(pid=None, method="ambiguous-holders", candidates=h)
    for c in ordered:  # pass 2: no holder found (client gone before lookup)
        if c["conn_id"] in res:
            continue
        t = when(c)
        cand = [i for i, (ts, p) in enumerate(connects) if i not in claimed and t - WINDOW_NS <= ts <= t + SLACK_NS]
        pids = sorted({connects[i][1] for i in cand})
        if len(cand) == 1:
            claimed.add(cand[0])
            res[c["conn_id"]] = dict(pid=pids[0], method="inferred-connect-window", candidates=pids)
        else:
            res[c["conn_id"]] = dict(pid=None, method="unresolved", candidates=pids)
    out = []
    for f in flows:
        r = dict(res.get(f["conn_id"], dict(pid=None, method="no-connection-record", candidates=[])))
        r["scope"] = "unknown" if r["pid"] is None else ("in-tree" if r["pid"] in tree else "outside-tree")
        r.update(path=f["path"], conn_id=f["conn_id"], client_port=f["client_port"], http_version=f.get("http_version"))
        out.append(r)
    return out


def join_run(rundir, proxy_port):
    fl = load(f"{rundir}/flows.jsonl")
    tr = [e for e in load(f"{rundir}/tracee.jsonl") if "eventName" in e and e["processName"] != "twprobe"]
    return join_records(fl, tr, proxy_port), fl, tr


if __name__ == "__main__":
    rows, _, _ = join_run(sys.argv[1], int(sys.argv[2]))
    for r in rows:
        print(
            f"{r['path']:<10} port={r['client_port']:<6} {r['scope']:<13} pid={r['pid']} "
            f"via {r['method']} cand={r['candidates']}"
        )
