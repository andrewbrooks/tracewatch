"""Post-facto flow->pid join. Pure function over the recorded files.
Inputs: flow/conn records written by the proxy addon, Tracee events (non-probe).
Per flow it returns: pid (or None), method, scope (in-tree/outside-tree/unknown), candidates."""

import json
import sys

WINDOW_NS = 2_000_000_000  # a connect this long before the proxy accepted still counts
SLACK_NS = 100_000_000  # tolerated clock skew (connect timestamped slightly after accept)
SEND_SLACK_NS = 10_000_000  # clock-calibration error tolerated when a send looks to be just after the request
SEND_NAMES = ("sendto", "sendmsg", "sendmmsg", "write", "writev")  # Tracee syscall events: who SENDS on a descriptor


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


def join_records(fl, tr, proxy_port, info=None, tracee_capped=False):
    conns = {r["conn_id"]: r for r in fl if r["kind"] == "conn"}
    flows = [r for r in fl if r["kind"] == "flow"]
    # a CONNECT tunnel that never produced an HTTP flow (refused, failed, non-HTTP) is still an event
    # worth attributing; one that did produce flows is represented by those flows, not twice
    with_flows = {r["conn_id"] for r in flows}
    flows += [
        {**r, "path": f"CONNECT {r['host']}:{r['port']}"}
        for r in fl
        if r["kind"] == "connect" and r["conn_id"] not in with_flows
    ]
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

    sends: dict[int, list[tuple[int, int]]] = {}  # pid -> [(tracee ts, fd)]
    for e in tr:
        if e["eventName"] in SEND_NAMES:
            fd = next((a["value"] for a in e["args"] if a["name"] in ("sockfd", "fd")), None)
            if isinstance(fd, int):
                sends.setdefault(e["processId"], []).append((e["timestamp"], fd))
    flow_times: dict[str, list[int]] = {}
    for f in flows:
        if f.get("t_mono_ns") is not None:
            flow_times.setdefault(f["conn_id"], []).append(f["t_mono_ns"])

    def writer(f, c):
        """Several processes hold this socket: who sent THIS request? The last send/write on one of the connection's
        descriptors before the request reached the proxy (earlier ones may be the opener's CONNECT or handshake).
        -> None when the socket is not shared, else (pid or None, all holders)."""
        if offset is None or c is None or f.get("t_mono_ns") is None or f.get("kind") == "connect":
            return None
        fds = {int(p): set(v) for p, v in (c.get("holder_fds") or {}).items()}
        for p, v in (f.get("holders_now") or {}).items():
            fds.setdefault(int(p), set()).update(v)
        if len(fds) < 2:
            return None
        t = f["t_mono_ns"] + offset
        before = [x for x in flow_times.get(f["conn_id"], []) if x < f["t_mono_ns"]]
        lo = max([t - WINDOW_NS] + [x + offset for x in before])
        hits = [(ts, p) for p in fds for ts, fd in sends.get(p, []) if fd in fds[p] and lo <= ts <= t + SEND_SLACK_NS]
        # the request cannot have been sent after it arrived: only if nothing was sent before it (clock error)
        # look a little past it. A later write on the same fd NUMBER is probably a reused descriptor, not this.
        early = [h for h in hits if h[0] <= t]
        hits = early or [h for h in hits if h[0] <= t + SEND_SLACK_NS]
        return (max(hits)[1] if hits else None), sorted(fds)

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
        w = writer(f, conns.get(f["conn_id"]))
        if w is not None:  # a shared socket: the opener is not necessarily the sender
            who, holders = w
            r["opener"] = r["pid"]
            if who is not None:
                r.update(pid=who, method="socket-holder+send-event", candidates=holders)
                if who == r["opener"]:
                    r["opener"] = None  # the opener also sent: nothing to add
            else:
                r.update(method="shared-socket-sender-unknown", candidates=holders)
            if info is not None and f.get("flow_id"):
                info.setdefault("flows", {})[f["flow_id"]] = {
                    k: r[k] for k in ("pid", "method", "candidates", "opener")
                }
        if r["pid"] is None:
            r["scope"] = "unknown"
        elif r["pid"] in tree:
            r["scope"] = "in-tree"
        else:
            # Tracee stopped recording at its size cap: a pid it never reported may well be in the tree.
            # "outside-tree" would be a confident claim the data cannot support.
            r["scope"] = "unknown-tracee-capped" if tracee_capped else "outside-tree"
        r.update(
            path=f["path"],
            conn_id=f["conn_id"],
            flow_id=f.get("flow_id"),
            client_port=f["client_port"],
            http_version=f.get("http_version"),
        )
        out.append(r)
    if info is not None:
        info["connections"] = res  # conn_id -> {pid, method, candidates}: every connection, flows or not
    return out


def join_run(rundir, proxy_port):
    fl = load(f"{rundir}/flows.jsonl")
    raw = load(f"{rundir}/tracee.jsonl")
    tr = [e for e in raw if "eventName" in e and e["processName"] != "twprobe"]
    capped = any(e.get("kind") == "cap_reached" for e in raw)
    return join_records(fl, tr, proxy_port, tracee_capped=capped), fl, tr


if __name__ == "__main__":
    rows, _, _ = join_run(sys.argv[1], int(sys.argv[2]))
    for r in rows:
        print(
            f"{r['path']:<10} port={r['client_port']:<6} {r['scope']:<13} pid={r['pid']} "
            f"via {r['method']} cand={r['candidates']}"
        )
