"""Post-facto flow->pid join. Pure function over the recorded files.
Inputs: flow/conn records written by the proxy addon, Tracee events (non-probe).
Per flow it returns: pid (or None), method, scope (in-tree/outside-tree/unknown), candidates."""

import json
import logging
import sys
from collections.abc import Callable
from pathlib import Path

logger = logging.getLogger(__name__)

WINDOW_NS = 2_000_000_000  # a connect this long before the proxy accepted still counts
SLACK_NS = 100_000_000  # tolerated clock skew (connect timestamped slightly after accept)
SEND_SLACK_NS = 10_000_000  # clock-calibration error tolerated when a send looks to be just after the request
SEND_NAMES = ("sendto", "sendmsg", "sendmmsg", "write", "writev")  # Tracee syscall events: who SENDS on a descriptor


def load(path: str | Path) -> list[dict]:
    """Read a JSONL file, skipping lines that do not parse. A kill can truncate the last line, which is expected;
    an unparseable line anywhere else means the file is damaged, and is logged (the file name and a count, never the
    line)."""
    out = []
    bad = []  # line numbers that did not parse
    last = 0
    with open(path, "rb") as f:
        for n, line in enumerate(f, 1):
            last = n
            try:
                out.append(json.loads(line))
            except ValueError:
                bad.append(n)
    damaged = [n for n in bad if n != last]
    if damaged:
        logger.warning(
            "%s: skipped %d unparseable line(s) that are not just a truncated last line; the data may be incomplete",
            Path(path).name,
            len(damaged),
        )
    elif bad:
        logger.debug("%s: skipped a truncated last line", Path(path).name)
    return out


def calibrate(conns: dict, connects: list[tuple[int, int]], bucket_ns: int = 20_000_000) -> tuple[int | None, int]:
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


class _ConnectIndex:
    """The (Tracee timestamp, pid) of every connect to the proxy, and which of them are already attributed to a
    connection. Attribution runs in passes, and a connect can answer only one connection."""

    def __init__(self, connects: list[tuple[int, int]]) -> None:
        self.connects = connects
        self.claimed: set[int] = set()

    def match(self, pid: int, t: int) -> int | None:
        """The index of the latest unclaimed connect by `pid` near time `t`, or None."""
        best = None
        for i, (ts, p) in enumerate(self.connects):
            if p == pid and i not in self.claimed and t - WINDOW_NS <= ts <= t + SLACK_NS:
                if best is None or ts > self.connects[best][0]:
                    best = i
        return best

    def window(self, t: int) -> list[int]:
        """The indices of every unclaimed connect, by any pid, near time `t`."""
        return [
            i
            for i, (ts, _) in enumerate(self.connects)
            if i not in self.claimed and t - WINDOW_NS <= ts <= t + SLACK_NS
        ]


def _flows_to_attribute(fl: list[dict]) -> tuple[dict[str, dict], list[dict]]:
    """The proxy's connection records by id, and the flows to attribute. A CONNECT tunnel that never produced an HTTP
    flow (refused, failed, non-HTTP) is still an event worth attributing; one that did produce flows is represented
    by those flows, not twice."""
    conns = {r["conn_id"]: r for r in fl if r["kind"] == "conn"}
    flows = [r for r in fl if r["kind"] == "flow"]
    with_flows = {r["conn_id"] for r in flows}
    flows += [
        {**r, "path": f"CONNECT {r['host']}:{r['port']}"}
        for r in fl
        if r["kind"] == "connect" and r["conn_id"] not in with_flows
    ]
    return conns, flows


def _proxy_connects(tr: list[dict], proxy_port: int | None) -> list[tuple[int, int]]:
    """(timestamp, pid) of every Tracee connect to the proxy's port, in time order."""
    return sorted(
        (e["timestamp"], e["processId"])
        for e in tr
        if e["eventName"] == "net_tcp_connect"
        and any(a["name"] == "dst_port" and a["value"] == proxy_port for a in e["args"])
    )


def _sends_by_pid(tr: list[dict]) -> dict[int, list[tuple[int, int]]]:
    """pid -> [(Tracee timestamp, descriptor)] for every send or write the kernel reported."""
    sends: dict[int, list[tuple[int, int]]] = {}
    for e in tr:
        if e["eventName"] in SEND_NAMES:
            fd = next((a["value"] for a in e["args"] if a["name"] in ("sockfd", "fd")), None)
            if isinstance(fd, int):
                sends.setdefault(e["processId"], []).append((e["timestamp"], fd))
    return sends


def _flow_times(flows: list[dict]) -> dict[str, list[int]]:
    """conn_id -> the proxy-clock times of its requests."""
    times: dict[str, list[int]] = {}
    for f in flows:
        if f.get("t_mono_ns") is not None:
            times.setdefault(f["conn_id"], []).append(f["t_mono_ns"])
    return times


def _attribute_connections(
    conns: dict[str, dict], when: Callable[[dict], int], index: _ConnectIndex
) -> dict[str, dict]:
    """conn_id -> {pid, method, candidates} for every connection, in two passes. Pass 1 handles connections with socket
    holders; pass 2 infers the rest from the connect window."""
    res: dict[str, dict] = {}
    ordered = sorted(conns.values(), key=when)
    for c in ordered:  # pass 1: connections with socket holders
        h, t = c["holder_pids"], when(c)
        if len(h) == 1:
            i = index.match(h[0], t)
            if i is not None:
                index.claimed.add(i)
            res[c["conn_id"]] = dict(
                pid=h[0], method="socket-holder" + ("" if i is not None else " (no tracee connect)"), candidates=h
            )
        elif len(h) > 1:
            cr = [(p, hit) for p in h if (hit := index.match(p, t)) is not None]
            if len(cr) == 1:
                index.claimed.add(cr[0][1])
                res[c["conn_id"]] = dict(pid=cr[0][0], method="socket-holder+connect-event", candidates=h)
            else:
                res[c["conn_id"]] = dict(pid=None, method="ambiguous-holders", candidates=h)
    for c in ordered:  # pass 2: no holder found (client gone before lookup)
        if c["conn_id"] in res:
            continue
        t = when(c)
        cand = index.window(t)
        pids = sorted({index.connects[i][1] for i in cand})
        if len(cand) == 1:
            index.claimed.add(cand[0])
            res[c["conn_id"]] = dict(pid=pids[0], method="inferred-connect-window", candidates=pids)
        else:
            res[c["conn_id"]] = dict(pid=None, method="unresolved", candidates=pids)
    return res


def _shared_socket_sender(
    f: dict,
    c: dict | None,
    offset: int | None,
    sends: dict[int, list[tuple[int, int]]],
    flow_times: dict[str, list[int]],
) -> tuple[int | None, list[int]] | None:
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


def _apply_sender(r: dict, sender: tuple[int | None, list[int]], f: dict, info: dict | None) -> None:
    """A shared socket: the opener is not necessarily the sender. Record who sent this request, in place."""
    who, holders = sender
    r["opener"] = r["pid"]
    if who is not None:
        r.update(pid=who, method="socket-holder+send-event", candidates=holders)
        if who == r["opener"]:
            r["opener"] = None  # the opener also sent: nothing to add
    else:
        r.update(method="shared-socket-sender-unknown", candidates=holders)
    if info is not None and f.get("flow_id"):
        info.setdefault("flows", {})[f["flow_id"]] = {k: r[k] for k in ("pid", "method", "candidates", "opener")}


def _scope(pid: int | None, tree: set[int], tracee_capped: bool) -> str:
    """Whether the sending process is in the traced tree."""
    if pid is None:
        return "unknown"
    if pid in tree:
        return "in-tree"
    # Tracee stopped recording at its size cap: a pid it never reported may well be in the tree.
    # "outside-tree" would be a confident claim the data cannot support.
    return "unknown-tracee-capped" if tracee_capped else "outside-tree"


def join_records(
    fl: list[dict], tr: list[dict], proxy_port: int | None, info: dict | None = None, tracee_capped: bool = False
) -> list[dict]:
    """Attribute each proxy flow to the process that sent it. Calibrates the proxy and Tracee clocks, matches each
    connection's socket holders to Tracee connect events, and uses send events to pick the sender when several
    processes share a socket. Returns one record per flow with its pid, method, scope and candidates; `info`, if
    given, receives the calibration and the per-connection attribution."""
    conns, flows = _flows_to_attribute(fl)
    tree = {e["processId"] for e in tr}
    index = _ConnectIndex(_proxy_connects(tr, proxy_port))
    offset, votes = calibrate(conns, index.connects)
    if info is not None:
        info.update(offset_ns=offset, votes=votes, clock="monotonic" if offset is not None else "wall-fallback")
    # time of a connection on the Tracee clock
    when = (lambda c: c["accept_mono_ns"] + offset) if offset is not None else (lambda c: c["t_wall_ns"])
    sends = _sends_by_pid(tr)
    flow_times = _flow_times(flows)
    res = _attribute_connections(conns, when, index)
    out = []
    for f in flows:
        r = dict(res.get(f["conn_id"], dict(pid=None, method="no-connection-record", candidates=[])))
        sender = _shared_socket_sender(f, conns.get(f["conn_id"]), offset, sends, flow_times)
        if sender is not None:
            _apply_sender(r, sender, f, info)
        r["scope"] = _scope(r["pid"], tree, tracee_capped)
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


def join_run(rundir: str | Path, proxy_port: int | None) -> tuple[list[dict], list[dict], list[dict]]:
    """Load a run directory's flows and Tracee events (leaving out the recorder's own probe) and join them. Returns the
    joined records, the flows and the Tracee events."""
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
