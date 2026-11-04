"""mitmproxy addon: append-only records, each stamped with wall AND monotonic time.

Records (JSONL, one per line, written with a single os.write so a kill cannot interleave them):
  conn         at client connect: who holds the client socket (pids), keyed by the unique conn_id
  flow         at REQUEST time (so a flow whose client/server vanished is still on disk)
  flow_result  status or error, keyed by flow_id
Loaded by mitmdump via `-s`; the output path comes from the TW_FLOWS environment variable.
"""

import glob
import json
import os
import time

from mitmproxy import http

_fd = None


def _write(rec: dict) -> None:
    global _fd
    if _fd is None:
        _fd = os.open(os.environ["TW_FLOWS"], os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    rec["t_wall_ns"] = time.time_ns()
    rec["t_mono_ns"] = time.monotonic_ns()
    os.write(_fd, (json.dumps(rec, separators=(",", ":")) + "\n").encode())


def _inode(sport: int, pport: int):
    for fn in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            rows = open(fn).read().splitlines()[1:]
        except OSError:
            continue
        for r in rows:
            p = r.split()
            if int(p[1].rsplit(":", 1)[1], 16) == sport and int(p[2].rsplit(":", 1)[1], 16) == pport and p[9] != "0":
                return p[9]
    return None


def _holders(inode: str):
    want, pids, n = f"socket:[{inode}]", set(), 0
    for d in glob.glob("/proc/[0-9]*/fd"):
        n += 1
        try:
            for fd in os.listdir(d):
                if os.readlink(f"{d}/{fd}") == want:
                    pids.add(int(d.split("/")[2]))
        except OSError:
            continue
    return sorted(pids), n


def client_connected(client) -> None:
    t0 = time.perf_counter()
    sport, pport = client.peername[1], client.sockname[1]
    inode = None
    for _ in range(4):  # the socket row may lag accept by ~ms; capped because this blocks the proxy loop
        inode = _inode(sport, pport)
        if inode:
            break
        time.sleep(0.002)
    holders, nproc = _holders(inode) if inode else ([], 0)
    lag = time.time_ns() - int(client.timestamp_start * 1e9)
    _write(
        {
            "kind": "conn",
            "conn_id": client.id,
            "client_port": sport,
            "proxy_port": pport,
            "inode": inode,
            "holder_pids": holders,
            "accept_mono_ns": time.monotonic_ns() - lag,
            "lookup_ms": round((time.perf_counter() - t0) * 1000, 2),
            "procs_scanned": nproc,
        }
    )


def request(flow: http.HTTPFlow) -> None:
    _write(
        {
            "kind": "flow",
            "flow_id": flow.id,
            "conn_id": flow.client_conn.id,
            "client_port": flow.client_conn.peername[1],
            "http_version": flow.request.http_version,
            "scheme": flow.request.scheme,
            "host": flow.request.pretty_host,
            "method": flow.request.method,
            "path": flow.request.path,
        }
    )


def response(flow: http.HTTPFlow) -> None:
    _write({"kind": "flow_result", "flow_id": flow.id, "status": flow.response.status_code})


def error(flow: http.HTTPFlow) -> None:
    _write({"kind": "flow_result", "flow_id": flow.id, "error": str(flow.error)})
