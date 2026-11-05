"""mitmproxy addon: append-only records, each stamped with wall AND monotonic time.

Records (JSONL, one per line, written with a single os.write so a kill cannot interleave them):
  conn               at client connect: who holds the client socket (pids), keyed by the unique conn_id
  connect            a CONNECT tunnel request with its destination (so a tunnel that fails is still visible)
  flow               at REQUEST time (so a flow whose client/server vanished is still on disk)
  flow_result        status, headers, body or error, keyed by flow_id
  redaction_summary  at shutdown: how many values were redacted, by kind
  redaction_failed   a record that could not be redacted was DROPPED (content never written)
Everything that can carry secrets goes through tracewatch.redact BEFORE the write. Loaded by mitmdump
via `-s`; the output path comes from TW_FLOWS and the redaction key from TW_REDACT_KEY (never on disk).
"""

import glob
import json
import os
import time

from mitmproxy import http

from tracewatch.redact import Redactor

BODY_CAP = 8192  # stored characters per body, after redaction
_fd = None
_red = Redactor(bytes.fromhex(os.environ["TW_REDACT_KEY"])) if os.environ.get("TW_REDACT_KEY") else Redactor()


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


def _emit(kind: str, build) -> None:
    """Build the (redacted) record, then write it. If redaction raises, the content is dropped, not written."""
    try:
        rec = build()
    except Exception as e:  # noqa: BLE001 - fail closed on anything
        rec = {"kind": "redaction_failed", "while_recording": kind, "error": type(e).__name__}
    _write(rec)


def _msg(msg) -> dict:
    ct = msg.headers.get("content-type", "")
    return {
        "headers": _red.headers(msg.headers.items(multi=True)),
        "body": _red.body(ct, len(msg.raw_content or b""), lambda: msg.get_text(strict=False) or "", BODY_CAP),
    }


def http_connect(flow: http.HTTPFlow) -> None:
    _emit(
        "connect",
        lambda: {
            "kind": "connect",
            "flow_id": flow.id,
            "conn_id": flow.client_conn.id,
            "client_port": flow.client_conn.peername[1],
            "host": _red.text(flow.request.host),
            "port": flow.request.port,
        },
    )


def http_connect_error(flow: http.HTTPFlow) -> None:
    _emit("flow_result", lambda: {"kind": "flow_result", "flow_id": flow.id, "error": _red.text(str(flow.error))})


def request(flow: http.HTTPFlow) -> None:
    _emit(
        "flow",
        lambda: {
            "kind": "flow",
            "flow_id": flow.id,
            "conn_id": flow.client_conn.id,
            "client_port": flow.client_conn.peername[1],
            "http_version": flow.request.http_version,
            "scheme": flow.request.scheme,
            "host": flow.request.pretty_host,
            "method": flow.request.method,
            "path": _red.url(flow.request.path),
            **_msg(flow.request),
        },
    )


def response(flow: http.HTTPFlow) -> None:
    _emit(
        "flow_result",
        lambda: {"kind": "flow_result", "flow_id": flow.id, "status": flow.response.status_code, **_msg(flow.response)},
    )


def error(flow: http.HTTPFlow) -> None:
    _emit("flow_result", lambda: {"kind": "flow_result", "flow_id": flow.id, "error": _red.text(str(flow.error))})


def done() -> None:
    _write({"kind": "redaction_summary", "source": "proxy", "counts": dict(_red.counts)})
