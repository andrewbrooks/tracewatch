"""mitmproxy addon: append-only records, each stamped with wall AND monotonic time.

Records (JSONL, one per line, written with a single os.write so a kill cannot interleave them):
  conn               at client connect: who holds the client socket (pids), keyed by the unique conn_id
  connect            a CONNECT tunnel request with its destination (so a tunnel that fails is still visible)
  flow               at REQUEST time (so a flow whose client/server vanished is still on disk)
  flow_result        status, headers, body or error, keyed by flow_id
  cap_reached        a size cap was hit (soft: bodies are no longer stored; hard: nothing more is written)
  redaction_summary / cap_summary   at shutdown: counts of redacted values / dropped records
  redaction_failed   a record that could not be redacted was DROPPED (content never written)
Everything that can carry secrets goes through tracewatch.redact BEFORE the write.

Responses are STREAMED: each chunk is forwarded the moment it arrives (a streaming agent must not stall)
while a bounded copy is kept, redacted and stored when the response ends.

Configuration comes from the environment (set by the recorder): TW_FLOWS (output file), TW_REDACT_KEY
(never on disk), TW_BODY_CAP, TW_SOFT_FLOWS_BYTES, TW_MAX_FLOWS_BYTES, TW_FLAGS_DIR.
"""

import glob
import json
import os
import time
import zlib
from collections import Counter

from mitmproxy import http

from tracewatch.redact import PROCESS_CAP, Redactor

BODY_CAP = int(os.environ.get("TW_BODY_CAP") or 8192)  # stored characters per body, after redaction
SOFT_CAP = int(os.environ.get("TW_SOFT_FLOWS_BYTES") or 0) or None  # past this, bodies are no longer stored
HARD_CAP = int(os.environ.get("TW_MAX_FLOWS_BYTES") or 0) or None  # past this, nothing more is written
RESERVE = 16384  # headroom below the hard cap kept for cap markers and the final summaries
RECORD_CAP = 262144  # no single record may exceed this; oversize records lose headers/body
FLAGS_DIR = os.environ.get("TW_FLAGS_DIR")
_BIG_ENCODED = 64 * 1024  # br/zstd have no bounded decoder here: only attempt small ones

_fd = None
_written = 0
_dropped: Counter = Counter()
_hit = {"soft": False, "hard": False}
_streams: dict = {}
_red = Redactor(bytes.fromhex(os.environ["TW_REDACT_KEY"])) if os.environ.get("TW_REDACT_KEY") else Redactor()


# ---- writing, with caps -------------------------------------------------------------------------
def _flag(name: str) -> None:
    if FLAGS_DIR:
        try:
            open(os.path.join(FLAGS_DIR, name), "w").close()
        except OSError:
            pass


def _raw_write(rec: dict) -> int:
    global _fd
    if _fd is None:
        _fd = os.open(os.environ["TW_FLOWS"], os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    rec["t_wall_ns"] = time.time_ns()
    rec["t_mono_ns"] = time.monotonic_ns()
    data = (json.dumps(rec, separators=(",", ":")) + "\n").encode()
    os.write(_fd, data)
    return len(data)


def _shrink(rec: dict) -> dict:
    """An oversize record keeps its identity fields (so it can still be attributed) and loses the bulk."""
    keep = {k: v for k, v in rec.items() if k not in ("headers", "body")}
    keep["oversize_dropped"] = [k for k in ("headers", "body") if k in rec]
    return keep


def _write(rec: dict, essential: bool = False) -> None:
    """essential records (cap markers, summaries) may use the reserve below the hard cap."""
    global _written
    if len(json.dumps(rec, separators=(",", ":"))) > RECORD_CAP:
        rec = _shrink(rec)
    est = len(json.dumps(rec, separators=(",", ":"))) + 64
    limit = HARD_CAP if essential else (HARD_CAP - RESERVE if HARD_CAP else None)
    if limit is not None and _written + est > limit:
        if not _hit["hard"] and not essential:
            _hit["hard"] = True
            _flag("flows_hard_cap")
            _written += _raw_write({"kind": "cap_reached", "level": "hard", "limit": HARD_CAP, "written": _written})
        if not essential:
            _dropped[rec.get("kind", "?")] += 1
        return
    _written += _raw_write(rec)


def _bodies_allowed() -> bool:
    """Past the soft cap bodies are no longer stored (the who-talked-to-whom trail continues)."""
    if SOFT_CAP and _written >= SOFT_CAP:
        if not _hit["soft"]:
            _hit["soft"] = True
            _flag("flows_soft_cap")
            _write({"kind": "cap_reached", "level": "soft", "limit": SOFT_CAP, "written": _written}, essential=True)
        return False
    return True


def _emit(kind: str, build) -> None:
    """Build the (redacted) record, then write it. If redaction raises, the content is dropped, not written."""
    try:
        rec = build()
    except Exception as e:  # noqa: BLE001 - fail closed on anything
        rec = {"kind": "redaction_failed", "while_recording": kind, "error": type(e).__name__}
    _write(rec)


# ---- bodies ----------------------------------------------------------------------------------------
def _charset(content_type: str) -> str:
    for part in (content_type or "").split(";")[1:]:
        k, _, v = part.strip().partition("=")
        if k.lower() == "charset" and v:
            return v.strip("\"'")
    return "utf-8"


def _decode(raw: bytes, encoding: str) -> bytes:
    """Content-Encoding -> bytes, with a hard output limit (a small compressed body must not be able to
    expand into a memory bomb). Raises ValueError when the body cannot be decoded within the limit."""
    enc = (encoding or "").strip().lower()
    if enc in ("", "identity"):
        return raw
    if enc in ("gzip", "x-gzip", "deflate"):
        d = zlib.decompressobj(16 + zlib.MAX_WBITS if "gzip" in enc else zlib.MAX_WBITS)
        try:
            out = d.decompress(raw, PROCESS_CAP + 1)
        except zlib.error as e:
            raise ValueError("undecodable") from e
        if len(out) > PROCESS_CAP or d.unconsumed_tail:
            raise ValueError("decoded size over the limit")
        return out
    if enc in ("br", "zstd") and len(raw) <= _BIG_ENCODED:
        from mitmproxy.net import encoding as menc

        out = menc.decode(raw, enc)
        if len(out) > PROCESS_CAP:
            raise ValueError("decoded size over the limit")
        return out
    raise ValueError(f"content-encoding {enc!r} not decodable for capture")


def _body_record(headers, size: int, raw: bytes | None) -> dict:
    """Captured-body record for a message whose (wire) size is `size` and whose bytes are `raw` (None when
    they were not kept). Never stores anything that was not redacted first."""
    ct = headers.get("content-type", "")
    if not _bodies_allowed():
        return {"size": size, "content_type": ct or None, "captured": False, "reason": "size cap: bodies disabled"}
    if raw is None:
        return {"size": size, "content_type": ct or None, "captured": False, "reason": "too large to redact"}

    def text() -> str:
        return _decode(raw, headers.get("content-encoding", "")).decode(_charset(ct), "replace")

    try:
        return _red.body(ct, size, text, BODY_CAP)
    except ValueError as e:
        return {"size": size, "content_type": ct or None, "captured": False, "reason": str(e)}


def _msg(msg) -> dict:
    """Headers + body for a fully buffered message (requests)."""
    ct = msg.headers.get("content-type", "")
    out = {"headers": _red.headers(msg.headers.items(multi=True))}
    if msg.stream:  # mitmproxy streamed it past stream_large_bodies; we never saw the bytes
        cl = msg.headers.get("content-length", "")
        out["body"] = {
            "size": int(cl) if cl.isdigit() else None,
            "content_type": ct or None,
            "captured": False,
            "reason": "streamed (over the large-body limit)",
        }
    else:
        raw = msg.raw_content or b""
        out["body"] = _body_record(msg.headers, len(raw), raw if len(raw) <= PROCESS_CAP else None)
    return out


# ---- hooks ---------------------------------------------------------------------------------------------
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


def responseheaders(flow: http.HTTPFlow) -> None:
    """Stream every response: forward each chunk immediately, keep a bounded copy for the record."""
    st = {"buf": bytearray(), "size": 0, "over": False}
    _streams[flow.id] = st

    def tee(chunk: bytes) -> bytes:
        st["size"] += len(chunk)
        if not st["over"]:
            if len(st["buf"]) + len(chunk) > PROCESS_CAP:
                st["over"] = True
                st["buf"].clear()
            else:
                st["buf"].extend(chunk)
        return chunk

    flow.response.stream = tee


def response(flow: http.HTTPFlow) -> None:
    st = _streams.pop(flow.id, None)

    def build():
        rec = {
            "kind": "flow_result",
            "flow_id": flow.id,
            "status": flow.response.status_code,
            "headers": _red.headers(flow.response.headers.items(multi=True)),
        }
        if st is None:
            rec.update(_msg(flow.response))
        else:
            rec["body"] = _body_record(flow.response.headers, st["size"], None if st["over"] else bytes(st["buf"]))
        return rec

    _emit("flow_result", build)


def error(flow: http.HTTPFlow) -> None:
    _streams.pop(flow.id, None)
    _emit("flow_result", lambda: {"kind": "flow_result", "flow_id": flow.id, "error": _red.text(str(flow.error))})


def done() -> None:
    _write({"kind": "redaction_summary", "source": "proxy", "counts": dict(_red.counts)}, essential=True)
    _write(
        {
            "kind": "cap_summary",
            "source": "proxy",
            "soft_hit": _hit["soft"],
            "hard_hit": _hit["hard"],
            "dropped": dict(_dropped),
            "written_bytes": _written,
        },
        essential=True,
    )
