"""Reconstruction: turn a run directory into ONE JSON-serializable model.

Everything a report shows (text, Markdown, the interactive HTML) is rendered from this structure, so the
formats cannot disagree. Pure function of the files in the run directory: no Docker, no network, no clock.

Time is nanoseconds relative to T0, the moment the target's root process exec'd, on the Tracee clock. Proxy
records carry CLOCK_MONOTONIC stamps; they are mapped onto the Tracee clock with the offset the join
calibrates from unambiguous (connection, connect) pairs (the wall clock steps on some hosts and is never used
when an anchor exists). Where a fact is not visible to the recorder the model says so in `notes`; it does not
guess."""

from __future__ import annotations

import json
import os
import shlex
from collections import Counter, defaultdict
from pathlib import Path

from . import __version__
from . import tracee as tracee_cfg
from .findings import find
from .findings_catalog import CATALOG
from .integrity import assess
from .join import join_records, load
from .plural import pl

SCHEMA = 1
STAGING = ("/tmp/", "/var/tmp/", "/dev/shm/")
SIGNAL_NAMES = {
    1: "SIGHUP",
    2: "SIGINT",
    3: "SIGQUIT",
    4: "SIGILL",
    6: "SIGABRT",
    7: "SIGBUS",
    8: "SIGFPE",
    9: "SIGKILL",
    11: "SIGSEGV",
    13: "SIGPIPE",
    14: "SIGALRM",
    15: "SIGTERM",
}
RESOLVER_SOCKETS = {
    "/var/run/nscd/socket": "nscd",
    "/run/nscd/socket": "nscd",
    "/run/systemd/resolve/io.systemd.Resolve": "systemd-resolved",
}
PROBE_WINDOW_NS = 1_000_000_000  # UDP connects this soon after a resolver contact are address-selection probes


def _args(e: dict) -> dict:
    return {a["name"]: a.get("value") for a in e.get("args", [])}


def cmdline(argv: list[str]) -> str:
    return " ".join(shlex.quote(str(a)) for a in argv)


def classify_path(path: str) -> str:
    """credential | staging | other, by the same name/directory rules the Tracee file filter uses."""
    base = os.path.basename(path)
    if base in tracee_cfg.SENSITIVE_NAMES or base.endswith(tracee_cfg.SENSITIVE_SUFFIXES):
        return "credential"
    if any(path == p or path.startswith(p.rstrip("*")) for p in tracee_cfg.SENSITIVE_ABSOLUTE):
        return "credential"
    if any(f"/{d}/" in path for d in tracee_cfg.SENSITIVE_HOME_DIRS):
        return "credential"
    if path.startswith(STAGING):
        return "staging"
    return "other"


def decode_open_flags(flags: int) -> str:
    """read | write | create-write from open(2) flags (O_WRONLY=1, O_RDWR=2, O_CREAT=0o100, O_TRUNC=0o1000)."""
    if flags & 0o100:
        return "create"
    if flags & 3 or flags & 0o1000 or flags & 0o2000:
        return "write"
    return "read"


def decode_exit(a: dict) -> dict:
    code, sig = int(a.get("exit_code") or 0), int(a.get("signal_code") or 0)
    if sig:
        n = sig & 0x7F
        name = SIGNAL_NAMES.get(n, f"signal {n}")
        core = bool(sig & 0x80)
        return {
            "code": None,
            "signal": n,
            "signal_name": name,
            "core": core,
            "status": f"killed by {name}" + (" (core dumped)" if core else ""),
        }
    return {
        "code": code,
        "signal": None,
        "signal_name": None,
        "core": False,
        "status": "exited 0" if code == 0 else f"exited {code}",
    }


def _is_ip(s: str) -> bool:
    import ipaddress

    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def _is_loopback(s: str) -> bool:
    import ipaddress

    try:
        return ipaddress.ip_address(s).is_loopback
    except ValueError:
        return False


class _Clock:
    """Maps proxy monotonic stamps onto the Tracee clock, relative to T0."""

    def __init__(self, offset: int, source: str, t0: int):
        self.offset, self.source, self.t0 = offset, source, t0

    def rel(self, rec: dict, key: str = "t_mono_ns") -> int:
        return rec[key] + self.offset - self.t0


class _Timeline:
    """The event log under construction: kernel and proxy events are added in any order, then sorted and numbered."""

    def __init__(self) -> None:
        self.events: list[dict] = []
        self._last_resolver: dict[tuple, dict] = {}

    def add(self, t: int, kind: str, proc: dict | None, title: str, sub: str | None = None, **detail) -> dict:
        e = {"t": t, "kind": kind, "sub": sub, "proc": proc["id"] if proc else None, "title": title, "detail": detail}
        self.events.append(e)
        return e

    def add_resolver(self, t: int, proc: dict | None, resolver: str, title: str, **detail) -> None:
        """glibc makes several socket calls per lookup; contacts with the same resolver by the same process within
        50 ms are ONE event with a count, so the log shows the lookup once, not as an echo."""
        key = (proc["id"] if proc else None, resolver)
        prev = self._last_resolver.get(key)
        if prev is not None and t - prev["t"] <= 50_000_000:
            prev["detail"]["count"] += 1
            prev["title"] = f"{title} ×{prev['detail']['count']}"
            return
        self._last_resolver[key] = self.add(t, "dns", proc, title, "resolver", resolver=resolver, count=1, **detail)

    def finish(self) -> list[dict]:
        self.events.sort(key=lambda x: x["t"])
        for i, e in enumerate(self.events):
            e["id"] = f"e{i}"
        return self.events


class _Attribution:
    """Who a proxy record belongs to: a pid from the join, resolved to the process that held it at that moment."""

    def __init__(self, procs: list[dict], info: dict):
        self.by_pid: dict[int, list[dict]] = defaultdict(list)
        for p in procs:
            self.by_pid[p["pid"]].append(p)
        self.conn_attr = info.get("connections", {})
        self.flow_attr = info.get("flows", {})  # per-request overrides: the sender on a socket several processes hold

    def proc_at(self, pid: int | None, t_rel: int) -> dict | None:
        cands = self.by_pid.get(pid, []) if pid is not None else []
        if not cands:
            return None
        live = [
            p
            for p in cands
            if p["start"] <= t_rel + 50_000_000 and (p["end"] is None or t_rel <= p["end"] + 50_000_000)
        ]
        return (live or cands)[-1]

    def conn_proc(self, conn_id: str, t_rel: int, flow_id: str | None = None) -> tuple[dict | None, dict]:
        a = self.flow_attr.get(flow_id) or self.conn_attr.get(conn_id) or {}
        return self.proc_at(a.get("pid"), t_rel), a


class _Kernel:
    """What reading the kernel events produced besides timeline entries."""

    def __init__(self, ca_loads: int, proxy_connects: int, udp_probes: Counter):
        self.ca_loads, self.proxy_connects, self.udp_probes = ca_loads, proxy_connects, udp_probes


def _load_optional(path: Path) -> list[dict]:
    return load(path) if path.exists() else []


def _time_zero(tr: list[dict], root_pid: int | None, notes: list[str]) -> int:
    """T0 = the root process's exec of the real command (the wrapper's probe loop before it is dropped)."""
    root_execs = [e["timestamp"] for e in tr if e["processId"] == root_pid and e["eventName"] == "sched_process_exec"]
    if root_execs:
        return min(root_execs)
    if tr:
        notes.append("The target's exec was not recorded; time zero is the first recorded event.")
        return min(e["timestamp"] for e in tr)
    notes.append("Tracee recorded no events for the target.")
    return 0


def _drop_wrapper_noise(tr: list[dict], root_pid: int | None, t0: int) -> list[dict]:
    """Drop what the recorder's wrapper spawned BEFORE the root's exec (its probe loop). A time window is not enough:
    such a child can exit a fraction of a millisecond after T0. Anything born before the root's exec, other than
    the root itself, is not part of the target."""
    born: dict[int, int] = {}
    for e in tr:
        born[e["processEntityId"]] = min(
            born.get(e["processEntityId"], 1 << 62), e.get("threadStartTime") or e["timestamp"]
        )
    root_eids = {e["processEntityId"] for e in tr if e["processId"] == root_pid}
    pre_exec = {eid for eid, b0 in born.items() if b0 < t0 - 1_000_000 and eid not in root_eids}
    return [e for e in tr if e["processEntityId"] not in pre_exec and e["timestamp"] >= t0 - 1_000_000]


def _align_clocks(
    fl: list[dict], tr: list[dict], raw: list[dict], manifest: dict, t0: int, notes: list[str]
) -> tuple[dict, _Clock]:
    """Proxy monotonic stamps -> Tracee clock, from the join's calibration (or the start-of-run pair as a fallback)."""
    info: dict = {}
    capped = any(e.get("kind") == "cap_reached" for e in raw)
    join_records(fl, tr, manifest.get("proxy_port"), info, tracee_capped=capped)
    offset = info.get("offset_ns")
    source = "anchors"
    if offset is None:
        started = manifest.get("started", {})
        offset = (started.get("t_wall_ns", 0) - started.get("t_mono_ns", 0)) if started else 0
        source = "manifest-pair"
        notes.append(
            "No unambiguous (connection, connect) pair was available to align the proxy and kernel clocks; the "
            "alignment uses the start-of-run clock pair and may be off by a second or two where the wall clock stepped."
        )
    return info, _Clock(offset, source, t0)


def _kernel_events(
    tr: list[dict], by_eid: dict, t0: int, proxy_port: int | None, ca_path: str, tl: _Timeline
) -> _Kernel:
    """Tracee events -> timeline entries (exec, exit, tcp, unix, udp, resolver contacts, watched file opens)."""
    dns_probe_until: dict[int, int] = {}  # eid -> abs ts until which UDP connects are lookup probes
    ca_loads = 0
    proxy_connects = 0
    udp_probes = Counter()
    for e in sorted(tr, key=lambda x: x["timestamp"]):
        p = by_eid.get(e["processEntityId"])
        t = e["timestamp"] - t0
        a = _args(e)
        name = e["eventName"]
        if name == "sched_process_exec":
            argv = [str(x) for x in (a.get("argv") or [])]
            tl.add(
                t,
                "exec",
                p,
                cmdline(argv) or a.get("pathname", "?"),
                exe=a.get("pathname"),
                argv=argv,
                cwd=a.get("pwd"),
            )
        elif name == "sched_process_exit":
            if a.get("process_group_exit"):
                x = decode_exit(a)
                tl.add(t, "exit", p, x["status"], **x)
        elif name == "net_tcp_connect":
            dst, port = a.get("dst"), a.get("dst_port")
            if port == proxy_port:
                proxy_connects += 1
                continue
            tl.add(t, "tcp", p, f"{dst}:{port}", dst=dst, port=port, loopback=_is_loopback(str(dst)))
        elif name == "security_socket_connect":
            ra = a.get("remote_addr") or {}
            fam, typ = ra.get("sa_family"), a.get("type")
            if fam == "AF_UNIX":
                path = ra.get("sun_path", "")
                res = RESOLVER_SOCKETS.get(path)
                if res and p:
                    dns_probe_until[p["_eid"]] = e["timestamp"] + PROBE_WINDOW_NS
                if res:
                    tl.add_resolver(t, p, res, f"lookup via {res}", path=path)
                else:
                    tl.add(t, "unix", p, path or "(abstract)", path=path)
            elif fam in ("AF_INET", "AF_INET6") and typ == 2:
                ip = ra.get("sin_addr") or ra.get("sin6_addr")
                port = int(ra.get("sin_port") or ra.get("sin6_port") or 0)
                if port == 53 and p:
                    dns_probe_until[p["_eid"]] = e["timestamp"] + PROBE_WINDOW_NS
                    tl.add_resolver(t, p, f"{ip}:53", f"query sent to resolver {ip}", ip=ip)
                else:
                    probe = bool(p and e["timestamp"] <= dns_probe_until.get(p["_eid"], 0))
                    if probe:
                        udp_probes[p["id"] if p else None] += 1
                    tl.add(t, "udp", p, f"{ip}:{port}", "probe" if probe else None, dst=ip, port=port, probe=probe)
        elif name == "security_file_open":
            path = a.get("pathname") or a.get("syscall_pathname") or ""
            if path == ca_path:
                ca_loads += 1
                continue
            mode = decode_open_flags(int(a.get("flags") or 0))
            tl.add(t, "file", p, f"{mode} {path}", mode, path=path, mode=mode, category=classify_path(path))
    return _Kernel(ca_loads, proxy_connects, udp_probes)


class _ProxyIndex:
    """The proxy's flat record list, indexed the ways the row builders need."""

    def __init__(self, fl: list[dict]):
        self.tls_by_conn: dict[str, dict] = {}
        for r in fl:
            if r["kind"] == "tls" and r["conn_id"] not in self.tls_by_conn:
                self.tls_by_conn[r["conn_id"]] = {k: r.get(k) for k in ("version", "cipher", "alpn", "sni", "cert")}
        self.results = {r["flow_id"]: r for r in fl if r["kind"] == "flow_result"}
        self.ws_msgs: dict[str, list[dict]] = defaultdict(list)
        self.ws_close: dict[str, dict] = {}
        self.ws_open: dict[str, dict] = {}
        for r in fl:
            if r["kind"] == "ws_message":
                self.ws_msgs[r["flow_id"]].append(
                    {"seq": r["seq"], "dir": r["dir"], "opcode": r["opcode"], "body": r["body"]}
                )
            elif r["kind"] == "ws_close":
                self.ws_close[r["flow_id"]] = r
            elif r["kind"] == "ws_open":
                self.ws_open[r["flow_id"]] = r
        self.port_by_conn = {r["conn_id"]: r.get("port") for r in fl if r["kind"] == "resolve"}
        self.tls_refused = {r["conn_id"]: r for r in fl if r["kind"] == "tls_failed" and r.get("side") == "client"}
        self.tls_ok = {r["conn_id"] for r in fl if r["kind"] == "tls_client"}


def _http_rows(fl: list[dict], px: _ProxyIndex, clock: _Clock, who: _Attribution, tl: _Timeline) -> list[dict]:
    """One row per proxied request (and one timeline event each)."""
    http: list[dict] = []
    for r in fl:
        if r["kind"] != "flow":
            continue
        t = clock.rel(r)
        p, attr = who.conn_proc(r["conn_id"], t, r["flow_id"])
        res = px.results.get(r["flow_id"], {})
        body_in, body_out = r.get("body") or {}, res.get("body") or {}
        is_ws = r["flow_id"] in px.ws_open
        status = res.get("status")
        err = res.get("error")
        title = f"{r['method']} {r['scheme']}://{r['host']}{r['path']}"
        h = {
            "id": r["flow_id"],
            "t": t,
            "proc": p["id"] if p else None,
            "method": r["method"],
            "scheme": r["scheme"],
            "host": r["host"],
            "path": r["path"],
            "status": status,
            "error": err,
            "http_version": r.get("http_version"),
            "port": px.port_by_conn.get(r["conn_id"]) or (443 if r["scheme"] in ("https", "wss") else 80),
            "duration_ms": res.get("duration_ms"),
            "ttfb_ms": res.get("ttfb_ms"),
            "server_ip": res.get("server_ip"),
            "req_headers": r.get("headers") or [],
            "req_body": body_in,
            "resp_headers": res.get("headers") or [],
            "resp_body": body_out,
            "conn_id": r["conn_id"],
            "websocket": is_ws,
            "tls": px.tls_by_conn.get(r["conn_id"]),
            "attribution": {
                "method": attr.get("method"),
                "pid": attr.get("pid"),
                "candidates": attr.get("candidates", []),
                "opener": attr.get("opener"),
                "opener_proc": (who.proc_at(attr["opener"], t) or {}).get("id") if attr.get("opener") else None,
            },
        }
        http.append(h)
        sub = "websocket" if is_ws else ("error" if err else None)
        tl.add(
            t,
            "http",
            p,
            title,
            sub,
            flow_id=r["flow_id"],
            status=status,
            error=err,
            host=r["host"],
            method=r["method"],
        )
    return http


def _websocket_rows(px: _ProxyIndex, clock: _Clock, who: _Attribution, tl: _Timeline) -> list[dict]:
    websockets = []
    for fid, o in px.ws_open.items():
        c = px.ws_close.get(fid, {})
        t = clock.rel(o)
        p, _ = who.conn_proc(o["conn_id"], t)
        websockets.append(
            {
                "flow_id": fid,
                "t": t,
                "proc": p["id"] if p else None,
                "host": o["host"],
                "path": o["path"],
                "subprotocol": o.get("subprotocol"),
                "close_code": c.get("close_code"),
                "close_reason": c.get("close_reason"),
                "clean": c.get("clean"),
                "closed_by_client": c.get("closed_by_client"),
                "messages": c.get("messages") or {},
                "bytes": c.get("bytes") or {},
                "suppressed": (c.get("suppressed") or {}).get("records", 0),
                "t_close": clock.rel(c) if c else None,
                "log": px.ws_msgs.get(fid, []),
            }
        )
        tl.add(t, "ws", p, f"websocket {o['host']}{o['path']}", "open", flow_id=fid)
        if c:
            tl.add(
                clock.rel(c),
                "ws",
                p,
                f"websocket closed {c.get('close_code')}",
                "close",
                flow_id=fid,
                clean=c.get("clean"),
            )
    return websockets


def _tunnel_note(px: _ProxyIndex, conn_id: str, res: dict) -> str | None:
    """Why a CONNECT tunnel produced no request, when the proxy saw the reason."""
    if conn_id in px.tls_refused:
        return "client refused the recorder's certificate (pinning, or it does not trust the CA): content not recorded"
    if conn_id in px.tls_ok and not res.get("status"):
        return (
            "TLS completed, then the client sent no request (a certificate pin checked after the handshake "
            "looks like this; so does an idle pre-connect)"
        )
    return None


def _tunnel_rows(
    fl: list[dict], px: _ProxyIndex, with_flows: set, clock: _Clock, who: _Attribution, tl: _Timeline
) -> list[dict]:
    """CONNECT tunnels that never carried a request (refused, failed, non-HTTP), so they still show up."""
    rows = []
    for r in fl:
        if r["kind"] != "connect" or r["conn_id"] in with_flows:
            continue
        t = clock.rel(r)
        p, attr = who.conn_proc(r["conn_id"], t)
        res = px.results.get(r["flow_id"], {})
        h = {
            "id": r["flow_id"],
            "t": t,
            "proc": p["id"] if p else None,
            "method": "CONNECT",
            "scheme": "tunnel",
            "host": r["host"],
            "path": f":{r['port']}",
            "port": r["port"],
            "status": res.get("status"),
            "error": res.get("error") or _tunnel_note(px, r["conn_id"], res),
            "http_version": None,
            "duration_ms": None,
            "ttfb_ms": None,
            "server_ip": None,
            "req_headers": [],
            "req_body": {},
            "resp_headers": [],
            "resp_body": {},
            "conn_id": r["conn_id"],
            "websocket": False,
            "tls": None,
            "tls_refused": px.tls_refused[r["conn_id"]]["error"] if r["conn_id"] in px.tls_refused else None,
            "attribution": {
                "method": attr.get("method"),
                "pid": attr.get("pid"),
                "candidates": attr.get("candidates", []),
            },
        }
        rows.append(h)
        tl.add(
            t,
            "http",
            p,
            f"CONNECT {r['host']}:{r['port']}",
            "error" if res.get("error") else "tunnel",
            flow_id=r["flow_id"],
            error=res.get("error"),
            host=r["host"],
        )
    return rows


def _resolved_names(
    fl: list[dict], clock: _Clock, who: _Attribution, tl: _Timeline
) -> tuple[dict[str, dict], dict[str, str]]:
    """DNS as the proxy saw it (name asked for -> address returned)."""
    resolved: dict[str, dict] = {}
    for r in fl:
        if r["kind"] != "resolve":
            continue
        t = clock.rel(r)
        p, _ = who.conn_proc(r["conn_id"], t)
        d = resolved.setdefault(
            r["name"],
            {
                "name": r["name"],
                "ips": [],
                "ports": [],
                "count": 0,
                "procs": [],
                "first_t": t,
                "ip_literal": _is_ip(r["name"]),
            },
        )
        d["count"] += 1
        d["first_t"] = min(d["first_t"], t)
        for key, val in (("ips", r.get("ip")), ("ports", r.get("port")), ("procs", p["id"] if p else None)):
            if val is not None and val not in d[key]:
                d[key].append(val)
        if not d["ip_literal"]:
            tl.add(t, "dns", p, f"{r['name']} → {r.get('ip')}", "resolve", name=r["name"], ip=r.get("ip"))
    ip_to_name = {ip: n for n, d in resolved.items() if not d["ip_literal"] for ip in d["ips"]}
    return resolved, ip_to_name


def _link_http_events(http: list[dict], ev: list[dict]) -> None:
    """An HTTP record's event is its own http event; a websocket's open/close events share the flow id and must not
    overwrite it (the upgrade request is what evidence should point at)."""
    ev_by_flow = {e["detail"]["flow_id"]: e["id"] for e in ev if e["kind"] == "http" and e["detail"].get("flow_id")}
    for h in http:
        h["event"] = ev_by_flow.get(h["id"])


def _count_events_per_process(procs: list[dict], ev: list[dict]) -> None:
    by_id = {p["id"]: p for p in procs}
    for e in ev:
        p = by_id.get(e["proc"])
        if p is not None:
            c = p["counts"]
            c[e["kind"]] = c.get(e["kind"], 0) + 1


def _closing_notes(notes: list[str], manifest: dict, ca_loads: int) -> None:
    """What the model cannot see, stated where the reader will find it."""
    if ca_loads:
        notes.append(
            f"{pl(ca_loads, 'open')} of the recorder's own CA bundle (loaded by TLS clients) "
            f"{'is' if ca_loads == 1 else 'are'} hidden from the file list."
        )
    if manifest.get("file_watch"):
        notes.append(
            "File activity covers only the watched paths (credential stores and temp directories), not every open."
        )
    notes.append(
        "DNS query names are not visible for lookups a process makes itself; names the proxy resolved are exact."
    )
    notes.append("UDP payloads (including QUIC/HTTP3) are never recorded; a UDP connect() is shown, not its traffic.")
    notes.append("Redaction is heuristic: treat the underlying run directory as sensitive.")


_RECORDER_EVENT_KINDS = (
    "component_died",
    "cap_reached",
    "signal_received",
    "target_stopped",
    "target_killed",
    "recording_armed",
)


def _recorder_events(rec_events: list[dict], clock: _Clock) -> list[dict]:
    return [
        {
            "t": e["t_mono_ns"] + clock.offset - clock.t0,
            "kind": e["kind"],
            **{k: v for k, v in e.items() if k in ("component", "cap", "reason", "signal")},
        }
        for e in rec_events
        if e["kind"] in _RECORDER_EVENT_KINDS
    ]


def _attach_findings(model: dict) -> None:
    """Run the rules, then mark each process with its most severe finding and the findings that cite it."""
    model["findings"] = find(model)
    model["catalog"] = (
        CATALOG  # the finding dictionary: what each rule means, its benign look-alikes, its evidence status
    )
    sev_by_proc: dict[str, int] = {}
    order = {"info": 0, "low": 1, "medium": 2, "high": 3}
    for f in model["findings"]:
        for pid_ in f["procs"]:
            sev_by_proc[pid_] = max(sev_by_proc.get(pid_, 0), order[f["severity"]])
    names = {v: k for k, v in order.items()}
    for p in model["processes"]:
        p["severity"] = names.get(sev_by_proc.get(p["id"], -1)) if p["id"] in sev_by_proc else None
        p["findings"] = [f["id"] for f in model["findings"] if p["id"] in f["procs"]]
    model["stats"]["findings"] = {s: sum(1 for f in model["findings"] if f["severity"] == s) for s in order}


def build(run_dir: Path | str) -> dict:
    """Read a run directory and assemble the model. The steps run in a fixed order (the event log is built up in that
    order before it is sorted, so the order is part of the output)."""
    run_dir = Path(run_dir)
    manifest = json.loads((run_dir / "manifest.json").read_text())
    integ = assess(run_dir)
    fl = _load_optional(run_dir / "flows.jsonl")
    raw = _load_optional(run_dir / "tracee.jsonl")
    rec_events = _load_optional(run_dir / "events.jsonl")
    tr = [e for e in raw if "eventName" in e and e.get("processName") != "twprobe"]
    notes: list[str] = []
    root_pid = manifest.get("root_pid")

    # time zero, the target's own events only, and the proxy clock mapped onto the kernel clock
    t0 = _time_zero(tr, root_pid, notes)
    tr = _drop_wrapper_noise(tr, root_pid, t0)
    info, clock = _align_clocks(fl, tr, raw, manifest, t0, notes)

    # processes, then everything that happened, in the order the timeline is built
    procs = _build_processes(tr, root_pid, t0)
    who = _Attribution(procs, info)
    tl = _Timeline()
    ca_path = str(run_dir.resolve() / "ca" / "mitmproxy-ca-cert.pem")
    kernel = _kernel_events(tr, {p["_eid"]: p for p in procs}, t0, manifest.get("proxy_port"), ca_path, tl)
    px = _ProxyIndex(fl)
    http = _http_rows(fl, px, clock, who, tl)
    websockets = _websocket_rows(px, clock, who, tl)
    http += _tunnel_rows(fl, px, {h["conn_id"] for h in http}, clock, who, tl)
    resolved, ip_to_name = _resolved_names(fl, clock, who, tl)
    ev = tl.finish()
    _link_http_events(http, ev)

    # aggregates
    destinations = _destinations(http, ev, ip_to_name, procs)
    dns = _dns(ev, resolved, kernel.udp_probes, ip_to_name)
    _count_events_per_process(procs, ev)
    end_t = max([e["t"] for e in ev] + [p["end"] or 0 for p in procs] + [0])
    root = next((p for p in procs if p["parent"] is None and p["pid"] == root_pid), procs[0] if procs else None)
    run_end = next((p["end"] for p in procs if root and p["id"] == root["id"] and p["end"] is not None), end_t)
    _closing_notes(notes, manifest, kernel.ca_loads)

    model = {
        "schema": SCHEMA,
        "generator": {"tracewatch": __version__},
        "run": _run_meta(manifest, integ, root, run_end),
        "integrity": {k: v for k, v in integ.items() if k not in ("files",)} | {"files": integ.get("files", {})},
        "clock": {"source": clock.source, "offset_ns": clock.offset, "votes": info.get("votes", 0), "t0_tracee_ns": t0},
        "processes": [{k: v for k, v in p.items() if not k.startswith("_")} for p in procs],
        "events": ev,
        "http": sorted(http, key=lambda h: h["t"]),
        "websockets": websockets,
        "destinations": destinations,
        "dns": dns,
        "notes": notes,
        "redactions": manifest.get("redactions") or {},
        "recorder_events": _recorder_events(rec_events, clock),
        "stats": {
            "processes": len(procs),
            "max_depth": max([p["depth"] for p in procs] + [0]),
            "events": len(ev),
            "http": len(http),
            "websockets": len(websockets),
            "destinations": len(destinations),
            "dns_names": len(dns["resolved"]),
            "files": sum(1 for e in ev if e["kind"] == "file"),
            "proxy_connects": kernel.proxy_connects,
            "duration_ns": run_end,
            "commands": sum(1 for e in ev if e["kind"] == "exec"),
        },
    }
    _attach_findings(model)
    return model


def _run_meta(manifest: dict, integ: dict, root: dict | None, run_end: int) -> dict:
    started = (manifest.get("started") or {}).get("t_wall_ns")
    return {
        "id": manifest.get("run_id"),
        "argv": manifest.get("argv") or [],
        "cmdline": cmdline(manifest.get("argv") or []),
        "cwd": manifest.get("cwd"),
        "started_wall_ns": started,
        "duration_ns": run_end,
        "status": manifest.get("status"),
        "verdict": integ.get("verdict"),
        "reasons": integ.get("reasons", []),
        "policy": manifest.get("policy"),
        "versions": manifest.get("versions"),
        "root_pid": manifest.get("root_pid"),
        "proxy_port": manifest.get("proxy_port"),
        "root_exit": root["exit"] if root else None,
        "limits": manifest.get("limits"),
        "caps_hit": manifest.get("caps_hit", []),
        "lost_components": manifest.get("lost_components", []),
        "degraded": manifest.get("degraded"),
        "file_watch": manifest.get("file_watch") or [],
    }


def _build_processes(tr: list[dict], root_pid: int | None, t0: int) -> list[dict]:
    nodes: dict[int, dict] = {}
    for e in sorted(tr, key=lambda x: x["timestamp"]):
        eid = e["processEntityId"]
        n = nodes.get(eid)
        if n is None:
            n = nodes[eid] = {
                "_eid": eid,
                "_parent_eid": e.get("parentEntityId"),
                "pid": e["processId"],
                "ppid": e["parentProcessId"],
                "uid": e.get("userId"),
                "name": e.get("processName"),
                "exe": None,
                "argv": [],
                "cwd": None,
                "execs": [],
                "_start_raw": e.get("threadStartTime") or e["timestamp"],
                "end": None,
                "exit": None,
                "children": [],
                "counts": {},
            }
        n["_start_raw"] = min(n["_start_raw"], e.get("threadStartTime") or e["timestamp"])
        n["name"] = e.get("processName") or n["name"]
        a = _args(e)
        if e["eventName"] == "sched_process_exec":
            argv = [str(x) for x in (a.get("argv") or [])]
            n["execs"].append({"t": e["timestamp"] - t0, "exe": a.get("pathname"), "argv": argv})
            n["exe"], n["argv"], n["cwd"] = a.get("pathname"), argv, a.get("pwd") or n["cwd"]
        elif e["eventName"] == "sched_process_exit" and a.get("process_group_exit"):
            n["end"] = e["timestamp"] - t0
            n["exit"] = decode_exit(a)
    for n in nodes.values():
        n["start"] = max(0, n["_start_raw"] - t0)
        n["cmdline"] = cmdline(n["argv"]) if n["argv"] else (n["name"] or "?")
        n["forked"] = False
        if n["argv"] and n["argv"][0]:
            n["name"] = os.path.basename(n["argv"][0].lstrip("-")) or n["name"]  # what was typed: `sh`, not `dash`
        elif n["exe"]:
            n["name"] = os.path.basename(n["exe"])
    # tree structure
    for n in nodes.values():
        par = nodes.get(n["_parent_eid"])
        n["_parent"] = par if par is not None and par is not n else None
        if n["_parent"] is not None:
            n["_parent"]["children"].append(n)
    roots = [n for n in nodes.values() if n["_parent"] is None]
    roots.sort(key=lambda n: (n["pid"] != root_pid, n["start"]))
    ordered: list[dict] = []

    def walk(n: dict, depth: int) -> None:
        n["depth"] = depth
        ordered.append(n)
        n["children"].sort(key=lambda c: c["start"])
        for c in n["children"]:
            walk(c, depth + 1)

    for r in roots:
        walk(r, 0)
    for n in ordered:  # a fork that never exec'd is the same program as its parent (a subshell, a worker)
        par = n["_parent"]
        if not n["execs"] and par is not None:
            n["exe"], n["argv"], n["cmdline"], n["cwd"] = (
                par["exe"],
                par["argv"],
                par["cmdline"],
                n["cwd"] or par["cwd"],
            )
            n["name"], n["forked"] = par["name"], True
    for i, n in enumerate(ordered, 1):
        n["id"] = f"p{i}"
    for n in ordered:
        n["parent"] = n["_parent"]["id"] if n["_parent"] else None
        n["detached"] = n["_parent"] is None and n["pid"] != root_pid
        n["children"] = [c["id"] for c in n["children"]]
        n["end_known"] = n["end"] is not None
    return ordered


def _destinations(http: list[dict], ev: list[dict], ip_to_name: dict[str, str], procs: list[dict]) -> list[dict]:
    d: dict[tuple, dict] = {}

    def slot(key: tuple, **init) -> dict:
        return d.setdefault(
            key,
            {
                "via": init["via"],
                "name": init.get("name"),
                "ip": init.get("ip"),
                "port": init["port"],
                "requests": 0,
                "errors": 0,
                "bytes_in": 0,
                "bytes_out": 0,
                "procs": [],
                "first_t": None,
                "tls": None,
                "loopback": init.get("loopback", False),
            },
        )

    def touch(x: dict, t: int, proc: str | None) -> None:
        x["first_t"] = t if x["first_t"] is None else min(x["first_t"], t)
        if proc and proc not in x["procs"]:
            x["procs"].append(proc)

    for h in http:
        port = h["port"]
        x = slot(
            ("proxy", h["host"], port),
            via="proxy",
            name=h["host"],
            port=port,
            ip=h.get("server_ip"),
            loopback=_is_loopback(h["host"]) or h["host"] == "localhost",
        )
        x["requests"] += 1
        x["errors"] += 1 if h["error"] or (h["status"] or 0) >= 400 else 0
        x["bytes_out"] += (h["req_body"] or {}).get("size") or 0
        x["bytes_in"] += (h["resp_body"] or {}).get("size") or 0
        x["ip"] = x["ip"] or h.get("server_ip")
        x["tls"] = x["tls"] or h.get("tls")
        touch(x, h["t"], h["proc"])
    for e in ev:
        if e["kind"] == "tcp":
            dd = e["detail"]
            x = slot(
                ("direct", dd["dst"], dd["port"]),
                via="direct",
                ip=dd["dst"],
                port=dd["port"],
                loopback=dd["loopback"],
                name=ip_to_name.get(dd["dst"]),
            )
            x["requests"] += 1
            touch(x, e["t"], e["proc"])
    out = sorted(d.values(), key=lambda x: (x["via"] != "direct", -x["requests"], x["name"] or x["ip"] or ""))
    return out


def _dns(ev: list[dict], resolved: dict, udp_probes: Counter, ip_to_name: dict[str, str]) -> dict:
    contacts: dict[tuple, dict] = {}
    for e in ev:
        if e["kind"] == "dns" and e["sub"] == "resolver":
            k = (e["proc"], e["detail"]["resolver"])
            c = contacts.setdefault(
                k, {"proc": e["proc"], "resolver": e["detail"]["resolver"], "count": 0, "first_t": e["t"]}
            )
            c["count"] += e["detail"].get("count", 1)
    probes = sum(udp_probes.values())
    return {
        "resolved": sorted(resolved.values(), key=lambda x: (x["ip_literal"], -x["count"], x["name"])),
        "resolver_contacts": sorted(contacts.values(), key=lambda c: (-c["count"], c["resolver"])),
        "lookup_probes": probes,
        "ip_names": ip_to_name,
    }
