"""Flat-file report (Markdown) rendered from the model. Readable raw in a terminal or an editor, and renders in any
Markdown viewer. All untrusted strings (command lines, URLs, headers) go through `code()` so they cannot inject
Markdown or HTML."""

from __future__ import annotations

import re
import time

from .plural import pl

SEV_MARK = {"high": "[HIGH]", "medium": "[MED] ", "low": "[LOW] ", "info": "[info]"}
VERDICT_MARK = {
    "complete": "OK",
    "complete-with-losses": "LOSSES",
    "incomplete": "INCOMPLETE",
    "in-progress": "IN PROGRESS",
}


def code(s, limit: int = 160) -> str:
    """An untrusted string as an inline code span: control characters removed, newlines flattened, pipes escaped,
    delimiter longer than any backtick run inside."""
    t = re.sub(r"[\x00-\x08\x0b-\x1f\x7f]", "", str(s if s is not None else "")).replace("\n", " ⏎ ").replace("\t", " ")
    if len(t) > limit:
        t = t[: limit - 1] + "…"
    run = max((len(m) for m in re.findall(r"`+", t)), default=0)
    d = "`" * (run + 1)
    pad = " " if t.startswith("`") or t.endswith("`") else ""
    return (d + pad + t.replace("|", "\\|") + pad + d) if t else "—"


def txt(s) -> str:
    """Untrusted prose in a table cell: no markup, no HTML, no pipes."""
    t = re.sub(r"[\x00-\x08\x0b-\x1f\x7f]", "", str(s if s is not None else "")).replace("\n", " ")
    return re.sub(r"([\\`*_{}\[\]<>|#])", r"\\\1", t)


def ts(ns: int | None) -> str:
    if ns is None:
        return "—"
    return f"+{ns / 1e9:.3f}s"


def size(n) -> str:
    if n is None:
        return "—"
    for unit, div in (("GB", 1 << 30), ("MB", 1 << 20), ("KB", 1 << 10)):
        if n >= div:
            return f"{n / div:.1f} {unit}"
    return f"{n} B"


def table(head: list[str], rows: list[list[str]]) -> str:
    if not rows:
        return "_none recorded_\n"
    out = ["| " + " | ".join(head) + " |", "|" + "|".join("---" for _ in head) + "|"]
    out += ["| " + " | ".join(r) + " |" for r in rows]
    return "\n".join(out) + "\n"


def _namer(m: dict):
    """pid-label lookup for a model: "name (pid)", or "unattributed"."""
    procs = {p["id"]: p for p in m["processes"]}

    def pname(pid):
        return f"{procs[pid]['name']} ({procs[pid]['pid']})" if pid in procs else "unattributed"

    return pname


def _header(m: dict, o: list[str]) -> None:
    """Title, verdict line, reasons, and the one-row summary table."""
    run, st = m["run"], m["stats"]
    started = (
        time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(run["started_wall_ns"] / 1e9))
        if run["started_wall_ns"]
        else "?"
    )
    o.append(f"# tracewatch report: {code(run['cmdline'], 120)}\n")
    o.append(f"**Verdict: {VERDICT_MARK.get(run['verdict'], run['verdict'])}** ({txt(run['verdict'])}). "
             f"Run `{txt(run['id'])}`, started {started} (wall clock, approximate), duration {run['duration_ns'] / 1e9:.2f} s, "
             f"target {txt((run['root_exit'] or {}).get('status', 'exit not recorded'))}.\n")  # fmt: skip
    for r in run["reasons"]:
        o.append(f"- {txt(r)}")
    o.append("")
    fc = st["findings"]
    o.append(
        table(
            [
                "Processes",
                "Commands",
                "Destinations",
                "HTTP",
                "WebSockets",
                "DNS names",
                "Watched files",
                "High",
                "Medium",
                "Low",
                "Info",
            ],
            [
                [
                    str(st["processes"]),
                    str(st["commands"]),
                    str(st["destinations"]),
                    str(st["http"]),
                    str(st["websockets"]),
                    str(st["dns_names"]),
                    str(st["files"]),
                    str(fc["high"]),
                    str(fc["medium"]),
                    str(fc["low"]),
                    str(fc["info"]),
                ]
            ],
        )
    )


def _findings(m: dict, o: list[str]) -> None:
    """The findings table and the evidence under it."""
    pname = _namer(m)
    o.append("## Findings\n")
    o.append("_Indicators to judge, not verdicts: each cites the evidence it rests on._\n")
    if m["findings"]:
        o.append(
            table(
                ["", "Rule", "Finding", "Process", "At"],
                [
                    [
                        SEV_MARK[f["severity"]],
                        f"`{f['rule']}`",
                        txt(f["title"]),
                        txt(pname(f["procs"][0])) if f["procs"] else "—",
                        ts(f["t"]),
                    ]
                    for f in m["findings"]
                ],
            )
        )
        for f in m["findings"]:
            if f["severity"] == "info":
                continue
            o.append(
                f"- **{SEV_MARK[f['severity']].strip()} {txt(f['title'])}**: {txt(f['why'])}"
                + (f" _{txt(f['detail'])}_" if f["detail"] else "")
            )
        o.append("")
    else:
        o.append("_No indicators fired._\n")


def _process_tree(m: dict, o: list[str]) -> None:
    """The process tree as text, with flagged processes marked."""
    procs = {p["id"]: p for p in m["processes"]}
    o.append("## Process tree\n")
    o.append("```text")
    flagged = {p["id"]: p["severity"] for p in m["processes"] if p["severity"] in ("medium", "high")}

    def line(p: dict, prefix: str, last: bool, root: bool) -> None:
        branch = "" if root else ("└─ " if last else "├─ ")
        ex = p["exit"]["status"] if p["exit"] else "no exit recorded"
        flag = f"  <== {flagged[p['id']].upper()}" if p["id"] in flagged else ""
        cmd = re.sub(r"[\x00-\x08\x0b-\x1f\x7f]", "", p["cmdline"]).replace("\n", " ⏎ ")
        cmd = (cmd[:100] + "…") if len(cmd) > 100 else cmd
        o.append(f"{prefix}{branch}{p['name']} [{p['pid']}] {ts(p['start'])} → {ts(p['end'])} {ex}{flag}")
        o.append(f"{prefix}{'' if root else ('   ' if last else '│  ')}   $ {cmd}")
        kids = p["children"]
        for i, c in enumerate(kids):
            line(procs[c], prefix + ("" if root else ("   " if last else "│  ")), i == len(kids) - 1, False)

    for p in m["processes"]:
        if p["parent"] is None:
            line(p, "", True, True)
    o.append("```\n")


def _destinations(m: dict, o: list[str]) -> None:
    """Network destinations."""
    o.append("## Network destinations\n")
    o.append(
        table(
            ["Via", "Destination", "Port", "Requests", "Errors", "In", "Out", "TLS"],
            [
                [
                    "proxy" if d["via"] == "proxy" else "**DIRECT (not recorded)**",
                    code(d["name"] or d["ip"]),
                    str(d["port"]),
                    str(d["requests"]),
                    str(d["errors"]),
                    size(d["bytes_in"]),
                    size(d["bytes_out"]),
                    txt(f"{d['tls']['version']} {d['tls']['alpn'] or ''}".strip()) if d.get("tls") else "—",
                ]
                for d in m["destinations"]
            ],
        )
    )


def _http(m: dict, o: list[str]) -> None:
    """HTTP requests, shared connections, and websockets."""
    pname = _namer(m)
    o.append("## HTTP requests\n")
    o.append(
        table(
            ["At", "Process", "Method", "URL", "Status", "Size", "Time"],
            [
                [
                    ts(h["t"]),
                    txt(pname(h["proc"])),
                    txt(h["method"]),
                    code(f"{h['scheme']}://{h['host']}{h['path']}", 110),
                    txt(h["status"] if h["status"] is not None else (h["error"] or "—")),
                    size((h["resp_body"] or {}).get("size")),
                    f"{h['duration_ms']} ms" if h["duration_ms"] is not None else "—",
                ]
                for h in m["http"]
            ],
        )
    )

    shared = [h for h in m["http"] if (h["attribution"] or {}).get("opener") is not None]
    if shared:
        o.append("**Shared connections** (several processes held the socket):\n")
        for h in shared:
            a, url = h["attribution"], code(f"{h['scheme']}://{h['host']}{h['path']}", 90)
            if a["method"] == "shared-socket-sender-unknown":
                o.append(f"- {url}: sender unknown; shown is the opener, candidates pids {txt(a['candidates'])}")
            else:
                o.append(
                    f"- {url}: sent by {txt(pname(h['proc']))}; connection opened by {txt(pname(a['opener_proc']))}"
                )
        o.append("")

    if m["websockets"]:
        o.append("## WebSockets\n")
        o.append(
            table(
                ["At", "Process", "Endpoint", "Messages out/in", "Close", "Clean"],
                [
                    [
                        ts(w["t"]),
                        txt(pname(w["proc"])),
                        code(f"{w['host']}{w['path']}"),
                        f"{(w['messages'] or {}).get('c2s', 0)}/{(w['messages'] or {}).get('s2c', 0)}",
                        txt(w["close_code"]),
                        "yes" if w["clean"] else "no",
                    ]
                    for w in m["websockets"]
                ],
            )
        )


def _dns(m: dict, o: list[str]) -> None:
    """DNS and name resolution."""
    pname = _namer(m)
    d = m["dns"]
    o.append("## DNS and name resolution\n")
    o.append(
        "_Names the proxy resolved are exact. For lookups a process makes itself, only the resolver contact is "
        "visible, not the name._\n"
    )
    o.append(
        table(
            ["Name", "Address(es)", "Ports", "Lookups", "Processes"],
            [
                [
                    code(x["name"]),
                    code(", ".join(x["ips"])),
                    ", ".join(map(str, x["ports"])),
                    str(x["count"]),
                    txt(", ".join(pname(p) for p in x["procs"])),
                ]
                for x in d["resolved"]
            ],
        )
    )
    o.append(
        table(
            ["Process", "Resolver contacted", "Times", "First"],
            [
                [txt(pname(c["proc"])), code(c["resolver"]), str(c["count"]), ts(c["first_t"])]
                for c in d["resolver_contacts"]
            ],
        )
    )
    if d["lookup_probes"]:
        o.append(
            f"_{pl(d['lookup_probes'], 'UDP connect() call')} right after a lookup {'is an' if d['lookup_probes'] == 1 else 'are'} address-selection {'probe' if d['lookup_probes'] == 1 else 'probes'} (no traffic)._\n"
        )


def _commands(m: dict, o: list[str]) -> None:
    """Every command that was started."""
    pname = _namer(m)
    o.append("## Commands\n")
    o.append(
        table(
            ["At", "PID", "Parent", "Command"],
            [
                [
                    ts(p["start"]),
                    str(p["pid"]),
                    txt(pname(p["parent"])) if p["parent"] else "—",
                    code(p["cmdline"], 200),
                ]
                for p in m["processes"]
            ],
        )
    )


def _files(m: dict, o: list[str]) -> None:
    """Watched file activity."""
    pname = _namer(m)
    files = [e for e in m["events"] if e["kind"] == "file"]
    o.append("## File activity (watched paths only)\n")
    o.append(
        table(
            ["At", "Process", "Access", "Class", "Path"],
            [
                [
                    ts(e["t"]),
                    txt(pname(e["proc"])),
                    txt(e["detail"]["mode"]),
                    txt(e["detail"]["category"]),
                    code(e["detail"]["path"]),
                ]
                for e in files
            ],
        )
    )


def _integrity(m: dict, o: list[str]) -> None:
    """What can be trusted in the recording."""
    o.append("## Recording integrity\n")
    ig = m["integrity"]
    o.append(
        f"Verdict **{txt(ig['verdict'])}**. Clock alignment: {txt(m['clock']['source'])} ({pl(m['clock']['votes'], 'anchor')}).\n"
    )
    for g in ig.get("gaps", []):
        o.append(f"- gap in **{txt(g['source'])}**: {txt(g['reason'])}")
    for c in ig.get("caps", []):
        o.append(f"- size cap reached: {txt(c['cap'])}")
    o.append("")


def _notes(m: dict, o: list[str]) -> None:
    """Notes, limits, and the footer."""
    o.append("## Notes and limits\n")
    for n in m["notes"]:
        o.append(f"- {txt(n)}")
    o.append(f"\n_Generated by tracewatch {txt(m['generator']['tracewatch'])}, model schema {m['schema']}._\n")


def render(m: dict) -> str:
    o: list[str] = []
    for section in (
        _header,
        _findings,
        _process_tree,
        _destinations,
        _http,
        _dns,
        _commands,
        _files,
        _integrity,
        _notes,
    ):
        section(m, o)
    return "\n".join(o)
