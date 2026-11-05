"""Behavioural diff of two recordings: what did the process do differently the second time?

Pure functions over two models (see model.py). Values that differ between any two runs of the same program
(pids, timestamps, temp names, hex ids, query strings) are normalised away so the diff shows behaviour, not noise.
Exit status of `tracewatch diff` is like diff(1): 0 = no behavioural change, 1 = changed."""

from __future__ import annotations

import re
from collections import Counter

from .report_md import code, table, txt

SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3}
NOTABLE_MAX = 15
VERDICT_RANK = {"complete": 0, "complete-with-losses": 1, "incomplete": 2, "in-progress": 2}


def norm(s: str) -> str:
    """Collapse the parts of a string that change from run to run."""
    s = re.sub(r"\?.*$", "", s) if s.startswith("/") else s
    s = re.sub(r"\[REDACTED:(\w+):[0-9a-f]+\]", r"[REDACTED:\1]", s)  # the tag is keyed per run: never equal
    s = re.sub(r"/tmp/[^/\s'\"]+", "/tmp/*", s)
    s = re.sub(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b", "<uuid>", s)
    s = re.sub(r"\b[0-9a-fA-F]{12,}\b", "<hex>", s)
    return re.sub(r"\d{4,}", "<n>", s)


def _set_diff(a: dict, b: dict) -> dict:
    """a, b: key -> info. Added/removed/common keys."""
    return {
        "added": [{"key": k, **b[k]} for k in sorted(b.keys() - a.keys())],
        "removed": [{"key": k, **a[k]} for k in sorted(a.keys() - b.keys())],
        "common": sorted(a.keys() & b.keys()),
    }


def _commands(m):
    c = Counter(norm(p["cmdline"]) for p in m["processes"])
    return {k: {"count": n} for k, n in c.items()}


def _destinations(m):
    out = {}
    for d in m["destinations"]:
        k = f"{d['name'] or d['ip']}:{d['port']}"
        o = out.setdefault(k, {"via": d["via"], "requests": 0, "errors": 0, "ip": d["ip"]})
        o["requests"] += d["requests"]
        o["errors"] += d["errors"]
        if d["via"] == "direct":
            o["via"] = "direct"
    return out


def _http(m):
    out = {}
    for h in m["http"]:
        k = f"{h['method']} {h['scheme']}://{h['host']}{norm(h['path'])}"
        o = out.setdefault(k, {"count": 0, "status": Counter()})
        o["count"] += 1
        o["status"][h.get("status") or h.get("error") or "—"] += 1
    return out


def _files(m):
    out = {}
    for e in m["events"]:
        if e["kind"] == "file":
            k = f"{e['sub']} {norm(e['detail']['path'])}"
            out[k] = {"category": e["detail"].get("category")}
    return out


def _findings(m):
    out = {}
    for f in m["findings"]:
        k = f"{f['rule']}: {norm(f['title'])}"
        o = out.setdefault(k, {"severity": f["severity"], "count": 0})
        o["count"] += 1
        if SEV_RANK[f["severity"]] > SEV_RANK[o["severity"]]:
            o["severity"] = f["severity"]
    return out


def _dns(m):
    return {d["name"]: {"ips": d["ips"]} for d in m["dns"]["resolved"] if not d.get("ip_literal")}


def _changed(a: dict, b: dict, fields) -> list[dict]:
    out = []
    for k in sorted(a.keys() & b.keys()):
        delta = {f: [a[k][f], b[k][f]] for f in fields if a[k].get(f) != b[k].get(f)}
        if delta:
            out.append({"key": k, "delta": delta})
    return out


def compare(a: dict, b: dict) -> dict:
    """Diff model a (before) against model b (after)."""
    cmds = _set_diff(_commands(a), _commands(b))
    ca, cb = _commands(a), _commands(b)
    cmds["changed"] = _changed(ca, cb, ["count"])
    dest = _set_diff(_destinations(a), _destinations(b))
    dest["changed"] = _changed(_destinations(a), _destinations(b), ["via", "requests", "errors"])
    ha, hb = _http(a), _http(b)
    for h in (ha, hb):
        for v in h.values():
            v["status"] = dict(v["status"])
    http = _set_diff(ha, hb)
    http["changed"] = _changed(ha, hb, ["count", "status"])
    dns = _set_diff(_dns(a), _dns(b))
    files = _set_diff(_files(a), _files(b))
    fa, fb = _findings(a), _findings(b)
    fnd = _set_diff(fa, fb)
    fnd["changed"] = _changed(fa, fb, ["severity", "count"])
    va, vb = a["integrity"]["verdict"], b["integrity"]["verdict"]
    integrity = {"before": va, "after": vb, "worse": VERDICT_RANK.get(vb, 2) > VERDICT_RANK.get(va, 2)}
    sections = {
        "commands": cmds,
        "destinations": dest,
        "http": http,
        "dns": dns,
        "files": files,
        "findings": fnd,
    }
    notable = []
    for d in dest["added"]:
        notable.append(f"new destination {d['key']}" + (" (BYPASSED THE PROXY)" if d["via"] == "direct" else ""))
    for d in dest["changed"]:
        if "via" in d["delta"] and d["delta"]["via"][1] == "direct":
            notable.append(f"{d['key']} now bypasses the proxy")
    for f in fnd["added"]:
        if SEV_RANK[f["severity"]] >= SEV_RANK["medium"]:
            notable.append(f"new {f['severity']} finding: {f['key']}")
    for f in fnd["changed"]:
        if "severity" in f["delta"] and SEV_RANK[f["delta"]["severity"][1]] > SEV_RANK[f["delta"]["severity"][0]]:
            notable.append(f"finding escalated to {f['delta']['severity'][1]}: {f['key']}")
    for f in files["added"]:
        if f["category"] and f["category"] != "other":
            notable.append(f"new {f['category']} file activity: {f['key']}")
    for c in cmds["added"]:
        notable.append(f"new command: {c['key']}")
    if integrity["worse"]:
        notable.append(f"recording trustworthiness got worse: {va} -> {vb}")
    changed = any(s["added"] or s["removed"] or s.get("changed") for s in sections.values())
    return {
        "before": _runinfo(a),
        "after": _runinfo(b),
        "integrity": integrity,
        "sections": sections,
        "notable": notable,
        "changed": changed,
    }


def _runinfo(m):
    r = m["run"]
    return {
        "id": r["id"],
        "cmdline": r["cmdline"],
        "verdict": m["integrity"]["verdict"],
        "duration_ns": r["duration_ns"],
        "stats": {k: m["stats"][k] for k in ("processes", "http", "destinations", "dns_names", "files", "commands")},
    }


# ----------------------------------------------------------------------------------------------- markdown
def _counts(s):
    return f"+{len(s['added'])} / -{len(s['removed'])}" + (f" / ~{len(s['changed'])}" if s.get("changed") else "")


def _dl(delta):
    return ", ".join(f"{k}: {code(v[0], 40)} → {code(v[1], 40)}" for k, v in delta.items())


def render_md(d: dict) -> str:
    b, a = d["before"], d["after"]
    o = ["# tracewatch diff\n"]
    o.append(f"- before: {code(b['id'])} {code(b['cmdline'], 100)} ({b['verdict']}, {b['duration_ns'] / 1e9:.1f}s)")
    o.append(f"- after:  {code(a['id'])} {code(a['cmdline'], 100)} ({a['verdict']}, {a['duration_ns'] / 1e9:.1f}s)\n")
    if not d["changed"]:
        o.append("**No behavioural change**: same commands, destinations, requests, files and findings.\n")
    else:
        o.append("## What changed\n")
        for n in (d["notable"] or ["no notable single change; see the sections below"])[:NOTABLE_MAX]:
            o.append(f"- {txt(n)}")
        if len(d["notable"]) > NOTABLE_MAX:
            o.append(f"- …and {len(d['notable']) - NOTABLE_MAX} more (see the sections below)")
        o.append("")
    stats = [[k, str(b["stats"][k]), str(a["stats"][k]), f"{a['stats'][k] - b['stats'][k]:+d}"] for k in b["stats"]]
    o.append("## Totals\n")
    o.append(table(["", "before", "after", "change"], stats))
    names = {
        "commands": "Commands",
        "destinations": "Destinations",
        "http": "HTTP requests",
        "dns": "DNS names",
        "files": "File activity",
        "findings": "Findings",
    }
    for key, s in d["sections"].items():
        o.append(f"## {names[key]} ({_counts(s)})\n")
        if not (s["added"] or s["removed"] or s.get("changed")):
            o.append("_no difference_\n")
            continue
        rows = []
        for it in s["added"]:
            rows.append(["added", code(it["key"], 150), txt(_extra(it))])
        for it in s["removed"]:
            rows.append(["removed", code(it["key"], 150), txt(_extra(it))])
        for it in s.get("changed", []):
            rows.append(["changed", code(it["key"], 150), _dl(it["delta"])])
        o.append(table(["", "item", "detail"], rows))
    if d["integrity"]["before"] != d["integrity"]["after"]:
        o.append(f"## Recording\n\nVerdict changed: {d['integrity']['before']} → {d['integrity']['after']}\n")
    return "\n".join(o)


def _extra(it):
    return ", ".join(f"{k}={v}" for k, v in it.items() if k != "key" and v not in (None, "", [], {}))
