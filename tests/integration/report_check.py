"""Does the report tell the truth? Checks the model of a REAL recorded run of tests/fixtures/demo_workload.sh against
what that workload is known to do.  usage: report_check.py RUN_DIR"""

import json
import re
import sys
from pathlib import Path

from tracewatch.model import build
from tracewatch.report_html import render
from tracewatch.report_md import render as render_md

run = Path(sys.argv[1])
m = build(run)
P = {p["id"]: p for p in m["processes"]}
ok = True


def check(name, cond, extra=""):
    global ok
    ok &= bool(cond)
    print(("PASS " if cond else "FAIL ") + name + (f"  [{extra}]" if extra and not cond else ""))


def kids(p):
    return [P[c] for c in p["children"]]


def find(name, contains=None, parent=None):
    return [
        p
        for p in m["processes"]
        if p["name"] == name
        and (contains is None or contains in p["cmdline"])
        and (parent is None or p["parent"] == parent["id"])
    ]


root = next(p for p in m["processes"] if p["parent"] is None)
check(
    "the root is the workload script and the run's root pid",
    root["pid"] == m["run"]["root_pid"] and "demo_workload.sh" in root["cmdline"],
)
# ---- the process chain, against what the workload does
stage1 = next(p for p in kids(root) if p["name"] == "bash" and "payload.bin" in p["cmdline"])
check("`bash -c` (stage 1) is a child of the root", stage1["parent"] == root["id"])
names1 = sorted(c["name"] for c in kids(stage1))
check(
    f"stage 1's children are exactly curl x2, cp, updater, sha256sum, head ({names1})",
    names1 == sorted(["curl", "curl", "cp", "updater", "sha256sum", "head"]),
)
pyhelper = next(p for p in kids(root) if p["name"] == "python" and "subprocess" in p["cmdline"])
check(
    "the python helper spawned curl, getent, curl",
    sorted(c["name"] for c in kids(pyhelper)) == ["curl", "curl", "getent"],
)
updater = next(p for p in kids(stage1) if p["name"] == "updater")
check(
    "`updater` (the dropped file) is a grandchild at depth 2 with the right path",
    updater["depth"] == 2 and updater["exe"] == "/tmp/tw_demo/updater",
)
check(
    "the pipeline processes ls, grep, wc are children of the root",
    all(find(n, parent=root) for n in ("ls", "grep", "wc")),
)
subshells = [p for p in kids(root) if p["forked"]]
check(
    f"the three background subshells are marked as forks, each owning a sleep ({len(subshells)})",
    len(subshells) == 3 and all([c["name"] for c in kids(s)] == ["sleep"] for s in subshells),
)
# ---- exit statuses
seg = find("sh", "kill -SEGV")[0]
check(
    "kill -SEGV: killed by SIGSEGV with a core dump",
    seg["exit"]["signal"] == 11 and seg["exit"]["core"] and seg["exit"]["status"] == "killed by SIGSEGV (core dumped)",
)
check(
    "`/bin/false` exited 1 and `sh -c 'exit 3'` exited 3",
    find("false")[0]["exit"]["code"] == 1 and find("sh", "exit 3")[0]["exit"]["code"] == 3,
)
check(
    "every other process exited 0",
    all(
        p["exit"] and p["exit"]["code"] == 0
        for p in m["processes"]
        if p["id"] not in (seg["id"], find("false")[0]["id"], find("sh", "exit 3")[0]["id"])
    ),
)
# ---- HTTP attribution against each curl's own command line
by_path = {h["path"]: h for h in m["http"]}
for path, needle in (
    ("/download", "payload.bin"),
    ("/api/json", "Authorization"),
    ("/submit", "-X POST"),
    ("/missing", "/missing"),
    ("/slow", "/slow"),
):
    h = next(h for h in m["http"] if h["path"].startswith(path))
    check(
        f"{path}: attributed to the curl whose command line made it",
        h["proc"] and needle in P[h["proc"]]["cmdline"] and P[h["proc"]]["name"] == "curl",
        h["proc"],
    )
check("the 404 is recorded as an error status and counted", by_path["/missing"]["status"] == 404)
check(
    "both websocket paths and an abrupt one are recorded (3 websockets, one closed 1006)",
    len(m["websockets"]) == 3 and any(w["close_code"] == 1006 for w in m["websockets"]),
)
ws_procs = {w["proc"] for w in m["websockets"]}
check(
    "all websockets are attributed to the python client",
    len(ws_procs) == 1 and "ws_client" in P[next(iter(ws_procs))]["cmdline"],
)
check(
    "timing and server address were recorded for requests",
    all(
        h["duration_ms"] is not None and h["server_ip"]
        for h in m["http"]
        if h["method"] != "CONNECT" and not h["websocket"]
    ),
)
check(
    "TLS details recorded for https requests",
    all(h["tls"] and h["tls"]["version"].startswith("TLS") for h in m["http"] if h["scheme"] == "https"),
)
# ---- DNS
check(
    "the proxy's name -> address answer for localhost is recorded",
    any(d["name"] == "localhost" and "127.0.0.1" in d["ips"] for d in m["dns"]["resolved"]),
)
getent = find("getent")[0]
check(
    "getent's lookup shows up as resolver contacts (nscd and/or the DNS server on port 53)",
    any(c["proc"] == getent["id"] for c in m["dns"]["resolver_contacts"]),
)
# ---- files
files = [e for e in m["events"] if e["kind"] == "file"]
check(
    "payload.bin written in /tmp was recorded as a create (staging)",
    any(
        e["detail"]["path"].endswith("payload.bin")
        and e["detail"]["mode"] == "create"
        and e["detail"]["category"] == "staging"
        for e in files
    ),
)
check(
    "the decoy id_rsa read was recorded as a credential read by `cat`",
    any(
        e["detail"]["path"].endswith(".ssh/id_rsa")
        and e["detail"]["category"] == "credential"
        and P[e["proc"]]["name"] == "cat"
        for e in files
    ),
)
check(
    "the recorder's own CA bundle opens are hidden",
    not any(e["detail"]["path"].endswith("mitmproxy-ca-cert.pem") for e in files)
    and any("CA bundle" in n for n in m["notes"]),
)
# ---- findings: each one the workload is known to trigger
rules = {f["rule"]: f for f in m["findings"]}
for rule, sev in (
    ("drop-and-execute", "high"),
    ("credential-file-access", "high"),
    ("cleartext-credentials", "high"),
    ("unproxied-connection", "medium"),
    ("killed-by-signal", "medium"),
    ("secret-in-command-line", "medium"),
    ("websocket-abnormal-close", "low"),
    ("secrets-redacted", "info"),
    ("nonzero-exit", "info"),
    ("inline-code", "info"),
):
    check(f"finding {rule} fired at {sev}", rule in rules and rules[rule]["severity"] == sev)
dx = rules["drop-and-execute"]
check(
    "drop-and-execute names the writer (cp) and the executor (updater)",
    [P[x]["name"] for x in dx["procs"]] == ["cp", "updater"],
)
check(
    "unproxied-connection cites the LAN address the workload connected to directly",
    re.search(r"\d+\.\d+\.\d+\.\d+:18461", rules["unproxied-connection"]["title"]) is not None,
)
check(
    "no finding fired that the workload did not cause (no raw-ip, tls-failure, large-upload, detached)",
    not ({"raw-ip-destination", "tls-verification-failure", "large-upload", "detached-process"} & set(rules)),
)
check(
    "the run verdict is complete-with-losses, because of the direct connection",
    m["run"]["verdict"] == "complete-with-losses" and any("bypassed" in r for r in m["run"]["reasons"]),
)
# ---- redaction survives into the report
blob = json.dumps(m)
check(
    "no planted secret in the model",
    not re.search(r"DEMO(bearertoken|secrettoken|formpassword|basicpassword|sessioncookie)", blob),
)
check(
    "no nested or malformed redaction tags (regression)",
    "[REDACTED:" not in re.sub(r"\[REDACTED:[A-Za-z0-9_\-]+:[0-9a-f]{8}\]", "", blob),
)
# ---- the model is complete and consistent
check("every event's process id exists", all(e["proc"] is None or e["proc"] in P for e in m["events"]))
check(
    "every finding cites events that exist",
    all(e in {x["id"] for x in m["events"]} for f in m["findings"] for e in f["events"]),
)
check("events are ordered by time", [e["t"] for e in m["events"]] == sorted(e["t"] for e in m["events"]))
check(
    "every process starts at or before it ends, and inside the run",
    all(p["start"] >= 0 and (p["end"] is None or p["end"] >= p["start"]) for p in m["processes"]),
)
check("the clock was aligned with anchors (not the wall-clock fallback)", m["clock"]["source"] == "anchors")
# ---- the three renderers all work and agree on the headline numbers
md = render_md(m)
html = render(m)
check(
    "the Markdown report states the verdict and every process",
    "**Verdict: LOSSES**" in md and all(str(p["pid"]) in md for p in m["processes"]),
)
check(
    "the Markdown findings table has one row per finding",
    sum(
        1
        for ln in md.split("## Findings")[1].split("## Process tree")[0].splitlines()
        if re.match(r"\| \[(HIGH|MED|LOW|info)\]", ln)
    )
    == len(m["findings"]),
)
check("the HTML report embeds the same model", json.loads(html.split('id="tw-data">')[1].split("</script>")[0]) == m)
sys.exit(0 if ok else 1)
