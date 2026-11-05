"""Scan a whole run directory for planted secrets (raw, URL-encoded, base64) and check the capture
still carries the non-secret markers.  usage: canary_check.py RUN_DIR SERVER_SEEN PORT"""

import base64
import json
import os
import sys
import tempfile
from urllib.parse import quote, quote_plus

from tracewatch.join import join_records, load

CANARIES = {k: v for k, v in (ln.strip().split("=", 1) for ln in open(os.environ["CANARY_FILE"]) if "=" in ln)}
SECRET_KEYS = [k for k in CANARIES if not k.startswith("VIS")]
MARKERS = {k: v for k, v in CANARIES.items() if k.startswith("VIS")}


def variants(secret: str) -> dict[str, bytes]:
    out = {
        "raw": secret.encode(),
        "urlenc": quote(secret, safe="").encode(),
        "urlenc+": quote_plus(secret).encode(),
        "b64": base64.b64encode(secret.encode()),
        "b64url": base64.urlsafe_b64encode(secret.encode()),
    }
    if len(secret) > 12:
        out["prefix12"] = secret[:12].encode()  # a truncated leak is still a leak
    return {k: v.rstrip(b"=") if k.startswith("b64") else v for k, v in out.items()}


def scan(root: str, secrets: dict[str, str]) -> list[tuple[str, str, str]]:
    hits = []
    for base, _, files in os.walk(root):
        for f in files:
            path = os.path.join(base, f)
            data = open(path, "rb").read()
            for name, secret in secrets.items():
                for vname, v in variants(secret).items():
                    if v and v in data:
                        hits.append((os.path.relpath(path, root), name, vname))
    return hits


def combos(creds: dict[str, str]) -> dict[str, str]:
    """Secrets that only ever appear embedded (basic-auth pairs are base64 of user:password)."""
    extra = {}
    for user, key in (("bob", "C_BASIC_PW"), ("alice", "C_URLPW")):
        extra[f"{user}:{key}"] = f"{user}:{creds[key]}"
    return extra


ok = True


def check(name, cond):
    global ok
    ok &= bool(cond)
    print(("PASS " if cond else "FAIL ") + name)


run, seen_path, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
secrets = {**{k: CANARIES[k] for k in SECRET_KEYS}}
secrets.update({k: v for k, v in combos(CANARIES).items()})

# 0. the scanner must be able to find something (sensitivity), or a clean scan means nothing
with tempfile.TemporaryDirectory() as d:
    leaks = {
        "raw": CANARIES["C_BEARER"],
        "b64": base64.b64encode(CANARIES["C_COOKIE"].encode()).decode(),
        "urlenc": quote(CANARIES["C_SK"], safe=""),
    }
    for i, text in enumerate(leaks.values()):
        open(f"{d}/leak{i}.txt", "w").write(f"x {text} y")
    found = {(h[1], h[2]) for h in scan(d, {k: CANARIES[k] for k in ("C_BEARER", "C_COOKIE", "C_SK")})}
    check(
        "scanner self-test: finds raw, base64 and url-encoded planted leaks",
        {("C_BEARER", "raw"), ("C_COOKIE", "b64"), ("C_SK", "urlenc")} <= found,
    )

# 1. the canaries really travelled to the server (so redaction was applied to the RECORD, not the traffic)
seen = open(seen_path).read()
needed = ["C_BEARER", "C_COOKIE", "C_XAPIKEY", "C_QUERY", "C_JSON_PW", "C_FORM_PW", "C_SK", "C_AWS", "C_JWT"]
check("server received every planted secret unmodified", all(CANARIES[k] in seen for k in needed))
check(
    "server received both Basic credentials (base64)",
    all(base64.b64encode(v.encode()).decode() in seen for v in combos(CANARIES).values()),
)

# 2. nothing planted is anywhere in the run directory
hits = scan(run, secrets)
for h in hits:
    print(f"  LEAK: {h[1]} ({h[2]}) in {h[0]}")
check("NO planted secret appears anywhere in the run directory (all files, 5 encodings)", not hits)

# 2b. Docker must not keep a raw copy of the Tracee output (the log driver is `none`)
base = os.path.dirname(os.path.dirname(os.path.abspath(run)))
drv = open(f"{base}/logdriver.txt").read().strip() if os.path.exists(f"{base}/logdriver.txt") else None
dl = open(f"{base}/dockerlogs.txt").read() if os.path.exists(f"{base}/dockerlogs.txt") else ""
check(f"the live Tracee container uses log driver 'none' (saw {drv!r})", drv == "none")
check(
    "`docker logs` on the live container yields no events (nothing persisted to read back)",
    drv is not None and '"eventName"' not in dl and "does not support reading" in dl,
)

# 3. the capture is real: non-secret markers survived, structure intact
flows_raw = open(f"{run}/flows.jsonl").read()
for k, v in MARKERS.items():
    check(f"marker {k} captured", v in flows_raw)
check(
    "numeric fields preserved (max_tokens, input_tokens)",
    '\\"max_tokens\\":5' in flows_raw and "input_tokens" in flows_raw,
)
fl = load(f"{run}/flows.jsonl")
tr = [e for e in load(f"{run}/tracee.jsonl") if "eventName" in e and e["processName"] != "twprobe"]
summary = [r for r in fl if r["kind"] == "redaction_summary"]
check("proxy wrote a redaction summary with counts", bool(summary) and sum(summary[-1]["counts"].values()) >= 10)
check("no redaction_failed records (nothing had to be dropped)", not [r for r in fl if r["kind"] == "redaction_failed"])
man = json.load(open(f"{run}/manifest.json"))
check(
    "manifest argv is redacted and still shows the program",
    "CANARY" not in json.dumps(man["argv"]) and man["argv"][0].endswith("canary_workload.sh"),
)
check("manifest records recorder-side redaction counts", sum(man["redactions"]["recorder"].values()) >= 3)
# argv in Tracee events: redacted but still informative
execs = [e for e in tr if e["eventName"] == "sched_process_exec"]
curl = [e for e in execs if e["processName"] == "curl"]
check(
    "tracee curl exec events kept (argv still visible, secrets gone)",
    len(curl) >= 7 and all(any(a["name"] == "argv" and a["value"][0] == "curl" for a in e["args"]) for e in curl),
)
check(
    "tracee env-assignment argv is redacted but the program is visible",
    any(
        a["name"] == "argv" and a["value"][:1] == ["env"] and any("FOO_API_KEY=[REDACTED:" in x for x in a["value"])
        for e in execs
        for a in e["args"]
    ),
)

# 4. redaction did not break attribution
rows = join_records(fl, tr, man["proxy_port"])
check(
    "join still attributes the 6 flows in-tree after redaction",
    sum(r["scope"] == "in-tree" and not r["path"].startswith("CONNECT") for r in rows) == 6,
)
failed = [r for r in rows if r["path"] == "CONNECT localhost:1"]
check(
    "the refused tunnel (CONNECT localhost:1) is recorded with its destination and attributed in-tree",
    len(failed) == 1 and failed[0]["scope"] == "in-tree" and failed[0]["pid"] is not None,
)
check(
    "the refused tunnel has an error result record",
    any(r["kind"] == "flow_result" and "error" in r for r in fl),
)
sys.exit(0 if ok else 1)
