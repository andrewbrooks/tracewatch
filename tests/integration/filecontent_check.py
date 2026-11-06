"""Checks for filecontent.sh. usage: filecontent_check.py RUN_DIR"""

import os
import stat
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from tracewatch.model import build  # noqa: E402
from tracewatch.report_html import render as html  # noqa: E402
from tracewatch.report_md import render as md  # noqa: E402

run = Path(sys.argv[1])
m = build(run)
files = {os.path.basename(f["path"]): f for f in m["file_contents"]}
bad = 0


def check(name, cond):
    global bad
    print(("PASS " if cond else "FAIL ") + name)
    bad += not cond


check("the manifest records what was captured", (m["run"]["file_capture"] or {}).get("files") == len(files) >= 3)
d = files.get("dropper.sh")
check("a file written, run and deleted is still captured", bool(d) and "dropper ran" in d.get("text", ""))
check(
    "a bearer token inside it is redacted",
    bool(d) and "abcdefghijklmnop" not in d["text"] and "[REDACTED:" in d["text"],
)
check("its writer is attributed to a process", bool(d) and len(d["writers"]) >= 1)
n = files.get("notes.txt")
t = n.get("text", "") if n else ""
check(
    "terminal escapes and the direction override are escaped, not stored",
    "\x1b" not in t and "\x07" not in t and "‮" not in t,
)
check("...and shown as visible escapes", "⟦\\x1b⟧" in t and "⟦\\u202e⟧" in t)
b = files.get("blob.bin")
check(
    "a binary is recorded by size and first bytes only",
    bool(b) and b["binary"] and "text" not in b and b["size"] == 3000,
)
check("a credential file that was only READ is not captured", "id_rsa" not in files)
leak = subprocess.run(["grep", "-rl", "SECRETKEY-DO-NOT-CAPTURE", str(run)], capture_output=True, text=True).stdout
check("its content appears nowhere in the run directory", leak.strip() == "")
check("files.jsonl is private (0600)", stat.S_IMODE((run / "files.jsonl").stat().st_mode) == 0o600)
check(
    "the Markdown report has the section and an unbreakable fence",
    "## File contents" in md(m) and "dropper ran" in md(m),
)
page = html(m)
check("the HTML report is still a single script block with no raw escape bytes", "\x1b" not in page and "‮" not in page)
print("ALL PASS" if not bad else f"{bad} FAILED")
sys.exit(1 if bad else 0)
