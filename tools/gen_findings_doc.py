"""Write docs/FINDINGS.md from the finding catalog.   usage: python tools/gen_findings_doc.py"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from tracewatch.findings_catalog import render_markdown  # noqa: E402

if __name__ == "__main__":
    out = ROOT / "docs" / "FINDINGS.md"
    out.write_text(render_markdown())
    print(f"wrote {out.relative_to(ROOT)}")
