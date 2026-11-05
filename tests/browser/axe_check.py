"""Optional accessibility audit with axe-core over the example reports (every view, desktop and phone widths).

usage: python tests/browser/axe_check.py [PAGE.html ...]        (default: docs/examples/*.html and docs/index.html)

axe-core is not a Python package, so this is not part of `pytest`. Get it once with
    npm install --prefix /tmp/axe axe-core        (or point AXE_JS at any axe.min.js)
The script exits non-zero if axe reports any violation. The last full run (axe-core 4.14, 114 page states: 5 reports x
11 views x desktop-dark and phone-light, plus the landing and diff pages) found none."""

import os
import sys
from collections import defaultdict
from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[2]
CANDIDATES = [
    os.environ.get("AXE_JS", ""),
    "/tmp/axe/node_modules/axe-core/axe.min.js",
    str(ROOT / "node_modules/axe-core/axe.min.js"),
]
JS = "axe.run(document, {resultTypes:['violations']}).then(r => r.violations.map(v => ({id: v.id, impact: v.impact, t: v.nodes[0].target.join(' ').slice(0, 90)})))"


def main(argv: list[str]) -> int:
    axe = next((Path(c) for c in CANDIDATES if c and Path(c).exists()), None)
    if axe is None:
        print("SKIP: axe-core not found (npm install --prefix /tmp/axe axe-core, or set AXE_JS)")
        return 0
    src = axe.read_text()
    pages = [Path(a).resolve() for a in argv] or sorted((ROOT / "docs" / "examples").glob("*.html")) + [
        ROOT / "docs" / "index.html"
    ]
    found: dict[tuple, list[str]] = defaultdict(list)
    states = 0
    with sync_playwright() as pw:
        b = pw.chromium.launch()
        for scheme, w, h in (("dark", 1280, 900), ("light", 390, 844)):
            for page in pages:
                pg = b.new_page(viewport={"width": w, "height": h}, color_scheme=scheme)
                pg.goto(page.as_uri())
                pg.wait_for_timeout(700)
                pg.evaluate(src)
                is_report = pg.evaluate("window.__tw_ready === true")
                keys = list("1234567890") + ["run"] if is_report else [None]
                for key in keys:
                    if key == "run":
                        pg.evaluate("document.querySelector('.tab[data-tab=run], .moretab[data-tab=run]').click()")
                    elif key:
                        pg.keyboard.press(key)
                    pg.wait_for_timeout(300)
                    states += 1
                    for v in pg.evaluate(JS):
                        found[(v["id"], v["impact"], v["t"])].append(f"{page.name}/{key or '-'}/{scheme}{w}")
                pg.close()
        b.close()
    print(f"axe-core: {states} page states checked, {len(found)} distinct violation(s)")
    for (vid, impact, target), where in sorted(found.items()):
        print(f"  [{impact}] {vid} on {target!r}: {len(where)} state(s), e.g. {where[:3]}")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
