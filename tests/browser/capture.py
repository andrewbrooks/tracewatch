"""Open a report in headless Chromium, collect console/page errors, screenshot every tab.
usage: capture.py REPORT.html OUT_DIR [tab ...]     (set LD_LIBRARY_PATH if Chromium libs are missing)"""

import os
import sys
from pathlib import Path

from playwright.sync_api import sync_playwright

TABS = ["overview", "tree", "timeline", "network", "http", "dns", "commands", "files", "events", "findings", "run"]


def main(report: str, outdir: str, tabs: list[str]) -> int:
    out = Path(outdir)
    out.mkdir(parents=True, exist_ok=True)
    errors: list[str] = []
    with sync_playwright() as p:
        b = p.chromium.launch()
        pg = b.new_page(viewport={"width": 1500, "height": 920}, color_scheme=os.environ.get("THEME", "dark"))
        pg.on(
            "console",
            lambda m: errors.append(f"console.{m.type}: {m.text}") if m.type in ("error", "warning") else None,
        )
        pg.on("pageerror", lambda e: errors.append(f"pageerror: {e}"))
        pg.on("requestfailed", lambda r: errors.append(f"requestfailed: {r.url}"))
        pg.goto(Path(report).resolve().as_uri())
        pg.wait_for_function("window.__tw_ready === true", timeout=15000)
        for t in tabs or TABS:
            pg.click(f'.tab[data-tab="{t}"]')
            pg.wait_for_timeout(700)
            pg.screenshot(path=str(out / f"{t}.png"))
        b.close()
    for e in errors:
        print("ERROR", e)
    print(f"{len(errors)} error(s); screenshots in {out}")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2], sys.argv[3:]))
