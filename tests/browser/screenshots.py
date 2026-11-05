"""README screenshots from a sanitized copy of a recording.
usage: screenshots.py RUN_DIR OUT_DIR [demo|sim]   (e.g. out/demo/runs/demo docs/screenshots)

The page is rendered from a model whose paths, user/host names and IP addresses have been replaced, and the script
refuses to take a single screenshot if any identifying literal of THIS machine is still present in that page."""

import sys
import tempfile
from pathlib import Path

from playwright.sync_api import sync_playwright
from sanitize import identity, leaks, sanitize

HERE = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(HERE / "src"))
from tracewatch.model import build  # noqa: E402
from tracewatch.report_html import render  # noqa: E402

SHOTS = [  # name, colour scheme, key to press, viewport, after-hook
    ("overview-dark", "dark", "1", (1400, 900), None),
    ("overview-light", "light", "1", (1400, 900), None),
    ("process-tree", "dark", "3", (1400, 900), None),
    ("http-detail", "dark", "8", (1400, 900), "row"),
    ("findings-light", "light", "2", (1400, 900), None),
    ("phone-dark", "dark", "1", (390, 844), None),
]


SIM_SHOTS = [  # the simulated-intruder run: where the chain, the findings drawer and the rule reference show up
    ("sim-overview-dark", "dark", "1", (1400, 900), None),
    ("sim-finding-detail-dark", "dark", "2", (1400, 900), "finding"),
    ("sim-rule-reference-light", "light", "2", (1400, 900), "reference"),
]


def main(run_dir: str, out_dir: str, profile: str = "demo") -> int:
    ident = identity()
    model = sanitize(build(Path(run_dir)), ident)
    html = render(model)
    bad = leaks(html, ident)
    if bad:
        print("REFUSING to screenshot: the sanitized page still contains:", *bad[:10], sep="\n  ")
        return 1
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as td, sync_playwright() as pw:
        page_file = Path(td) / "report.html"
        page_file.write_text(html)
        b = pw.chromium.launch()
        for name, scheme, key, (w, h), hook in SIM_SHOTS if profile == "sim" else SHOTS:
            pg = b.new_page(viewport={"width": w, "height": h}, color_scheme=scheme)
            pg.goto(page_file.as_uri())
            pg.wait_for_function("window.__tw_ready === true")
            pg.keyboard.press(key)
            pg.wait_for_timeout(700)
            if hook == "finding":
                pg.locator(".view.on .finding", has_text="reverse shell").first.click()
                pg.wait_for_timeout(600)
            if hook == "reference":
                pg.locator("details.refrules summary").click()
                pg.locator("details.refrules").scroll_into_view_if_needed()
                pg.wait_for_timeout(400)
            if hook == "row":
                pg.locator(".view.on .tbl-row").nth(1).click()
                pg.wait_for_timeout(600)
            text = pg.evaluate("document.title + ' ' + document.body.innerText")
            bad = leaks(text, ident)
            if bad:
                print(f"REFUSING {name}: visible text contains", *bad[:5], sep="\n  ")
                return 1
            pg.screenshot(path=str(out / f"{name}.png"))
            print("wrote", out / f"{name}.png")
            pg.close()
        b.close()
    return 0


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:4]))
