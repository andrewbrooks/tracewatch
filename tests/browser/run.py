"""Browser tests for the interactive report (headless Chromium via Playwright).

usage: run.py [DEMO_RUN_DIR]      (default out/demo/runs/demo; produced by tests/fixtures/demo.sh)
If Chromium cannot start because system libraries are missing, set LD_LIBRARY_PATH to a directory holding them."""

import json
import sys
import tempfile
import time
from pathlib import Path

from playwright.sync_api import sync_playwright

HERE = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(HERE / "tests"))
sys.path.insert(0, str(HERE / "tests" / "browser"))
import synth  # noqa: E402

from tracewatch import report_html  # noqa: E402
from tracewatch.model import build  # noqa: E402

OUT = HERE / "out" / "browser"
ok = True


def check(name, cond, extra=""):
    global ok
    ok &= bool(cond)
    print(("PASS " if cond else "FAIL ") + name + (f"  [{extra}]" if extra and not cond else ""))


def skip(name, why):
    print(f"SKIP {name}: {why}")


def write_report(model, name):
    OUT.mkdir(parents=True, exist_ok=True)
    p = OUT / name
    p.write_text(report_html.render(model))
    return p


class Session:
    """A page with every console message / page error / failed request / dialog recorded."""

    def __init__(self, browser, path, hash_="", width=1500, height=920):
        self.errors, self.dialogs, self.violations = [], [], []
        self.page = browser.new_page(viewport={"width": width, "height": height})
        self.page.on(
            "console", lambda m: self.errors.append(f"{m.type}: {m.text}") if m.type in ("error", "warning") else None
        )
        self.page.on("pageerror", lambda e: self.errors.append(f"pageerror: {e}"))
        self.page.on("requestfailed", lambda r: self.errors.append(f"requestfailed: {r.url}"))
        self.page.on("dialog", lambda d: (self.dialogs.append(d.message), d.dismiss()))
        t0 = time.time()
        self.page.goto(Path(path).resolve().as_uri() + hash_)
        self.page.wait_for_function("window.__tw_ready === true", timeout=30000)
        self.load_s = time.time() - t0

    def tab(self, t):
        self.page.click(f'.tab[data-tab="{t}"]')
        self.page.wait_for_timeout(450)

    def rows(self):
        return self.page.locator(".view.on .tbl-row").count()

    def count_label(self):  # "N rows" text of the visible table
        return self.page.locator(".view.on .tools .muted.num, .view.on .card-h .muted.num").first.inner_text()


def n_rows(sess):
    txt = sess.page.locator(".view.on .muted.num").filter(has_text="row").first.inner_text()
    return int(txt.split()[0].replace(",", ""))


def run_demo(b, demo_dir):
    model = build(demo_dir)
    path = write_report(model, "demo.html")
    st = model["stats"]
    s = Session(b, path)
    p = s.page
    check("demo report loads and the app starts", True)
    kpis = [int(x.replace(",", "")) for x in p.locator(".kpi .v").all_inner_texts()]
    check(
        f"KPI tiles match the model {kpis}",
        kpis == [len(model["findings"]), st["processes"], st["destinations"], st["http"], st["dns_names"], st["files"]],
    )
    for t in (
        "overview",
        "tree",
        "timeline",
        "network",
        "http",
        "dns",
        "commands",
        "files",
        "events",
        "findings",
        "run",
    ):
        s.tab(t)
        shown = p.evaluate("() => [...document.querySelectorAll('.view.on')].map(v => v.id)")
        check(
            f"tab {t}: exactly its own view is shown and the hash follows",
            shown == [f"view-{t}"] and p.evaluate("location.hash").startswith(f"#/{t}"),
        )
    # --- process tree
    s.tab("tree")
    shown = p.locator("#view-tree .toolbar .muted").inner_text()
    check(f"tree shows every process ({shown})", shown.startswith(f"{st['processes']} of {st['processes']}"))
    check("tree has one node per process", p.locator("g.node").count() == st["processes"])
    target = next(x for x in model["processes"] if x["depth"] == 2 and x["name"] == "cp")
    p.locator(f'g.node[aria-label^="cp pid {target["pid"]}"]').dispatch_event("click")
    p.wait_for_timeout(500)
    check(
        "selecting a node opens the drawer with the exact command line",
        p.locator("#drawer.open").count() == 1
        and target["cmdline"][:40] in p.locator("#drawer pre.code").first.inner_text(),
    )
    chain = p.locator("#drawer .chain").first.locator(".cn").all_inner_texts()
    check(f"the process chain has depth+1 links ({len(chain)})", len(chain) == target["depth"] + 1)
    check(
        "the selected node is marked and its lineage highlighted",
        p.locator("g.node.sel").count() == 1 and p.locator(".edge.hl").count() >= 1,
    )
    p.keyboard.press("Escape")
    p.wait_for_timeout(350)
    check("Escape closes the drawer", p.locator("#drawer.open").count() == 0)
    p.click("button:has-text('Flagged paths only')")
    p.wait_for_timeout(300)
    flagged = int(p.locator("#view-tree .toolbar .muted").inner_text().split()[0])
    want = len(
        {
            c.id if hasattr(c, "id") else c["id"]
            for pr in model["processes"]
            if pr["severity"] in ("medium", "high")
            for c in _chain(model, pr["id"])
        }
    )
    check(f"'flagged paths only' keeps exactly the flagged processes and their ancestors ({flagged})", flagged == want)
    # --- global search -> commands
    s.tab("commands")
    total = n_rows(s)
    check(f"commands table lists every process ({total})", total == st["processes"])
    p.fill("#search", "curl")
    p.wait_for_timeout(450)
    want = sum(
        1 for x in model["processes"] if "curl" in (x["cmdline"] + x["name"] + str(x["pid"]) + (x["cwd"] or "")).lower()
    )
    check(
        f"global search filters the table to matching commands ({n_rows(s)} of {total})",
        n_rows(s) == want and want < total,
    )
    p.fill("#search", "")
    p.wait_for_timeout(450)
    check("clearing the search restores every row", n_rows(s) == total)
    # --- http filters + drawer
    s.tab("http")
    errs = sum(1 for h in model["http"] if h["error"] or (h["status"] or 0) >= 400)
    p.select_option('select[aria-label="Status"]', "err")
    p.wait_for_timeout(350)
    check(f"HTTP 'errors' filter shows only failures ({n_rows(s)})", n_rows(s) == errs)
    p.select_option('select[aria-label="Status"]', "")
    p.locator(".view.on .tbl-row").first.click()
    p.wait_for_timeout(400)
    h0 = sorted(model["http"], key=lambda h: h["t"])[0]
    dr = p.locator("#drawer").inner_text()
    check(
        "clicking a request opens its detail (URL, status, headers, TLS)",
        h0["host"] in dr and h0["path"] in dr and "REQUEST HEADERS" in dr.upper() and "TLS" in dr.upper(),
    )
    p.keyboard.press("Escape")
    # --- findings filter
    s.tab("findings")
    cards = p.locator("#view-findings .finding").count()
    check(f"findings view shows every finding ({cards})", cards == len(model["findings"]))
    p.click("#view-findings .lg:has(.sev-info)")
    p.wait_for_timeout(250)
    non_info = sum(1 for f in model["findings"] if f["severity"] != "info")
    check(
        "turning 'info' off hides exactly the info findings", p.locator("#view-findings .finding").count() == non_info
    )
    # --- time range brush on the overview chart
    s.tab("overview")
    box = p.locator("#view-overview svg.chart rect[fill='transparent']").bounding_box()
    p.mouse.move(box["x"] + box["width"] * 0.05, box["y"] + 40)
    p.mouse.down()
    p.mouse.move(box["x"] + box["width"] * 0.30, box["y"] + 40, steps=6)
    p.mouse.up()
    p.wait_for_timeout(400)
    check(
        "dragging on the chart sets a global time range", p.locator("button:has-text('Clear time range')").count() >= 1
    )
    s.tab("events")
    in_range = n_rows(s)
    all_events = sum(1 for e in model["events"] if not (e["kind"] == "udp" and e["detail"].get("probe")))
    check(f"the time range filters the events table ({in_range} of {all_events})", 0 < in_range < all_events)
    p.locator(".view.on button:has-text('Clear time range')").first.click()
    p.wait_for_timeout(350)
    check("clearing the range restores all events", n_rows(s) == all_events)
    # --- keyboard
    p.keyboard.press("/")
    check("'/' focuses the search box", p.evaluate("document.activeElement.id") == "search")
    p.keyboard.press("Escape")
    # --- download
    s.tab("run")
    with p.expect_download() as dl:
        p.click("button:has-text('Download report data')")
    data = json.loads(Path(dl.value.path()).read_text())
    check(
        "the downloaded JSON is the full model",
        data["schema"] == model["schema"]
        and data["stats"] == model["stats"]
        and len(data["events"]) == len(model["events"]),
    )
    check(
        "no console errors, page errors or failed requests while exercising every view",
        not s.errors,
        "; ".join(s.errors[:3]),
    )
    # --- security: CSP blocks injected scripts and every network request
    p.evaluate("window.__v = 0; document.addEventListener('securitypolicyviolation', () => { window.__v++; })")
    p.evaluate(
        "(() => { const x = document.createElement('script'); x.textContent = 'window.__csp_probe = 1'; document.body.appendChild(x); })()"
    )
    p.wait_for_timeout(200)
    check(
        "a script injected at runtime does not execute (CSP nonce)",
        p.evaluate("window.__csp_probe") is None and p.evaluate("window.__v") >= 1,
    )
    res = p.evaluate("fetch('https://example.com/').then(() => 'allowed', () => 'blocked')")
    check("any network request from the page is blocked by CSP", res == "blocked")
    # --- routing
    p.goto(Path(path).resolve().as_uri() + "#/findings")
    p.wait_for_function("window.__tw_ready === true")
    check("a #/findings link opens the findings view", p.locator("#view-findings.on").count() == 1)
    pid = next(x["id"] for x in model["processes"] if x["name"] == "updater")
    p.goto(Path(path).resolve().as_uri() + f"#/tree/proc/{pid}")
    p.wait_for_function("window.__tw_ready === true")
    p.wait_for_timeout(500)
    check(
        "a #/tree/proc/<id> link opens that process",
        p.locator("#drawer.open").count() == 1 and "updater" in p.locator("#drawer").inner_text(),
    )
    p.screenshot(path=str(OUT / "demo_linked_process.png"))
    s.page.close()


def _chain(model, pid):
    by = {p["id"]: p for p in model["processes"]}
    out, cur = [], by.get(pid)
    while cur:
        out.append(cur)
        cur = by.get(cur["parent"]) if cur["parent"] else None
    return out


def run_hostile(b):
    with tempfile.TemporaryDirectory() as d:
        model = build(synth.hostile_run(Path(d)))
    path = write_report(model, "hostile.html")
    s = Session(b, path)
    p = s.page
    for t in (
        "overview",
        "tree",
        "timeline",
        "network",
        "http",
        "dns",
        "commands",
        "files",
        "events",
        "findings",
        "run",
    ):
        s.tab(t)
        if t in ("commands", "events", "http", "files"):
            p.locator(".view.on .tbl-row").first.click()
            p.wait_for_timeout(250)
    p.goto(Path(path).resolve().as_uri() + "#/http")
    p.wait_for_function("window.__tw_ready === true")
    p.locator(".view.on .tbl-row").first.click()
    p.wait_for_timeout(400)
    body = p.evaluate("document.body.innerText")
    check("hostile strings are rendered as visible TEXT", "window.__pwned=1" in body)
    check("no hostile script ran (no global set, no dialog)", p.evaluate("window.__pwned") is None and not s.dialogs)
    check(
        "no injected elements: exactly the report's 2 script tags, no <img>, no inline handlers",
        p.evaluate("document.scripts.length") == 2
        and p.evaluate("document.querySelectorAll('img, iframe, object, embed').length") == 0
        and p.evaluate(
            "[...document.querySelectorAll('*')].filter(e => [...e.attributes].some(a => /^on/i.test(a.name))).length"
        )
        == 0,
    )
    check("no console errors on the hostile report", not s.errors, "; ".join(s.errors[:3]))
    p.screenshot(path=str(OUT / "hostile_http.png"))
    s.page.close()


def run_big(b):
    with tempfile.TemporaryDirectory() as d:
        t0 = time.time()
        model = build(synth.big_run(Path(d)))
        build_s = time.time() - t0
    path = write_report(model, "big.html")
    size = path.stat().st_size / 1e6
    print(
        f"INFO big report: {len(model['processes'])} processes, {len(model['events'])} events, {size:.1f} MB, model built in {build_s:.1f}s"
    )
    s = Session(b, path)
    p = s.page
    check(f"a {len(model['processes'])}-process report loads in under 8 s ({s.load_s:.1f}s)", s.load_s < 8)
    for t in ("tree", "timeline", "commands", "events", "network", "http"):
        t0 = time.time()
        s.tab(t)
        check(f"big report: the {t} view renders within 4 s ({time.time() - t0:.1f}s)", time.time() - t0 < 4.5)
    s.tab("timeline")
    dom = p.evaluate("document.querySelector('#view-timeline .tl svg').querySelectorAll('*').length")
    check(f"the timeline is virtualised: {dom} SVG nodes for {len(model['processes'])} lanes", dom < 6000)
    p.evaluate("document.querySelector('#view-timeline .tl').scrollTop = 20000")
    p.wait_for_timeout(300)
    check("scrolling the timeline re-renders the visible lanes", p.locator("#view-timeline .tl-label").count() > 5)
    s.tab("commands")
    check("the commands table is virtualised", p.locator(".view.on .tbl-row").count() < 120)
    check("no errors on the big report", not s.errors, "; ".join(s.errors[:3]))
    s.page.close()


def main(demo_dir):
    OUT.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as pw:
        b = pw.chromium.launch()
        if Path(demo_dir, "manifest.json").exists():
            run_demo(b, demo_dir)
        else:
            skip("demo-run checks", f"{demo_dir} not found (record it with tests/fixtures/demo.sh)")
        run_hostile(b)
        run_big(b)
        b.close()
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else str(HERE / "out/demo/runs/demo")))
