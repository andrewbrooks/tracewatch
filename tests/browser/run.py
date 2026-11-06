"""Browser tests for the interactive report (headless Chromium via Playwright; TW_BROWSER=firefox for Firefox).

usage: run.py [DEMO_RUN_DIR]      (default out/demo/runs/demo; produced by tests/fixtures/demo.sh)
If Chromium cannot start because system libraries are missing, set LD_LIBRARY_PATH to a directory holding them."""

import json
import os
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
        loc = self.page.locator(f'.tab[data-tab="{t}"]')
        if loc.is_visible():
            loc.click()
        else:  # phones show four tabs and a "More" menu
            self.page.click(".tab.more")
            self.page.click(f'.moretab[data-tab="{t}"]')
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
    shown = p.locator("#view-tree .toolbar .muted.num").inner_text()
    check(f"tree shows every process ({shown})", shown.startswith(f"{st['processes']} of {st['processes']}"))
    check("tree has one node per process", p.locator("g.node").count() == st["processes"])
    target = next(x for x in model["processes"] if x["depth"] == 2 and x["name"] == "cp")
    p.locator(f'g.node[aria-description*="Process cp, pid {target["pid"]}"]').dispatch_event("click")
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
    flagged = int(p.locator("#view-tree .toolbar .muted.num").inner_text().split()[0])
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
    non_info = sum(1 for f in model["findings"] if f["severity"] != "info")
    check(f"INFO findings start collapsed: only high, medium and low are listed ({cards})", cards == non_info)
    check(
        "the severity filters say whether they are on (aria-pressed and a visible 'shown'/'hidden')",
        p.locator("#view-findings .fchip[aria-pressed='false'] .fstate").first.inner_text().lower() == "hidden"
        and p.locator("#view-findings .fchip[aria-pressed='true'] .fstate").first.inner_text().lower() == "shown",
    )
    p.click("#view-findings .fchip:has(.sev-info)")
    p.wait_for_timeout(250)
    check(
        "turning 'info' on lists every finding", p.locator("#view-findings .finding").count() == len(model["findings"])
    )
    check(
        "each finding card carries its rule's dictionary entry",
        p.locator("#view-findings .finding details.about-rule").count() == len(model["findings"]),
    )
    p.locator("#view-findings .finding details.about-rule summary").first.click()
    check(
        "'About this rule' opens in place and says what the rule cannot tell you",
        "Cannot tell" in p.locator("#view-findings details.about-rule[open]").first.inner_text(),
    )
    p.click("#view-findings .fchip:has(.sev-info)")
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


def _lum(hexcol):
    h = hexcol.strip().lstrip("#")
    r, g, b = (int(h[i : i + 2], 16) / 255 for i in (0, 2, 4))
    f = lambda c: c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4  # noqa: E731
    return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b)


def _contrast(a, b):
    la, lb = sorted((_lum(a), _lum(b)), reverse=True)
    return (la + 0.05) / (lb + 0.05)


TOKENS = [
    "--page",
    "--surface",
    "--raised",
    "--raised-2",
    "--text",
    "--text-2",
    "--text-3",
    "--t-good",
    "--t-warning",
    "--t-serious",
    "--t-critical",
    "--k-exec",
    "--k-http",
    "--k-net",
    "--k-file",
    "--k-dns",
    "--k-ws",
    "--k-sys",
    "--critical",
    "--serious",
    "--warning",
    "--good",
]
# categorical marks below 3:1 on the LIGHT surface: the skill's documented exceptions (relief = marker shapes, labelled
# legend, table view). Anything else below 3:1 is a regression.
LIGHT_MARK_EXCEPTIONS = {"--k-net", "--k-file", "--k-dns"}


def run_themes(b, path):
    for scheme in ("dark", "light"):
        pg = b.new_page(viewport={"width": 1400, "height": 900}, color_scheme=scheme)
        errs = []
        pg.on("console", lambda m, errs=errs: errs.append(m.text) if m.type in ("error", "warning") else None)
        pg.on("pageerror", lambda e, errs=errs: errs.append(str(e)))
        pg.goto(Path(path).resolve().as_uri())
        pg.wait_for_function("window.__tw_ready === true")
        check(
            f"[{scheme}] 'auto' follows the system preference",
            pg.evaluate("document.documentElement.dataset.theme") == scheme,
        )
        tok = pg.evaluate(
            "t => Object.fromEntries(t.map(k => [k, getComputedStyle(document.documentElement).getPropertyValue(k).trim()]))",
            TOKENS,
        )
        bad = [
            (t, s_, round(_contrast(tok[t], tok[s_]), 2))
            for t in ("--text", "--text-2", "--text-3")
            for s_ in ("--page", "--surface", "--raised", "--raised-2")
            if _contrast(tok[t], tok[s_]) < 4.5
        ]
        check(f"[{scheme}] body, secondary and muted text clear 4.5:1 on every surface", not bad, str(bad))
        bad = [
            (t, round(_contrast(tok[t], tok["--surface"]), 2))
            for t in ("--t-good", "--t-warning", "--t-serious", "--t-critical")
            if _contrast(tok[t], tok["--surface"]) < 4.5
        ]
        check(f"[{scheme}] status TEXT colours clear 4.5:1 on the surface", not bad, str(bad))
        low = {
            t
            for t in ("--k-exec", "--k-http", "--k-net", "--k-file", "--k-dns", "--k-ws", "--k-sys")
            if _contrast(tok[t], tok["--surface"]) < 3
        }
        expected = LIGHT_MARK_EXCEPTIONS if scheme == "light" else set()
        check(
            f"[{scheme}] categorical marks clear 3:1 except exactly the documented light-mode set ({sorted(low)})",
            low == expected,
            str(sorted(low ^ expected)),
        )
        bg = pg.evaluate("getComputedStyle(document.body).backgroundColor")
        lum = sum(int(x) for x in bg[bg.index("(") + 1 : bg.index(")")].split(",")[:3]) / 3
        check(
            f"[{scheme}] the page background really is {scheme} ({bg})", (lum < 60) if scheme == "dark" else (lum > 200)
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
            pg.click(f'.tab[data-tab="{t}"]')
            pg.wait_for_timeout(250)
        check(f"[{scheme}] all 11 views render without console errors", not errs, "; ".join(errs[:2]))
        pg.close()
    # ---- manual override, persistence, and re-colouring
    pg = b.new_page(viewport={"width": 1400, "height": 900}, color_scheme="dark")
    pg.goto(Path(path).resolve().as_uri())
    pg.wait_for_function("window.__tw_ready === true")
    pg.click('.tab[data-tab="overview"]')
    pg.wait_for_timeout(400)
    fill_dark = pg.evaluate("document.querySelector('#view-overview svg.chart path[fill]').getAttribute('fill')")
    pg.click("#themebtn")  # auto -> light
    pg.wait_for_timeout(400)
    fill_light = pg.evaluate("document.querySelector('#view-overview svg.chart path[fill]').getAttribute('fill')")
    check(
        "the toggle switches auto -> light even though the system is dark",
        pg.evaluate("document.documentElement.dataset.theme") == "light",
    )
    check(f"charts are re-coloured live for the new theme ({fill_dark} -> {fill_light})", fill_dark != fill_light)
    pg.click("#themebtn")  # light -> dark
    check(
        "the toggle then goes to dark",
        pg.evaluate("document.documentElement.dataset.theme") == "dark"
        and "dark" in pg.get_attribute("#themebtn", "aria-label").lower(),
    )
    pg.click("#themebtn")  # dark -> auto
    check(
        "and back to auto",
        pg.evaluate("document.documentElement.dataset.theme") == "dark"
        and "auto" in pg.get_attribute("#themebtn", "aria-label").lower().replace("theme: auto", "auto"),
    )
    pg.click("#themebtn")  # auto -> light again, then reload: the choice persists
    stored = pg.evaluate(
        "(() => { try { return localStorage.getItem('tw-theme'); } catch (e) { return 'blocked'; } })()"
    )
    pg.reload()
    pg.wait_for_function("window.__tw_ready === true")
    if stored == "blocked":
        skip("theme persistence", "localStorage is blocked for file:// in this browser")
    else:
        check(
            "the chosen theme persists across a reload",
            pg.evaluate("document.documentElement.dataset.theme") == "light" and stored == "light",
        )
    pg.emulate_media(color_scheme="dark")
    pg.wait_for_timeout(200)
    check(
        "an explicit choice is not overridden by a later system change",
        pg.evaluate("document.documentElement.dataset.theme") == "light",
    )
    pg.screenshot(path=str(OUT / "theme_light_override.png"))
    pg.close()


ALL_TABS = ("overview", "tree", "timeline", "network", "http", "dns", "commands", "files", "events", "findings", "run")


def run_edges(b):
    """Empty and broken recordings must say so plainly, never look like a success."""
    with tempfile.TemporaryDirectory() as d:
        (Path(d) / "e").mkdir()
        (Path(d) / "i").mkdir()
        empty = build(synth.empty_run(Path(d) / "e"))
        incomplete = build(synth.incomplete_run(Path(d) / "i"))
    pe, pi = write_report(empty, "empty.html"), write_report(incomplete, "incomplete.html")
    s = Session(b, pe)
    p = s.page
    banner = p.locator("#view-overview .banner").inner_text()
    check(
        "an EMPTY recording is not shown as a success (neutral 'No activity recorded' banner)",
        "No activity recorded" in banner and "Recording complete" not in banner,
    )
    check(
        "the header verdict for an empty recording is neutral, not green",
        "NO ACTIVITY RECORDED" in p.locator("#top .verdict").inner_text(),
    )
    check(
        "the empty activity chart explains itself instead of drawing a 0..1 axis",
        p.locator("#view-overview .emptystate:has-text('No activity to chart')").count() == 1,
    )
    for t in ALL_TABS:
        s.tab(t)
    s.tab("tree")
    check(
        "the empty process tree says why it is empty",
        p.locator("#view-tree .emptystate:has-text('No processes were recorded')").count() == 1,
    )
    s.tab("commands")
    check("an empty table shows an explanatory empty state", p.locator("#view-commands .emptystate").count() == 1)
    check("no console errors on an empty recording across all views", not s.errors, "; ".join(s.errors[:2]))
    s.page.close()
    s = Session(b, pi)
    p = s.page
    banner = p.locator("#view-overview .banner").inner_text()
    check(
        "an INCOMPLETE recording says what is untrustworthy",
        "Recording incomplete" in banner and "can be trusted" in banner,
    )
    check(
        "the untrusted region is marked on the activity chart and the coverage strip",
        p.locator("#view-overview svg.chart text:has-text('UNTRUSTED')").count() == 1
        and p.locator("#view-overview .cov .untrusted").count() == 3,
    )
    check(
        "the untrusted time shown is inside the run (no absurd number)",
        "+5.000s" in banner or "can be trusted" in banner and "e+" not in banner and "699" not in banner,
    )
    p.click("#top .verdict")
    check("clicking the verdict opens the integrity details", p.locator("#view-run.on").count() == 1)
    check("no console errors on an incomplete recording", not s.errors, "; ".join(s.errors[:2]))
    s.page.close()


def run_responsive(b, path):
    for w, h, label in ((390, 844, "phone"), (820, 1000, "small tablet"), (1100, 800, "laptop")):
        s = Session(b, path, width=w, height=h)
        p = s.page
        over = []
        for t in ALL_TABS:
            s.tab(t)
            sw = p.evaluate(
                "[document.documentElement.scrollWidth, innerWidth, document.querySelector('#main').scrollWidth, document.querySelector('#main').clientWidth]"
            )
            if sw[0] > sw[1] + 1:
                over.append((t, sw))
        check(f"[{label} {w}px] no view causes horizontal page overflow", not over, str(over))
        top = p.evaluate(
            "(() => { const r = document.querySelector('#top').getBoundingClientRect(); return [r.right, r.height]; })()"
        )
        check(
            f"[{label}] the header fits the viewport ({top[0]:.0f}px of {w}px, {top[1]:.0f}px tall)",
            top[0] <= w + 1 and (w > 820 or top[1] < 170),
        )
        rail = p.evaluate(
            "(() => { const r = document.querySelector('#rail').getBoundingClientRect(); return [r.top, r.bottom, r.width, innerHeight]; })()"
        )
        if w <= 820:
            check(f"[{label}] navigation is a bottom bar", rail[1] >= rail[3] - 2 and rail[2] >= w - 2)
        else:
            check(f"[{label}] navigation is a side rail", rail[2] < 100)
        tiny = p.evaluate(
            "[...document.querySelectorAll('button, .tab, .btn, .iconbtn')].filter(e => e.offsetParent !== null).map(e => { const r = e.getBoundingClientRect(); return [e.textContent.trim().slice(0, 14) || e.getAttribute('aria-label'), Math.round(r.width), Math.round(r.height)]; }).filter(x => x[1] < 24 || x[2] < 24)"
        )
        check(f"[{label}] every visible control is at least 24x24 px (WCAG target size)", not tiny, str(tiny[:4]))
        if w <= 820:
            s.tab("http")
            p.locator(".view.on .tbl-row").first.click()
            p.wait_for_timeout(450)
            dw = p.evaluate("document.querySelector('#drawer').getBoundingClientRect().width")
            check(f"[{label}] the detail drawer takes the full screen width ({dw:.0f}px)", abs(dw - w) < 2)
            p.screenshot(path=str(OUT / f"responsive_{label.replace(' ', '_')}_drawer.png"))
        check(f"[{label}] no console errors", not s.errors, "; ".join(s.errors[:2]))
        s.page.close()


def run_keyboard(b, path):
    s = Session(b, path)
    p = s.page
    p.evaluate("document.body.focus()")
    p.keyboard.press("Tab")
    check("the first Tab stop is the 'Skip to content' link", p.evaluate("document.activeElement.className") == "skip")
    p.keyboard.press("?")
    check("'?' opens the keyboard-shortcuts dialog", p.locator("#help.on").count() == 1)
    p.keyboard.press("Escape")
    check("Esc closes the dialog", p.locator("#help.on").count() == 0)
    p.keyboard.press("3")
    p.wait_for_timeout(300)
    check(
        "number keys switch views ('3' = process tree)",
        p.locator("#view-tree.on").count() == 1 and p.evaluate("document.title").startswith("Process tree"),
    )
    # tree keyboard navigation
    rootid = p.evaluate("document.querySelector('g.node[tabindex=\"0\"]').getAttribute('data-fk')")
    check(
        f"the tree has ONE tab stop, not one per process ({rootid.split(',')[0]})",
        p.locator("g.node[tabindex='0']").count() == 1 and p.locator("g.node[tabindex='-1']").count() >= 5,
    )
    p.locator("g.node[tabindex='0']").focus()
    p.keyboard.press("ArrowRight")
    moved = p.evaluate("document.activeElement.getAttribute('data-fk')")
    check("ArrowRight moves from the root to its first child", moved is not None and moved != rootid)
    p.keyboard.press("ArrowLeft")
    check("ArrowLeft moves back to the parent", p.evaluate("document.activeElement.getAttribute('data-fk')") == rootid)
    p.keyboard.press("ArrowRight")
    p.keyboard.press("Enter")
    p.wait_for_timeout(400)
    inside = p.evaluate("document.querySelector('#drawer').contains(document.activeElement)")
    check("Enter opens the drawer and moves keyboard focus into it", p.locator("#drawer.open").count() == 1 and inside)
    p.keyboard.press("Escape")
    p.wait_for_timeout(350)
    back = p.evaluate("document.activeElement.classList.contains('node')")
    check(
        "Esc closes the drawer and returns focus to the node that opened it",
        p.locator("#drawer.open").count() == 0 and back,
    )
    check(
        "the closed drawer is inert (not reachable by Tab)",
        p.evaluate("document.querySelector('#drawer').hasAttribute('inert')"),
    )
    # zoom controls
    before = p.locator("#view-tree .zl").inner_text()
    p.click("#view-tree button[aria-label='Zoom in']")
    check(
        f"the zoom buttons work ({before} -> {p.locator('#view-tree .zl').inner_text()})",
        p.locator("#view-tree .zl").inner_text() != before,
    )
    # table keyboard navigation
    s.tab("commands")
    p.locator(".view.on .tbl-row").first.focus()
    p.keyboard.press("ArrowDown")
    p.keyboard.press("ArrowDown")
    check("ArrowDown moves through table rows", p.evaluate("document.activeElement.dataset.i") == "2")
    p.keyboard.press("End")
    p.wait_for_timeout(200)
    check("End jumps to the last row", int(p.evaluate("document.activeElement.dataset.i")) >= 5)
    p.keyboard.press("Enter")
    p.wait_for_timeout(350)
    check("Enter on a row opens its details", p.locator("#drawer.open").count() == 1)
    p.keyboard.press("Escape")
    check(
        "the sorted column header exposes aria-sort",
        p.locator(
            ".view.on .tbl-head [role=columnheader][aria-sort='ascending'], .view.on .tbl-head [role=columnheader][aria-sort='descending']"
        ).count()
        == 1,
    )
    # search -> contextual empty state -> recovery
    p.fill("#search", "zzzz-no-such-command")
    p.wait_for_timeout(450)
    check(
        "a search that matches nothing says so and offers recovery",
        p.locator(".view.on .emptystate:has-text('No matches')").count() == 1,
    )
    p.locator(".view.on .emptystate .btn").click()
    p.wait_for_timeout(400)
    check(
        "'Clear search' restores the rows",
        p.locator(".view.on .tbl-row").count() > 3 and p.input_value("#search") == "",
    )
    # header actions
    p.click(".copycmd")
    p.wait_for_timeout(200)
    check("the copy button copies the command and confirms with a toast", p.locator(".toast.on").count() == 1)
    p.click(".runcmd")
    p.wait_for_timeout(200)
    full = p.locator("#cmdfull.on")
    check(
        "clicking the command shows all of it, wrapped",
        full.count() == 1
        and len(full.inner_text()) >= len(p.evaluate("document.querySelector('.runcmd').textContent")) - 2,
    )
    p.keyboard.press("Escape")
    check("Esc closes the full command", p.locator("#cmdfull.on").count() == 0)
    s.tab("overview")
    check("switching views resets the scroll position", p.evaluate("document.querySelector('#main').scrollTop") == 0)
    check("no console errors during the keyboard session", not s.errors, "; ".join(s.errors[:2]))
    s.page.close()


def run_print(b, path):
    """Printing: always the light theme, every view and every table row, no screen-only controls, nothing clipped."""
    s = Session(b, path, width=704, height=1000)  # an A4 page minus its margins, in CSS pixels
    p = s.page
    s.tab("commands")
    on_screen = int(
        p.locator(".view.on .tbl-head")
        .evaluate("e => e.parentElement.parentElement.querySelector('.muted.num').textContent")
        .split()[0]
        .replace(",", "")
    )
    p.emulate_media(media="print")
    p.wait_for_timeout(1200)
    check(
        "print uses the light theme whatever the screen theme was",
        p.evaluate("document.documentElement.dataset.theme") == "light",
    )
    check(
        "print hides the navigation, search, drawer and screen-only buttons",
        p.evaluate(
            "['#rail', '#search', '#drawer', '.view .btn'].every(q => [...document.querySelectorAll(q)].every(e => getComputedStyle(e).display === 'none'))"
        ),
    )
    check(
        "print shows every view, not just the active one (and skips the timeline)",
        p.evaluate("[...document.querySelectorAll('.view')].filter(v => getComputedStyle(v).display !== 'none').length")
        == len(ALL_TABS) - 1,
    )
    check(
        "print renders EVERY table row, not the on-screen window",
        p.locator("#view-commands .tbl-row").count() == on_screen,
    )
    check(
        "a view that was never opened is filled in for print",
        p.locator("#view-http .tbl-row").count() > 0 and p.locator("#view-dns .tbl-row").count() > 0,
    )
    check("nothing overflows the page width", p.evaluate("document.documentElement.scrollWidth - innerWidth") <= 1)
    check(
        "findings print with their rule definitions expanded",
        p.evaluate("[...document.querySelectorAll('details.about-rule')].every(d => d.open)"),
    )
    check(
        "print colours are dark-on-light (text is not the dark theme's light grey)",
        p.evaluate("getComputedStyle(document.querySelector('#view-commands .tbl-row')).color").startswith("rgb(1"),
    )
    p.emulate_media(media="screen")
    p.wait_for_timeout(700)
    check(
        "leaving print restores the screen layout",
        p.evaluate("getComputedStyle(document.querySelector('#rail')).display") != "none"
        and p.locator(".view.on").count() == 1,
    )
    check("no console errors through a print round trip", not s.errors, "; ".join(s.errors[:2]))
    s.page.close()


def run_story(b, path):
    """ "How it unfolded": a one-line ribbon of the notable steps, inside the activity card."""
    s = Session(b, path)
    p = s.page
    n = p.locator(".rchip:not(.more)").count()
    check(f"the activity card carries a ribbon of notable steps ({n})", n >= 3)
    check(
        "the ribbon is inside the activity card, not a card of its own",
        p.locator("#view-overview .card:has(h3:text-is('Activity over time')) .ribbon").count() == 1
        and p.locator("#view-overview .story").count() == 0,
    )
    check(
        "the ribbon is a single line",
        p.evaluate(
            "(() => { const r = document.querySelector('.ribbon'); return r.getBoundingClientRect().height < 56; })()"
        ),
    )
    ts = p.evaluate(
        "[...document.querySelectorAll('.rchip:not(.more) .rtime')].map(e => parseFloat(e.textContent.replace('+', '')))"
    )
    check("the steps are in time order", ts == sorted(ts))
    check(
        "a high-severity step is visibly stronger than a medium one (different border colour)",
        p.evaluate(
            "(() => { const a = document.querySelector('.rchip.st-high'), b = document.querySelector('.rchip.st-medium'); return !a || !b || getComputedStyle(a).borderLeftColor !== getComputedStyle(b).borderLeftColor; })()"
        ),
    )
    first = p.locator(".rchip:not(.more)").first
    title = first.get_attribute("title")
    first.focus()
    p.keyboard.press("Enter")
    p.wait_for_timeout(500)
    check(
        "Enter on a step opens that finding's details",
        p.locator("#drawer.open").count() == 1 and title.split(": ", 1)[1][:20] in p.locator("#drawer").inner_text(),
    )
    p.keyboard.press("Escape")
    check(
        "the step stays focusable after the drawer closes",
        p.evaluate("document.activeElement.classList.contains('rchip')"),
    )
    check("no console errors", not s.errors, "; ".join(s.errors[:2]))
    s.page.close()
    for w, h, label in ((390, 844, "phone"), (820, 1000, "tablet")):
        s = Session(b, path, width=w, height=h)
        over = s.page.evaluate("document.documentElement.scrollWidth - innerWidth")
        check(f"[{label}] the ribbon causes no page overflow", over <= 1)
        s.page.close()


def run_zoom(b, path):
    """The activity lanes zoom (buttons, Ctrl+wheel, keys, zoom-to-selection) and scroll with a real scroll bar."""
    s = Session(b, path)
    p = s.page
    q = lambda js: p.evaluate(js)  # noqa: E731
    base_w = q("document.querySelector('.lanes-scroll').scrollWidth")
    check(
        "fully zoomed out, the whole run fits (nothing to scroll)",
        base_w <= q("document.querySelector('.lanes-scroll').clientWidth") + 1,
    )
    check(
        "zoom-out and Fit are disabled at the widest view",
        p.locator(".zoomctl button[aria-label='Zoom out']").is_disabled()
        and p.locator(".zoomctl button:text-is('Fit')").is_disabled(),
    )
    p.click(".zoomctl button[aria-label='Zoom in']")
    p.click(".zoomctl button[aria-label='Zoom in']")
    p.wait_for_timeout(250)
    sw, cw = (
        q("document.querySelector('.lanes-scroll').scrollWidth"),
        q("document.querySelector('.lanes-scroll').clientWidth"),
    )
    check(f"zooming in makes the plot scrollable ({sw} px of content in {cw} px)", sw > cw * 2)
    check(
        "the scroller is a real scrollable box with a horizontal scroll bar",
        q("getComputedStyle(document.querySelector('.lanes-scroll')).overflowX") == "auto",
    )
    check(
        "the zoom level is shown",
        "\u00d7" in p.locator(".zoomctl .zl").inner_text() and p.locator(".zoomctl .zl").inner_text() != "\u00d71.0",
    )
    left_before = q("document.querySelector('.lane-labels').getBoundingClientRect().left")
    q("document.querySelector('.lanes-scroll').scrollLeft = 400")
    p.wait_for_timeout(150)
    check(
        "scrolling moves the plot but not the lane labels",
        abs(q("document.querySelector('.lane-labels').getBoundingClientRect().left") - left_before) < 1
        and q("document.querySelector('.lanes-scroll').scrollLeft") > 100,
    )
    ticks = q("[...document.querySelectorAll('.lanes-scroll .axis text')].map(t => t.textContent)")
    check(
        f"the time axis gets finer as you zoom ({ticks[:4]})",
        len(ticks) > 3 and any("ms" in t or "\u00b5s" in t for t in ticks),
    )
    # Ctrl + wheel zooms around the pointer
    zl = p.locator(".zoomctl .zl").inner_text()
    box = p.locator(".lanes-scroll").bounding_box()
    p.mouse.move(box["x"] + box["width"] / 2, box["y"] + 60)
    p.keyboard.down("Control")
    p.mouse.wheel(0, -400)
    p.keyboard.up("Control")
    p.wait_for_timeout(300)
    check(
        f"Ctrl + wheel zooms in ({zl} -> {p.locator('.zoomctl .zl').inner_text()})",
        p.locator(".zoomctl .zl").inner_text() != zl,
    )
    p.locator(".zoomctl button:text-is('Fit')").click()
    p.wait_for_timeout(250)
    check(
        "Fit shows the whole run again",
        q("document.querySelector('.lanes-scroll').scrollLeft") == 0
        and q("document.querySelector('.lanes-scroll').scrollWidth")
        <= q("document.querySelector('.lanes-scroll').clientWidth") + 1,
    )
    p.focus(".lanes-scroll")
    p.keyboard.press("+")
    p.wait_for_timeout(200)
    check("the + key zooms when the chart is focused", p.locator(".zoomctl .zl").inner_text() != "\u00d71.0")
    p.keyboard.press("-")
    p.wait_for_timeout(200)
    check("the - key zooms back out", p.locator(".zoomctl .zl").inner_text() == "\u00d71.0")
    # a brushed selection can be zoomed to
    box = p.locator(".lanes-scroll svg.chart rect[fill='transparent']").bounding_box()
    p.mouse.move(box["x"] + box["width"] * 0.05, box["y"] + 40)
    p.mouse.down()
    p.mouse.move(box["x"] + box["width"] * 0.25, box["y"] + 40, steps=6)
    p.mouse.up()
    p.wait_for_timeout(300)
    zts = p.locator(".zoomctl button:text-is('Zoom to selection')")
    check("a brushed time range offers 'Zoom to selection'", zts.count() == 1)
    zts.click()
    p.wait_for_timeout(300)
    check("zooming to the selection zooms in", p.locator(".zoomctl .zl").inner_text() != "\u00d71.0")
    p.click("button:has-text('Clear time range')")
    check("no console errors while zooming", not s.errors, "; ".join(s.errors[:2]))
    s.page.close()


def run_design_feedback(b, path):
    """The changes from the design review: nav order and groups, the page making room for the drawer, the phone More
    menu, the at-a-glance summary, honest plurals, and the swim-lane activity chart."""
    s = Session(b, path)
    p = s.page
    order = p.evaluate("[...document.querySelectorAll('#rail .tab[data-tab]')].map(t => t.dataset.tab)")
    check(
        f"Findings is second in the side bar, right under Overview ({order[:3]})", order[:2] == ["overview", "findings"]
    )
    check("the side bar has dividers between its groups", p.locator("#rail .tab-sep").count() == 4)
    check(
        "the active tab is highlighted neutrally (no red: red means HIGH)",
        "255, 59, 71"
        not in p.evaluate("getComputedStyle(document.querySelector('.tab[aria-current=page]')).backgroundImage"),
    )
    check(
        "the Findings badge explains itself",
        "high and" in (p.locator(".tab[data-tab=findings]").get_attribute("title") or ""),
    )
    glance = p.locator("#view-overview .glance").inner_text()
    check("the Overview leads with a plain-language summary", glance.startswith("Ran ") and "process" in glance)
    check(
        "no '(s)' plural shortcuts anywhere in the page text",
        "(s)" not in p.evaluate("document.body.innerText") and "(es)" not in p.evaluate("document.body.innerText"),
    )
    link = p.locator("#view-overview .glance-link").first
    if link.count():
        link.click()
        p.wait_for_timeout(500)
        check("a high-severity link in the summary opens that finding", p.locator("#drawer.open").count() == 1)
        p.keyboard.press("Escape")
        p.wait_for_timeout(300)
    check(
        "the activity chart is swim lanes: a lane label per kind, no stacked bars",
        p.locator("#view-overview svg.lane-labels .lane-label").count() >= 3,
    )
    check("findings are marked along the top of the chart", p.locator("#view-overview svg.chart svg").count() >= 1)
    # the drawer takes its space from the page instead of covering the table
    s.tab("http")
    before = p.evaluate("document.querySelector('#main').getBoundingClientRect().width")
    p.locator(".view.on .tbl-row").first.click()
    p.wait_for_timeout(600)
    after = p.evaluate("document.querySelector('#main').getBoundingClientRect().width")
    check(
        f"an open drawer makes the page narrower instead of covering it ({before:.0f} -> {after:.0f} px)",
        before - after > 400,
    )
    cols = p.evaluate(
        "[...document.querySelectorAll('#view-http .tbl-head button')].map(b => b.textContent.trim().replace(/[ ▲▼]+$/, ''))"
    )
    check(
        "Status stays visible beside the open drawer",
        "Status" in cols
        and p.evaluate(
            "(() => { const h = [...document.querySelectorAll('#view-http .tbl-head button')].find(b => b.textContent.startsWith('Status')); return h.getBoundingClientRect().right <= document.querySelector('#drawer').getBoundingClientRect().left + 1; })()"
        ),
    )
    p.keyboard.press("Escape")
    s.tab("tree")
    check(
        "the process-tree toolbar carries the legend (nothing floats over the nodes)",
        p.locator("#view-tree .toolbar .legend-inline").count() == 1
        and p.locator("#view-tree .legend-float").count() == 0,
    )
    check(
        "a failed exit is marked and a clean one recedes",
        p.locator("#view-tree text.ex:not(.ok)").count() >= 1 and p.locator("#view-tree text.ex.ok").count() >= 1,
    )
    check("no console errors", not s.errors, "; ".join(s.errors[:2]))
    s.page.close()
    # phones: four tabs and a More menu
    s = Session(b, path, width=390, height=844)
    p = s.page
    shown = p.evaluate(
        "[...document.querySelectorAll('#rail .tab')].filter(t => getComputedStyle(t).display !== 'none').map(t => t.textContent.trim().replace(/[0-9]+$/, ''))"
    )
    check(f"phones show four tabs plus More ({shown})", len(shown) == 5 and shown[-1] == "More")
    p.click(".tab.more")
    p.wait_for_timeout(250)
    check("More opens a panel with the other views", p.locator("#morepanel.on .moretab").count() == len(ALL_TABS) - 4)
    p.click('#morepanel .moretab[data-tab="commands"]')
    p.wait_for_timeout(500)
    check(
        "choosing a view from More opens it and closes the panel",
        p.locator("#view-commands.on").count() == 1 and p.locator("#morepanel.on").count() == 0,
    )
    check(
        "More shows as selected while a view it holds is open", p.get_attribute(".tab.more", "aria-current") == "true"
    )
    clipped = p.evaluate(
        "(() => { const b = document.querySelector('#view-overview .banner'); return [...b.querySelectorAll('p, li, button, h2')].filter(e => e.scrollWidth > e.clientWidth + 1 || e.getBoundingClientRect().right > b.getBoundingClientRect().right + 1).map(e => e.textContent.slice(0, 30)); })()"
    )
    check("the Overview summary wraps inside the banner on a phone (nothing clipped)", not clipped, str(clipped))
    check("no console errors on the phone", not s.errors, "; ".join(s.errors[:2]))
    s.page.close()


def run_a11y_structure(b, path):
    """Structural accessibility checks that automated tools (axe-core) flagged once; kept so they stay fixed."""
    s = Session(b, path)
    p = s.page
    check("the page has exactly one level-one heading", p.locator("h1").count() == 1)
    check(
        "the side bar is a real navigation landmark",
        p.locator("nav[aria-label] #rail").count() == 1,
    )
    check(
        "no ARIA role is put on a button that is not allowed there (column headers are cells)",
        p.locator("button[role=columnheader]").count() == 0
        and p.locator(".tbl-head [role=columnheader] button").count() >= 1,
    )
    s.tab("findings")
    check(
        "finding cards use a heading one level below the view's heading",
        p.locator("#view-findings .finding h3").count() >= 1 and p.locator("#view-findings .finding h4").count() == 0,
    )
    name = p.get_attribute('.tab[data-tab="findings"]', "aria-label") or ""
    badge = p.locator('.tab[data-tab="findings"] .badge').inner_text()
    check(
        f"a tab's accessible name starts with its visible text, count included ({name[:40]!r})",
        name.startswith("Findings " + badge),
    )
    s.tab("tree")
    node = p.locator("g.node").first
    check(
        "a tree node is named by its visible text (no aria-label to disagree with it) and described in full",
        node.get_attribute("aria-label") is None and "pid" in (node.get_attribute("aria-description") or ""),
    )
    s.tab("tree")
    spot = p.evaluate(
        """(() => { for (const g of document.querySelectorAll('g.node')) { const r = g.getBoundingClientRect();
        if (r.left > 90 && r.top > 120 && r.right < innerWidth - 20 && r.bottom < innerHeight - 20)
          return [r.left + r.width / 2, r.top + r.height / 2]; } return null; })()"""
    )
    p.mouse.move(spot[0] - 4, spot[1] - 3)
    p.mouse.move(spot[0], spot[1])
    p.wait_for_timeout(150)
    tip_h = p.evaluate(
        "(() => { const t = document.querySelector('.tip'); return t ? t.getBoundingClientRect().height : -1 })()"
    )
    check(f"a tooltip is only as tall as its text ({tip_h:.0f}px, not a 300px+ box)", 0 < tip_h < 200, tip_h)
    p.mouse.move(2, 2)
    s.tab("timeline")
    check(
        "the scrolling timeline can be reached with the keyboard",
        p.locator("#view-timeline .tl[tabindex='0']").count() == 1,
    )
    ratio = p.evaluate("""(() => {
      const b = document.querySelector('.tab[data-tab=findings] .badge'); if (!b) return 99;
      const lum = c => { const [r, g, bl] = c.match(/[0-9.]+/g).slice(0, 3).map(Number).map(v => v / 255).map(v => v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4); return 0.2126 * r + 0.7152 * g + 0.0722 * bl; };
      const cs = getComputedStyle(b), a = lum(cs.color), d = lum(cs.backgroundColor); return (Math.max(a, d) + 0.05) / (Math.min(a, d) + 0.05); })()""")
    check(f"the Findings badge meets 4.5:1 text contrast ({ratio:.2f})", ratio >= 4.5)
    check("no console errors", not s.errors, "; ".join(s.errors[:2]))
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
    s.tab("files")
    p.locator("details.fc > summary").first.click()
    shown = p.evaluate("document.querySelector('pre.fcode') ? document.querySelector('pre.fcode').textContent : null")
    check("captured file contents are shown as plain text, markup and all", bool(shown) and "window.__pwned=1" in shown)
    check("the section lists who wrote the file", "written by" in p.locator("details.fc > summary").first.inner_text())
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
        b = getattr(
            pw, os.environ.get("TW_BROWSER", "chromium")
        ).launch()  # TW_BROWSER=firefox to run the suite on Firefox
        print("INFO browser:", b.browser_type.name, b.version)
        if Path(demo_dir, "manifest.json").exists():
            run_demo(b, demo_dir)
        else:
            skip("demo-run checks", f"{demo_dir} not found (record it with tests/fixtures/demo.sh)")
        if Path(demo_dir, "manifest.json").exists():
            run_themes(b, OUT / "demo.html")
        if Path(demo_dir, "manifest.json").exists():
            run_keyboard(b, OUT / "demo.html")
            run_responsive(b, OUT / "demo.html")
            run_print(b, OUT / "demo.html")
            run_story(b, OUT / "demo.html")
            run_zoom(b, OUT / "demo.html")
            run_a11y_structure(b, OUT / "demo.html")
            run_design_feedback(b, OUT / "demo.html")
        run_edges(b)
        run_hostile(b)
        run_big(b)
        b.close()
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else str(HERE / "out/demo/runs/demo")))
