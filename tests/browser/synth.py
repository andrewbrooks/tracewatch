"""Synthetic run directories for the browser tests (no Docker): a hostile one and a large one."""

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
from test_model import T0, S, execev, exitev, fileev, make_run, proxy_data, tcpev, te, tree_events  # noqa: E402

HOSTILE = '</script><script>window.__pwned=1</script><img src=x onerror="window.__pwned=2"><svg onload=window.__pwned=3> "\'` \\u2028 ${x}'


def hostile_run(tmp: Path) -> Path:
    t, f = proxy_data()
    f[3]["host"] = "evil.example" + HOSTILE
    f[3]["path"] = "/" + HOSTILE
    f[3]["headers"] = [["X-" + HOSTILE, HOSTILE]]
    f[4]["headers"] = [["Set-Cookie", HOSTILE]]
    f[4]["body"] = {"size": 99, "captured": True, "text": HOSTILE, "content_type": "text/html"}
    f[1]["name"] = HOSTILE
    tr = (
        tree_events()
        + t
        + [
            execev(5, 110, 1, T0 + 2 * S, ["echo", HOSTILE, "/tmp/" + HOSTILE]),
            fileev(5, 110, 1, T0 + 2.1 * S, "/tmp/" + HOSTILE, 33345),
            exitev(5, 110, 1, T0 + 2.5 * S),
        ]
    )
    tr.append(te("sched_process_exec", 6, 111, 1, T0 + 3 * S, comm=HOSTILE[:15], pathname="/tmp/x", argv=[HOSTILE]))
    return make_run(tmp, tr, f)


def big_run(tmp: Path, nproc: int = 1500, nev: int = 6000) -> Path:
    tr = [execev(1, 100, 0, T0, ["/work/target"])]
    for i in range(2, nproc + 2):
        parent = 1 if i < 40 else 2 + (i * 7) % min(i - 1, 400)
        tr.append(execev(i, 100 + i, parent, T0 + i * 1_000_000, ["tool%d" % (i % 23), "--arg", str(i)]))
        tr.append(exitev(i, 100 + i, parent, T0 + i * 1_000_000 + 40_000_000, code=i % 5 == 0))
        if i < nev // 4:
            for k in range(3):
                tr.append(
                    fileev(
                        i,
                        100 + i,
                        parent,
                        T0 + i * 1_000_000 + 2_000_000 * (k + 1),
                        f"/tmp/f{i}_{k}",
                        33345 if k else 32768,
                    )
                )
            tr.append(tcpev(i, 100 + i, parent, T0 + i * 1_000_000 + 10_000_000, f"10.0.{i % 200}.{i % 250}", 443))
    tr.append(exitev(1, 100, 0, T0 + (nproc + 3) * 1_000_000))
    return make_run(tmp, tr)


def empty_run(tmp: Path) -> Path:
    """A recording in which nothing happened (e.g. the command failed to start)."""
    return make_run(tmp, [])


def incomplete_run(tmp: Path) -> Path:
    """The recorder died: a heartbeat, then a proxy loss, and no run_finished."""
    evs = [
        {"kind": "run_started", "t_mono_ns": 1, "t_wall_ns": 1},
        {"kind": "recording_armed", "t_mono_ns": 2, "t_wall_ns": 1},
        {"kind": "heartbeat", "t_mono_ns": 3 * 10**9, "t_wall_ns": 1},
        {"kind": "component_died", "component": "mitm", "t_mono_ns": 4 * 10**9, "t_wall_ns": 1},
    ]
    return make_run(tmp, tree_events(), manifest={"status": "running"}, events=evs)
