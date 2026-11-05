import json
import os

from tracewatch.integrity import EXIT_CODES, assess
from tracewatch.procinfo import start_ticks

S = 1_000_000_000


def make_run(tmp_path, status="finished", events=None, manifest=None, flows="", tracee="", name="r"):
    d = tmp_path / name
    d.mkdir()
    m = {"run_id": "r", "status": status, "recorder_pid": 2**22 + 5, "recorder_start_ticks": 1, "lost_components": []}
    m.update(manifest or {})
    (d / "manifest.json").write_text(json.dumps(m))
    evs = events if events is not None else standard_events()
    (d / "events.jsonl").write_text("".join(json.dumps(e) + "\n" for e in evs))
    (d / "flows.jsonl").write_text(flows)
    (d / "tracee.jsonl").write_text(tracee)
    return d


def ev(kind, t, **kw):
    return {"kind": kind, "t_mono_ns": int(t * S), "t_wall_ns": int(t * S) + 10**18, **kw}


def standard_events(end=20.0, beats_every=2.0):
    out = [ev("run_started", 0), ev("recording_armed", 5)]
    t = 5.0
    while t < end:
        out.append(ev("heartbeat", t))
        t += beats_every
    out += [ev("root_exited", end), ev("teardown_started", end), ev("run_finished", end + 5)]
    return out


def test_clean_finished_run_is_complete(tmp_path):
    a = assess(make_run(tmp_path))
    assert a["verdict"] == "complete" and not a["gaps"] and not a["caps"]
    assert EXIT_CODES[a["verdict"]] == 0


def test_component_death_is_a_gap_to_the_end_and_complete_with_losses(tmp_path):
    events = standard_events() + [ev("component_died", 12, component="mitm")]
    a = assess(make_run(tmp_path, events=events))
    assert a["verdict"] == "complete-with-losses"
    (g,) = a["gaps"]
    assert g["source"] == "proxy" and g["start_mono"] == 12 * S and g["end_mono"] == 20 * S
    assert "proxy lost" in a["reasons"]


def test_tracee_collector_death_counts_as_tracee(tmp_path):
    a = assess(make_run(tmp_path, events=standard_events() + [ev("component_died", 9, component="tracee-collector")]))
    assert [g["source"] for g in a["gaps"]] == ["tracee"]


def test_soft_cap_is_reported_but_not_a_gap_hard_cap_is(tmp_path):
    events = standard_events() + [ev("cap_reached", 8, cap="proxy:soft"), ev("cap_reached", 10, cap="proxy:hard")]
    a = assess(make_run(tmp_path, events=events))
    assert a["verdict"] == "complete-with-losses" and [c["cap"] for c in a["caps"]] == ["proxy:soft", "proxy:hard"]
    assert [g["reason"] for g in a["gaps"]] == ["proxy:hard size cap reached"]


def test_heartbeat_stall_is_a_recorder_gap(tmp_path):
    events = [e for e in standard_events() if not (9 < e["t_mono_ns"] / S < 17 and e["kind"] == "heartbeat")]
    a = assess(make_run(tmp_path, events=events))
    stall = [g for g in a["gaps"] if g["source"] == "recorder"]
    assert (
        a["verdict"] == "complete-with-losses"
        and len(stall) == 1
        and stall[0]["end_mono"] - stall[0]["start_mono"] > 6 * S
    )


def test_dead_recorder_not_swept_is_incomplete_with_untrusted_tail(tmp_path):
    events = [
        ev("run_started", 0),
        ev("recording_armed", 5),
        ev("heartbeat", 5),
        ev("heartbeat", 7),
        ev("heartbeat", 9),
    ]
    a = assess(make_run(tmp_path, status="running", events=events))
    assert a["verdict"] == "incomplete" and "not yet swept" in " ".join(a["reasons"])
    assert a["untrusted_after_mono"] == 9 * S + 2 * S and a["end_mono"] == 9 * S


def test_aborted_run_is_incomplete(tmp_path):
    events = standard_events()[:6] + [ev("swept", 100)]
    a = assess(make_run(tmp_path, status="aborted", events=events))
    assert a["verdict"] == "incomplete" and "untrusted_after_mono" in a


def test_running_with_live_recorder_is_in_progress(tmp_path):
    me = os.getpid()
    a = assess(
        make_run(
            tmp_path,
            status="running",
            events=standard_events()[:4],
            manifest={"recorder_pid": me, "recorder_start_ticks": start_ticks(me)},
        )
    )
    assert a["verdict"] == "in-progress" and EXIT_CODES["in-progress"] == 3


def test_recycled_pid_is_not_mistaken_for_a_live_recorder(tmp_path):
    me = os.getpid()
    a = assess(
        make_run(
            tmp_path,
            status="running",
            events=standard_events()[:4],
            manifest={"recorder_pid": me, "recorder_start_ticks": start_ticks(me) + 1},
        )
    )
    assert a["verdict"] == "incomplete"


def test_finished_manifest_without_run_finished_event_is_not_believed(tmp_path):
    events = [e for e in standard_events() if e["kind"] != "run_finished"]
    a = assess(make_run(tmp_path, status="finished", events=events))
    assert a["verdict"] == "incomplete" and "no run_finished" in " ".join(a["reasons"])


def test_failed_to_start(tmp_path):
    a = assess(
        make_run(
            tmp_path, status="failed_to_start", events=[ev("run_started", 0)], manifest={"why": "proxy did not come up"}
        )
    )
    assert a["verdict"] == "incomplete" and "proxy did not come up" in " ".join(a["reasons"])


def test_corrupt_lines_and_half_written_last_line(tmp_path):
    d = make_run(tmp_path, flows='{"kind":"conn"}\nNOT JSON\n{"kind":"flow"}\n{"kind":"flo')
    a = assess(d)
    assert a["files"]["flows.jsonl"] == {"lines": 4, "corrupt": 1, "truncated_last": True}
    assert a["verdict"] == "complete-with-losses" and "corrupt lines {'flows.jsonl': 1}" in a["reasons"]


def test_half_written_last_line_alone_downgrades_a_finished_run(tmp_path):
    a = assess(make_run(tmp_path, tracee='{"eventName":"x"}\n{"event'))
    assert a["verdict"] == "complete-with-losses" and "half-written" in " ".join(a["reasons"])


def test_unreadable_manifest(tmp_path):
    d = tmp_path / "r"
    d.mkdir()
    assert assess(d)["verdict"] == "unreadable"
    (d / "manifest.json").write_text("{not json")
    assert assess(d)["verdict"] == "unreadable"


def test_target_stopped_by_policy_is_surfaced(tmp_path):
    a = assess(
        make_run(
            tmp_path, manifest={"target_stopped": {"reason": "mitm died"}, "policy": {"on_component_loss": "stop"}}
        )
    )
    assert a["target_stopped"]["reason"] == "mitm died" and a["policy"]["on_component_loss"] == "stop"


def test_swept_run_with_target_still_running_says_so(tmp_path):
    a = assess(
        make_run(
            tmp_path,
            status="aborted",
            events=standard_events()[:5],
            manifest={"target_still_running": True},
            name="second",
        )
    )
    assert any("still running" in r for r in a["reasons"])
