"""The reconstruction model, from synthetic run directories (deterministic)."""

import json

import pytest

from tracewatch.model import build, classify_path, decode_exit, decode_open_flags

S = 1_000_000_000
T0 = 5_000 * S  # Tracee-clock time of the root's exec
OFF = 7_000_000 * S  # tracee_clock = proxy_monotonic + OFF
PROXY_PORT = 4000


def te(name, eid, pid, parent_eid, ts, comm="x", ppid=1, start=None, **args):
    return {"eventName": name, "processEntityId": eid, "parentEntityId": parent_eid, "processId": pid,
            "parentProcessId": ppid, "timestamp": ts, "threadStartTime": start or ts, "processName": comm,
            "userId": 1000, "args": [{"name": k, "value": v} for k, v in args.items()]}  # fmt: skip


def execev(eid, pid, parent_eid, ts, argv, path=None, **kw):
    return te("sched_process_exec", eid, pid, parent_eid, ts, comm=argv[0].split("/")[-1][:15],
              pathname=path or argv[0], argv=argv, pwd="/work", **kw)  # fmt: skip


def exitev(eid, pid, parent_eid, ts, code=0, sig=0):
    return te("sched_process_exit", eid, pid, parent_eid, ts, exit_code=code, signal_code=sig, process_group_exit=True)


def fileev(eid, pid, parent_eid, ts, path, flags=32768):
    return te("security_file_open", eid, pid, parent_eid, ts, pathname=path, flags=flags)


def sockev(eid, pid, parent_eid, ts, typ, addr):
    return te("security_socket_connect", eid, pid, parent_eid, ts, type=typ, remote_addr=addr)


def tcpev(eid, pid, parent_eid, ts, dst, port):
    return te("net_tcp_connect", eid, pid, parent_eid, ts, dst=dst, dst_port=port)


def make_run(tmp_path, tracee, flows=(), manifest=None, events=None):
    d = tmp_path / "run"
    d.mkdir()
    m = {"run_id": "r", "status": "finished", "recorder_pid": 2**22 + 9, "recorder_start_ticks": 1, "root_pid": 100,
         "proxy_port": PROXY_PORT, "argv": ["/work/target", "--x"], "lost_components": [], "degraded": False,
         "started": {"t_wall_ns": OFF + 10**9, "t_mono_ns": 10**9}}  # fmt: skip
    m.update(manifest or {})
    (d / "manifest.json").write_text(json.dumps(m))
    evs = events if events is not None else [
        {"kind": "run_started", "t_mono_ns": 10**9, "t_wall_ns": 1}, {"kind": "recording_armed", "t_mono_ns": 2 * 10**9, "t_wall_ns": 1},
        {"kind": "root_exited", "t_mono_ns": 3 * 10**9, "t_wall_ns": 1}, {"kind": "run_finished", "t_mono_ns": 4 * 10**9, "t_wall_ns": 1}]  # fmt: skip
    (d / "events.jsonl").write_text("".join(json.dumps(e) + "\n" for e in evs))
    (d / "tracee.jsonl").write_text("".join(json.dumps(e) + "\n" for e in tracee))
    (d / "flows.jsonl").write_text("".join(json.dumps(e) + "\n" for e in flows))
    return d


def tree_events():
    """root (eid1,pid100) -> bash -c (eid2) -> curl (eid3); plus wrapper noise BEFORE the root's exec."""
    return [
        te(
            "sched_process_exec", 90, 90, 1, T0 - 3 * S, comm="twprobe", pathname="/run/flags/twprobe", argv=["twprobe"]
        ),
        execev(1, 100, 0, T0, ["/work/target", "--x"]),
        execev(
            2, 101, 1, T0 + 1 * S, ["bash", "-c", "curl 'http://h/a b'"], path="/usr/bin/bash", start=T0 + S - 5_000_000
        ),
        execev(3, 102, 2, T0 + 2 * S, ["curl", "http://h/a b"], path="/usr/bin/curl"),
        exitev(3, 102, 2, T0 + 3 * S, code=22),
        exitev(2, 101, 1, T0 + 4 * S, code=0),
        exitev(1, 100, 0, T0 + 5 * S, code=0),
    ]


def test_process_tree_names_cmdlines_depth_and_exit_status(tmp_path):
    m = build(make_run(tmp_path, tree_events()))
    p = {x["name"]: x for x in m["processes"]}
    assert [x["name"] for x in m["processes"]] == ["target", "bash", "curl"]
    assert (
        p["target"]["parent"] is None
        and p["bash"]["parent"] == p["target"]["id"]
        and p["curl"]["parent"] == p["bash"]["id"]
    )
    assert [x["depth"] for x in m["processes"]] == [0, 1, 2]
    assert p["bash"]["cmdline"] == "bash -c 'curl '\"'\"'http://h/a b'\"'\"''"  # quoted so it can be pasted
    assert p["curl"]["exit"]["status"] == "exited 22" and p["curl"]["exit"]["code"] == 22
    assert p["target"]["start"] == 0 and p["curl"]["end"] == 3 * S and p["curl"]["start"] == 2 * S
    assert m["stats"]["processes"] == 3 and m["stats"]["max_depth"] == 2 and m["stats"]["commands"] == 3


def test_wrapper_probe_noise_before_the_root_exec_is_dropped(tmp_path):
    m = build(make_run(tmp_path, tree_events()))
    assert all(x["name"] != "twprobe" for x in m["processes"])
    assert min(e["t"] for e in m["events"]) >= 0


def test_fork_without_exec_inherits_the_parents_program_and_is_marked(tmp_path):
    tr = tree_events() + [
        te("sched_process_exit", 4, 103, 1, T0 + 3 * S, exit_code=0, signal_code=0, process_group_exit=True)
    ]
    m = build(make_run(tmp_path, tr))
    fork = next(x for x in m["processes"] if x["pid"] == 103)
    assert fork["forked"] and fork["name"] == "target" and fork["cmdline"] == "/work/target --x" and fork["parent"]


def test_pid_reuse_creates_two_processes_not_one(tmp_path):
    tr = tree_events() + [execev(7, 102, 1, T0 + 4.2 * S, ["tool"]), exitev(7, 102, 1, T0 + 4.5 * S)]
    m = build(make_run(tmp_path, tr))
    assert [x["name"] for x in m["processes"] if x["pid"] == 102] == ["curl", "tool"]


def test_process_with_unrecorded_parent_is_marked_detached(tmp_path):
    tr = tree_events() + [execev(8, 555, 424242, T0 + 3 * S, ["daemon"])]
    m = build(make_run(tmp_path, tr))
    d = next(x for x in m["processes"] if x["pid"] == 555)
    assert d["detached"] and d["parent"] is None
    assert any(f["rule"] == "detached-process" for f in m["findings"])


def test_missing_exit_event_leaves_the_end_unknown_not_invented(tmp_path):
    tr = [e for e in tree_events() if not (e["eventName"] == "sched_process_exit" and e["processEntityId"] == 3)]
    m = build(make_run(tmp_path, tr))
    curl = next(x for x in m["processes"] if x["name"] == "curl")
    assert curl["end"] is None and curl["exit"] is None and not curl["end_known"]


@pytest.mark.parametrize(
    "a,want",
    [
        ({"exit_code": 0, "signal_code": 0}, "exited 0"),
        ({"exit_code": 3, "signal_code": 0}, "exited 3"),
        ({"exit_code": 0, "signal_code": 139}, "killed by SIGSEGV (core dumped)"),
        ({"exit_code": 0, "signal_code": 9}, "killed by SIGKILL"),
        ({"exit_code": 0, "signal_code": 40}, "killed by signal 40"),
    ],
)
def test_decode_exit(a, want):
    assert decode_exit(a)["status"] == want


def test_open_flags_and_path_classes():
    assert (
        decode_open_flags(32768) == "read"
        and decode_open_flags(33345) == "create"
        and decode_open_flags(32770) == "write"
    )
    assert classify_path("/home/u/.ssh/id_rsa") == "credential" and classify_path("/x/y/credentials") == "credential"
    assert classify_path("/etc/shadow") == "credential" and classify_path("/home/u/.aws/config") == "credential"
    assert (
        classify_path("/tmp/x") == "staging"
        and classify_path("/dev/shm/a") == "staging"
        and classify_path("/usr/lib/x") == "other"
    )


def test_udp_connect_after_a_resolver_contact_is_a_lookup_probe_not_traffic(tmp_path):
    base = T0 + 2 * S
    tr = tree_events() + [
        sockev(3, 102, 2, base, 2, {"sa_family": "AF_INET", "sin_addr": "10.0.0.2", "sin_port": "53"}),
        sockev(
            3, 102, 2, base + 5_000_000, 2, {"sa_family": "AF_INET", "sin_addr": "93.184.216.34", "sin_port": "443"}
        ),
        sockev(3, 102, 2, base + 3 * S, 2, {"sa_family": "AF_INET", "sin_addr": "93.184.216.34", "sin_port": "443"}),
    ]
    m = build(make_run(tmp_path, tr))
    udp = [e for e in m["events"] if e["kind"] == "udp"]
    assert [e["detail"]["probe"] for e in udp] == [True, False]  # the first follows the lookup, the second does not
    assert m["dns"]["lookup_probes"] == 1
    assert m["dns"]["resolver_contacts"][0]["resolver"] == "10.0.0.2:53"


def test_nscd_and_other_unix_sockets(tmp_path):
    tr = tree_events() + [
        sockev(3, 102, 2, T0 + 2 * S, 1, {"sa_family": "AF_UNIX", "sun_path": "/var/run/nscd/socket"}),
        sockev(3, 102, 2, T0 + 2 * S + 1, 1, {"sa_family": "AF_UNIX", "sun_path": "/var/run/docker.sock"}),
    ]
    m = build(make_run(tmp_path, tr))
    assert [
        (e["kind"], e["detail"].get("resolver") or e["detail"]["path"])
        for e in m["events"]
        if e["kind"] in ("dns", "unix")
    ] == [("dns", "nscd"), ("unix", "/var/run/docker.sock")]


def test_recorders_own_ca_bundle_open_is_hidden_and_counted(tmp_path):
    d = tmp_path / "run"
    ca = str(d.resolve() / "ca" / "mitmproxy-ca-cert.pem")
    tr = tree_events() + [fileev(3, 102, 2, T0 + 2 * S, ca), fileev(3, 102, 2, T0 + 2 * S + 5, "/tmp/payload", 33345)]
    m = build(make_run(tmp_path, tr))
    assert [e["detail"]["path"] for e in m["events"] if e["kind"] == "file"] == ["/tmp/payload"]
    assert any("CA bundle" in n for n in m["notes"])


def test_connections_to_the_proxy_are_not_listed_as_direct_but_other_tcp_is(tmp_path):
    tr = tree_events() + [
        tcpev(3, 102, 2, T0 + 2 * S, "127.0.0.1", PROXY_PORT),
        tcpev(3, 102, 2, T0 + 2.5 * S, "93.184.216.34", 443),
    ]
    m = build(make_run(tmp_path, tr))
    assert [e["title"] for e in m["events"] if e["kind"] == "tcp"] == ["93.184.216.34:443"]
    assert m["stats"]["proxy_connects"] == 1


def proxy_data(connect_ts_offset=-3_000_000):
    """A curl (pid 102) request through the proxy: conn, flow, result, resolve, tls; calibratable against Tracee."""
    m_accept = T0 + 2 * S - OFF  # proxy monotonic time of the accept
    return [
        te("net_tcp_connect", 3, 102, 2, T0 + 2 * S + connect_ts_offset, comm="curl", dst="127.0.0.1", dst_port=PROXY_PORT),
    ], [
        {"kind": "conn", "conn_id": "C1", "client_port": 5, "proxy_port": PROXY_PORT, "inode": "1", "holder_pids": [102],
         "accept_mono_ns": m_accept, "t_mono_ns": m_accept + 10**6, "t_wall_ns": 1},
        {"kind": "resolve", "conn_id": "C1", "name": "example.com", "port": 443, "ip": "93.184.216.34", "t_mono_ns": m_accept + 2 * 10**6, "t_wall_ns": 1},
        {"kind": "tls", "conn_id": "C1", "host": "example.com", "sni": "example.com", "version": "TLSv1.3", "cipher": "X", "alpn": "h2",
         "cert": {"subject_cn": "example.com", "issuer_cn": "CA", "not_after": "2027-01-01"}, "t_mono_ns": m_accept + 3 * 10**6, "t_wall_ns": 1},
        {"kind": "flow", "flow_id": "F1", "conn_id": "C1", "client_port": 5, "http_version": "HTTP/2.0", "scheme": "https",
         "host": "example.com", "method": "GET", "path": "/a", "headers": [["Host", "example.com"]], "body": {"size": 0, "captured": False, "reason": "empty"},
         "t_mono_ns": m_accept + 10 * 10**6, "t_wall_ns": 1},
        {"kind": "flow_result", "flow_id": "F1", "status": 200, "headers": [["Content-Type", "text/html"]], "duration_ms": 42, "ttfb_ms": 30,
         "server_ip": "93.184.216.34", "body": {"size": 1256, "captured": True, "text": "<html>"}, "t_mono_ns": m_accept + 50 * 10**6, "t_wall_ns": 1},
    ]  # fmt: skip


def test_proxy_records_are_attributed_to_the_process_and_placed_on_the_kernel_timeline(tmp_path):
    t, f = proxy_data()
    m = build(make_run(tmp_path, tree_events() + t, f))
    assert m["clock"]["source"] == "anchors" and abs(m["clock"]["offset_ns"] - (OFF - 3_000_000)) < 1000
    (h,) = m["http"]
    curl = next(x for x in m["processes"] if x["name"] == "curl")
    assert h["proc"] == curl["id"] and h["host"] == "example.com" and h["port"] == 443 and h["status"] == 200
    assert h["duration_ms"] == 42 and h["server_ip"] == "93.184.216.34" and h["tls"]["version"] == "TLSv1.3"
    assert abs(h["t"] - (2 * S + 10 * 10**6)) < 10 * 10**6  # ~2 s after the root's exec, on the shared timeline
    assert m["dns"]["resolved"][0]["name"] == "example.com" and m["dns"]["resolved"][0]["ips"] == ["93.184.216.34"]
    (dest,) = m["destinations"]
    assert (
        dest["via"] == "proxy"
        and dest["name"] == "example.com"
        and dest["bytes_in"] == 1256
        and dest["tls"]["alpn"] == "h2"
    )


def test_without_any_anchor_the_clock_falls_back_and_says_so(tmp_path):
    _, f = proxy_data()
    m = build(make_run(tmp_path, tree_events(), f))  # no Tracee connect to pair with
    assert m["clock"]["source"] == "manifest-pair" and any("No unambiguous" in n for n in m["notes"])


def test_direct_destination_gets_a_name_hint_when_the_proxy_resolved_that_ip(tmp_path):
    t, f = proxy_data()
    tr = tree_events() + t + [tcpev(3, 102, 2, T0 + 3 * S, "93.184.216.34", 443)]
    m = build(make_run(tmp_path, tr, f))
    direct = next(d for d in m["destinations"] if d["via"] == "direct")
    assert direct["name"] == "example.com"


def sev(m, rule):
    return [f["severity"] for f in m["findings"] if f["rule"] == rule]


def test_finding_drop_and_execute_outranks_plain_staging_execution(tmp_path):
    tr = tree_events() + [
        fileev(3, 102, 2, T0 + 2.1 * S, "/tmp/stage.bin", 33345),
        execev(5, 110, 2, T0 + 2.5 * S, ["/tmp/stage.bin"]),
        execev(6, 111, 2, T0 + 2.6 * S, ["/tmp/other"]),
    ]
    m = build(make_run(tmp_path, tr))
    assert sev(m, "drop-and-execute") == ["high"] and sev(m, "exec-from-staging") == ["medium"]
    f = next(f for f in m["findings"] if f["rule"] == "drop-and-execute")
    assert len(f["events"]) == 2 and len(f["procs"]) == 2 and "stage.bin" in f["title"]


def test_finding_credential_access_is_high_for_unknown_tools_low_for_known_clients(tmp_path):
    tr = tree_events() + [
        execev(5, 110, 1, T0 + 2 * S, ["cat", "/home/u/.ssh/id_rsa"]),
        fileev(5, 110, 1, T0 + 2.01 * S, "/home/u/.ssh/id_rsa"),
        execev(6, 111, 1, T0 + 2.2 * S, ["ssh", "host"]),
        fileev(6, 111, 1, T0 + 2.21 * S, "/home/u/.ssh/id_rsa"),
    ]
    m = build(make_run(tmp_path, tr))
    assert sorted(sev(m, "credential-file-access")) == ["high", "low"]


def test_finding_cleartext_credentials_only_on_plain_http(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    t, f = proxy_data()
    f[3]["scheme"] = "http"
    f[3]["headers"] = [["Authorization", "Basic [REDACTED:auth:abcd1234]"]]
    m = build(make_run(tmp_path / "a", tree_events() + t, f))
    assert sev(m, "cleartext-credentials") == ["high"]
    t, f = proxy_data()  # same credential over https: expected for authenticated APIs, informational only
    f[3]["headers"] = [["Authorization", "Bearer [REDACTED:auth:abcd1234]"]]
    m = build(make_run(tmp_path / "b", tree_events() + t, f))
    assert sev(m, "cleartext-credentials") == [] and sev(m, "credentials-in-requests") == ["info"]


def test_finding_unproxied_connection_comes_from_the_kernel_trace(tmp_path):
    tr = tree_events() + [tcpev(3, 102, 2, T0 + 2 * S, "93.184.216.34", 443)]
    m = build(make_run(tmp_path, tr))
    assert sev(m, "unproxied-connection") == ["medium"] and m["run"]["verdict"] == "complete-with-losses"


def test_finding_signal_death_and_nonzero_exit_and_inline_code(tmp_path):
    tr = tree_events() + [
        execev(5, 110, 1, T0 + 2 * S, ["sh", "-c", "kill -SEGV $$"]),
        exitev(5, 110, 1, T0 + 2.1 * S, sig=139),
    ]
    m = build(make_run(tmp_path, tr))
    assert (
        sev(m, "killed-by-signal") == ["medium"]
        and sev(m, "nonzero-exit") == ["info"]
        and "inline-code" in [f["rule"] for f in m["findings"]]
    )


def test_finding_secret_in_command_line_and_redaction_summary(tmp_path):
    tr = tree_events() + [execev(5, 110, 1, T0 + 2 * S, ["curl", "-u", "[REDACTED:argv:abcd1234]", "http://h"])]
    m = build(make_run(tmp_path, tr, manifest={"redactions": {"recorder": {"argv": 2, "kv": 1}, "proxy": {"auth": 4}}}))
    assert sev(m, "secret-in-command-line") == ["medium"]
    red = next(f for f in m["findings"] if f["rule"] == "secrets-redacted")
    assert "7 secret" in red["title"] and "auth x4" in red["detail"]


def test_findings_are_sorted_most_severe_first_and_processes_carry_their_worst_severity(tmp_path):
    tr = tree_events() + [
        execev(5, 110, 1, T0 + 2 * S, ["/tmp/x"]),
        execev(6, 111, 1, T0 + 2.2 * S, ["sh", "-c", "true"]),
    ]
    m = build(make_run(tmp_path, tr))
    order = {"info": 0, "low": 1, "medium": 2, "high": 3}
    sevs = [order[f["severity"]] for f in m["findings"]]
    assert sevs == sorted(sevs, reverse=True) and [f["id"] for f in m["findings"]] == [
        f"f{i}" for i in range(1, len(sevs) + 1)
    ]
    px = next(x for x in m["processes"] if x["pid"] == 110)
    assert px["severity"] == "medium" and px["findings"]


def test_incomplete_run_still_builds_and_says_so(tmp_path):
    evs = [
        {"kind": "run_started", "t_mono_ns": 1, "t_wall_ns": 1},
        {"kind": "recording_armed", "t_mono_ns": 2, "t_wall_ns": 1},
    ]
    m = build(make_run(tmp_path, tree_events(), manifest={"status": "running"}, events=evs))
    assert m["run"]["verdict"] == "incomplete" and sev(m, "recording-integrity") == ["high"]


def test_empty_recording_does_not_crash(tmp_path):
    m = build(make_run(tmp_path, []))
    assert m["processes"] == [] and m["stats"]["events"] == 0 and any("no events" in n for n in m["notes"])


def test_model_is_json_serializable_deterministic_and_keeps_hostile_text_verbatim(tmp_path):
    hostile = '</script><img src=x onerror=alert(1)>"\\u2028'
    tr = tree_events() + [execev(5, 110, 1, T0 + 2 * S, ["echo", hostile])]
    d = make_run(tmp_path, tr)
    a, b = build(d), build(d)
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)
    assert json.dumps(hostile)[1:-1] in json.dumps(a)  # escaping is the renderer's job; the model never alters data


def test_websocket_upgrade_evidence_points_at_the_http_request_not_the_close_event(tmp_path):
    t, f = proxy_data()
    f.append(
        {
            "kind": "ws_open",
            "flow_id": "F1",
            "conn_id": "C1",
            "host": "example.com",
            "path": "/a",
            "t_mono_ns": T0 + 3 * S - OFF,
            "t_wall_ns": 1,
        }
    )
    f.append(
        {
            "kind": "ws_close",
            "flow_id": "F1",
            "close_code": 1000,
            "clean": True,
            "messages": {"c2s": 1, "s2c": 1},
            "bytes": {},
            "suppressed": {"records": 0},
            "t_mono_ns": T0 + 4 * S - OFF,
            "t_wall_ns": 1,
        }
    )
    f[3]["headers"] = [["Authorization", "Bearer [REDACTED:auth:abcd1234]"]]
    m = build(make_run(tmp_path, tree_events() + t, f))
    (h,) = m["http"]
    ev = next(e for e in m["events"] if e["id"] == h["event"])
    assert ev["kind"] == "http"
    cred = next(x for x in m["findings"] if x["rule"] == "credentials-in-requests")
    assert [m_["kind"] for m_ in m["events"] if m_["id"] in cred["events"]] == ["http"]


def test_wrapper_child_that_exits_just_after_t0_is_not_part_of_the_target(tmp_path):
    """Regression (intermittent in real runs): a probe-loop child born before the root's exec whose exit event falls
    a fraction of a millisecond before/after T0 used to appear as a forked process that ended before the run began."""
    noise = te(
        "sched_process_exit",
        91,
        91,
        1,
        T0 - 700_000,
        comm="bash",
        exit_code=0,
        signal_code=0,
        process_group_exit=True,
        start=T0 - 300_000_000,
    )
    late = te(
        "sched_process_exit",
        92,
        92,
        1,
        T0 + 200_000,
        comm="bash",
        exit_code=0,
        signal_code=0,
        process_group_exit=True,
        start=T0 - 250_000_000,
    )
    child = te(
        "sched_process_exit",
        93,
        93,
        1,
        T0 + 2 * S,
        comm="x",
        exit_code=0,
        signal_code=0,
        process_group_exit=True,
        start=T0 + 1 * S,
    )  # a genuine fork of the target that never exec'd: must still appear
    m = build(make_run(tmp_path, tree_events() + [noise, late, child]))
    assert 91 not in [p["pid"] for p in m["processes"]] and 92 not in [p["pid"] for p in m["processes"]]
    assert 93 in [p["pid"] for p in m["processes"]]
    assert all(p["end"] is None or p["end"] >= p["start"] for p in m["processes"])
