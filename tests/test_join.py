"""Deterministic edge cases for the post-facto flow->pid join (the real run is not deterministic)."""

from tracewatch.join import join_records

PP, S = 18107, 1_000_000_000
OFF = 5_000_000_000_000  # tracee clock = proxy monotonic + OFF


def conn(cid, port, holders, t):
    return {"kind": "conn", "conn_id": cid, "client_port": port, "holder_pids": holders, "t_wall_ns": t}


def mconn(cid, m, holders, wall_step=0):
    return {
        "kind": "conn",
        "conn_id": cid,
        "client_port": 1,
        "holder_pids": holders,
        "accept_mono_ns": m,
        "t_mono_ns": m,
        "t_wall_ns": m + wall_step,
    }


def flow(cid, path):
    return {"kind": "flow", "conn_id": cid, "client_port": 1, "path": path}


def connect(pid, t, port=PP):
    return {
        "eventName": "net_tcp_connect",
        "processId": pid,
        "timestamp": t,
        "processName": "x",
        "args": [{"name": "dst_port", "value": port}],
    }


def exe(pid):
    return {"eventName": "sched_process_exec", "processId": pid, "timestamp": 0, "processName": "x", "args": []}


def by(rows):
    return {r["path"]: r for r in rows}


def test_port_reuse_uses_conn_id():
    r = by(
        join_records(
            [conn("a", 5000, [10], 10 * S), flow("a", "/1"), conn("b", 5000, [11], 20 * S), flow("b", "/2")],
            [exe(10), exe(11), connect(10, 10 * S), connect(11, 20 * S)],
            PP,
        )
    )
    assert (r["/1"]["pid"], r["/2"]["pid"]) == (10, 11)


def test_shared_socket_connecting_holder_wins():
    r = by(
        join_records(
            [conn("a", 5000, [10, 12], 10 * S), flow("a", "/s")], [exe(10), exe(12), connect(10, 10 * S - 5)], PP
        )
    )
    assert r["/s"]["pid"] == 10 and r["/s"]["method"] == "socket-holder+connect-event"


def test_shared_socket_without_evidence_is_ambiguous():
    r = by(join_records([conn("a", 5000, [10, 12], 10 * S), flow("a", "/s")], [exe(10), exe(12)], PP))
    assert r["/s"]["pid"] is None and r["/s"]["candidates"] == [10, 12] and r["/s"]["scope"] == "unknown"


def test_shared_socket_two_connecters_is_ambiguous():
    r = by(
        join_records(
            [conn("a", 5000, [10, 12], 10 * S), flow("a", "/s")],
            [exe(10), exe(12), connect(10, 10 * S - 5), connect(12, 10 * S - 9)],
            PP,
        )
    )
    assert r["/s"]["pid"] is None and r["/s"]["method"] == "ambiguous-holders"


def test_gone_client_single_candidate_is_inferred():
    r = by(join_records([conn("a", 5000, [], 10 * S), flow("a", "/g")], [exe(10), connect(10, 10 * S - 1000)], PP))
    assert r["/g"]["pid"] == 10 and r["/g"]["method"] == "inferred-connect-window" and r["/g"]["scope"] == "in-tree"


def test_two_gone_clients_are_not_guessed():
    r = by(
        join_records(
            [conn("a", 5000, [], 10 * S), flow("a", "/g1"), conn("b", 5001, [], 10 * S + 1000), flow("b", "/g2")],
            [exe(10), exe(11), connect(10, 10 * S - 1000), connect(11, 10 * S - 500)],
            PP,
        )
    )
    assert all(
        r[p]["pid"] is None and r[p]["method"] == "unresolved" and r[p]["candidates"] == [10, 11]
        for p in ("/g1", "/g2")
    )


def test_claimed_connect_is_not_reused_for_inference():
    r = by(
        join_records(
            [conn("a", 5000, [10], 10 * S), flow("a", "/k"), conn("b", 5001, [], 10 * S + 5000), flow("b", "/g")],
            [exe(10), connect(10, 10 * S - 1000)],
            PP,
        )
    )
    assert r["/k"]["pid"] == 10 and r["/g"]["pid"] is None


def test_stale_connect_outside_window_ignored():
    r = by(join_records([conn("a", 5000, [], 100 * S), flow("a", "/g")], [exe(10), connect(10, 10 * S)], PP))
    assert r["/g"]["pid"] is None


def test_holder_unseen_by_tracee_is_outside_tree():
    r = by(join_records([conn("a", 5000, [99], 10 * S), flow("a", "/o")], [exe(10), connect(10, 5 * S)], PP))
    assert r["/o"]["pid"] == 99 and r["/o"]["scope"] == "outside-tree"


def test_keepalive_flows_share_attribution():
    r = by(
        join_records(
            [conn("a", 5000, [10], 10 * S), flow("a", "/k1"), flow("a", "/k2")], [exe(10), connect(10, 10 * S - 5)], PP
        )
    )
    assert r["/k1"]["pid"] == r["/k2"]["pid"] == 10


def test_flow_without_connection_record_is_unknown():
    r = by(join_records([flow("zzz", "/n")], [exe(10)], PP))
    assert r["/n"]["pid"] is None and r["/n"]["method"] == "no-connection-record"


def _stepped_clock_data():
    fl = [
        mconn("a", 10 * S, [10]),
        flow("a", "/a"),
        mconn("b", 20 * S, [11]),
        flow("b", "/b"),
        mconn("g", 30 * S, [], wall_step=5 * S),
        flow("g", "/g"),
    ]  # wall clock stepped +5 s before g
    tr = [
        exe(10),
        exe(11),
        exe(12),
        connect(10, 10 * S - 3_000_000 + OFF),
        connect(11, 20 * S - 3_000_000 + OFF),
        connect(12, 30 * S - 3_000_000 + OFF),
    ]
    return fl, tr


def test_monotonic_calibration_survives_wall_clock_step():
    fl, tr = _stepped_clock_data()
    info = {}
    r = by(join_records(fl, tr, PP, info))
    assert info["clock"] == "monotonic" and abs(info["offset_ns"] - (OFF - 3_000_000)) < 1000
    assert r["/g"]["pid"] == 12 and r["/g"]["method"] == "inferred-connect-window"


def test_wall_fallback_is_flagged_and_fails_on_stepped_clock():
    """Negative control: without monotonic stamps the same data cannot be joined correctly."""
    fl, tr = _stepped_clock_data()
    fl = [{k: v for k, v in x.items() if k not in ("accept_mono_ns", "t_mono_ns")} for x in fl]
    fl = [dict(x, t_wall_ns=x["t_wall_ns"] + OFF) if x["kind"] == "conn" else x for x in fl]
    info = {}
    r = by(join_records(fl, tr, PP, info))
    assert info["clock"] == "wall-fallback" and r["/g"]["pid"] != 12


def test_one_process_many_connections_calibrates_by_voting():
    fl, tr = [], [exe(20)]
    for i in range(6):
        fl += [mconn(f"c{i}", (10 + 7 * i) * S, [20]), flow(f"c{i}", f"/m{i}")]
        tr.append(connect(20, (10 + 7 * i) * S - 2_000_000 + OFF))
    info = {}
    r = by(join_records(fl, tr, PP, info))
    assert info["clock"] == "monotonic" and abs(info["offset_ns"] - (OFF - 2_000_000)) < 1000 and info["votes"] >= 6
    assert all(r[f"/m{i}"]["pid"] == 20 for i in range(6))


def test_tunnel_without_flows_is_attributed_and_tunnel_with_flows_is_not_duplicated():
    fl = [
        conn("a", 5000, [10], 10 * S),
        {"kind": "connect", "conn_id": "a", "client_port": 5000, "host": "evil.example", "port": 443},
        conn("b", 5001, [10], 20 * S),
        {"kind": "connect", "conn_id": "b", "client_port": 5001, "host": "ok.example", "port": 443},
        flow("b", "/x"),
    ]
    rows = join_records(fl, [exe(10), connect(10, 10 * S - 5), connect(10, 20 * S - 5)], PP)
    assert sorted(r["path"] for r in rows) == ["/x", "CONNECT evil.example:443"]
    assert all(r["pid"] == 10 for r in rows)
