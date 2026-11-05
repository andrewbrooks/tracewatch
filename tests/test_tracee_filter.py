"""Collector pre-filter for write() events: keep sockets, drop files and pipes, never guess the unknown away."""

import json
import os
import socket

from tracewatch.tracee import keep_line


def line(name, pid, fd):
    e = {"eventName": name, "processId": pid, "args": [{"name": "fd", "value": fd}]}
    return (json.dumps(e, separators=(",", ":")) + "\n").encode()


def test_a_write_to_a_socket_is_kept_and_to_a_file_or_pipe_is_dropped(tmp_path):
    a, b = socket.socketpair()
    f = open(tmp_path / "x", "w")
    r, w = os.pipe()
    try:
        assert keep_line(line("write", os.getpid(), a.fileno()))
        assert keep_line(line("writev", os.getpid(), b.fileno()))
        assert not keep_line(line("write", os.getpid(), f.fileno()))
        assert not keep_line(line("writev", os.getpid(), w))
    finally:
        a.close(), b.close(), f.close(), os.close(r), os.close(w)


def test_an_unknown_descriptor_or_vanished_process_is_kept_not_guessed_away():
    assert keep_line(line("write", os.getpid(), 987654))  # no such fd
    assert keep_line(line("write", 2**22 + 5, 3))  # no such process
    assert keep_line(b'not json but mentions "eventName":"write"\n')  # unparsable: kept


def test_other_events_are_never_filtered():
    for name in ("sendto", "sched_process_exec", "security_socket_connect", "net_tcp_connect"):
        assert keep_line(line(name, os.getpid(), 1))
