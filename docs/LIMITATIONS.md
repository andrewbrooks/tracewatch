# Limitations

tracewatch is an experiment, not a security product. This is what it does not do, as far as the author knows.

## What it cannot see

- **Only proxied traffic has content.** A program that ignores proxy settings still shows up (the kernel sees the
  connection, and the report flags it as bypassing the proxy), but what it sent is not recorded.
- **Clients that refuse the recorder's certificate** (certificate pinning, or no trust in the per-run CA) are reported as
  such; their content is not recorded.
- **QUIC / HTTP/3 and other UDP payloads** are visible as connections only.
- **File activity is a short watch list**, not every file: credential stores (SSH, cloud, `.env`, private keys) and
  temporary directories. Something written to a path outside the list is invisible, which includes persistence such as
  editing `~/.bashrc` or a crontab.
- **File contents are a best effort**, for files the target created or wrote on that same watch list. Not captured:
  files only read (by design), anything outside the list, files bigger than 16 KiB beyond their first 16 KiB, anything
  past the per-run caps (256 KiB, 100 files), and a file written and deleted within about a tenth of a millisecond of its
  directory being created, or inside a temp directory that already existed when the run began, if it is also deleted
  before the recorder looks. Redaction recognises known secret shapes; it is not a guarantee that no secret is stored,
  so treat `files.jsonl` like the rest of the recording.
- **DNS:** names the proxy resolved are exact. For a process that resolves a name itself, only the contact with the
  resolver is visible, not the name.
- **No syscall-level behaviour** beyond process start/exit, connects, sends and the watched opens.

## Where attribution can be wrong or missing

- A request is attributed to the process that sent it when the evidence supports that. A child that inherits a socket,
  sends, and exits before the proxy looks can be missed; the report then names the connection's opener and says so.
- Time alignment between the two recordings assumes a constant offset. It was checked over runs of about 100 seconds;
  hours-long runs and a suspended machine were not tested.

## Findings

- The rules are heuristics written by hand. Severities are rough estimates, not measurements, and there is no tuning
  against real incidents. Each rule's entry in [FINDINGS.md](FINDINGS.md) lists what it cannot tell you and what benign
  activity looks the same.
- Some rules have never fired on a real recording (marked "synthetic only"): they are tested only on fabricated events.

## Redaction

- It is pattern-based and keyed by name. It catches the common shapes (bearer tokens, API keys, passwords in forms,
  PEM private keys, URL credentials) and will miss secrets that look like ordinary text. **Treat run directories and
  reports as private.**
- A real bug of this kind was found while testing (a private key posted with a "form" content type was stored
  unredacted) and fixed; it is a reminder that a content type is a claim, not a fact.

## Platform

- **Linux only.** Developed and tested on WSL2 with Docker Desktop; plain Linux with Docker should work but has been
  exercised less. No Windows or macOS support.
- **Needs a privileged Docker container** for Tracee (host PID namespace). See [SECURITY.md](../SECURITY.md).
- **Slow start**: about five seconds before the target runs and two more after it ends.
- Tested with Tracee v0.24.1 only.

## The report

- Tested in Chromium and Firefox. Safari/WebKit and a physical printer were not tried.
- Zoom has buttons, keys and Ctrl + wheel; two-finger pinch on a touch screen is not supported.
- Automated accessibility checks (axe-core) find no violations, and keyboard and focus handling are tested, but the report has not been
  used with a real screen reader.
- The timeline view is not printed.

## Not done on purpose

Real AI-agent workloads, running several recorders at once, disk-full behaviour, and hours-long runs were left out of
scope.
