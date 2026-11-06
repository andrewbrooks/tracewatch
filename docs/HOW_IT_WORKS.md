# How tracewatch works

A short tour for someone reading the code. It describes what the code does today; the limits are in
[LIMITATIONS.md](LIMITATIONS.md) and the rule definitions in [FINDINGS.md](FINDINGS.md).

## The idea

Two independent observers watch the same process:

- **The kernel's view** (Tracee, eBPF): which processes were started, by whom, with what command line; which files on a
  short watch list were opened; which TCP connections were made; which process wrote to which socket.
- **The network view** (mitmproxy): decrypted HTTP(S) and websocket traffic, DNS answers, and TLS facts.

Neither knows what the other saw. After the run, the two recordings are joined so that every request is attributed to
the process that sent it, and the result is rendered as a report.

## Recording (`tracewatch record -- <command>`)

1. **A private run directory** is created (directories `0700`, files `0600`).
2. **mitmproxy starts** with a fresh CA made for this run. The CA's private key is deleted when the run ends.
3. **The target is held, not started.** It is launched as a small wrapper that waits for a flag file, so the kernel
   tracer can attach before the real command exists. The target gets `HTTP_PROXY`/`HTTPS_PROXY` and the usual CA
   environment variables (`SSL_CERT_FILE`, `CURL_CA_BUNDLE`, `REQUESTS_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`, `GIT_SSL_CAINFO`),
   all with absolute paths.
4. **Tracee runs in Docker**, scoped to the target's process tree. Scoping needs the target's pid *as the Tracee container
   sees it*, which differs from the pid on the host (notably on WSL2 with Docker Desktop), so a short-lived Tracee first
   watches a probe binary to learn it. That is why a recording takes several seconds to start.
5. **The target is released** (it `exec`s the real command) once Tracee has produced its first event.
6. **Recording ends when the root process exits.** The recorder waits for the root's own exit event plus a short grace
   period, stops Tracee and the proxy, removes the CA private key, and writes the manifest.

While it runs, a heartbeat is written every two seconds. If a component dies, the loss is recorded and, depending on
policy, the target is stopped or left running unrecorded. `tracewatch sweep` finalizes runs whose recorder was killed.

### What is written

| File | Contents |
|---|---|
| `flows.jsonl` | One record per proxy event: connections, requests, results, TLS facts, DNS answers, websocket messages |
| `tracee.jsonl` | Kernel events from Tracee |
| `events.jsonl` | The recorder's own log: component starts and deaths, caps, heartbeats |
| `files.jsonl` | What the target left in files it created or wrote on the watched paths (see below) |
| `manifest.json` | Command, versions, policy, limits, status |

**Secrets are redacted before anything is written.** A keyed hash gives each distinct secret a stable tag
(`[REDACTED:bearer:1a2b3c4d]`), so you can tell two uses of the same token apart without storing it. If redaction fails
for a line, the line is dropped, not written. Size caps (soft: stop storing bodies; hard: stop writing) keep a chatty
run bounded, and the report says when a cap was hit.

### File contents

Only files the target **created or wrote** (opened for writing, on the watched paths) are captured; a file it merely
read is never stored, so a credential store it opened does not end up in the recording. What the target writes is as
attacker-controlled as anything else, so (`filecapture.py`):

- a file is read only if it is a regular file, opened one path component at a time with `O_NOFOLLOW` (a symlink swapped
  in after the event cannot redirect the read) and without blocking (a FIFO cannot hang the recorder);
- at most 16 KiB per file, 256 KiB and 100 files per run; binary files keep only their size, hash and first bytes;
- text is made inert before it is stored: control characters, bidirectional overrides and invisible characters become
  visible `⟦\x1b⟧` escapes, then the same redaction as everything else is applied; the HTML report shows it as text nodes
  only and the Markdown report fences it with a fence longer than anything inside it.

A file that is written, run and deleted within milliseconds is gone before Tracee's event reaches the recorder. To catch
that case a small inotify watcher on `/tmp`, `/var/tmp` and `/dev/shm` keeps the last 16 KiB of each file closed after
writing **in memory only, for ten seconds**; it is written out only if Tracee then names the traced process as the
writer of that path, and is discarded otherwise.

## Reconstruction (`tracewatch report`)

Reading the run directory and building one JSON **model** (`model.py`) is deterministic and needs no Docker.

- **Process tree** from exec/exit events, with pid-reuse handled and the recorder's own wrapper noise removed.
- **Joining requests to processes** (`join.py`). When the proxy accepts a connection it looks through `/proc` for the
  processes holding that socket. Tracee's timestamps and the proxy's monotonic clock differ by a constant, which is
  estimated from connections that had exactly one holder. If a socket is held by several processes (a child inherited
  it), the proxy looks again when the request arrives, and the request is attributed to the process whose last `send`/
  `write` on that socket preceded it. If that cannot be shown, the report says "sender unknown" rather than guessing.
- **Integrity** (`integrity.py`): a verdict (complete, complete with losses, incomplete), the gaps, and any traffic that
  bypassed the proxy (kernel-visible connections that never reached it) or was refused by the client's TLS stack.
- **Findings** (`findings.py`): rule-based indicators, each citing the events that triggered it. The catalog
  (`findings_catalog.py`) records what each rule means, what it cannot tell you, what benign activity looks the same, and
  whether the rule has ever fired on a real recording.

## Rendering

The model has three renderers: the **interactive HTML report**, a flat **Markdown** report, and the raw **JSON**.
`tracewatch diff` compares two models (Markdown, JSON, or a static HTML page).

The HTML report is one self-contained file, and **the recording is hostile data** (command lines, URLs, headers and
bodies are attacker-controlled text). So:

- the model is embedded as JSON with `<`, `>` and `&` escaped, so it cannot close the script tag;
- the page builds its DOM with `textContent` only; a test fails the build if the source ever uses `innerHTML`, `eval`,
  `document.write` and similar;
- a Content-Security-Policy with a per-render nonce forbids every network request and every script not in the file.

The page has swim-lane activity charts (zoomable), a process tree, a timeline, tables with keyboard navigation, a detail
drawer, dark and light themes, and a print layout. It is written in plain JavaScript with no dependencies.

## How it is tested

| Layer | What it covers | Needs Docker |
|---|---|---|
| Unit tests (`tests/`) | Redaction, the join, the model, the findings rules and catalog, the renderers and their security invariants | No |
| Browser tests (`tests/browser/run.py`) | The report in Chromium and Firefox: keyboard use, responsive layouts, themes, print, zoom, hostile data | No (a recorded demo run unlocks more checks) |
| Accessibility audit (`tests/browser/axe_check.py`, optional) | axe-core over every report view at desktop and phone widths, both themes (needs `npm install axe-core`) | No |
| Integration scripts (`tests/integration/*.sh`) | Real recordings: fault injection, secrets that must never reach disk, websockets, HTTP/2, shared sockets, size caps | Yes |

Several security claims are checked by **mutation**: break the code on purpose and confirm a test fails.
