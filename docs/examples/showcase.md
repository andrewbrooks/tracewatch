# tracewatch report: `out/showcase/session.sh`

**Verdict: LOSSES** (complete-with-losses). Run `showcase`, started 2026-11-06 00:28:29 UTC (wall clock, approximate), duration 1.74 s, target exited 0.

- 1 connection to 1 destination bypassed the proxy: content not recorded

| Processes | Commands | Destinations | HTTP | WebSockets | DNS names | Watched files | High | Medium | Low | Info |
|---|---|---|---|---|---|---|---|---|---|---|
| 12 | 12 | 6 | 8 | 0 | 5 | 0 | 0 | 3 | 0 | 4 |

## Findings

_Indicators to judge, not verdicts: each cites the evidence it rests on._

|  | Rule | Finding | Process | At |
|---|---|---|---|---|
| [MED]  | `recording-integrity` | The recording is complete with losses | — | +0.000s |
| [MED]  | `secret-in-command-line` | Secret passed on the command line: curl | curl (3915452) | +0.641s |
| [MED]  | `unproxied-connection` | Connection bypassed the proxy: 203.0.113.10:443 | curl (3915470) | +1.375s |
| [info] | `secrets-redacted` | 8 secret values were redacted from this recording | — | +0.000s |
| [info] | `credentials-in-requests` | Credentials seen in 1 request to httpbin.org | curl (3915452) | +0.763s |
| [info] | `nonzero-exit` | 2 processes exited with a non-zero status | python3 (3915469) | +1.357s |
| [info] | `inline-code` | Inline code run through sh | sh (3915472) | +1.405s |

- **[MED] The recording is complete with losses**: Conclusions drawn from this report may be missing activity. _1 connection to 1 destination bypassed the proxy: content not recorded_
- **[MED] Secret passed on the command line: curl**: Command-line arguments can be read by other local users through /proc (unless the system hides them) and end up in shell history and logs.
- **[MED] Connection bypassed the proxy: 203.0.113.10:443**: This process opened a TCP connection that did not go through the recorder's proxy (it ignored the proxy settings, or NO\_PROXY matched). The kernel trace shows the connection; its content was NOT recorded. _1 connection_

## Process tree

```text
bash [3915146] +0.000s → +1.740s exited 0
   $ /bin/bash /home/dev/project/out/showcase/session.sh
├─ curl [3915448] +0.001s → +0.073s exited 0
│     $ curl -s -o /dev/null https://example.com/
├─ curl [3915450] +0.074s → +0.401s exited 0
│     $ curl -s -o /dev/null https://api.github.com/zen
├─ curl [3915451] +0.402s → +0.640s exited 0
│     $ curl -s -o /dev/null --compressed https://httpbin.org/json
├─ curl [3915452] +0.641s → +0.790s exited 0  <== MEDIUM
│     $ curl -s -o /dev/null -X POST https://httpbin.org/post -H 'Authorization: Bearer [REDACTED:bearer:94f…
├─ git [3915453] +0.791s → +1.224s exited 0
│     $ git ls-remote --heads https://github.com/git/git master
│  └─ git [3915454] +0.792s → +1.224s exited 0
│        $ /usr/lib/git-core/git remote-https https://github.com/git/git https://github.com/git/git
│     └─ git-remote-https [3915455] +0.793s → +1.223s exited 0
│           $ /usr/lib/git-core/git-remote-https https://github.com/git/git https://github.com/git/git
├─ python3 [3915469] +1.225s → +1.357s exited 1
│     $ python3 -
├─ curl [3915470] +1.358s → +1.404s exited 0  <== MEDIUM
│     $ curl -s -o /dev/null https://example.com/
└─ sh [3915472] +1.404s → +1.740s exited 2
      $ sh -c 'curl -s -o /dev/null https://api.github.com/octocat; exit 2'
   └─ curl [3915473] +1.405s → +1.739s exited 0
         $ curl -s -o /dev/null https://api.github.com/octocat
```

## Network destinations

| Via | Destination | Port | Requests | Errors | In | Out | TLS |
|---|---|---|---|---|---|---|---|
| **DIRECT (not recorded)** | `203.0.113.10` | 443 | 1 | 0 | 0 B | 0 B | — |
| proxy | `api.github.com` | 443 | 2 | 0 | 892 B | 0 B | TLSv1.3 h2 |
| proxy | `github.com` | 443 | 2 | 0 | 687 B | 129 B | TLSv1.3 h2 |
| proxy | `httpbin.org` | 443 | 2 | 0 | 906 B | 42 B | TLSv1.3 h2 |
| proxy | `example.com` | 443 | 1 | 0 | 577 B | 0 B | TLSv1.3 h2 |
| proxy | `example.org` | 443 | 1 | 1 | 17 B | 0 B | TLSv1.3 http/1.1 |

## HTTP requests

| At | Process | Method | URL | Status | Size | Time |
|---|---|---|---|---|---|---|
| +0.059s | curl (3915448) | GET | `https://example.com/` | 200 | 577 B | 16 ms |
| +0.304s | curl (3915450) | GET | `https://api.github.com/zen` | 200 | 19 B | 99 ms |
| +0.613s | curl (3915451) | GET | `https://httpbin.org/json` | 200 | 429 B | 30 ms |
| +0.763s | curl (3915452) | POST | `https://httpbin.org/post` | 200 | 477 B | 30 ms |
| +0.997s | git-remote-https (3915455) | GET | `https://github.com/git/git/info/refs?service=git-upload-pack` | 200 | 191 B | 122 ms |
| +1.123s | git-remote-https (3915455) | POST | `https://github.com/git/git/git-upload-pack` | 200 | 496 B | 99 ms |
| +1.299s | python3 (3915469) | GET | `https://example.org/` | 403 | 17 B | 11 ms |
| +1.636s | curl (3915473) | GET | `https://api.github.com/octocat` | 200 | 873 B | 104 ms |

## DNS and name resolution

_Names the proxy resolved are exact. For lookups a process makes itself, only the resolver contact is visible, not the name._

| Name | Address(es) | Ports | Lookups | Processes |
|---|---|---|---|---|
| `api.github.com` | `203.0.113.12` | 443 | 2 | curl (3915450), curl (3915473) |
| `httpbin.org` | `203.0.113.13, 203.0.113.14` | 443 | 2 | curl (3915451), curl (3915452) |
| `example.com` | `203.0.113.11` | 443 | 1 | curl (3915448) |
| `example.org` | `203.0.113.17` | 443 | 1 | python3 (3915469) |
| `github.com` | `203.0.113.15` | 443 | 1 | git-remote-https (3915455) |

| Process | Resolver contacted | Times | First |
|---|---|---|---|
| curl (3915470) | `nscd` | 4 | +1.360s |
| curl (3915448) | `nscd` | 2 | +0.005s |
| curl (3915450) | `nscd` | 2 | +0.077s |
| curl (3915451) | `nscd` | 2 | +0.407s |
| curl (3915452) | `nscd` | 2 | +0.644s |
| python3 (3915469) | `nscd` | 2 | +1.252s |
| curl (3915473) | `nscd` | 2 | +1.407s |
| python3 (3915469) | `192.0.2.10:53` | 1 | +1.252s |
| curl (3915470) | `192.0.2.10:53` | 1 | +1.361s |

_8 UDP connect() calls right after a lookup are address-selection probes (no traffic)._

## Commands

| At | PID | Parent | Command |
|---|---|---|---|
| +0.000s | 3915146 | — | `/bin/bash /home/dev/project/out/showcase/session.sh` |
| +0.001s | 3915448 | bash (3915146) | `curl -s -o /dev/null https://example.com/` |
| +0.074s | 3915450 | bash (3915146) | `curl -s -o /dev/null https://api.github.com/zen` |
| +0.402s | 3915451 | bash (3915146) | `curl -s -o /dev/null --compressed https://httpbin.org/json` |
| +0.641s | 3915452 | bash (3915146) | `curl -s -o /dev/null -X POST https://httpbin.org/post -H 'Authorization: Bearer [REDACTED:bearer:94f234e8]' -d 'user=alice&password=[REDACTED:kv:eae4654c]'` |
| +0.791s | 3915453 | bash (3915146) | `git ls-remote --heads https://github.com/git/git master` |
| +0.792s | 3915454 | git (3915453) | `/usr/lib/git-core/git remote-https https://github.com/git/git https://github.com/git/git` |
| +0.793s | 3915455 | git (3915454) | `/usr/lib/git-core/git-remote-https https://github.com/git/git https://github.com/git/git` |
| +1.225s | 3915469 | bash (3915146) | `python3 -` |
| +1.358s | 3915470 | bash (3915146) | `curl -s -o /dev/null https://example.com/` |
| +1.404s | 3915472 | bash (3915146) | `sh -c 'curl -s -o /dev/null https://api.github.com/octocat; exit 2'` |
| +1.405s | 3915473 | sh (3915472) | `curl -s -o /dev/null https://api.github.com/octocat` |

## File activity (watched paths only)

_none recorded_

## Recording integrity

Verdict **complete-with-losses**. Clock alignment: anchors (7 anchors).


## Notes and limits

- 8 opens of the recorder's own CA bundle (loaded by TLS clients) are hidden from the file list.
- File activity covers only the watched paths (credential stores and temp directories), not every open.
- DNS query names are not visible for lookups a process makes itself; names the proxy resolved are exact.
- UDP payloads (including QUIC/HTTP3) are never recorded; a UDP connect() is shown, not its traffic.
- Redaction is heuristic: treat the underlying run directory as sensitive.

_Generated by tracewatch 0.1.0, model schema 1._
