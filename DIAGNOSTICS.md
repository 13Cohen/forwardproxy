# Optional CONNECT diagnostics

Enable `diagnostics` inside `forward_proxy` (JSON: `"diagnostics": true`). Disabled
by default. Auth checks, probe routing, TLS and valid padding wire format are
unchanged. No diagnostic response headers or public endpoints are added.

The existing Caddy access log receives one bounded set of fields when an
authenticated CONNECT handler finishes. No per-packet events, payload inspection,
extra destination IPs, account IDs or credentials are recorded. Existing Caddy
request logging/redaction is a separate concern. If access logging is disabled,
no observation object is created. Random `proxy_trace_id` is request-local, never
sent to the client, and not a cross-request user identifier.

| Fields | Meaning |
| --- | --- |
| `proxy_diag_version`, `proxy_trace_id` | Schema version 1 and random 128-bit identifier for this log record |
| `proxy_stage` | Last stage: response, validation, ACL, DNS, direct/upstream dial, or transfer |
| `proxy_dns_ms` | Resolver call duration, omitted when DNS was not attempted; includes local cache hits |
| `proxy_dial_candidates`, `proxy_dial_attempts` | ACL-approved addresses and number of started attempts; canceled losers count as attempts |
| `proxy_dial_ms`, `proxy_dial_ok` | Existing overall DNS/ACL/dial duration and actual connection result; CONNECT 200 can precede failure |
| `proxy_end_reason` | clean_eof, request_canceled, or error; clean EOF does not prove application success |
| `proxy_error_class` | none/canceled/deadline/timeout/peer_reset/refused/broken_pipe/closed/unexpected_eof/short_write/dns/stream_error/other |
| `proxy_error_side` | client_read, target_write, target_read, client_write, client_flush; none when outside stream copy |
| `proxy_request_canceled` | Whether the request context was canceled at handler return, kept separate from the initiating error |
| `proxy_total_ms` | Handler lifetime from accepted CONNECT diagnostics start; not page latency |
| `proxy_{upload,download}_written_bytes` | Bytes accepted by target/client writer respectively; download includes Naive framing/padding, upload excludes removed padding |
| `proxy_{upload,download}_first_read_ms` | Delay from that copy loop's start until first nonempty read; omitted when no data was read |
| `proxy_{upload,download}_max_{read,write,flush}_block_ms` | Longest individual blocking call per direction, milliseconds |

Read blocking can mean a legitimately idle application; it is not automatically a
stall. Write/flush duration includes local buffering/flow control and does not
prove delivery to the remote application. These fields are final aggregates,
not live gauges for still-open tunnels. Socket retransmission/queue sampling in
the deployment monitor complements them. HTTP1 bytes already buffered before
hijacking are not included in copy-loop statistics.

Each copy loop owns its statistics; the handler joins both before updating
Caddy ExtraLogFields (which is not safe for concurrent mutation). Errors retain
their typed unwrap chain. Cleanup-induced upload errors must not overwrite the
original download failure; the first reported real stream error is retained.
Simultaneous independent errors are ordered by goroutine reporting, not inferred
as a causal network timeline.

Validation: existing auth/ACL/probe/padding/HTTP2 tests, cancellation/half-close
regressions, typed reset attribution, no-content field checks, blocked-write
measurement, optional config parsing, race tests, and a copy-loop microbenchmark.
The microbenchmark is not a public-path throughput benchmark. See PCS deployment
operations for isolated end-to-end validation and post-release observations.

For upstream contribution, split deterministic bug fixes and regression tests
from deployment-specific observability and tuning. Check the current upstream
branch for an existing fix, follow CONTRIBUTING.md, and provide a minimal local
reproducer plus baseline/fixed results. Do not submit production logs containing
addresses, credentials or browsing history. No upstream PR is implied by this
experimental branch.
