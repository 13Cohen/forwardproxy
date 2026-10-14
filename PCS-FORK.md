# Reliability fork

Maintained at https://github.com/13Cohen/forwardproxy/tree/pcs/reliability
Upstream: https://github.com/klzgrad/forwardproxy
Base commit: `d62c80d3dd2c706b6b87579844d2397bddd18317`

This branch preserves upstream Git history and license. The repository's original
default branch is retained for upstream tracking. PCS owns deployment and pins
this independent repository by full commit and archive SHA256; source development
does not belong in PCS. The former temporary PCS source branch is retired after
migration. Runtime secrets, real client IPs and certificates are never committed.

Upstream workflow files were removed from the initial experimental branch; this
branch does not publish upstream release artifacts. CI/deployment is controlled
by PCS. Contribution branches must start from current upstream, carry only the
relevant fix and regression test, and preserve the upstream workflow structure.

Integration versions: Caddy 2.11.1, Go 1.25.6, x/net 0.50.0.
Refer to PCS `caddy/OPERATIONS.md` for experiments, rollout and limitations.

Changes: bounded context-aware DNS/dial attempts; at most two ACL-checked numeric
addresses in flight; request cancellation closes origin connections; upload
errors release tunnels while clean half-closes preserve responses; malformed
padding fails correctly; access logs distinguish target dial completion from
the early CONNECT 200. Authentication, probe routing, TLS configuration and
valid Naive padding wire format are preserved.

Run `go test -tags=nobadger,nomysql,nopgx ./...` and
`go test -race -tags=nobadger,nomysql,nopgx -run TestReliability -count=3 .`.
Tests include local TLS/HTTP2 multiplexing, reset storms and ACL checks.
The existing suite also uses public DNS for some ACL fixtures.
