# PCS source fork

Upstream: https://github.com/klzgrad/forwardproxy
Base commit: `d62c80d3dd2c706b6b87579844d2397bddd18317`

This source fork preserves upstream Git history and license. It is hosted on the
`source/forwardproxy-reliability` branch of the private `13Cohen/PCS` repository because
the connected GitHub interface cannot create a separate fork repository. The
branch can be pushed into a standalone repository later without losing history.
Upstream workflow files are removed from this source branch; PCS owns deployment.

The production build uses the pinned upstream module plus an audited patch in
PCS `caddy/`, so Docker builds need no credentials for private Git repositories.
Runtime secrets, real client IPs and certificates are never stored in this fork.

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
