# Challenge Direct Listener Review

Scope: direct challenge mode where CSM serves `/challenge` on its own port
and the webserver redirects only challenge-listed clients to that URL.

## Current Behavior

- The challenge listener is loopback by default. Direct mode requires a
  non-loopback `challenge.listen_addr` plus `challenge.public_url` ending in
  `/challenge`.
- `challenge.port_gate.enabled` installs a separate nftables gate for the
  challenge port. Loopback, `infra_ips`, and currently challenged IPs can
  reach the listener; other sources are dropped.
- Webserver snippets read CSM-managed maps under `/run/csm/` and redirect
  only IPs present in those maps.
- The direct listener can serve HTTPS from `challenge.tls_cert` /
  `challenge.tls_key`, or from the Web UI TLS pair for non-loopback binds.

## Changes Made In This Branch

- Added `csm doctor challenge` for public URL, TLS file, port-gate,
  webserver snippet, webserver configtest, and live `/challenge/gate`
  checks.
- Added health/status automation state with dry-run block count, challenge
  pending count, port-gate activity, firewall rollback pending state, and the
  last automation action.
- Added API contract tests for the status, components, email groups, and
  ModSecurity JSON surfaces that phpanel can consume.

## Recommended Changes

### High: fail closed when the gate cannot install

Today, if `challenge.port_gate.enabled` is true but gate installation fails,
the daemon logs the error and still starts the public listener. That is the
wrong failure mode for a port that is meant to be visible only when a user is
currently challenged.

Change the startup path so a non-loopback challenge listener fails to start
when port-gate install fails. If there is a real need for a permanently public
listener, make that an explicit operator opt-in with a name that states the
risk.

### High: do not publish redirects when per-IP gate opens fail

`IPList.Add` writes the webserver maps and then asks the port gate to allow the
source IP. If the gate update fails, the webserver may redirect the visitor to
a port that the firewall still drops. The visitor cannot solve the challenge
and may later be escalated to a hard block.

Change the flow so per-IP gate allow happens before the IP is published in the
webserver maps, and make the add path return an error. Callers should either
retry or fall back to a clear action instead of creating a broken redirect.

### Medium: rate-limit all browser challenge endpoints

Only the admin-token endpoint has a failed-attempt limiter. A direct listener
that is temporarily reachable by a challenged IP can still be hammered on
`/challenge`, `/challenge/verify`, and `/challenge/captcha-verify`.

Add per-IP sliding-window limits for challenge page generation and verify
attempts. Keep the thresholds generous for shared NATs, but bounded. Also cap
the verified nonce map by TTL and size so repeated bad clients cannot grow it
without bound.

### Medium: enforce HTTPS readiness for public direct mode

The listener currently starts in plain HTTP on a public bind and logs a
warning when TLS material is missing. That is acceptable for loopback mode, but
direct mode commonly uses HSTS-pinned control-panel hostnames and will fail in
browser-visible ways without TLS.

Keep the new doctor failure, then promote this to config validation for
`challenge.public_url` with `https` and a non-loopback listener.

### Medium: expose every direct-mode field in Settings

The Settings schema exposes `enabled`, `listen_port`, `difficulty`, and
`trusted_proxies`, but direct mode also depends on `listen_addr`,
`public_url`, `tls_cert`, `tls_key`, and `port_gate.enabled`.

Add those fields to the Challenge section with restart warnings and lockout
copy. Without them, operators can enable the feature from the UI but cannot
complete the direct-mode setup there.

### Low: add metrics for challenge gate state

The new status payload is enough for operators and phpanel. Prometheus should
also get counters or gauges for pending challenge IPs, port-gate active state,
gate allow failures, and gate install failures.

## Suggested Order

1. Fail closed on gate install failure for non-loopback listeners.
2. Make per-IP gate allow part of the IPList add transaction.
3. Add challenge endpoint rate limits and nonce map bounds.
4. Promote public HTTPS readiness from doctor failure to config validation.
5. Add the missing direct-mode fields to Settings.
6. Add Prometheus metrics for gate health and failures.
