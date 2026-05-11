# Challenge Pages

JavaScript proof-of-work challenge pages - a CAPTCHA alternative for suspicious IPs.

## How It Works

1. Suspicious IP hits a protected resource
2. CSM serves a challenge page requiring client-side SHA-256 proof-of-work
3. Browser computes the proof (shows progress bar)
4. On valid solution, CSM issues an HMAC-verified token
5. Subsequent requests pass through automatically

## Features

- **SHA-256 based difficulty** - configurable 0-5 levels
- **Client-side computation** - no server load
- **HMAC token verification** - prevents replay attacks
- **Nonce-based anti-replay**
- **User-friendly** - progress bar, instant feedback
- **Bot filtering** - headless browsers and scripts fail the challenge

## Use Cases

- Gray-listing alternative to hard IP blocks
- Protecting WordPress login pages
- Rate limiting without blocking legitimate users
- DDoS mitigation layer

## Routing Behavior

When `challenge.enabled: true`, CSM routes eligible IPs to the challenge page instead of hard-blocking them. This works independently of `auto_response` settings.

### Challenge-Eligible Checks

Pre-auth, browser-visible attack signals only: `wp_login_bruteforce`,
`xmlrpc_abuse`, `wp_user_enumeration`, `webmail_bruteforce`, `ip_reputation`,
`local_threat_score`, `waf_attack_blocked`. Post-auth audit events (cPanel,
webmail, file upload, WHM logins) and non-browser protocols (SSH, FTP, DNS
recursion, outbound traffic, API auth) are excluded - their IPs have no
browser session to render the PoW page and every match would time out
into a 24h hard block.

### Always Hard-Blocked

Confirmed malware (webshells, YARA/signature matches), C2 connections, backdoor ports, phishing pages, database injections, and spam outbreaks are always hard-blocked immediately, even when challenge is enabled.

### Timeout Escalation

If an IP doesn't solve the PoW challenge within 30 minutes, it is automatically escalated to a hard firewall block.

### Bind address

The listener binds to `127.0.0.1` by default. The production path is to
reverse-proxy challenged requests to `/challenge` from the host's webserver
(Apache / Nginx / LSWS); the webserver terminates TLS with the SNI cert
it already owns for the customer vhost and proxies plain HTTP to CSM on
loopback. Operators that want to expose the listener directly to the
internet set `challenge.listen_addr: 0.0.0.0` and provide TLS material
via `challenge.tls_cert` / `tls_key` (see below).

```yaml
challenge:
  listen_addr: 127.0.0.1   # default - reachable only from loopback
  listen_port: 8439
```

### TLS

The challenge listener serves HTTPS when challenge-specific TLS material is
configured. Loopback listeners stay on plain HTTP by default, even when the
Web UI has TLS configured, because the webserver reverse proxy is the TLS
endpoint. Direct/public listeners can reuse the Web UI cert.

Resolution order:

1. `challenge.tls_cert` + `challenge.tls_key` (explicit per-service).
2. `webui.tls_cert` + `webui.tls_key` (shared cert; cPanel
   `mycpanel.pem` covers both webui and the challenge port without
   extra config) only when `challenge.listen_addr` is not loopback.
3. Plain HTTP. This is expected for the default loopback reverse-proxy path.
   Public listeners without TLS log a startup warning.
   HSTS-pinned parent domains (cPanel, phpanel, customer apex) will
   fail with `ERR_SSL_PROTOCOL_ERROR` because the browser auto-
   upgrades the URL to https; ship TLS material in production.

```yaml
challenge:
  tls_cert: /var/cpanel/ssl/cpanel/mycpanel.pem
  tls_key:  /var/cpanel/ssl/cpanel/mycpanel.pem
```

### Trusted Proxies

By default, the challenge server uses `RemoteAddr` to identify clients. If deployed behind a reverse proxy (e.g. Apache with `mod_rewrite`), configure `trusted_proxies` so X-Forwarded-For is trusted only from those IPs:

```yaml
challenge:
  enabled: true
  trusted_proxies:
    - "127.0.0.1"
    - "::1"
```

Without `trusted_proxies`, X-Forwarded-For is ignored to prevent IP spoofing.

### Successful Verification

When a client passes the challenge:
1. The IP is temporarily allowed through the firewall for 4 hours
2. A verification cookie is set
3. The IP is removed from the challenge list (Apache stops redirecting)

## Bypass Paths

Three opt-in bypass mechanisms let legitimate traffic skip the PoW page entirely. All default off; an upgraded csm.yaml with no new blocks behaves exactly as before.

### CAPTCHA Fallback (JS-Disabled Visitors)

The PoW solver requires JavaScript. Visitors with JS off (older mobile browsers, accessibility tooling, text browsers, scripted integrations) would otherwise be locked out. When configured, CSM renders a Cloudflare Turnstile or hCaptcha widget inside a `<noscript>` block; on completion the form posts to `/challenge/captcha-verify` and CSM validates the token server-side against the provider's `siteverify` endpoint.

```yaml
challenge:
  captcha_fallback:
    provider: turnstile         # turnstile | hcaptcha | "" (off)
    site_key: "0xAAAA..."       # public key embedded in the widget
    secret_key: "0xBBBB..."     # verified server-side; never sent to client
    timeout: 10s
```

### Verified Operator Sessions

Operators who repeatedly hit the challenge during normal admin work can mint a signed cookie that bypasses PoW for the cookie's TTL. The signing key is generated at daemon startup and rotates on every restart -- old cookies stop working automatically.

```yaml
challenge:
  verified_session:
    enabled: true
    cookie_name: csm_admin_session    # default
    ttl: 4h                            # default
    admin_secret: "long-shared-secret" # required
```

To issue a cookie, POST the secret to the challenge server:

```bash
curl -i -X POST -d "secret=long-shared-secret" \
  https://your-host:8439/challenge/admin-token
# 204 No Content
# Set-Cookie: csm_admin_session=...; Path=/; HttpOnly; Secure; SameSite=Lax
```

The cookie binds to the requester's IP, so a stolen cookie does not work from a different network.

### Verified Search Crawlers

Googlebot and Bingbot can be allow-passed by reverse-DNS forward-confirm. CSM looks up the visitor's PTR, checks it ends in a known crawler suffix (e.g. `.googlebot.com`), then forward-resolves that name to confirm the original IP appears in the result. A spoofed `User-Agent: Googlebot` from a residential IP fails forward-confirm and falls through to PoW.

```yaml
challenge:
  verified_crawlers:
    enabled: true
    providers: [googlebot, bingbot]
    cache_ttl: 15m
```

Positive results cache for `cache_ttl`; negative results cache for one-fifth that long so a transiently-broken resolver does not lock out a real crawler for the full window.

## Operational

### Backups

`csm store export` and `csm store import` capture the bbolt store, state JSON files (baseline file hashes), and signature-rules cache into a single tar+zstd archive. Use these for re-provisioning, cluster cloning, and disaster recovery rather than re-baselining a 200k-file account tree from scratch.

```bash
csm store export /var/backups/csm-$(date +%F).csmbak
sha256sum -c /var/backups/csm-$(date +%F).csmbak.sha256
# transfer the .csmbak + .sha256 to the target host
systemctl stop csm
csm store import /var/backups/csm-2026-04-27.csmbak
systemctl start csm
```

Partial restore: `--only=baseline` restores only the file-hash state (useful after a full re-install where firewall and history should stay fresh); `--only=firewall` merges the firewall buckets into an existing daemon (useful for cloning blocklists across a cluster).
