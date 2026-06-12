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
`xmlrpc_abuse`, `wp_user_enumeration`, `webmail_bruteforce`,
`http_scanner_profile`, `ip_reputation`, `local_threat_score`. Post-auth audit
events (cPanel, webmail, file upload, WHM logins), WAF high-volume attacker
findings, and non-browser protocols (SSH, FTP, DNS recursion, outbound
traffic, API auth) are excluded - their IPs have no useful challenge step or
no browser session to render the PoW page.

`http_scanner_profile` routing is operator-selectable:
`auto_response.http_scanner_action: "challenge"` (default) routes the IP here;
`"block"` skips the challenge and hard-blocks directly. With the challenge
subsystem disabled, both values block.

### Always Hard-Blocked

Confirmed malware (webshells, YARA/signature matches), WAF high-volume attackers, C2 connections, backdoor ports, phishing pages, database injections, and spam outbreaks are hard-block candidates immediately, even when challenge is enabled.

### Timeout Escalation

If an IP doesn't solve the PoW challenge within 30 minutes, it is automatically escalated to a hard firewall block.

### Bind address

The listener binds to `127.0.0.1` by default, so enabling the challenge
server alone does not expose a new public port. The webserver integration
uses direct redirects to `challenge.public_url`; installed direct mode
therefore needs a non-loopback listener and a public URL ending in
`/challenge`.

```yaml
challenge:
  enabled: true
  listen_addr: 0.0.0.0
  listen_port: 8439
  public_url: https://cpanel.example.com:8439/challenge
  tls_cert: /var/cpanel/ssl/cpanel/mycpanel.pem
  tls_key:  /var/cpanel/ssl/cpanel/mycpanel.pem
```

When CSM's firewall is enabled and `challenge.port_gate.enabled` is true,
the daemon also opens `challenge.listen_port` in the main firewall rules.
The port-gate chain still drops traffic to that port unless the source is
loopback, an `infra_ips` entry, or an IP currently on the challenge list.
Port-gate rules follow the configured listener address family. An IPv6-only
listener gates only IPv6 clients; IPv4 challenge entries stay in the
webserver map but are ignored by the IPv6 nftables set.

Run `csm doctor challenge` after changing these fields. The command checks
the public URL shape, TLS files, port-gate setting, installed webserver
snippet version, webserver configtest, and the live `/challenge/gate`
endpoint. Add `--json` for automation.

### TLS

The challenge listener serves HTTPS when challenge-specific TLS material is
configured. Loopback listeners stay on plain HTTP by default. Direct/public
listeners can reuse the Web UI cert.

Resolution order:

1. `challenge.tls_cert` + `challenge.tls_key` (explicit per-service).
2. `webui.tls_cert` + `webui.tls_key` (shared cert; cPanel
   `mycpanel.pem` covers both webui and the challenge port without
   extra config) only when `challenge.listen_addr` is not loopback.
3. Plain HTTP. This is expected for the default loopback-only path.
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

By default, the challenge server uses `RemoteAddr` to identify clients.
The shipped webserver integration redirects browsers directly to
`challenge.public_url`, so it does not need `trusted_proxies`. Configure
trusted proxies only for a custom proxy deployment where CSM receives
traffic from a proxy and must trust `X-Forwarded-For` from that proxy.

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
3. The IP is removed from the challenge list so the webserver stops
   sending that visitor to the challenge flow

## Webserver Integration

The webserver integration redirects challenge-listed IPs to
`challenge.public_url`. The installer refuses to run until that URL is
an absolute `http` or `https` URL ending in `/challenge`, and the
configured challenge listener is non-loopback.

```bash
csm webserver-integration install     # initial wire-up
csm webserver-integration upgrade     # re-apply after a CSM upgrade
csm webserver-integration status      # show detected stack + version drift
csm webserver-integration validate    # run the webserver's configtest
csm webserver-integration remove      # uninstall the snippet
```

The installer auto-detects the active webserver via
`internal/platform`. Supported stacks and snippet paths:

| Stack                       | Snippet path                                        |
|-----------------------------|-----------------------------------------------------|
| cPanel + Apache (EasyApache)| `/etc/apache2/conf.d/csm-challenge.conf`            |
| Debian/Ubuntu Apache        | `/etc/apache2/conf-enabled/csm-challenge.conf`      |
| RHEL family Apache (httpd)  | `/etc/httpd/conf.d/csm-challenge.conf`              |
| LiteSpeed (LSWS)            | `/usr/local/lsws/conf/templates/csm-challenge.conf` |
| Nginx (plain + Engintron + phpanel) | `/etc/nginx/conf.d/csm-challenge.conf`      |

The snippets are rendered from the effective CSM config. Apache and LSWS
read their RewriteMap from `/run/csm/challenge_ips.txt`; Nginx reads a
native map include from `/run/csm/challenge_ips.nginx.map`. Both live
outside the private state directory so the webserver user can read them.
CSM rewrites the Nginx include on challenge-list changes and reloads
Nginx only when the file content changes.

On every run, the installer:

1. Writes the new snippet to a sibling temp file and renames it into
   place atomically.
2. Runs the webserver's own configtest (`apachectl configtest`,
   `nginx -t`, `lswsctrl conftest`).
3. On pass: reloads the webserver gracefully and exits 0.
4. On fail: restores the previous snippet bytes (or removes the file
   if it did not exist before) and exits non-zero with the captured
   configtest output. The webserver is never reloaded with a broken
   config.

The snippet header carries a version marker; `upgrade` is a no-op when
the on-disk version matches the shipped version. Hand-edited files
(missing or mismatched marker) trip a "modified" status and the
installer refuses to overwrite them - remove or rename first.

Hosts with no detectable webserver exit with `status=skipped` so
package post-install hooks succeed cleanly on, e.g., a plain phpanel
worker that doesn't run nginx locally.

## Bypass Paths

Three opt-in bypass mechanisms let legitimate traffic skip the PoW page entirely. All default off; an upgraded csm.yaml with no new blocks behaves exactly as before.

### CAPTCHA Fallback (JS-Disabled Visitors)

The PoW solver requires JavaScript. Visitors with JS off (older mobile browsers, accessibility tooling, text browsers, scripted integrations) would otherwise be locked out. When configured, CSM renders a Cloudflare Turnstile or hCaptcha widget inside a `<noscript>` block; on completion the form posts to `/challenge/captcha-verify` and CSM validates the token server-side against the provider's `siteverify` endpoint.
Provider rejections do not spend the page nonce, so a visitor can retry the
same challenge page after a mistyped, expired, or failed widget response.

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
