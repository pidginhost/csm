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

Addresses the firewall refuses to block are never routed: entries in
`infra_ips` or `firewall.infra_ips` and, while the CSM firewall runs, the
current addresses of infra hostnames and the server's own addresses. Entries
only in `firewall.infra_ips` still produce alerts and spam evidence.

### Challenge-Eligible Checks

Pre-auth, browser-visible attack signals only: `wp_login_bruteforce`,
`xmlrpc_abuse`, `wp_user_enumeration`, `webmail_bruteforce`,
`http_scanner_profile`, `http_claimed_bot_unverified`, `ip_reputation`,
`email_php_form_relay` (routing and timeout blocks require `ip_recipient_mode: enforce`).
Post-auth audit events (cPanel, webmail, file upload, WHM
logins), WAF high-volume attacker findings, and non-browser protocols (SSH,
FTP, DNS recursion, outbound traffic, API auth) are excluded - their IPs have
no useful challenge step or no browser session to render the PoW page.

Local threat scores no longer route addresses to the challenge page, and no
check produces `local_threat_score` findings any more.

`http_scanner_profile` routing is operator-selectable:
`auto_response.http_scanner_action: "challenge"` (default) routes the IP here;
`"block"` skips the challenge and hard-blocks directly. With the challenge
subsystem disabled, both values block.

### Always Hard-Blocked

Confirmed malware (webshells, YARA/signature matches), WAF high-volume attackers, C2 connections, backdoor ports, phishing pages, database injections, and spam outbreaks are hard-block candidates immediately, even when challenge is enabled.

### Timeout Escalation

If an IP doesn't solve the PoW challenge within 30 minutes, it is
automatically escalated to a hard firewall block while
`auto_response.enabled` and `auto_response.block_ips` are on; otherwise the
entry only expires. The pending claimed-bot path
(`http_claimed_bot_unverified`) is the exception: it expires without timeout
escalation because the reverse-DNS verifier decides the next action. A confirmed
spoof is hard-blocked by the later `http_ua_spoof` finding after it reaches the
UA threshold, while a real crawler is removed from the challenge list once
verification succeeds.

A timeout block of an address that recently logged in as a customer sends
the [known-customer block alert](auto-response.md#known-customer-block-alert)
at once. The block still applies.

### Passed challenges

Each pass is logged as `CHALLENGE-PASS: <ip> passed (<method>)` and counted
in `csm_challenge_passed_total` and the `passed` field of the challenge stats.
CSM remembers passes for 7 days, across restarts:

- A challenge that times out within 4 hours of the address's last pass
  expires without a block. The visitor proved a browser and left; a returning
  browser is waved through by its verification cookie for the same 4 hours.
- WordPress login, XML-RPC and user enumeration counts read each site's last
  log lines, which on a quiet site can be days old. Lines an address logged
  before its last pass no longer count against it; newer ones do.

### Bind address

The listener binds to `127.0.0.1` by default, so enabling the challenge
server alone does not expose a new public port. The webserver integration
uses direct redirects to `challenge.public_url`; installed direct mode
therefore needs a non-loopback listener and a public URL ending in
`/challenge`. For your own proxy on this host, listen on a Unix socket
instead (see [Proxy on the same host](#proxy-on-the-same-host)).

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
   extra config) only when `challenge.listen_addr` is not loopback or a
   Unix socket.
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
traffic from a proxy on another machine and must trust `X-Forwarded-For`
from that proxy.

```yaml
challenge:
  enabled: true
  trusted_proxies:
    - "192.0.2.10"
    - "198.51.100.0/24"
```

Entries are addresses or CIDR ranges. Legacy zero-padded prefix lengths
remain accepted. CSM skips other entries and never trusts a catch-all,
such as `0.0.0.0/0`. A peer covered only by a refused catch-all names no
visitor when it forwards a request, even if truncation leaves an empty
header. This includes native IPv6 peers covered by a broad IPv4-mapped
range. A direct request from such a peer still names its own address.
`csm validate` and plain `csm doctor` warn about unusable entries; they do
not reject the configuration. Saving the challenge section in Settings
rejects them.
Trust only proxies you control, not ranges that also contain visitors. Each proxy must append its observed peer
address to X-Forwarded-For or replace the header with that address. The
challenge server also trusts the proxies in `web_server.trusted_proxies`,
the list the HTTP checks use.

CSM reads all X-Forwarded-For field lines as one ordered chain, from the
right, past other trusted proxies, and takes the first other address as the
visitor. An entry that is not an address ends the read.

If no visitor can be identified because the chain is missing, malformed,
over 4 KiB, more than 31 trusted hops before the visitor, or contains only
trusted proxies, challenge endpoints return HTTP 400. They do not issue a
puzzle or cookie, accept a bypass, or clear a pending challenge for the
proxy. This also applies to the gate and admin-token endpoints.

CSM rejects proxy trust for loopback, the unspecified
addresses, and every address on the host's interfaces, link-local ones
included. Any local account can connect from those and write
X-Forwarded-For. An entry containing one of them does not prevent the
daemon or challenge listener from starting or reloading. Requests attributed
to a listed local address receive HTTP 400. Remote proxies in the same
range remain usable. `csm validate` and plain `csm doctor` warn;
`csm doctor challenge` reports the unusable local proxy as a failure, and
the webserver integration installer refuses it. This applies to both TCP
and Unix socket listeners. For a proxy on this host, use the
[socket](#proxy-on-the-same-host) and remove host-local entries from
`trusted_proxies`.

While serving requests, CSM uses a cached interface address list, refreshed
on demand after five minutes. If a refresh fails, it keeps the last
successful list. An address added while the daemon runs can still be
trusted until a successful refresh discovers it. Before assigning this
host an address covered by `trusted_proxies`, remove or narrow the covering
entries to remote proxies and restart CSM. Only then assign the address.
Run `csm doctor challenge` to check the resulting configuration.

With `trusted_proxies` set, point `challenge.public_url` at the proxy.
`listen_addr` holds a host only; the port goes in `listen_port`.

`csm doctor challenge` leaves TLS to the proxy and does not ask for the
port gate. It does not check the proxy itself, so confirm HTTPS works at
`public_url` and keep `listen_port` closed to everything except the proxy.
A `public_url` that names the listener's own address and port is direct
mode, and the usual TLS and port-gate checks apply.

With both `challenge.trusted_proxies` and `web_server.trusted_proxies`
empty, X-Forwarded-For from a TCP peer is ignored to prevent IP spoofing.
Only `challenge.trusted_proxies` says the listener itself sits behind a
proxy: the installer and `csm doctor challenge`'s TLS and port gate rows
read it alone, so a site CDN in `web_server.trusted_proxies`
does not change them. A listed address is never a visitor in either mode.

### Proxy on the same host

A proxy on the same host reaches the challenge server through a Unix
socket. Only root and members of `challenge.listen_group` can open it, so
local accounts cannot pose as the proxy. Shared hosts that do not need a
proxy should use direct mode (see [Bind address](#bind-address)), which
trusts nothing.

```yaml
challenge:
  enabled: true
  listen_addr: unix:/run/csm/challenge.sock
  listen_group: nginx     # the group your proxy runs as; nobody on cPanel
  public_url: https://challenge.example.com/challenge
```

CSM creates the socket with mode 0660, owned by root and `listen_group`,
and removes it on shutdown. Its directory must be owned by root, not
writable by anyone else, and writable by the CSM service; with the shipped
systemd unit that means `/run/csm`. The path must be absolute, without
repeated separators, dot components or a trailing slash. It may use at
most 107 bytes, and its directory at most 91 bytes, since CSM first binds
under a temporary name that needs up to 16 more bytes. `listen_port`, the port gate
and the Web UI TLS fallback do not apply. The proxy must send
X-Forwarded-For; a request without a readable visitor address gets HTTP
400. `trusted_proxies` stays optional and lists any proxies in front of
the local one.

nginx:

```nginx
location /challenge {
    proxy_pass http://unix:/run/csm/challenge.sock;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $remote_addr;
}
```

With a CDN or another proxy in front of nginx, list those proxies in
`trusted_proxies` and use `proxy_set_header X-Forwarded-For
$proxy_add_x_forwarded_for;` so the visitor address they add is kept.

Apache 2.4.7 or later, with mod_proxy and mod_proxy_http (it adds
X-Forwarded-For itself):

```apache
ProxyPass "/challenge" "unix:/run/csm/challenge.sock|http://localhost/challenge"
```

The socket proves only that a request came through a process in
`listen_group`. Two things outside CSM decide whether that process can be
trusted, and CSM cannot check them:

- Tenant code must not run as the proxy's user or group. On cPanel the web
  servers run as `nobody`, which is safe when PHP and CGI run as each
  account's own user (suEXEC, LSAPI with suEXEC, per-account PHP-FPM). It
  is not safe with mod_php (DSO), CGI without suEXEC, mod_ruid2 or
  mpm-itk. Use direct mode on those hosts.
- The proxy must take the visitor's address from its own connection. It
  must not accept forwarded-address headers from addresses on this host,
  such as nginx `set_real_ip_from 127.0.0.1` or Apache
  `RemoteIPInternalProxy 127.0.0.1` (set up for ea-nginx in front of
  Apache). The proxy browsers connect to must be the one that talks to the
  socket.

LiteSpeed's proxy emulation does not support this setup, and SELinux in
enforcing mode may stop a confined web server from opening the socket.
Use direct mode on those hosts.

`csm doctor challenge` checks the group and the socket directory, then
probes the gate through the socket.

### Successful Verification

When a client passes the challenge:
1. The IP is removed from the challenge list so the webserver stops
   sending that visitor to the challenge flow
2. A verification cookie is set, so a visitor who is challenged again
   within its lifetime passes without seeing the puzzle

Passing the challenge changes nothing in the firewall. The visitor is
treated like any other client from then on: normal rate limits and blocks
still apply, and a later attack signal can list the IP again. The
challenge page, the verify endpoint and the CAPTCHA fallback answer only
for IPs currently on the challenge list; anyone else gets 404.

## Webserver Integration

The webserver integration redirects challenge-listed IPs to
`challenge.public_url`. The installer refuses to run until that URL is
an absolute `http` or `https` URL ending in `/challenge`, and the
configured challenge listener uses non-loopback TCP or a Unix socket.
For a socket, `challenge.listen_addr` must use `unix:/absolute/path` and
`challenge.listen_group` must name the proxy's group. Invalid socket settings
are rejected before the installer writes runtime maps or changes the webserver.

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
read their RewriteMap from `/var/cache/csm/challenge_ips.txt`; Nginx reads
a native map include from `/var/cache/csm/challenge_ips.nginx.map`. The
directory is the service's systemd cache directory: it is world-readable so
the webserver user can read the maps, and unlike the runtime directory it
survives `systemctl stop csm`, package upgrades and reboots. That matters
because Apache and LSWS validate the map at config-parse time and Nginx
fails on a missing include, so a map that vanished with the daemon would
take every site down at the next webserver reload. CSM rewrites the Nginx
include on challenge-list changes and reloads Nginx only when the file
content changes.

Older installers also deployed a legacy proxy-mode snippet on cPanel
Apache and LiteSpeed (`/etc/apache2/conf.d/csm_challenge.conf`). Installs
no longer do. On those stacks `csm webserver-integration install` and
`upgrade` remove the legacy snippet in the same configtest-then-reload run
that writes the integration snippet, and restore it if that run fails.
If either file cannot be restored, the error reports the incomplete rollback
and no recovery reload runs with that incomplete configuration.
While both are present and the integration template is not newer than the
binary, `status` reports the integration as `stale`, so
the daemon's startup refresh below removes the legacy snippet on hosts
that already run the integration. Newer templates are left alone at startup,
including after a binary rollback. Observe mode skips this refresh.

At startup the daemon creates the default maps if they are absent,
including when challenge mode is disabled. It also checks the legacy
snippet when one is still present. If
its RewriteMap points at a map file the daemon does not maintain -- which
makes webserver config validation fail host-wide once that file goes
missing -- the daemon re-deploys the shipped template. A CSM-managed
integration snippet from an older template version is refreshed the same
way, through the configtest-then-reload flow below. Files without the
directive, operator-edited snippets, and snippets already pointing at the
daemon maps are never touched. While such a snippet still references a map
under the old runtime directory, the daemon keeps that file present until
the snippet is refreshed with `csm webserver-integration upgrade`.

`csm uninstall` and the package post-removal hook remove the snippets
before the maps, and keep the maps whenever a snippet cannot be removed
(for example an Nginx `server {}` block that still uses `$csm_challenged`).

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
the on-disk content matches the rendered template and no legacy snippet
remains to retire. Hand-edited files
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

Requests from this server's own addresses, loopback included, get HTTP 403
without a check of the secret, because every local account can send from
them. Request the cookie from the network you browse from.

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

`csm store export` and `csm store import` capture the bbolt store, state JSON files (baseline file hashes), and signature-rules cache into a single tar+zstd archive. Use these for re-provisioning, cluster cloning, and disaster recovery rather than re-baselining a 200k-file account tree from scratch. The daemon writes the archive under its state directory (the only tree its systemd sandbox can write) and the CLI moves it to the path you give, so any destination the CLI can write works, including `/var/backups`. The destination directory and every directory above it must be owned by root or by the account running the command, and must not be writable by other accounts unless they carry the sticky bit as `/tmp` does; the destination itself must not already exist as a symlink or as another account's file. Otherwise another account could swap the archive out after the CLI has verified it, and the export is refused before the daemon writes anything. In-progress staging files and unconfirmed firewall rollback artifacts are excluded from backups, so restoring an archive cannot re-arm an old confirmation window.

```bash
csm store export /var/backups/csm-$(date +%F).csmbak
sha256sum -c /var/backups/csm-$(date +%F).csmbak.sha256
# transfer the .csmbak + .sha256 to the target host
systemctl stop csm
csm store import /var/backups/csm-2026-04-27.csmbak
systemctl start csm
```

Partial restore: `--only=baseline` restores only the file-hash state (useful after a full re-install where firewall and history should stay fresh); `--only=firewall` merges the firewall buckets into an existing daemon (useful for cloning blocklists across a cluster); a durable firewall journal and its snapshot in the archive replace the target's. It refuses while either side has a durable firewall action unresolved or its audit undelivered.
