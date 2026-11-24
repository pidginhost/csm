# Challenge Pages

A challenge page makes the browser of a suspicious IP solve a JavaScript proof-of-work puzzle before its requests go through. It is a CAPTCHA alternative, and a softer response than a hard IP block. Challenge pages are off until you set `challenge.enabled: true`.

## How It Works

1. A suspicious IP hits a protected resource.
2. CSM serves a challenge page that requires a client-side SHA-256 proof-of-work.
3. The browser computes the proof and shows a progress bar.
4. On a valid solution, CSM issues an HMAC-verified token.
5. Subsequent requests pass through automatically.

## Features

- The difficulty is SHA-256 based and configurable in levels 0-5.
- The computation runs on the client, so it puts no load on the server.
- HMAC token verification prevents replay attacks.
- Nonces add anti-replay protection.
- The page is user-friendly: a progress bar and instant feedback.
- It filters bots: clients that do not run JavaScript never pass. Headless browsers and scripts written for the puzzle can solve it, and a higher difficulty costs real visitors more time than such clients.

## Use Cases

- Gray-listing alternative to hard IP blocks
- Protecting WordPress login pages
- Rate limiting without blocking legitimate users
- DDoS mitigation layer

## Turning it on

1. Set `challenge.enabled: true`.
2. Make the listener reachable. For direct mode, set a non-loopback `challenge.listen_addr` and a `challenge.public_url` ending in `/challenge`; see [Bind address](#bind-address). For your own proxy on this host, use a Unix socket; see [Proxy on the same host](#proxy-on-the-same-host).
3. Give a public listener TLS material. See [TLS](#tls).
4. Run `csm webserver-integration install` so the web server redirects challenge-listed IPs. See [Webserver Integration](#webserver-integration).
5. Run `csm doctor challenge` to check the result.

## Routing Behavior

When `challenge.enabled: true`, CSM routes eligible IPs to the challenge page instead of hard-blocking them. This works independently of `auto_response` settings.

Addresses the firewall refuses to block are never routed:

- entries in `infra_ips` or `firewall.infra_ips`
- while the CSM firewall runs, the current addresses of infra hostnames and the server's own addresses

Entries only in `firewall.infra_ips` still produce alerts and spam evidence.

### Challenge-Eligible Checks

Only pre-auth attack signals that a browser can see are eligible:

- `wp_login_bruteforce`
- `xmlrpc_abuse`
- `wp_user_enumeration`
- `webmail_bruteforce`
- `http_scanner_profile`
- `http_claimed_bot_unverified`
- `ip_reputation`
- `email_php_form_relay` (routing and timeout blocks require `ip_recipient_mode: enforce`)

These are excluded, because their IPs have no useful challenge step or no browser session to render the PoW page:

- post-auth audit events (cPanel, webmail, file upload, WHM logins)
- WAF high-volume attacker findings
- non-browser protocols (SSH, FTP, DNS recursion, outbound traffic, API auth)

Local threat scores do not route addresses to the challenge page, and no check produces `local_threat_score` findings.

`http_scanner_profile` routing is operator-selectable. `auto_response.http_scanner_action: "challenge"` (default) routes the IP here. `"block"` skips the challenge and hard-blocks directly. With the challenge subsystem disabled, both values block.

### Always Hard-Blocked

These are hard-block candidates immediately, even when challenge is enabled:

- confirmed malware (webshells, YARA/signature matches)
- WAF high-volume attackers
- C2 connections
- backdoor ports
- phishing pages
- database injections
- spam outbreaks

### Timeout Escalation

If an IP does not solve the PoW challenge within 30 minutes, CSM escalates it to a hard firewall block. This happens while `auto_response.enabled` and `auto_response.block_ips` are on; otherwise the entry only expires.

A timeout block of an address that recently logged in as a customer sends the [known-customer block alert](auto-response.md#known-customer-block-alert) at once. The block still applies.

Two kinds of entry expire without timeout escalation.

The first is the pending claimed-bot path (`http_claimed_bot_unverified`). The reverse-DNS verifier decides the next action for it:

- A confirmed spoof is hard-blocked by the later `http_ua_spoof` finding after it reaches the UA threshold.
- A real crawler is removed from the challenge list once verification succeeds.

The second is a client named only by a trusted proxy's X-Forwarded-For header. Its requests reach this host from the proxy, so neither the challenge page nor a firewall block reaches it.

Such an entry can still escalate on timeout when the count behind the finding includes requests the client sent directly to this host, or when the same scan has a direct finding for the same address. An existing listing that does not escalate stays until it expires.

### Successful Verification

When a client passes the challenge:

1. CSM removes the IP from the challenge list, so the webserver stops sending that visitor to the challenge flow.
2. CSM sets a verification cookie, so a visitor who is challenged again within its lifetime passes without seeing the puzzle.

Passing the challenge changes nothing in the firewall. The visitor is treated like any other client from then on: normal rate limits and blocks still apply, and a later attack signal can list the IP again.

The challenge page, the verify endpoint and the CAPTCHA fallback answer only for IPs currently on the challenge list. Anyone else gets 404.

### Passed challenges

Each pass is logged as `CHALLENGE-PASS: <ip> passed (<method>)` and counted in `csm_challenge_passed_total` and the `passed` field of the challenge stats. CSM remembers passes for 7 days, across restarts, and expires stored passes during normal operation.

A remembered pass has two effects.

First, a challenge that times out within 4 hours of the address's last pass expires without a block. A returning browser is waved through by its verification cookie for the same 4 hours.

Second, it changes which log lines the WordPress login, XML-RPC and user enumeration checks count. These checks read each site's last log lines, which on a quiet site can be days old. Lines are counted as follows:

| Log line | Counted |
|----------|---------|
| Logged by the address before or at its last pass | No. It does not count against the address or attribute a distributed attack to that site. |
| Logged by the address after its last pass | Yes. |
| Older than the pass retention period, while the challenge service is active | No, so forgotten passes cannot revive answered requests. |
| Without a readable timestamp | Yes, because CSM cannot establish its age. |

A pass does not exempt an address from new challenges or hard-block checks. A client without a valid verification cookie must solve a new challenge when routed again, including during the timeout grace period.

## Listener setup

Browsers can reach the challenge server in three ways:

| Mode | How it works | Section |
|------|--------------|---------|
| Direct | The shipped webserver integration redirects browsers to a public listener. It trusts nothing. | [Bind address](#bind-address) |
| Proxy on this host | Your own proxy forwards to a Unix socket. | [Proxy on the same host](#proxy-on-the-same-host) |
| Proxy on another machine | CSM trusts X-Forwarded-For from the proxies you list. | [Trusted Proxies](#trusted-proxies) |

### Bind address

The listener binds to `127.0.0.1` by default, so enabling the challenge server alone does not expose a new public port.

The webserver integration uses direct redirects to `challenge.public_url`. Installed direct mode therefore needs a non-loopback listener and a public URL ending in `/challenge`. For your own proxy on this host, listen on a Unix socket instead (see [Proxy on the same host](#proxy-on-the-same-host)).

```yaml
challenge:
  enabled: true
  listen_addr: 0.0.0.0
  listen_port: 8439
  public_url: https://cpanel.example.com:8439/challenge
  tls_cert: /var/cpanel/ssl/cpanel/mycpanel.pem
  tls_key:  /var/cpanel/ssl/cpanel/mycpanel.pem
```

Run `csm doctor challenge` after changing these fields. Add `--json` for automation. The command checks:

- the public URL shape
- the TLS files
- the port-gate setting
- the installed webserver snippet version
- the webserver configtest
- the live `/challenge/gate` endpoint

### Port gate

When CSM's firewall is enabled and `challenge.port_gate.enabled` is true, the daemon also opens `challenge.listen_port` in the main firewall rules. The port-gate chain still drops traffic to that port unless the source is one of:

- loopback
- an `infra_ips` entry
- an IP currently on the challenge list

Port-gate rules follow the configured listener address family. An IPv6-only listener gates only IPv6 clients. IPv4 challenge entries stay in the webserver map but are ignored by the IPv6 nftables set.

### TLS

The challenge listener serves HTTPS when challenge-specific TLS material is configured. Loopback listeners stay on plain HTTP by default. Direct/public listeners can reuse the Web UI cert.

Resolution order:

1. `challenge.tls_cert` + `challenge.tls_key` (explicit per-service).
2. `webui.tls_cert` + `webui.tls_key`, only when `challenge.listen_addr` is not loopback or a Unix socket. This is the shared cert: cPanel `mycpanel.pem` covers both webui and the challenge port without extra config.
3. Plain HTTP. This is expected for the default loopback-only path.

Public listeners without TLS log a startup warning. HSTS-pinned parent domains (cPanel, phpanel, customer apex) will fail with `ERR_SSL_PROTOCOL_ERROR`, because the browser auto-upgrades the URL to https. Ship TLS material in production.

```yaml
challenge:
  tls_cert: /var/cpanel/ssl/cpanel/mycpanel.pem
  tls_key:  /var/cpanel/ssl/cpanel/mycpanel.pem
```

### Trusted Proxies

By default, the challenge server uses `RemoteAddr` to identify clients. The shipped webserver integration redirects browsers directly to `challenge.public_url`, so it does not need `trusted_proxies`.

Configure trusted proxies only for a custom proxy deployment where CSM receives traffic from a proxy on another machine and must trust `X-Forwarded-For` from that proxy.

```yaml
challenge:
  enabled: true
  trusted_proxies:
    - "192.0.2.10"
    - "198.51.100.0/24"
```

Entries are addresses or CIDR ranges. Rules for the list:

- Trust only proxies you control, not ranges that also contain visitors.
- Each proxy must append its observed peer address to X-Forwarded-For or replace the header with that address.
- CSM never trusts a catch-all, such as `0.0.0.0/0`. See [Unusable trusted proxy entries](#unusable-trusted-proxy-entries).
- CSM rejects proxy trust for this host's own addresses, loopback included. See [Local addresses as proxies](#local-addresses-as-proxies).

With `trusted_proxies` set:

- Point `challenge.public_url` at the proxy.
- `listen_addr` holds a host only. The port goes in `listen_port`.
- `csm doctor challenge` leaves TLS to the proxy and does not ask for the port gate. It does not check the proxy itself, so confirm HTTPS works at `public_url` and keep `listen_port` closed to everything except the proxy.
- A `public_url` that names the listener's own address and port is direct mode, and the usual TLS and port-gate checks apply.

#### The two proxy lists

The challenge server also trusts the proxies in `web_server.trusted_proxies`, the list the HTTP checks use. With both `challenge.trusted_proxies` and `web_server.trusted_proxies` empty, X-Forwarded-For from a TCP peer is ignored to prevent IP spoofing.

Only `challenge.trusted_proxies` tells CSM that the challenge listener itself sits behind a proxy. The installer and the TLS and port-gate rows of `csm doctor challenge` read only that list, so a site CDN in `web_server.trusted_proxies` does not change them. A listed address is never a visitor in either mode.

#### How CSM finds the visitor

CSM joins all X-Forwarded-For header lines into one list and reads it from the right. It skips entries that are trusted proxies and takes the first address that is not one as the visitor. An entry that is not an address ends the read.

Challenge endpoints return HTTP 400 if no visitor can be identified. That is the case when the chain:

- is missing
- is malformed
- is over 4 KiB
- has more than 31 trusted hops before the visitor
- contains only trusted proxies

On that error the endpoints do not issue a puzzle or cookie, accept a bypass, or clear a pending challenge for the proxy. This also applies to the gate and admin-token endpoints.

#### Local addresses as proxies

CSM rejects proxy trust for loopback, the unspecified addresses, and every address on the host's interfaces, link-local ones included. Any local account can connect from those and write X-Forwarded-For. This applies to both TCP and Unix socket listeners.

An entry that contains one of these addresses has the following effects:

- It does not prevent the daemon or challenge listener from starting or reloading.
- Requests attributed to a listed local address receive HTTP 400.
- Remote proxies in the same range remain usable.
- `csm validate` and plain `csm doctor` warn.
- `csm doctor challenge` reports the unusable local proxy as a failure.
- The webserver integration installer refuses it.

For a proxy on this host, use the [socket](#proxy-on-the-same-host) and remove host-local entries from `trusted_proxies`.

Before you give this host a new address that `trusted_proxies` covers, read [Adding an address to this host](#adding-an-address-to-this-host).

### Proxy on the same host

A proxy on the same host reaches the challenge server through a Unix socket. Only root and members of `challenge.listen_group` can open it, so local accounts cannot pose as the proxy. Shared hosts that do not need a proxy should use direct mode (see [Bind address](#bind-address)), which trusts nothing.

```yaml
challenge:
  enabled: true
  listen_addr: unix:/run/csm/challenge.sock
  listen_group: nginx     # the group your proxy runs as; nobody on cPanel
  public_url: https://challenge.example.com/challenge
```

With a socket:

- `listen_port`, the port gate and the Web UI TLS fallback do not apply.
- The proxy must send X-Forwarded-For. A request without a readable visitor address gets HTTP 400.
- `trusted_proxies` stays optional and lists any proxies in front of the local one.

CSM creates the socket with mode 0660, owned by root and `listen_group`, and removes it on shutdown. The socket path has these requirements:

- Its directory must be owned by root, not writable by anyone else, and writable by the CSM service. With the shipped systemd unit that means `/run/csm`.
- The path must be absolute, without repeated separators, dot components or a trailing slash.
- The path may use at most 107 bytes, and its directory at most 91 bytes, since CSM first binds under a temporary name that needs up to 16 more bytes.

`csm doctor challenge` checks the group and the socket directory, then probes the gate through the socket.

#### Proxy configuration

nginx:

```nginx
location /challenge {
    proxy_pass http://unix:/run/csm/challenge.sock;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $remote_addr;
}
```

With a CDN or another proxy in front of nginx, list those proxies in `trusted_proxies` and use `proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;` so the visitor address they add is kept.

Apache 2.4.7 or later, with mod_proxy and mod_proxy_http (it adds X-Forwarded-For itself):

```apache
ProxyPass "/challenge" "unix:/run/csm/challenge.sock|http://localhost/challenge"
```

#### What the socket does not prove

The socket proves only that a request came through a process in `listen_group`. Two things outside CSM decide whether that process can be trusted, and CSM cannot check them.

Tenant code must not run as the proxy's user or group. On cPanel the web servers run as `nobody`:

| PHP and CGI setup | Safe with the socket |
|-------------------|----------------------|
| Run as each account's own user: suEXEC, LSAPI with suEXEC, per-account PHP-FPM | Yes |
| mod_php (DSO), CGI without suEXEC, mod_ruid2 or mpm-itk | No. Use direct mode on those hosts. |

The proxy must take the visitor's address from its own connection:

- It must not accept forwarded-address headers from addresses on this host, such as nginx `set_real_ip_from 127.0.0.1` or Apache `RemoteIPInternalProxy 127.0.0.1` (set up for ea-nginx in front of Apache).
- The proxy browsers connect to must be the one that talks to the socket.

LiteSpeed's proxy emulation does not support this setup, and SELinux in enforcing mode may stop a confined web server from opening the socket. Use direct mode on those hosts.

## Webserver Integration

The webserver integration redirects challenge-listed IPs to `challenge.public_url`.

```bash
csm webserver-integration install     # initial wire-up
csm webserver-integration upgrade     # re-apply after a CSM upgrade
csm webserver-integration status      # show detected stack + version drift
csm webserver-integration validate    # run the webserver's configtest
csm webserver-integration remove      # uninstall the snippet
```

The installer refuses to run until both of these hold:

- `challenge.public_url` is an absolute `http` or `https` URL ending in `/challenge`.
- The configured challenge listener uses non-loopback TCP or a Unix socket.

For a socket, `challenge.listen_addr` must use `unix:/absolute/path` and `challenge.listen_group` must name the proxy's group. Invalid socket settings are rejected before the installer writes runtime maps or changes the webserver.

### Supported stacks

The installer auto-detects the active webserver. Supported stacks and snippet paths:

| Stack                       | Snippet path                                        |
|-----------------------------|-----------------------------------------------------|
| cPanel + Apache (EasyApache)| `/etc/apache2/conf.d/csm-challenge.conf`            |
| Debian/Ubuntu Apache        | `/etc/apache2/conf-enabled/csm-challenge.conf` + per-site include |
| RHEL family Apache (httpd)  | `/etc/httpd/conf.d/csm-challenge.conf` + per-site include |
| LiteSpeed (LSWS)            | `/usr/local/lsws/conf/templates/csm-challenge.conf` |
| Nginx (plain + Engintron + phpanel) | `/etc/nginx/conf.d/csm-challenge.conf`      |

Hosts with no detectable webserver exit with `status=skipped`. Package post-install hooks then succeed cleanly on, for example, a plain phpanel worker that does not run nginx locally.

### What the installer does on every run

1. Writes the new snippet to a sibling temp file and renames it into place atomically.
2. Runs the webserver's own configtest (`apachectl configtest`, `nginx -t`, `lswsctrl conftest`).
3. On pass: reloads the webserver gracefully and exits 0.
4. On fail: restores the previous snippet bytes (or removes the file if it did not exist before) and exits non-zero with the captured configtest output.

The webserver is never reloaded with a broken config.

The snippet header carries a version marker. `upgrade` is a no-op when the on-disk content matches the rendered template and no legacy snippet remains to retire.

Hand-edited files (missing or mismatched marker) trip a "modified" status, and the installer refuses to overwrite them. Remove or rename the file first.

### Apache without cPanel

Apache without cPanel applies the server-wide snippet inside no `<VirtualHost>` on its own, HTTP or HTTPS. The installer also writes the rule to `/var/cache/csm/apache-challenge-site.conf`, next to the maps, and prints the one line each site needs. Add it inside every `<VirtualHost>`:

```apache
<VirtualHost *:443>
    ...
    Include /var/cache/csm/apache-challenge-site.conf
</VirtualHost>
```

Then run `apachectl configtest` and reload Apache.

CSM never edits site files. `csm doctor challenge` warns while any `<VirtualHost>` in the files Apache loads lacks the line:

- The check follows loaded includes through shared configuration fragments and ignores includes in inactive conditions.
- If Apache does not report its loaded configuration, doctor warns that coverage is unknown.

Uninstall leaves a disabled per-site include so existing site configuration remains valid. Remove the Include lines before deleting that retained file.

### cPanel

On cPanel, Apache and LiteSpeed alike, HTTPS site blocks do not inherit the server-wide snippet. The installer therefore also writes the rule to the per-site include `/etc/apache2/conf.d/userdata/csm-challenge.conf`. It skips `/.well-known/` paths so certificate validation keeps working.

cPanel adds that include to every site block when it rebuilds `httpd.conf` with a file present. Who triggers the rebuild depends on who wrote the file:

| Writer | Rebuild of `httpd.conf` |
|--------|-------------------------|
| `csm webserver-integration install` and `upgrade` | Run it once when needed, inside the same configtest-then-reload run. |
| The daemon's startup refresh | Never. HTTPS sites are covered after cPanel's next rebuild, and `csm doctor challenge` warns until they are. |

Coverage checks inspect each HTTPS site block and require the per-site snippet to be present.

If a rebuild, configtest, or reload fails, the installer restores the previous snippets and the saved `httpd.conf`, including its permissions. It does not run a second rebuild during recovery. A failed restore or recovery configtest prevents a recovery reload and reports the failure.

Automatic startup refreshes leave both snippets alone if either has a newer template version than the running binary.

### Removing the integration

`csm webserver-integration remove` disables both redirects even if one snippet is missing.

- It leaves a managed, comment-only per-site snippet. cPanel's required wildcard include must still match a file for the web server to start.
- Removal never rebuilds `httpd.conf`.
- Installing again replaces the placeholder with the redirect rule.

`csm uninstall` and the package post-removal hook remove the snippets before the maps. They keep the maps whenever a snippet cannot be removed (for example an Nginx `server {}` block that still uses `$csm_challenged`).

### Map files

The snippets are rendered from the effective CSM config.

| Web server | Reads |
|------------|-------|
| Apache and LSWS | Their RewriteMap from `/var/cache/csm/challenge_ips.txt` |
| Nginx | A native map include from `/var/cache/csm/challenge_ips.nginx.map` |

The directory is the service's systemd cache directory. It is world-readable so the webserver user can read the maps. Unlike the runtime directory it survives `systemctl stop csm`, package upgrades and reboots.

That matters because Apache and LSWS validate the map at config-parse time and Nginx fails on a missing include. A map that vanished with the daemon would take every site down at the next webserver reload.

CSM rewrites the Nginx include on challenge-list changes and reloads Nginx only when the file content changes.

### Peer log commands

The [web peer log](detection-realtime.md#web-peer-log-and-forged-client-addresses) has its own verbs: `csm webserver-integration peer-log install`, `status` and `remove`. They need no challenge settings.

- `upgrade` refreshes an installed peer log, and the other verbs leave it alone.
- Uninstall and package removal remove the managed peer log snippet. Files without the CSM header are left alone.
- An unreadable peer-log snippet fails the upgrade and is reported in its peer-log result.

### Flags

Every `csm webserver-integration` command accepts `--json`, `--config` and `--config-dir`. Other flags and extra arguments are usage errors, and these commands do not accept `--dry-run`.

Configuration overrides accept both `--config <file>` and `--config=<file>`, and both `--config-dir <directory>` and `--config-dir=<directory>`. An empty value or another flag in place of a spaced value is a usage error, even for commands that need no configuration.

## Bypass Paths

Three opt-in bypass mechanisms let legitimate traffic skip the PoW page entirely. All default off, so a `csm.yaml` without these blocks behaves the same after an upgrade.

### CAPTCHA Fallback (JS-Disabled Visitors)

The PoW solver requires JavaScript. Visitors with JS off (older mobile browsers, accessibility tooling, text browsers, scripted integrations) would otherwise be locked out.

When configured, CSM renders a Cloudflare Turnstile or hCaptcha widget inside a `<noscript>` block. On completion the form posts to `/challenge/captcha-verify`, and CSM validates the token server-side against the provider's `siteverify` endpoint.

Provider rejections do not spend the page nonce, so a visitor can retry the same challenge page after a mistyped, expired, or failed widget response.

```yaml
challenge:
  captcha_fallback:
    provider: turnstile         # turnstile | hcaptcha | "" (off)
    site_key: "0xAAAA..."       # public key embedded in the widget
    secret_key: "0xBBBB..."     # verified server-side; never sent to client
    timeout: 10s
```

### Verified Operator Sessions

Operators who repeatedly hit the challenge during normal admin work can mint a signed cookie that bypasses PoW for the cookie's TTL. The signing key is generated at daemon startup and rotates on every restart, so old cookies stop working automatically.

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

Requests from this server's own addresses, loopback included, get HTTP 403 without a check of the secret, because every local account can send from them. Request the cookie from the network you browse from.

#### Integration contract

`/challenge/admin-token` is a stable contract. A WordPress companion plugin, kept in a separate repository, depends on it. A change to the path, the `secret` form field, the status codes or the cookie attributes below needs a roadmap item before it ships.

| Response | When |
|---|---|
| 204, with `Set-Cookie` | The secret matches. The cookie carries `cookie_name`, `Path=/`, `Max-Age` equal to `ttl`, `Secure`, `HttpOnly` and `SameSite=Lax`. |
| 403 | The secret is wrong, or the request comes from this server's own addresses. |
| 429 | Too many failed attempts from one address. Wait and retry. |
| 405 | Any method other than `POST`. |
| 404 | `verified_session` is off. |
| 503 | CSM cannot read this server's current addresses. |

Integration notes:

- The plugin cannot fetch the cookie from the server side, because requests from this server's own addresses get 403. The administrator's browser must send the `POST`, so the cookie binds to the address the administrator browses from.
- `admin_secret` is one secret for the whole server. Whoever holds it can skip challenges on every site on the server from their own address, so give it to the plugin only on sites whose administrators you trust with that.

### Verified Search Crawlers

Googlebot and Bingbot can be allow-passed by reverse-DNS forward-confirm:

1. CSM looks up the visitor's PTR.
2. It checks that the name ends in a known crawler suffix (e.g. `.googlebot.com`).
3. It forward-resolves that name to confirm the original IP appears in the result.

A spoofed `User-Agent: Googlebot` from a residential IP fails forward-confirm and falls through to PoW.

```yaml
challenge:
  verified_crawlers:
    enabled: true
    providers: [googlebot, bingbot]
    cache_ttl: 15m
```

Positive results cache for `cache_ttl`. Negative results cache for one-fifth that long, so a transiently-broken resolver does not lock out a real crawler for the full window.

## Operational

### Backups

`csm store export` and `csm store import` capture the bbolt store, state JSON files (baseline file hashes), and signature-rules cache into a single tar+zstd archive. Use these for re-provisioning, cluster cloning, and disaster recovery rather than re-baselining a 200k-file account tree from scratch.

The daemon writes the archive under its state directory (the only tree its systemd sandbox can write) and the CLI moves it to the path you give. Any destination the CLI can write works, including `/var/backups`, if it passes these checks:

- The destination directory and every directory above it must be owned by root or by the account running the command.
- Those directories must not be writable by other accounts unless they carry the sticky bit as `/tmp` does.
- The destination itself must not already exist as a symlink or as another account's file.

Otherwise another account could swap the archive out after the CLI has verified it, and the export is refused before the daemon writes anything.

In-progress staging files and unconfirmed firewall rollback artifacts are excluded from backups, so restoring an archive cannot re-arm an old confirmation window.

```bash
csm store export /var/backups/csm-$(date +%F).csmbak
sha256sum -c /var/backups/csm-$(date +%F).csmbak.sha256
# transfer the .csmbak + .sha256 to the target host
systemctl stop csm
csm store import /var/backups/csm-2026-04-27.csmbak
systemctl start csm
```

Partial restore:

| Flag | What it does |
|------|--------------|
| `--only=baseline` | Restores only the file-hash state. Useful after a full re-install where firewall and history should stay fresh. |
| `--only=firewall` | Merges the firewall buckets into an existing daemon. Useful for cloning blocklists across a cluster. |

With `--only=firewall`, a durable firewall journal and its snapshot in the archive replace the target's. The restore refuses while either side has a durable firewall action unresolved or its audit undelivered.

#### Scheduled backups

Set `backup.enabled: true` and the daemon runs the same export on its own.

| Key | Default | Meaning |
|-----|---------|---------|
| `backup.schedule` | `24h` | How often the export runs. At least `1h`. |
| `backup.destination_dir` | `/var/lib/csm/backups` | Where each archive lands, with its `.sha256` companion. |
| `backup.filename` | `csm-{date}.csmbak` | The archive name. `{date}` is the run's UTC start time, such as `20261121T030000Z`. |
| `backup.retention_days` | 14 | After a successful export the daemon deletes the archives older than this, together with their companions. |

Changes to the block apply on reload.

How exports behave:

- Only completed exports appear under their final names.
- Store exports include regular files and skip symlinks and special files inside the source trees.
- The newest matching archive with a checksum sets the schedule after a restart.
- On its next check of that destination, CSM clears temporary files from interrupted exports.
- Retention applies to regular files matching the configured archive and checksum names.
- A failed export keeps earlier archives.
- A failed run raises a `backup_export_failed` Warning and is tried again one schedule later.

Choose a destination inside `/var/lib/csm` and outside both `state_path` and `signatures.rules_dir`. Copy archives off the host from there. Each directory from `/var/lib/csm` to the destination must be owned by root and writable only by root. The daemon rejects symlinks along that path.

`csm validate` rejects invalid backup settings, and a rejected reload keeps the current configuration. At startup an invalid backup plan produces a warning and pauses scheduled exports. Monitoring continues.

## Details

This section is reference material for edge cases.

### Unusable trusted proxy entries

Entries in `trusted_proxies` are addresses or CIDR ranges. Legacy zero-padded prefix lengths remain accepted. CSM skips other entries and never trusts a catch-all, such as `0.0.0.0/0`.

CSM does not accept a visitor address from a peer that only a refused catch-all covers. A request such a peer forwards identifies no visitor, even if truncation leaves the X-Forwarded-For header empty. This includes native IPv6 peers covered by a broad IPv4-mapped range. A request the peer makes directly, without forwarding, is still attributed to the peer's own address.

`csm validate` and plain `csm doctor` warn about unusable entries; they do not reject the configuration. Saving the challenge section in Settings rejects them.

### Adding an address to this host

While serving requests, CSM uses a cached interface address list, refreshed on demand after five minutes. If a refresh fails, it keeps the last successful list. An address added while the daemon runs can still be trusted until a successful refresh discovers it.

To assign this host an address covered by `trusted_proxies`:

1. Remove the covering entries, or narrow them to remote proxies.
2. Restart CSM.
3. Only then assign the address.
4. Run `csm doctor challenge` to check the resulting configuration.

### Legacy proxy-mode snippet

Older installers also deployed a legacy proxy-mode snippet on cPanel Apache and LiteSpeed (`/etc/apache2/conf.d/csm_challenge.conf`). Current installs do not.

On those stacks `csm webserver-integration install` and `upgrade` remove the legacy snippet in the same configtest-then-reload run that writes the integration snippet, and restore it if that run fails. If either file cannot be restored, the error reports the incomplete rollback, and no recovery reload runs with that incomplete configuration.

While both snippets are present and the integration template is not newer than the binary, `status` reports the integration as `stale`. The daemon's [startup refresh](#daemon-startup-refresh) then removes the legacy snippet on hosts that already run the integration.

### Daemon startup refresh

At startup the daemon creates the default maps if they are absent, including when challenge mode is disabled. It also refreshes two kinds of snippet:

- A legacy snippet whose RewriteMap points at a map file the daemon does not maintain. That pointer makes webserver config validation fail host-wide once the file goes missing, so the daemon re-deploys the shipped template.
- A CSM-managed integration snippet from an older template version. This refresh runs through the configtest-then-reload flow in [What the installer does on every run](#what-the-installer-does-on-every-run).

Files without a RewriteMap directive, operator-edited snippets, and snippets already pointing at the daemon maps are never touched. While any snippet still references a map under the old runtime directory, the daemon keeps that map file present until the snippet is refreshed with `csm webserver-integration upgrade`.

Newer templates are left alone at startup, including after a binary rollback. Observe mode skips this refresh.

### Nginx config validation

Nginx config validation runs outside the daemon's read-only sandbox via `systemd-run`, so it can open its logs.

- The availability probe and the configtest each get a separate 15-second command timeout.
- If the probe fails or times out, or `systemd-run` is absent, CSM tries `nginx -t` directly.
- A failed configtest is reported without retrying it.
