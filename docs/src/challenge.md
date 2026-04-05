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

Login brute force (`wp_login_bruteforce`, `cpanel_login_*`), WAF triggers (`modsec_*`), XML-RPC abuse, FTP/SSH brute force, IP reputation, and other suspicious-but-not-confirmed-malicious activity.

### Always Hard-Blocked

Confirmed malware (webshells, YARA/signature matches), C2 connections, backdoor ports, phishing pages, database injections, and spam outbreaks are always hard-blocked immediately, even when challenge is enabled.

### Timeout Escalation

If an IP doesn't solve the PoW challenge within 30 minutes, it is automatically escalated to a hard firewall block.

### Successful Verification

When a client passes the challenge:
1. The IP is temporarily allowed through the firewall for 4 hours
2. A verification cookie is set
3. The IP is removed from the challenge list (Apache stops redirecting)
