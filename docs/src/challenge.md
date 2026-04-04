# Challenge Pages

JavaScript proof-of-work challenge pages — a CAPTCHA alternative for suspicious IPs.

## How It Works

1. Suspicious IP hits a protected resource
2. CSM serves a challenge page requiring client-side SHA-256 proof-of-work
3. Browser computes the proof (shows progress bar)
4. On valid solution, CSM issues an HMAC-verified token
5. Subsequent requests pass through automatically

## Features

- **SHA-256 based difficulty** — configurable 0-5 levels
- **Client-side computation** — no server load
- **HMAC token verification** — prevents replay attacks
- **Nonce-based anti-replay**
- **User-friendly** — progress bar, instant feedback
- **Bot filtering** — headless browsers and scripts fail the challenge

## Use Cases

- Gray-listing alternative to hard IP blocks
- Protecting WordPress login pages
- Rate limiting without blocking legitimate users
- DDoS mitigation layer
