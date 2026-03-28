# Roadmap

## Fanotify Real-Time Scanner

- **GAP-1 — Per-path alert debounce**: A single frequently-written file triggers one alert per write with no deduplication. A WordPress plugin update can generate 500+ duplicate alerts in 60s. Add a per-path cooldown inside `sendAlert` (e.g., suppress re-alert on same path within 60s).

- **GAP-2 — Include process info in alerts**: Fanotify event metadata contains the PID of the writing process but it is never used. Read `/proc/<pid>/comm` (process name) and `/proc/<pid>/loginuid` (cPanel username) and include both in alert payloads to improve incident response.

- **GAP-3 — Monitor /home/*/tmp for executable drops**: cPanel per-account tmp dirs (`/home/<user>/tmp`) are a known vector for PHP exploits dropping executables. Already covered by the `/home` mount watch but lacks location-specific severity escalation.

- **GAP-4 — Location-based severity for PHP outside public_html**: PHP files written to `/home/<user>/mail/`, `/home/<user>/.cpanel/`, or `/home/<user>/.ssh/` should trigger higher severity than files in web-accessible directories.

- **GAP-5 — In-flight event deduplication**: Rapid writes to the same file (e.g., PHP session) queue N separate scan events for identical content. Use a `sync.Map` of recently-queued paths with a short TTL (few seconds) to deduplicate before events reach workers.

## Signature Engine

- Improve ZIP phishing kit detection with content inspection — check the ZIP central directory for `.html`/`.php` entries instead of relying only on filename patterns.
- Add ability to exclude specific signature rules per-account to handle known false positives on specific sites.
