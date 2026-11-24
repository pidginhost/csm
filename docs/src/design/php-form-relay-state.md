# PHP form-relay state

The form-relay store keeps the per-client recipient history behind php_relay Path 6, described in [PHP-Relay](../detection-realtime.md#php-relay-mail-abuse-cpanel-only). Path 6 counts, for each client address, the distinct outside recipients that hosted sites mail. This note describes what the store keeps, when it forgets, and how the evaluator reads it.

The store adds no settings. The `ip_recipient_spread` and `ip_recipient_window_hours` settings supply the recipient limit and the observation window.

## Recipient capacity

Counts saturate at the recipient limit. At capacity the store retains the most recent distinct outside recipients, including one entry per unparsed message. New activity replaces older evidence, so a busy client does not lose its recent history when its first recipients expire.

A change of the limit has these effects:

- Lowering the limit retains the newest evidence within the new bound.
- Raising the limit cannot recover recipients the store already discarded.

## The observation window

The window ends at the latest time observed by recording, cooldown checks, or sweeping. The window follows these rules:

- Delayed messages may contribute only while they remain in that window.
- Replaying expired mail cannot recreate expired history or cooldowns.
- The time boundary survives removal of idle clients.
- Expired recipients are removed before capacity eviction, so stale counts cannot displace active clients.
- Expiry alone does not report capacity loss.

## Staff history

A staff client is exempt from Path 6 on the account where it is staff. Each account retains its most recently observed staff clients. A delayed staff record cannot replace a newer one merely because it arrived later.

Staff history is stored apart from recipient history and expires on its existing schedule.

## How the evaluator reads the store

All state transitions and reads hold the store mutex. The evaluator runs only for a message the store counted.

One call under that lock reads the client's count, script shares and recipient domains, and claims the client cooldown. Expiry therefore cannot remove evidence between counting it and building the finding.

Before counting, that call drops the recipients the client reached in either of these ways:

- Through an account where the client has staff status.
- Through a script on the ignore list.

A current exemption therefore also covers mail recorded before it applied.

Script shares are grouped by the script's normalized name, the one findings print. Returned script shares and recipient domains are copies.

## Staff evidence from access logs

When that call shows the client would cross the threshold, the evaluator first reads the sites' access logs for staff evidence. It reads them outside the lock and does not claim the cooldown yet. Each distinct log is read once per crossing, even when several scripts share it.

These rules decide which requests count as evidence:

- Only successful GET requests to recognized staff pages qualify.
- Public or subscriber pages and ambiguous request paths do not qualify.
- Invalid, future and expired timestamps do not qualify.

The latest qualifying request time across those logs sets the staff expiry, so rereading an old log cannot renew an exemption.

The evaluator marks any account with evidence as staff, then repeats the call. The repeated call claims the cooldown only if the remaining accounts still cross the threshold.

## Findings

Client findings carry the triggering Exim message ID as their observation in the spool stream. Admission, the step that decides whether an automatic block goes ahead, can trace direct responses and later challenge timeouts to that same mail.

Script findings remain advisory and carry no address evidence. The store also records when each normalized script name was last reported. A script finding therefore repeats neither for a later client nor after the routine sweep of per-script state within the window.
