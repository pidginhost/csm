# PHP form-relay state

The form-relay store keeps the per-client recipient history behind php_relay
Path 6, described in [PHP-Relay](../detection-realtime.md#php-relay-mail-abuse-cpanel-only).
The `ip_recipient_spread` and `ip_recipient_window_hours` settings supply the
recipient limit and observation window; the store adds no settings.

Counts saturate at the recipient limit. At capacity the store retains the most
recent distinct outside recipients, including one entry per unparsed message.
New activity replaces older evidence so a busy client does not lose its recent
history when its first recipients expire. Lowering the limit retains the newest
evidence within the new bound. Raising it cannot recover previously discarded
recipients.

The window ends at the latest time observed by recording, cooldown checks, or
sweeping. Delayed messages may contribute only while they remain in that window;
replaying expired mail cannot recreate expired history or cooldowns. The time
boundary survives removal of idle clients. Expired recipients are removed before
capacity eviction, so stale counts cannot displace active clients. Expiry alone
does not report capacity loss.

Each account retains its most recently observed staff clients. A delayed staff
record cannot replace a newer one merely because it arrived later. Staff history
is stored apart from recipient history and expires on its existing schedule.

All state transitions and reads hold the store mutex. The evaluator runs only
for a message the store counted. It reads the client's count, script shares and
recipient domains and claims the client cooldown in one call under that lock, so
expiry cannot remove evidence between counting it and building the finding.
Before counting, that call drops recipients the client reached through an
account where it is now staff, or through a script that is now ignored, so a
current exemption also covers mail recorded before it applied. Script shares
are grouped by the script's normalized name, the one findings print. Returned
script shares and recipient domains are copies.

The store also records when each normalized script name was last reported, so
a script finding repeats neither for a later client nor after the routine sweep
of per-script state within the window.

Client findings carry the triggering Exim message ID as their observation in
the spool stream. Admission previews and forecasts can trace direct responses
and later challenge timeouts to that same mail. Script findings remain advisory
and carry no address evidence.
