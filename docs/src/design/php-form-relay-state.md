# PHP form-relay state

The form-relay store prepares per-client recipient history for a future detector
path. It is not yet connected to the evaluator. The existing
`ip_recipient_spread` and `ip_recipient_window_hours` settings supply the recipient
limit and observation window; this store adds no settings.

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
remains separate from recipient history and expires on its existing schedule.

All state transitions and reads hold the store mutex. Returned script shares and
recipient domains are copies. Separate calls are not an atomic snapshot, so a
future evaluator must account for changes between recording and reading evidence.
