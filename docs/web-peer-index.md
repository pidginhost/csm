# Web peer index

The peer log parser and in-memory index are available in `internal/checks`;
daemon ingestion and admission wiring are separate work. They do not yet change
automatic responses on installed hosts.

The index reads the hour before a finding and two minutes after it. Forged
observations take precedence over proxied, then direct; no observations means
unknown. Request start times can arrive out of order because the server writes
at completion. Runs only combine observations whose gaps fit a complete verdict
window, including skew, so an empty interval cannot supply evidence.

Replacing a disjoint run marks older verdicts for that client unknown. Pruning
and capacity overflow also retain a loss watermark: replaying direct lines
cannot erase lost forged or proxied evidence. Windows that start after the
watermark can use new observations normally. Observation and lookup normalize
IPv4-mapped addresses to the same key.
