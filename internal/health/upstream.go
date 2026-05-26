package health

import "time"

// UpstreamResult describes whether a watcher's upstream input source is
// still feeding it. Watchers register a probe with the daemon; the
// components API surfaces "deaf" verdicts so operators can tell the
// difference between "attached and quiet" and "attached but nothing
// upstream is talking to me".
type UpstreamResult struct {
	Fresh        bool
	LastActivity time.Time
	Reason       string
}
