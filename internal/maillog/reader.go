// Package maillog reads postfix/dovecot log lines from either a tailed file
// or systemd-journald, normalizing them into a single Line type so the
// daemon's mail-brute and PHP-relay parsers don't have to care which
// source supplied the line.
package maillog

import "context"

// Line is one mail-log entry, normalized across file and journal sources.
type Line struct {
	Source  string // "file" | "journal"
	Unit    string // e.g., "postfix", "dovecot" (empty when from a file)
	Message string // raw log message (for file: full line; for journal: MESSAGE field)
}

// Reader streams mail-log lines until the context is cancelled. Implementations
// must close the returned channel when ctx is done so consumers can drain
// cleanly.
type Reader interface {
	Run(ctx context.Context) (<-chan Line, error)
}
