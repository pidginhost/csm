package webserver

import (
	"errors"
)

// ErrUnknownWebserver is returned when the host has no recognized
// webserver and the installer can do nothing useful.
var ErrUnknownWebserver = errors.New("webserver integration: no supported webserver detected")

// ErrManualEdits is returned when the on-disk snippet exists but does
// not carry the CSM-managed marker, signalling that an operator edited
// it. Upgrade refuses to touch it; the operator must remove it first.
var ErrManualEdits = errors.New("webserver integration: on-disk snippet is not CSM-managed")

// Handler is the per-webserver contract the installer drives. Each
// implementation knows its own canonical snippet path, validation
// command, and reload command. The installer composes them into the
// write-or-revert flow.
type Handler interface {
	// Kind returns a short stable name for status output ("apache",
	// "lsws", "nginx").
	Kind() string
	// SnippetPath returns the canonical path the integration writes to.
	SnippetPath() string
	// Template returns the rendered snippet content for the current
	// CSM binary. Includes the version marker the installer reads
	// back to decide if an upgrade is needed.
	Template() string
	// Validate runs the webserver's own configtest with the snippet
	// already in place. Returns nil on pass, error with captured
	// stderr on fail.
	Validate() error
	// Reload performs a graceful reload of the webserver.
	Reload() error
}
