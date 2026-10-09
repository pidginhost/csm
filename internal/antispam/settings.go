// Package antispam renders the Exim and rspamd configuration CSM owns for
// inbound spam filtering and evaluates the host preconditions for it. Every
// function here is pure: callers supply command output and file facts.
package antispam

import (
	"errors"
	"fmt"
	"path"
)

const (
	// DefaultSocket is the rspamd normal-worker socket CSM scans through.
	DefaultSocket = "/run/rspamd/csm-normal.sock"
	// DefaultRejectScore and DefaultTagScore are the score thresholds used
	// when the operator sets none.
	DefaultRejectScore = 15
	DefaultTagScore    = 6

	maxScore = 1000
	// maxSocketPath is the sun_path size (108 bytes) minus its NUL.
	maxSocketPath = 107
)

// Settings are the validated values rendered into Exim and rspamd files.
type Settings struct {
	DryRun      bool
	Socket      string
	RejectScore int
	TagScore    int
}

// Validate checks every value that reaches a rendered file.
func (s Settings) Validate() error {
	if err := ValidateSocket(s.Socket); err != nil {
		return err
	}
	return ValidateScores(s.RejectScore, s.TagScore)
}

// ValidateSocket accepts a clean absolute path made only of ASCII letters,
// digits, '/', '.', '_' and '-'. The socket path is the only operator string
// rendered into Exim configuration, so it may hold no expansion, list or
// whitespace character.
func ValidateSocket(p string) error {
	if p == "" {
		return errors.New("rspamd_socket is empty")
	}
	if len(p) > maxSocketPath {
		return fmt.Errorf("rspamd_socket is longer than %d bytes", maxSocketPath)
	}
	if p[0] != '/' || p == "/" {
		return errors.New("rspamd_socket must be an absolute path to a socket file")
	}
	for i := 0; i < len(p); i++ {
		c := p[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '/', c == '.', c == '_', c == '-':
		default:
			return fmt.Errorf("rspamd_socket contains %q; only letters, digits, '/', '.', '_' and '-' are allowed", c)
		}
	}
	if path.Clean(p) != p {
		return errors.New("rspamd_socket must be a clean path: no empty, '.' or '..' elements and no trailing slash")
	}
	return nil
}

// ValidateScores requires 0 < tag < reject <= 1000. Exim compares scores in
// tenths, so the bound keeps every rendered threshold a small integer.
func ValidateScores(reject, tag int) error {
	if reject < 1 || reject > maxScore {
		return fmt.Errorf("reject_score must be between 1 and %d", maxScore)
	}
	if tag < 1 || tag > maxScore {
		return fmt.Errorf("tag_score must be between 1 and %d", maxScore)
	}
	if tag >= reject {
		return errors.New("tag_score must be lower than reject_score")
	}
	return nil
}
