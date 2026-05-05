//go:build !linux || !journal

package maillog

import (
	"context"
	"errors"
)

// JournalReader is a no-op stub on builds without the `journal` tag.
// The factory (T4) uses this to produce a clear error rather than
// silently downgrading to file mode when the operator explicitly asked
// for journald.
type JournalReader struct{}

// NewJournalReader satisfies the same constructor signature as the
// linux+journal build, so the factory and tests compile identically
// on default builds.
func NewJournalReader(_ []string) *JournalReader { return &JournalReader{} }

func JournalSupported() bool { return false }

// ErrJournalUnsupported is returned when the build was produced without
// the `journal` tag (default builds).
var ErrJournalUnsupported = errors.New("journal reader not compiled in (build with JOURNAL=1)")

// Run returns ErrJournalUnsupported immediately on stub builds.
func (*JournalReader) Run(_ context.Context) (<-chan Line, error) {
	return nil, ErrJournalUnsupported
}
