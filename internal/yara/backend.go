package yara

import "sync/atomic"

// Backend is the consumable scanning surface shared by the in-process
// *Scanner and out-of-process process supervisor. Callers should depend
// on this interface (via Active()) so they keep working when the daemon
// switches backends at startup. String-valued rule metadata travels on
// Match.Meta, so adapters that historically reached for the compiled
// *yara_x.Rules object (e.g. emailav) now work uniformly under both
// backends -- see internal/emailav/yarax.go.
type Backend interface {
	ScanFile(path string, maxBytes int) []Match
	ScanBytes(data []byte) []Match
	RuleCount() int
	Reload() error
}

var activeBackend atomic.Pointer[backendHolder]

type backendHolder struct{ b Backend }

// Active returns the configured scanning backend. When SetActive has
// not been called, it falls back to the in-process singleton Global().
// Returns a nil interface if neither is available (e.g. a !yara build
// with no supervisor wired up); callers must nil-check.
func Active() Backend {
	if h := activeBackend.Load(); h != nil && h.b != nil {
		return h.b
	}
	if g := Global(); g != nil {
		return g
	}
	return nil
}

// SetActive installs a scanning backend. Calling with nil clears the
// override and restores the Global() fallback. Safe to call at any
// time; reads in-flight see the prior backend finish and the next read
// sees the new one.
func SetActive(b Backend) {
	if b == nil {
		activeBackend.Store(nil)
		return
	}
	activeBackend.Store(&backendHolder{b: b})
}
