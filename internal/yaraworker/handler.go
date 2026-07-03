// Package yaraworker implements the `csm yara-worker` subcommand: a
// child process that exists only to host the YARA-X cgo surface and
// reply to scan requests over a Unix socket. See ROADMAP.md item 2.
//
// The handler here adapts a yara.Scanner (real in `-tags yara` builds,
// no-op in plain builds) to the yaraipc.Handler wire contract. The
// package is deliberately thin: IPC lives in internal/yaraipc, rule
// compilation lives in internal/yara, and supervision lives in
// internal/daemon.
package yaraworker

import (
	"fmt"
	"sync"

	"github.com/pidginhost/csm/internal/yara"
	"github.com/pidginhost/csm/internal/yaraipc"
)

// Scanner is the subset of *yara.Scanner that the handler uses. An
// interface (rather than the concrete type) so tests can inject a fake
// without pulling in the cgo build tag.
type Scanner interface {
	ScanFile(path string, maxBytes int) []yara.Match
	ScanBytes(data []byte) []yara.Match
	ScanBytesChecked(data []byte) ([]yara.Match, error)
	Reload() error
	RuleCount() int
}

// NewHandler returns a yaraipc.Handler backed by s. A nil scanner is
// permitted: the handler reports Alive=true with zero matches, which is
// the expected behaviour on builds compiled without the yara tag and on
// hosts where no rules directory has been provisioned yet. This constructor
// has no recovery factory, so a nil scanner stays nil (used by tests and the
// no-engine path).
func NewHandler(s Scanner) yaraipc.Handler {
	return &handler{scanner: s}
}

// newRecoverableHandler adds a rebuild factory and a startup compile error, so
// a worker that came up with a failed rule compile (scanner == nil,
// compileErr != "") can recover on a later Reload instead of no-op'ing
// forever. rebuild returns a fresh scanner from the current rules on disk, an
// error if they still do not compile, or (nil, nil) when there is no engine to
// build (plain build).
func newRecoverableHandler(s Scanner, rebuild func() (Scanner, error), compileErr string) yaraipc.Handler {
	return &handler{scanner: s, rebuild: rebuild, compileErr: compileErr}
}

type handler struct {
	// mu guards scanner and compileErr: the wire contract allows more than
	// one connection, and a Reload that swaps the scanner in must not race a
	// concurrent Ping/Scan reading it.
	mu         sync.Mutex
	scanner    Scanner
	rebuild    func() (Scanner, error)
	compileErr string
}

func (h *handler) currentState() (Scanner, string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.scanner, h.compileErr
}

func (h *handler) ScanFile(a yaraipc.ScanFileArgs) (yaraipc.ScanResult, error) {
	sc, compileErr := h.currentState()
	if sc == nil {
		if compileErr != "" {
			return yaraipc.ScanResult{}, fmt.Errorf("yara scanner unavailable: %s", compileErr)
		}
		return yaraipc.ScanResult{}, nil
	}
	return yaraipc.ScanResult{Matches: convertMatches(sc.ScanFile(a.Path, a.MaxBytes))}, nil
}

func (h *handler) ScanBytes(a yaraipc.ScanBytesArgs) (yaraipc.ScanResult, error) {
	sc, compileErr := h.currentState()
	if sc == nil {
		if compileErr != "" {
			return yaraipc.ScanResult{}, fmt.Errorf("yara scanner unavailable: %s", compileErr)
		}
		return yaraipc.ScanResult{}, nil
	}
	matches, err := sc.ScanBytesChecked(a.Data)
	if err != nil {
		return yaraipc.ScanResult{}, err
	}
	return yaraipc.ScanResult{Matches: convertMatches(matches)}, nil
}

func (h *handler) Reload(_ yaraipc.ReloadArgs) (yaraipc.ReloadResult, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.scanner == nil {
		// No live scanner. Either there is no engine (no rebuild factory ->
		// no-op, matching the pre-recovery behaviour) or the startup compile
		// failed and we now retry it.
		if h.rebuild == nil {
			return yaraipc.ReloadResult{}, nil
		}
		newSc, err := h.rebuild()
		if err != nil {
			h.compileErr = err.Error()
			return yaraipc.ReloadResult{CompileError: h.compileErr}, err
		}
		if newSc == nil {
			// No engine to build (plain build): stay a no-op, not an error.
			h.compileErr = ""
			return yaraipc.ReloadResult{}, nil
		}
		h.scanner = newSc
		h.compileErr = ""
		return yaraipc.ReloadResult{RuleCount: newSc.RuleCount()}, nil
	}

	if err := h.scanner.Reload(); err != nil {
		return yaraipc.ReloadResult{}, err
	}
	return yaraipc.ReloadResult{RuleCount: h.scanner.RuleCount()}, nil
}

func (h *handler) Ping() (yaraipc.PingResult, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.scanner == nil {
		return yaraipc.PingResult{Alive: true, CompileError: h.compileErr}, nil
	}
	return yaraipc.PingResult{Alive: true, RuleCount: h.scanner.RuleCount()}, nil
}

func convertMatches(in []yara.Match) []yaraipc.Match {
	if len(in) == 0 {
		return nil
	}
	out := make([]yaraipc.Match, len(in))
	for i := range in {
		out[i] = yaraipc.Match{
			RuleName: in[i].RuleName,
			Meta:     in[i].Meta,
		}
	}
	return out
}
