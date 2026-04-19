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
	"github.com/pidginhost/csm/internal/yara"
	"github.com/pidginhost/csm/internal/yaraipc"
)

// Scanner is the subset of *yara.Scanner that the handler uses. An
// interface (rather than the concrete type) so tests can inject a fake
// without pulling in the cgo build tag.
type Scanner interface {
	ScanFile(path string, maxBytes int) []yara.Match
	ScanBytes(data []byte) []yara.Match
	Reload() error
	RuleCount() int
}

// NewHandler returns a yaraipc.Handler backed by s. A nil scanner is
// permitted: the handler reports Alive=true with zero matches, which is
// the expected behaviour on builds compiled without the yara tag and on
// hosts where no rules directory has been provisioned yet.
func NewHandler(s Scanner) yaraipc.Handler {
	return &handler{scanner: s}
}

type handler struct {
	scanner Scanner
}

func (h *handler) ScanFile(a yaraipc.ScanFileArgs) (yaraipc.ScanResult, error) {
	if h.scanner == nil {
		return yaraipc.ScanResult{}, nil
	}
	return yaraipc.ScanResult{Matches: convertMatches(h.scanner.ScanFile(a.Path, a.MaxBytes))}, nil
}

func (h *handler) ScanBytes(a yaraipc.ScanBytesArgs) (yaraipc.ScanResult, error) {
	if h.scanner == nil {
		return yaraipc.ScanResult{}, nil
	}
	return yaraipc.ScanResult{Matches: convertMatches(h.scanner.ScanBytes(a.Data))}, nil
}

func (h *handler) Reload(_ yaraipc.ReloadArgs) (yaraipc.ReloadResult, error) {
	if h.scanner == nil {
		return yaraipc.ReloadResult{}, nil
	}
	if err := h.scanner.Reload(); err != nil {
		return yaraipc.ReloadResult{}, err
	}
	return yaraipc.ReloadResult{RuleCount: h.scanner.RuleCount()}, nil
}

func (h *handler) Ping() (yaraipc.PingResult, error) {
	if h.scanner == nil {
		return yaraipc.PingResult{Alive: true}, nil
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
