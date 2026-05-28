package daemon

import (
	"bufio"
	"context"
	"os"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

// ScanEximHistoryForPHPRelayAccountVolume replays exim_mainlog through the
// Path 2b parser, used at daemon startup to populate perAccountWindow with
// recent outbound activity. Each accepted finding is delivered via emit.
//
// Bounded by file size; reads full file lazily via bufio. Caller passes
// `now` to keep retro replays deterministic for tests; production passes
// time.Now() once and the parser uses it for window math.
//
// ctx scopes the scan to daemon lifetime: a large mainlog combined with a
// graceful shutdown would otherwise let the scan outlive d.wg and block
// the state.Close call that drives bbolt sync. ctx==nil falls through to
// the unbounded behavior used by older callers.
func ScanEximHistoryForPHPRelayAccountVolume(ctx context.Context, path string, eng *evaluator, now time.Time, emit func(alert.Finding)) {
	// #nosec G304 -- path is operator-configured / hardcoded to cPanel default.
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 4096), 1024*1024)
	for sc.Scan() {
		if ctx != nil {
			select {
			case <-ctx.Done():
				return
			default:
			}
		}
		for _, ev := range eng.parsePHPRelayAccountVolume(sc.Text(), now) {
			emit(ev)
		}
	}
}
