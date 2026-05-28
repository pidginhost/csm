package daemon

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

const phpRelayHistoryMaxLineBytes = 1024 * 1024

// ScanEximHistoryForPHPRelayAccountVolume replays exim_mainlog through the
// Path 2b parser, used at daemon startup to populate perAccountWindow with
// recent outbound activity. Each accepted finding is delivered via emit.
//
// Reads the file lazily and skips a single oversized line instead of
// abandoning later entries. Caller passes `now` to keep retro replays
// deterministic for tests; production passes time.Now() once and the parser
// uses it for window math.
//
// ctx scopes the scan to daemon lifetime; nil leaves the scan unbounded for
// direct helper callers.
func ScanEximHistoryForPHPRelayAccountVolume(ctx context.Context, path string, eng *evaluator, now time.Time, emit func(alert.Finding)) {
	// #nosec G304 -- path is operator-configured / hardcoded to cPanel default.
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()
	reader := bufio.NewReaderSize(f, 64*1024)
	var line []byte
	oversized := false
	for {
		if phpRelayScanContextDone(ctx) {
			return
		}
		part, rerr := reader.ReadSlice('\n')
		if len(part) > 0 && !oversized {
			if len(line)+len(part) > phpRelayHistoryMaxLineBytes {
				oversized = true
				line = nil
			} else {
				line = append(line, part...)
			}
		}
		switch {
		case rerr == nil:
			if !oversized {
				emitPHPRelayHistoryLine(line, eng, now, emit)
			}
			line = nil
			oversized = false
		case errors.Is(rerr, bufio.ErrBufferFull):
			continue
		case errors.Is(rerr, io.EOF):
			if len(line) > 0 && !oversized {
				emitPHPRelayHistoryLine(line, eng, now, emit)
			}
			return
		default:
			return
		}
	}
}

func phpRelayScanContextDone(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	select {
	case <-ctx.Done():
		return true
	default:
		return false
	}
}

func emitPHPRelayHistoryLine(line []byte, eng *evaluator, now time.Time, emit func(alert.Finding)) {
	line = bytes.TrimSuffix(line, []byte("\n"))
	line = bytes.TrimSuffix(line, []byte("\r"))
	for _, ev := range eng.parsePHPRelayAccountVolume(string(line), now) {
		emit(ev)
	}
}
