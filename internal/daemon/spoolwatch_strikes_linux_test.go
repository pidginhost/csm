//go:build linux

package daemon

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	emime "github.com/pidginhost/csm/internal/mime"
	"github.com/pidginhost/csm/internal/workerproc"
)

// strikeWatcher is an extract watcher with the repeat-failure tables a real
// watcher gets.
func strikeWatcher(mode string, ex mailExtractor) (*SpoolWatcher, chan alert.Finding) {
	sw, ch := extractWatcher(mode, ex)
	sw.initStrikes()
	return sw, ch
}

// A message that killed the worker twice is not unpacked again: each retry
// would cost another worker and still end incomplete.
func TestSpoolRepeatFailureSkipsWorker(t *testing.T) {
	timeout := workerFailure(t, workerproc.ReasonTimeout)
	for _, mode := range []string{"open", "tempfail"} {
		t.Run(mode, func(t *testing.T) {
			ex := &recordingExtractor{size: 1, extract: func(context.Context, int) (*emime.ExtractionResult, error) { return nil, timeout }}
			sw, ch := strikeWatcher(mode, ex)
			dir := t.TempDir()
			msgID := "1abcDE-000001-AB"
			buildMinimalEximSpool(t, dir, msgID)
			for range 2 {
				captureResponses(t)
				sw.handleSpoolEvent(bodyEvent(t, dir, msgID))
			}
			takeFindings(ch)
			sw.lastDegradedAt = time.Time{} // the degraded warning is rate-limited
			responses := captureResponses(t)
			sw.handleSpoolEvent(bodyEvent(t, dir, msgID))
			if n := len(ex.recorded()); n != 2 {
				t.Fatalf("extractor calls = %d, want the third event skipped", n)
			}
			if got := responses(); len(got) != 1 || got[0].response != wantResponse(mode) {
				t.Fatalf("responses %+v, want %d", got, wantResponse(mode))
			}
			d := findingsFor(takeFindings(ch), "email_av_degraded")
			if len(d) != 1 || !strings.Contains(d[0].Message, "(parse worker failed on this message before)") {
				t.Fatalf("degraded findings %+v, want the repeat-failure reason", d)
			}
		})
	}
}

// A unit that cannot start is the host's fault, not the message's.
func TestSpoolSpawnFailureDoesNotStrike(t *testing.T) {
	spawn := fmt.Errorf("%w: no systemd-run", workerproc.ErrSpawn)
	ex := &recordingExtractor{size: 1, extract: func(context.Context, int) (*emime.ExtractionResult, error) { return nil, spawn }}
	sw, _ := strikeWatcher("open", ex)
	captureResponses(t)
	dir := t.TempDir()
	msgID := "1abcDE-000002-AB"
	buildMinimalEximSpool(t, dir, msgID)
	for range 3 {
		sw.handleSpoolEvent(bodyEvent(t, dir, msgID))
	}
	if n := len(ex.recorded()); n != 3 {
		t.Fatalf("extractor calls = %d, want every event to reach the extractor", n)
	}
}

func TestSpoolSourceKillsRaiseHigh(t *testing.T) {
	crash := workerFailure(t, workerproc.ReasonCrash)
	run := func(t *testing.T, sources []string) []alert.Finding {
		t.Helper()
		ex := &recordingExtractor{size: 1, extract: func(context.Context, int) (*emime.ExtractionResult, error) { return nil, crash }}
		sw, ch := strikeWatcher("open", ex)
		captureResponses(t)
		dir := t.TempDir()
		for i, src := range sources {
			msgID := fmt.Sprintf("1abcDE-00010%d-AB", i)
			buildMinimalEximSpool(t, dir, msgID)
			evt := bodyEvent(t, dir, msgID)
			evt.source = src
			sw.handleSpoolEvent(evt)
		}
		return takeFindings(ch)
	}
	fs := run(t, []string{"ip:192.0.2.10", "ip:192.0.2.10", "ip:192.0.2.10"})
	high := findingsFor(fs, "email_av_parse_worker_source")
	if len(high) != 1 || high[0].Severity != alert.High || !strings.Contains(high[0].Message, `"ip:192.0.2.10"`) {
		t.Fatalf("source findings %+v, want one High naming the source", high)
	}
	failed := findingsFor(fs, "email_av_parse_worker_failed")
	if len(failed) != 1 || !strings.Contains(failed[0].Message, `"ip:192.0.2.10"`) {
		t.Fatalf("worker failed findings %+v, want the source named", failed)
	}
	if high := findingsFor(run(t, []string{"ip:192.0.2.10", "ip:192.0.2.10"}), "email_av_parse_worker_source"); len(high) != 0 {
		t.Fatalf("two crashes raised %+v", high)
	}
	if high := findingsFor(run(t, []string{"ip:192.0.2.10", "ip:198.51.100.7", "auth:user@example.com"}), "email_av_parse_worker_source"); len(high) != 0 {
		t.Fatalf("crashes from three sources raised %+v", high)
	}
	failed = findingsFor(run(t, []string{""}), "email_av_parse_worker_failed")
	if len(failed) != 1 || !strings.Contains(failed[0].Message, "unknown source") {
		t.Fatalf("worker failed findings %+v, want unknown source", failed)
	}
}
