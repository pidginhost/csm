package daemon

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/platform"
)

func hitHandler(line string, _ *config.Config) []alert.Finding {
	if strings.HasPrefix(line, "hit") {
		return []alert.Finding{{Check: "fixture", Message: line}}
	}
	return nil
}

func observingWatcher(t *testing.T, producer admission.ProducerID) (*LogWatcher, string, chan alert.Finding) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "log")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	ch := make(chan alert.Finding, 16)
	w, err := newObservedLogWatcher(logWatchSpec{path: path, handler: hitHandler, producer: producer}, &config.Config{}, ch)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(w.closeFile)
	return w, path, ch
}

func appendLog(t *testing.T, path, text string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.WriteString(text); err != nil {
		t.Fatal(err)
	}
}

func drainObservedFindings(ch chan alert.Finding) []alert.Finding {
	var out []alert.Finding
	for {
		select {
		case f := <-ch:
			out = append(out, f)
		default:
			return out
		}
	}
}

// A finding names the log line it came from: the producer, one generation
// of the file as the stream, the line's start offset as the cursor, and the
// read time.
func TestLogWatcherStampsObservation(t *testing.T) {
	w, path, ch := observingWatcher(t, checks.ProducerEximLog)
	appendLog(t, path, "miss\nhit one\nhit two\n")
	before := time.Now()
	w.readNewLines()
	after := time.Now()
	got := drainObservedFindings(ch)
	if len(got) != 2 {
		t.Fatalf("findings %+v, want two", got)
	}
	stream := fmt.Sprintf("f:%x:%x:%s.0", w.fileID.dev, w.fileID.ino, observationEpoch)
	if len(stream) > 128 {
		t.Fatalf("stream %q is longer than admission accepts", stream)
	}
	for i, cursor := range []string{"5", "13"} {
		o := got[i].Observation
		if o.Producer != "exim_log" || o.Stream != stream || o.Cursor != cursor || o.ObservedAt.Before(before) || o.ObservedAt.After(after) {
			t.Errorf("finding %d observation %+v, want exim_log %s at %s read now", i, o, stream, cursor)
		}
	}
}

// A file that starts over, rewritten in place, truncated or replaced by
// rotation, starts a new stream, so a reused offset never names an earlier
// line.
func TestLogWatcherObservationStreamChangesWhenTheFileRestarts(t *testing.T) {
	for name, restart := range map[string]func(t *testing.T, path string){
		"rewritten": func(t *testing.T, path string) {
			if err := os.WriteFile(path, []byte("hit two\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"truncated": func(t *testing.T, path string) {
			if err := os.WriteFile(path, []byte("hit\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"rotated": func(t *testing.T, path string) {
			if err := os.Rename(path, path+".1"); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte("hit two and more\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
	} {
		// Run reopens the path every few minutes; a rotation is seen then.
		reopen := name == "rotated"
		t.Run(name, func(t *testing.T) {
			w, path, ch := observingWatcher(t, checks.ProducerEximLog)
			appendLog(t, path, "hit one\n")
			w.readNewLines()
			first := drainObservedFindings(ch)
			restart(t, path)
			if reopen {
				w.reopen()
			}
			// A shrunk file is reopened on one tick and read on the next.
			w.readNewLines()
			w.readNewLines()
			second := drainObservedFindings(ch)
			if len(first) != 1 || len(second) != 1 {
				t.Fatalf("findings %+v then %+v, want one each", first, second)
			}
			a, b := first[0].Observation, second[0].Observation
			if a.Cursor != "0" || b.Cursor != "0" || a.Stream == b.Stream || b.Stream == "" {
				t.Fatalf("observations %+v then %+v, want offset 0 in two streams", a, b)
			}
		})
	}
}

// Returning to an earlier inode must not reuse a stream and offset.
func TestLogWatcherRotatingBackStartsAnotherGeneration(t *testing.T) {
	w, path, ch := observingWatcher(t, checks.ProducerEximLog)
	appendLog(t, path, "hit one\n")
	w.readNewLines()
	first := drainObservedFindings(ch)
	if err := os.Rename(path, path+".first"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("hit two\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	w.reopen()
	w.readNewLines()
	_ = drainObservedFindings(ch)
	if err := os.Rename(path, path+".second"); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path+".first", path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("hit new\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	w.reopen()
	w.readNewLines()
	last := drainObservedFindings(ch)
	if len(first) != 1 || len(last) != 1 || first[0].Observation.Stream == last[0].Observation.Stream || last[0].Observation.Cursor != "0" {
		t.Fatalf("rotated observations %+v then %+v reused a position", first, last)
	}
}

// A fresh process epoch distinguishes a reused offset after downtime.
func TestLogWatcherRestartEpochSeparatesPositions(t *testing.T) {
	w, _, _ := observingWatcher(t, checks.ProducerEximLog)
	old := observationEpoch
	t.Cleanup(func() { observationEpoch = old })
	a := w.observation(0, time.Unix(1, 0))
	observationEpoch = alert.NewObservationEpoch()
	b := w.observation(0, time.Unix(1, 0))
	if a.Stream == b.Stream || a.Cursor != b.Cursor {
		t.Fatalf("restart reused %+v as %+v", a, b)
	}
}

// Non-finding lines pay no formatting cost even when a producer is named.
func TestLogWatcherDoesNotFormatObservationsForMisses(t *testing.T) {
	w, path, _ := observingWatcher(t, checks.ProducerEximLog)
	appendLog(t, path, "miss\n")
	read := func() { w.offset = 0; w.marker = nil; w.readNewLines() }
	withProducer := testing.AllocsPerRun(10, read)
	w.producer = ""
	withoutProducer := testing.AllocsPerRun(10, read)
	if withProducer != withoutProducer {
		t.Fatalf("miss allocations with producer %v, without %v", withProducer, withoutProducer)
	}
}

// A watcher that feeds no evidence producer leaves findings without one.
func TestLogWatcherWithoutProducerLeavesObservationZero(t *testing.T) {
	w, path, ch := observingWatcher(t, "")
	appendLog(t, path, "hit one\n")
	w.readNewLines()
	if got := drainObservedFindings(ch); len(got) != 1 || got[0].Observation != (alert.Observation{}) {
		t.Fatalf("findings %+v, want one without an observation", got)
	}
}

// An observed handler sees each line's observation, so a finding it keeps
// and emits later can still name its line.
func TestLogWatcherPassesTheObservationToAnObservedHandler(t *testing.T) {
	w, path, ch := observingWatcher(t, checks.ProducerCpanelAccessLog)
	var seen []alert.Observation
	w.observed = func(line string, o alert.Observation, _ *config.Config) []alert.Finding {
		seen = append(seen, o)
		return nil
	}
	appendLog(t, path, "first\nsecond\n")
	w.readNewLines()
	if len(drainObservedFindings(ch)) != 0 || len(seen) != 2 || seen[0].Cursor != "0" || seen[1].Cursor != "6" || seen[1].Producer != "cpanel_access_log" {
		t.Fatalf("observations %+v, want one per line", seen)
	}
}

// A held cPanel 401 keeps the observation of the line it was read from.
func TestHeldStaleSession401KeepsItsObservation(t *testing.T) {
	d := New(&config.Config{}, nil, nil, "")
	d.staleSession401 = newStaleSession401s()
	o := alert.Observation{Producer: "cpanel_access_log", Stream: "f:801:42:x.0", Cursor: "512", ObservedAt: time.Now()}
	if got := d.cpanelAccessLogObservedHandler(guesserSessionLine, o, &config.Config{}); len(got) != 0 {
		t.Fatalf("session-URL 401 emitted before the hold: %+v", got)
	}
	held := d.staleSession401.due(time.Now().Add(staleSession401Hold + time.Second))
	if len(held) != 1 || held[0].Observation != o {
		t.Fatalf("held findings %+v, want one keeping its observation", held)
	}
}

// The daemon starts the access-log watcher as its evidence producer, both
// at start and when the log appears later.
func TestAccessLogWatchersNameTheirProducer(t *testing.T) {
	oldInterval := logWatcherRetryInterval
	logWatcherRetryInterval = 10 * time.Millisecond
	t.Cleanup(func() { logWatcherRetryInterval = oldInterval })
	for _, late := range []bool{false, true} {
		t.Run(fmt.Sprintf("late=%v", late), func(t *testing.T) {
			root := t.TempDir()
			logPath := filepath.Join(root, "access_log")
			if !late {
				if err := os.WriteFile(logPath, nil, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			panel, server := platform.PanelNone, platform.WSApache
			platform.ResetForTest()
			platform.SetOverrides(platform.Overrides{
				Panel: &panel, WebServer: &server,
				AccessLogPaths: []string{logPath},
				ErrorLogPaths:  []string{filepath.Join(root, "error_log")},
			})
			t.Cleanup(platform.ResetForTest)
			cfg := &config.Config{}
			cfg.MailLogs.Source = "file"
			cfg.MailLogs.File = filepath.Join(root, "mail_log")
			d := New(cfg, nil, nil, "")
			d.startLogWatchers()
			t.Cleanup(func() {
				close(d.stopCh)
				d.wg.Wait()
			})
			if late {
				if err := os.WriteFile(logPath, nil, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			deadline := time.Now().Add(2 * time.Second)
			for {
				d.logWatchersMu.Lock()
				var producer admission.ProducerID
				found := false
				for _, w := range d.logWatchers {
					if w.path == logPath {
						producer, found = w.producer, true
					}
				}
				d.logWatchersMu.Unlock()
				if found {
					if producer != checks.ProducerAccessLog {
						t.Fatalf("access log watcher producer %q, want %q", producer, checks.ProducerAccessLog)
					}
					return
				}
				if time.Now().After(deadline) {
					t.Fatal("access log watcher not started")
				}
				time.Sleep(10 * time.Millisecond)
			}
		})
	}
}
