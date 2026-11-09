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
	"github.com/pidginhost/csm/internal/maillog"
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

// recordRef is the reference every reader gives a record: the file by device
// and inode, the record by offset and bytes.
func recordRef(t *testing.T, path string, offset int64, text string) alert.Observation {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	id := fileID(info)
	return alert.Observation{Stream: alert.FileStream(id.dev, id.ino), Cursor: alert.RecordCursor(offset, text)}
}

func sameRef(a, b alert.Observation) bool { return a.Stream == b.Stream && a.Cursor == b.Cursor }

// A finding names the log line it came from: the producer, the file as the
// stream, the line's start offset and bytes as the cursor, and the read time.
func TestLogWatcherStampsObservation(t *testing.T) {
	w, path, ch := observingWatcher(t, checks.ProducerEximLog)
	appendLog(t, path, "miss\nhit one\nhit two\r\n")
	before := time.Now()
	w.readNewLines()
	after := time.Now()
	got := drainObservedFindings(ch)
	if len(got) != 2 {
		t.Fatalf("findings %+v, want two", got)
	}
	for i, want := range []alert.Observation{recordRef(t, path, 5, "hit one"), recordRef(t, path, 13, "hit two")} {
		o := got[i].Observation
		if o.Producer != "exim_log" || !sameRef(o, want) || o.ObservedAt.Before(before) || o.ObservedAt.After(after) {
			t.Errorf("finding %d observation %+v, want exim_log %+v read now", i, o, want)
		}
	}
}

// A file that starts over, rewritten in place, truncated or replaced by
// rotation, names its new line anew, so a reused offset never names an
// earlier line.
func TestLogWatcherNamesARestartedFileAnew(t *testing.T) {
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
			if want := recordRef(t, path, 0, second[0].Message); !sameRef(b, want) || sameRef(a, b) {
				t.Fatalf("observations %+v then %+v, want the new line named %+v", a, b, want)
			}
		})
	}
}

// Returning to an earlier inode keeps its stream; a new line written at a
// reused offset is still another record.
func TestLogWatcherRotatingBackNamesNewBytesAnew(t *testing.T) {
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
	if len(first) != 1 || len(last) != 1 || first[0].Observation.Stream != last[0].Observation.Stream ||
		sameRef(first[0].Observation, last[0].Observation) || !sameRef(last[0].Observation, recordRef(t, path, 0, "hit new")) {
		t.Fatalf("rotated observations %+v then %+v reused a record", first, last)
	}
}

// A restarted reader names a record as the earlier one did (design A7), and
// another record at the same offset differently.
func TestLogWatcherRestartKeepsRecordRefs(t *testing.T) {
	w, path, ch := observingWatcher(t, checks.ProducerEximLog)
	a := w.observation(0, "hit one", time.Unix(1, 0))
	w.Stop()
	restarted, err := newObservedLogWatcher(logWatchSpec{path: path, handler: hitHandler, producer: checks.ProducerEximLog}, &config.Config{}, ch)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(restarted.Stop)
	b := restarted.observation(0, "hit one", time.Unix(1, 0))
	other := restarted.observation(0, "hit two", time.Unix(1, 0))
	if a != b || !sameRef(a, recordRef(t, path, 0, "hit one")) || sameRef(a, other) {
		t.Fatalf("restart named %+v as %+v (other line %+v)", a, b, other)
	}
}

func TestLogWatcherReattachmentNamesNewLinesAnew(t *testing.T) {
	w, path, ch := observingWatcher(t, checks.ProducerEximLog)
	appendLog(t, path, "hit old\n")
	w.readNewLines()
	a := drainObservedFindings(ch)
	w.Stop()
	if err := os.Truncate(path, 0); err != nil {
		t.Fatal(err)
	}
	reattached, err := newObservedLogWatcher(logWatchSpec{path: path, handler: hitHandler, producer: checks.ProducerEximLog}, &config.Config{}, ch)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(reattached.Stop)
	appendLog(t, path, "hit new\n")
	reattached.readNewLines()
	b := drainObservedFindings(ch)
	if len(a) != 1 || len(b) != 1 || sameRef(a[0].Observation, b[0].Observation) ||
		!sameRef(a[0].Observation, recordRef(t, path, 0, "hit old")) || !sameRef(b[0].Observation, recordRef(t, path, 0, "hit new")) {
		t.Fatalf("reattachment reused a record: %+v then %+v", a, b)
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
	if len(drainObservedFindings(ch)) != 0 || len(seen) != 2 || !sameRef(seen[0], recordRef(t, path, 0, "first")) ||
		!sameRef(seen[1], recordRef(t, path, 6, "second")) || seen[1].Producer != "cpanel_access_log" {
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

// A mail log line's position becomes the observation of every finding the
// mail handler returns for it.
func TestMailLogDispatchStampsObservation(t *testing.T) {
	d := New(&config.Config{}, nil, nil, "")
	at := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	line := maillog.Line{Message: "dovecot: auth failed", Position: maillog.Position{Stream: "m:2a:x.0", Cursor: "77", ObservedAt: at}}
	handler := func(string, alert.Observation, *config.Config) []alert.Finding {
		return []alert.Finding{{Check: "mail_bruteforce"}}
	}
	if !d.dispatchMailLogLine(line, handler) {
		t.Fatal("mail log dispatch stopped")
	}
	got := <-d.alertCh
	want := alert.Observation{Producer: "mail_log", Stream: "m:2a:x.0", Cursor: "77", ObservedAt: at}
	if got.Observation != want {
		t.Fatalf("observation %+v, want %+v", got.Observation, want)
	}
	if !d.dispatchMailLogLine(maillog.Line{Message: "dovecot: auth failed"}, handler) {
		t.Fatal("mail log dispatch stopped")
	}
	if got := <-d.alertCh; got.Observation != (alert.Observation{}) {
		t.Fatalf("a line without a position stamped %+v", got.Observation)
	}
}

// The ModSecurity error log feeds address evidence, at startup and when it
// appears later, so its watcher names its producer either way.
func TestModSecWatcherNamesItsProducer(t *testing.T) {
	oldInterval := logWatcherRetryInterval
	logWatcherRetryInterval = 10 * time.Millisecond
	t.Cleanup(func() { logWatcherRetryInterval = oldInterval })
	for _, late := range []bool{false, true} {
		t.Run(fmt.Sprintf("late=%v", late), func(t *testing.T) {
			root := t.TempDir()
			errorLog := filepath.Join(root, "error_log")
			if !late {
				if err := os.WriteFile(errorLog, nil, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			panel, server := platform.PanelNone, platform.WSApache
			platform.ResetForTest()
			platform.SetOverrides(platform.Overrides{
				Panel: &panel, WebServer: &server,
				AccessLogPaths: []string{filepath.Join(root, "access_log")},
				ErrorLogPaths:  []string{errorLog},
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
				if err := os.WriteFile(errorLog, nil, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			deadline := time.Now().Add(2 * time.Second)
			for {
				d.logWatchersMu.Lock()
				var producer admission.ProducerID
				found := false
				for _, w := range d.logWatchers {
					if w.path == errorLog {
						producer, found = w.producer, true
					}
				}
				d.logWatchersMu.Unlock()
				if found {
					if producer != checks.ProducerModSecLog {
						t.Fatalf("ModSecurity watcher producer %q, want %q", producer, checks.ProducerModSecLog)
					}
					return
				}
				if time.Now().After(deadline) {
					t.Fatal("ModSecurity watcher not started")
				}
				time.Sleep(10 * time.Millisecond)
			}
		})
	}
}

// An observed log formats an observation for every line, so the stream name
// is built once per file, not per line: a line costs its cursor and the copy
// of its bytes the cursor's hash reads.
func TestLogWatcherObservationReusesTheStream(t *testing.T) {
	w, _, _ := observingWatcher(t, checks.ProducerEximLog)
	first := w.observation(12345, "hit", time.Unix(1, 0))
	if allocs := testing.AllocsPerRun(20, func() { _ = w.observation(12345, "hit", time.Unix(1, 0)) }); allocs > 2 {
		t.Fatalf("observation allocates %v times per line, want at most the cursor and its hashed copy", allocs)
	}
	w.fileID.ino++
	if again := w.observation(12345, "hit", time.Unix(1, 0)); again.Stream == first.Stream {
		t.Fatalf("another file kept stream %q", again.Stream)
	}
}

// startWatcherAt starts an observing watcher at the end of the log at path.
func startWatcherAt(t *testing.T, path string, ch chan alert.Finding) *LogWatcher {
	t.Helper()
	w, err := newObservedLogWatcher(logWatchSpec{path: path, handler: hitHandler, producer: checks.ProducerEximLog}, &config.Config{}, ch)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(w.closeFile)
	return w
}

// A watcher started inside a line reads the rest of that line, but the record
// began before the watcher did: the remainder keeps its legacy finding and
// names no observation. The next line is named as every reader names it.
func TestLogWatcherDoesNotNameAStartupFragment(t *testing.T) {
	newLog := func(t *testing.T, content string) (string, chan alert.Finding) {
		path := filepath.Join(t.TempDir(), "log")
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return path, make(chan alert.Finding, 16)
	}
	unnamedThenNamed := func(t *testing.T, path string, got []alert.Finding, fragment string, next int64) {
		t.Helper()
		if len(got) != 2 || got[0].Message != fragment || got[1].Message != "hit next" {
			t.Fatalf("findings %+v, want %q then %q", got, fragment, "hit next")
		}
		if got[0].Observation != (alert.Observation{}) {
			t.Fatalf("startup fragment %q named %+v", fragment, got[0].Observation)
		}
		if o, want := got[1].Observation, recordRef(t, path, next, "hit next"); o.Producer != "exim_log" || !sameRef(o, want) {
			t.Fatalf("next line named %+v, want %+v", o, want)
		}
	}
	firstNamed := func(t *testing.T, path string, got []alert.Finding, offset int64) {
		t.Helper()
		if len(got) != 1 || got[0].Message != "hit fresh" {
			t.Fatalf("findings %+v, want one fresh line", got)
		}
		if o, want := got[0].Observation, recordRef(t, path, offset, "hit fresh"); o.Producer != "exim_log" || !sameRef(o, want) {
			t.Fatalf("first complete record named %+v, want %+v", o, want)
		}
	}
	t.Run("one poll", func(t *testing.T) {
		path, ch := newLog(t, "before ")
		w := startWatcherAt(t, path, ch)
		appendLog(t, path, "hit suffix\nhit next\n")
		w.readNewLines()
		unnamedThenNamed(t, path, drainObservedFindings(ch), "hit suffix", 18)
	})
	t.Run("split polls", func(t *testing.T) {
		path, ch := newLog(t, "before ")
		w := startWatcherAt(t, path, ch)
		appendLog(t, path, "hit suf")
		w.readNewLines()
		appendLog(t, path, "fix\nhit next\n")
		w.readNewLines()
		unnamedThenNamed(t, path, drainObservedFindings(ch), "hit suffix", 18)
	})
	t.Run("new reader", func(t *testing.T) {
		path, ch := newLog(t, "before ")
		w := startWatcherAt(t, path, ch)
		appendLog(t, path, "hit suf")
		w.readNewLines()
		w.Stop()
		restarted := startWatcherAt(t, path, ch)
		appendLog(t, path, "hit\nhit next\n")
		restarted.readNewLines()
		unnamedThenNamed(t, path, drainObservedFindings(ch), "hit", 18)
	})
	t.Run("empty", func(t *testing.T) {
		path, ch := newLog(t, "")
		w := startWatcherAt(t, path, ch)
		appendLog(t, path, "hit fresh\n")
		w.readNewLines()
		firstNamed(t, path, drainObservedFindings(ch), 0)
	})
	t.Run("terminated", func(t *testing.T) {
		path, ch := newLog(t, "before\n")
		w := startWatcherAt(t, path, ch)
		appendLog(t, path, "hit fresh\n")
		w.readNewLines()
		firstNamed(t, path, drainObservedFindings(ch), 7)
	})
	t.Run("copytruncate", func(t *testing.T) {
		path, ch := newLog(t, "before before ")
		w := startWatcherAt(t, path, ch)
		appendLog(t, path, "hit suf")
		w.readNewLines()
		if err := os.WriteFile(path, []byte("hit fresh\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		// A shrunk file is reopened on one tick and read on the next.
		w.readNewLines()
		w.readNewLines()
		firstNamed(t, path, drainObservedFindings(ch), 0)
	})
	t.Run("regrown", func(t *testing.T) {
		path, ch := newLog(t, "before before ")
		w := startWatcherAt(t, path, ch)
		if err := os.WriteFile(path, []byte("hit fresh\nhit next in a longer file\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		w.readNewLines()
		got := drainObservedFindings(ch)
		if len(got) != 2 {
			t.Fatalf("findings %+v, want both lines of the regrown file", got)
		}
		firstNamed(t, path, got[:1], 0)
	})
	t.Run("rotation", func(t *testing.T) {
		path, ch := newLog(t, "before ")
		w := startWatcherAt(t, path, ch)
		appendLog(t, path, "hit suf")
		w.readNewLines()
		if err := os.Rename(path, path+".1"); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("hit fresh\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		w.reopen()
		w.readNewLines()
		firstNamed(t, path, drainObservedFindings(ch), 0)
	})
}

// The watcher names a raw record as the shared helper does: one LF, CRLF or
// repeated CR before LF ends it, and leading and trailing spaces are content.
// Unchanged bytes keep their ref when a restarted watcher reads them again.
func TestLogWatcherLineEndingsMatchTheSharedRef(t *testing.T) {
	raw := []string{"hit x\n", "hit x\r\n", "hit x\r\r\n", " hit x \n", "hit x  \r\n", "hit y\n"}
	every := func(line string, _ *config.Config) []alert.Finding {
		return []alert.Finding{{Check: "fixture", Message: line}}
	}
	w, path, ch := observingWatcher(t, checks.ProducerEximLog)
	w.handler = every
	appendLog(t, path, strings.Join(raw, ""))
	w.readNewLines()
	first := drainObservedFindings(ch)
	restarted := startWatcherAt(t, path, ch)
	restarted.handler = every
	restarted.offset, restarted.marker = 0, nil
	restarted.readNewLines()
	again := drainObservedFindings(ch)
	if len(first) != len(raw) || len(again) != len(raw) {
		t.Fatalf("findings %d then %d, want %d each", len(first), len(again), len(raw))
	}
	seen := map[string]int{}
	var offset int64
	for i, record := range raw {
		want := recordRef(t, path, offset, record)
		if o := first[i].Observation; !sameRef(o, want) {
			t.Errorf("record %d %q named %+v, want %+v", i, record, o, want)
		}
		if !sameRef(again[i].Observation, first[i].Observation) {
			t.Errorf("record %d %q named %+v after restart, first %+v", i, record, again[i].Observation, first[i].Observation)
		}
		if j, dup := seen[first[i].Observation.Cursor]; dup {
			t.Errorf("records %d and %d share cursor %q", j, i, first[i].Observation.Cursor)
		}
		seen[first[i].Observation.Cursor] = i
		offset += int64(len(record))
	}
}
