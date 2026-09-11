package attackdb

import (
	"bytes"
	"encoding/json"
	"io"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

func TestAttackEventQueueBufferInterruptRetainsUnsubmittedCurrent(t *testing.T) {
	for _, exitMode := range []string{"panic", "goexit"} {
		for _, firstSize := range []int{4095, 4096, 4097} {
			name := exitMode + "/" + map[int]string{4095: "partial_current", 4096: "no_current_bytes", 4097: "direct_first_control"}[firstSize]
			t.Run(name, func(t *testing.T) {
				first := alert.Finding{Check: "webshell", SourceIP: "198.51.100.23", Timestamp: time.Date(2026, 9, 10, 0, 0, 0, 0, time.UTC), TenantID: "x"}
				calibration := eventQueueFlatDB(t)
				calibration.RecordFinding(first)
				encoded, err := json.Marshal(calibration.pendingEvents[0])
				if err != nil {
					t.Fatal("calibration encoding failed")
				}
				first.TenantID = strings.Repeat("x", 1+firstSize-len(encoded)-1)
				db := eventQueueFlatDB(t)
				db.RecordFinding(first)
				db.RecordFinding(alert.Finding{Check: "webshell", SourceIP: "203.0.113.24"})
				db.RecordFinding(alert.Finding{Check: "webshell", SourceIP: "203.0.113.25"})
				encoded, err = json.Marshal(db.pendingEvents[0])
				if err != nil || len(encoded)+1 != firstSize {
					t.Fatalf("first event framing wrong: size=%d wanted=%d encodingOK=%v", len(encoded)+1, firstSize, err == nil)
				}
				var submitted bytes.Buffer
				closing, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
				var once sync.Once
				unblock := func() { once.Do(func() { close(release) }) }
				t.Cleanup(func() {
					unblock()
					select {
					case <-done:
					case <-time.After(5 * time.Second):
						t.Error("close did not join")
					}
				})
				writes := 0
				db.openEvents = func(string) (io.WriteCloser, error) {
					return eventQueueFaultFile{
						write: func(data []byte) (int, error) {
							writes++
							_, _ = submitted.Write(data)
							if exitMode == "goexit" {
								runtime.Goexit()
							}
							panic("interrupted first physical write")
						},
						close: func() error { close(closing); <-release; return nil },
					}, nil
				}
				returned, panicked := false, false
				go func() {
					defer close(done)
					defer func() { panicked = recover() != nil }()
					_ = db.Flush()
					returned = true
				}()
				select {
				case <-closing:
				case <-time.After(5 * time.Second):
					t.Fatal("close not entered")
				}
				data := submitted.Bytes()
				if writes != 1 || bytes.Count(data, []byte{'\n'}) != 1 {
					t.Fatalf("unexpected physical submissions: writes=%d complete=%d", writes, bytes.Count(data, []byte{'\n'}))
				}
				var only Event
				if err := json.Unmarshal(data[:bytes.IndexByte(data, '\n')], &only); err != nil || only.IP != "198.51.100.23" {
					t.Fatal("physical write did not contain exactly the first complete event")
				}
				if firstSize == 4096 && len(data) != firstSize {
					t.Fatalf("current event unexpectedly submitted: bytes=%d wanted=%d", len(data), firstSize)
				}
				s := eventQueueStatus(t, db, time.Now())
				if s.Depth != 0 || s.InFlight != 3 || s.DroppedTotal != 2 || s.RecentDrops != 2 || !s.DroppedLowerBound {
					t.Errorf("unsubmitted current event missing during close: %+v; want two confirmed losses", s)
				}
				unblock()
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					t.Fatal("flush not joined")
				}
				if returned || panicked != (exitMode == "panic") {
					t.Fatalf("exit semantics changed: returned=%v panicked=%v", returned, panicked)
				}
				s = eventQueueStatus(t, db, time.Now())
				if s.Depth != 0 || s.InFlight != 0 || s.DroppedTotal != 2 || s.RecentDrops != 2 || !s.DroppedLowerBound {
					t.Errorf("unsubmitted current event missing after close: %+v; want two confirmed losses", s)
				}
			})
		}
	}
}

func TestAttackEventQueueShortWriteBeforeInterrupt(t *testing.T) {
	for _, exitMode := range []string{"panic", "goexit"} {
		t.Run(exitMode, func(t *testing.T) {
			db := eventQueueFlatDB(t)
			first := findingFromIP("198.51.100.23")
			first.TenantID = strings.Repeat("x", 12000)
			db.RecordFinding(first)
			db.RecordFinding(findingFromIP("203.0.113.24"))
			db.RecordFinding(findingFromIP("203.0.113.25"))
			var accepted bytes.Buffer
			writes, closed := 0, false
			db.openEvents = func(string) (io.WriteCloser, error) {
				return eventQueueFaultFile{
					write: func(p []byte) (int, error) {
						writes++
						if writes == 1 {
							return accepted.Write(p[:17])
						}
						_, _ = accepted.Write(p)
						if exitMode == "goexit" {
							runtime.Goexit()
						}
						panic("interrupted resumed write")
					}, close: func() error { closed = true; return nil },
				}, nil
			}
			returned, panicked := false, false
			done := make(chan struct{})
			go func() {
				defer close(done)
				defer func() { panicked = recover() != nil }()
				_ = db.Flush()
				returned = true
			}()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("flush did not release")
			}
			if writes != 2 || !closed || returned || panicked != (exitMode == "panic") {
				t.Fatalf("unexpected lifecycle: writes=%d closed=%v returned=%v panicked=%v", writes, closed, returned, panicked)
			}
			if n := bytes.Count(accepted.Bytes(), []byte{'\n'}); n != 1 {
				t.Fatalf("accepted %d complete events, want 1", n)
			}
			if s := eventQueueStatus(t, db, time.Now()); s.Depth != 0 || s.InFlight != 0 || s.DroppedTotal != 2 || !s.DroppedLowerBound {
				t.Fatalf("reoffered delimiter counted as another submitted event: %+v", s)
			}
		})
	}
}
