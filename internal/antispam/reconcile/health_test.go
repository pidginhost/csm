package reconcile

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

const (
	scanOKLine    = `2026-10-13 09:00:00 1xF5ol-00000000SdK-2TMA CSM-ANTISPAM event=scan mode=enforce policy=on result=ok score=0 action="no action" decision=none`
	scanErrorLine = `2026-10-13 09:00:00 1xF5ol-00000000SdK-2TMA CSM-ANTISPAM event=scan mode=enforce policy=on result=error score=none action="unavailable" decision=none`
	// forgedLine is a sender's HELO carrying marker text.
	forgedLine = `2026-10-13 09:00:00 H=(mail.example.test CSM-ANTISPAM event=scan mode=enforce policy=on result=error score=none action="unavailable" decision=none) [192.0.2.1] rejected`
)

var errRefused = errors.New("connection refused")

const (
	testSocket  = "/run/rspamd/csm-normal.sock"
	otherSocket = "/run/rspamd/other.sock"
)

func enabledHealth() *Health {
	h := &Health{}
	h.SetEnabled(true, testSocket)
	return h
}

func checksOf(fs []alert.Finding) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.Check)
	}
	return out
}

func at(sec int) time.Time { return testNow.Add(time.Duration(sec) * time.Second) }

func TestHealthRaisesDownOncePerOutage(t *testing.T) {
	h := enabledHealth()
	for i, err := range []error{errRefused, errRefused, nil, errRefused, errRefused, errRefused, errRefused, errRefused} {
		got := h.Ping(testSocket, err, at(i))
		if i == 5 {
			assertHealthFinding(t, got, CheckRspamdDown, "rspamd", at(5))
		} else if len(got) != 0 {
			t.Fatalf("probe %d: unexpected transition %+v", i, got)
		}
		if i < 5 {
			if active := h.Active(); len(active) != 0 {
				t.Fatalf("probe %d: premature outage %+v", i, active)
			}
		} else {
			assertHealthFinding(t, h.Active(), CheckRspamdDown, "rspamd", at(5))
		}
	}
}

func TestHealthRecoversAfterTwoSuccesses(t *testing.T) {
	h := enabledHealth()
	for i := range 3 {
		h.Ping(testSocket, errRefused, at(i))
	}
	for i, err := range []error{nil, errRefused, nil, nil, nil} {
		got := h.Ping(testSocket, err, at(10+i))
		if i == 3 {
			assertHealthFinding(t, got, CheckRspamdRecovered, "", at(13))
		} else if len(got) != 0 {
			t.Fatalf("probe %d: unexpected transition %+v", i, got)
		}
		if i < 3 {
			assertHealthFinding(t, h.Active(), CheckRspamdDown, "rspamd", at(2))
		} else if active := h.Active(); len(active) != 0 {
			t.Fatalf("probe %d: outage remained after recovery: %+v", i, active)
		}
	}
	// Successes without an outage report nothing.
	if got := h.Ping(testSocket, nil, at(20)); len(got) != 0 {
		t.Fatalf("recovery without an outage: %+v", got)
	}
	for i := range 2 {
		if got := h.Ping(testSocket, errRefused, at(30+i)); len(got) != 0 {
			t.Fatalf("new outage raised early: %+v", got)
		}
	}
	assertHealthFinding(t, h.Ping(testSocket, errRefused, at(32)), CheckRspamdDown, "rspamd", at(32))
	assertHealthFinding(t, h.Active(), CheckRspamdDown, "rspamd", at(32))
	if got := h.Ping(testSocket, nil, at(33)); len(got) != 0 {
		t.Fatalf("new outage recovered early: %+v", got)
	}
	assertHealthFinding(t, h.Ping(testSocket, nil, at(34)), CheckRspamdRecovered, "", at(34))
	if active := h.Active(); len(active) != 0 {
		t.Fatalf("new outage remained after recovery: %+v", active)
	}
}

func assertHealthFinding(t *testing.T, got []alert.Finding, check, key string, when time.Time) {
	t.Helper()
	if len(got) != 1 || got[0].Check != check || got[0].Severity != alert.Warning ||
		got[0].DedupKey != key || !got[0].Timestamp.Equal(when) {
		t.Fatalf("findings %+v, want one Warning %s with key %q at %s", got, check, key, when)
	}
}

func assertScanErrors(t *testing.T, got []alert.Finding, count int, first, last time.Time) {
	t.Helper()
	assertHealthFinding(t, got, CheckScanError, "scan", last)
	scans := "scans"
	if count == 1 {
		scans = "scan"
	}
	want := fmt.Sprintf("Exim logged %d failed %s since %s, the last at %s.",
		count, scans, first.UTC().Format(time.RFC3339), last.UTC().Format(time.RFC3339))
	if !strings.HasPrefix(got[0].Details, want) {
		t.Fatalf("scan error details %q, want prefix %q", got[0].Details, want)
	}
}

// One finding identity covers every failed scan; a later success clears it
// and a ping never does (spec section 7).
func TestHealthTracksScanErrors(t *testing.T) {
	h := enabledHealth()
	first, recovered := h.Line(scanErrorLine, at(0))
	if recovered {
		t.Fatal("failed scan reported recovery")
	}
	assertScanErrors(t, first, 1, at(0), at(0))
	for i := range 3 {
		h.Ping(testSocket, errRefused, at(i+1))
	}
	if got, _ := h.Line(scanErrorLine, at(5)); len(got) != 0 {
		t.Fatalf("second error reported again: %+v", got)
	}
	if got := h.Ping(testSocket, nil, at(6)); len(got) != 0 {
		t.Fatalf("outage recovered early: %+v", got)
	}
	assertHealthFinding(t, h.Ping(testSocket, nil, at(7)), CheckRspamdRecovered, "", at(7))
	assertScanErrors(t, h.Active(), 2, at(0), at(5))
	if got, recovered := h.Line(scanOKLine, at(8)); len(got) != 0 || !recovered {
		t.Fatalf("scan success: notices %+v, recovered %t", got, recovered)
	}
	if len(h.Active()) != 0 {
		t.Fatalf("success left %+v", h.Active())
	}
	if got, recovered := h.Line(scanOKLine, at(8)); len(got) != 0 || recovered {
		t.Fatalf("unchanged healthy state: notices %+v, recovered %t", got, recovered)
	}
	next, _ := h.Line(scanErrorLine, at(9))
	assertScanErrors(t, next, 1, at(9), at(9))
	assertScanErrors(t, h.Active(), 1, at(9), at(9))
}

func TestHealthIgnoresForgedMarkers(t *testing.T) {
	h := enabledHealth()
	if got, _ := h.Line(forgedLine, at(0)); len(got) != 0 || len(h.Active()) != 0 {
		t.Fatalf("forged marker counted: %+v", got)
	}
	h.Line(scanErrorLine, at(1))
	for _, line := range []string{forgedLine, strings.Replace(forgedLine, "result=error score=none", "result=ok score=0", 1), scanOKLine + " extra"} {
		if got, _ := h.Line(line, at(2)); len(got) != 0 {
			t.Fatalf("invalid marker reported: %+v", got)
		}
		assertScanErrors(t, h.Active(), 1, at(1), at(1))
	}
}

// Disabling forgets every count and active finding without a recovery
// notice, and markers after it are ignored (spec section 7).
func TestHealthDisableResets(t *testing.T) {
	h := enabledHealth()
	for i := range 3 {
		h.Ping(testSocket, errRefused, at(i))
	}
	h.Line(scanErrorLine, at(4))
	h.SetEnabled(false, "")
	if len(h.Active()) != 0 {
		t.Fatalf("active after disable: %+v", h.Active())
	}
	scanFindings, _ := h.Line(scanErrorLine, at(5))
	scanFindings = append(scanFindings, h.Ping(testSocket, errRefused, at(6))...)
	if len(scanFindings) != 0 {
		t.Fatalf("disabled tracking reported %+v", scanFindings)
	}
	h.SetEnabled(true, testSocket)
	if got := append(h.Ping(testSocket, nil, at(7)), h.Ping(testSocket, nil, at(8))...); len(got) != 0 || len(h.Active()) != 0 {
		t.Fatalf("recovery reported after a reset: %+v", got)
	}
	next, _ := h.Line(scanErrorLine, at(9))
	assertScanErrors(t, next, 1, at(9), at(9))
	if got, _ := h.Line(scanErrorLine, at(10)); len(got) != 0 {
		t.Fatalf("second error reported again after re-enable: %+v", got)
	}
	assertScanErrors(t, h.Active(), 2, at(9), at(10))
}

// A new socket is a new probe target: the old outage is forgotten.
func TestHealthForgetsOutageOnSocketChange(t *testing.T) {
	h := enabledHealth()
	for i := range 3 {
		h.Ping(testSocket, errRefused, at(i))
	}
	h.SetEnabled(true, otherSocket)
	if len(h.Active()) != 0 {
		t.Fatalf("outage of the old socket still active: %+v", h.Active())
	}
	h.SetEnabled(true, otherSocket)
	for i := range 2 {
		h.Ping(otherSocket, errRefused, at(10+i))
	}
	if got := h.Ping(otherSocket, errRefused, at(12)); strings.Join(checksOf(got), ",") != CheckRspamdDown {
		t.Fatalf("new outage: %+v", got)
	}
}

func TestHealthSocketChangePreservesScanErrors(t *testing.T) {
	h := enabledHealth()
	h.Line(scanErrorLine, at(0))
	for i := range 2 {
		h.Ping(testSocket, errRefused, at(i+1))
	}
	h.SetEnabled(true, otherSocket)
	assertScanErrors(t, h.Active(), 1, at(0), at(0))
	for i := range 2 {
		if got := h.Ping(otherSocket, errRefused, at(i+3)); len(got) != 0 {
			t.Fatalf("old socket's failures reached the new target: %+v", got)
		}
	}
	got := h.Ping(otherSocket, errRefused, at(5))
	assertHealthFinding(t, got, CheckRspamdDown, "rspamd", at(5))
	if !strings.Contains(got[0].Details, "/run/rspamd/other.sock") || strings.Contains(got[0].Details, "/run/rspamd/csm-normal.sock") {
		t.Fatalf("outage names the wrong socket: %+v", got)
	}
	if got, _ := h.Line(scanOKLine, at(6)); len(got) != 0 {
		t.Fatalf("scan success returned a transition: %+v", got)
	}
	assertHealthFinding(t, h.Active(), CheckRspamdDown, "rspamd", at(5))
}

func TestHealthConcurrentErrorsKeepOneIdentity(t *testing.T) {
	h := enabledHealth()
	const workers, scans = 4, 50
	var downNotices, scanNotices atomic.Int64
	var wg sync.WaitGroup
	for range workers {
		wg.Go(func() {
			for range scans {
				h.SetEnabled(true, testSocket)
				downNotices.Add(int64(len(h.Ping(testSocket, errRefused, at(0)))))
				findings, _ := h.Line(scanErrorLine, at(0))
				scanNotices.Add(int64(len(findings)))
				h.Active()
			}
		})
	}
	wg.Wait()
	if downNotices.Load() != 1 || scanNotices.Load() != 1 {
		t.Fatalf("got %d down notices and %d scan notices, want one each", downNotices.Load(), scanNotices.Load())
	}
	active := h.Active()
	if len(active) != 2 {
		t.Fatalf("active %+v, want both conditions", active)
	}
	assertHealthFinding(t, active[:1], CheckRspamdDown, "rspamd", at(0))
	assertScanErrors(t, active[1:], workers*scans, at(0), at(0))
}

// The probe loop, the Exim log watcher and config reloads use Health at
// the same time; run with -race.
func TestHealthConcurrentUse(t *testing.T) {
	h := enabledHealth()
	var wg sync.WaitGroup
	for g := range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 200 {
				switch (g + i) % 4 {
				case 0:
					h.Ping(testSocket, errRefused, at(i))
				case 1:
					h.Line(scanErrorLine, at(i))
				case 2:
					h.Active()
				default:
					h.SetEnabled(i%2 == 0, testSocket)
				}
			}
		}()
	}
	wg.Wait()
	h.SetEnabled(false, "")
	if active := h.Active(); len(active) != 0 {
		t.Fatalf("active after disabling concurrent tracking: %+v", active)
	}
	h.SetEnabled(true, testSocket)
	next, _ := h.Line(scanErrorLine, at(300))
	assertScanErrors(t, next, 1, at(300), at(300))
	assertScanErrors(t, h.Active(), 1, at(300), at(300))
}

// Every Exim main-log line reaches Line; lines without a marker must cost
// no allocation.
func TestHealthLineIgnoresOrdinaryLinesCheaply(t *testing.T) {
	h := enabledHealth()
	line := "2026-10-13 09:00:00 1xF5ol-00000000SdK-2TMA <= sender@example.test H=(mail.example.test) [192.0.2.1] P=esmtp S=1234"
	if n := testing.AllocsPerRun(100, func() {
		if got, _ := h.Line(line, testNow); len(got) != 0 {
			t.Fatalf("ordinary line reported: %+v", got)
		}
	}); n != 0 {
		t.Fatalf("%v allocations per ordinary line", n)
	}
	if active := h.Active(); len(active) != 0 {
		t.Fatalf("ordinary line changed health: %+v", active)
	}
}

// A probe of the previous socket can finish after a reload switched
// sockets; its result says nothing about the socket now tracked.
func TestHealthIgnoresPingsOfAnotherSocket(t *testing.T) {
	h := enabledHealth()
	for i := range 3 {
		if got := h.Ping(otherSocket, errRefused, at(i)); len(got) != 0 {
			t.Fatalf("probe of another socket reported %+v", got)
		}
	}
	for i := range 2 {
		h.Ping(testSocket, errRefused, at(10+i))
	}
	assertHealthFinding(t, h.Ping(testSocket, errRefused, at(12)), CheckRspamdDown, "rspamd", at(12))
	for i := range 2 {
		if got := h.Ping(otherSocket, nil, at(20+i)); len(got) != 0 {
			t.Fatalf("probe of another socket recovered %+v", got)
		}
	}
	assertHealthFinding(t, h.Active(), CheckRspamdDown, "rspamd", at(12))
}

// A late result from the old socket must not interrupt either consecutive
// probe streak on the new socket.
func TestHealthStalePingsPreserveCurrentStreaks(t *testing.T) {
	h := enabledHealth()
	h.SetEnabled(true, otherSocket)
	for i := range pingDown - 1 {
		if got := h.Ping(otherSocket, errRefused, at(i)); len(got) != 0 {
			t.Fatalf("new socket reported down early: %+v", got)
		}
	}
	if got := h.Ping(testSocket, nil, at(10)); len(got) != 0 {
		t.Fatalf("stale success reported %+v", got)
	}
	assertHealthFinding(t, h.Ping(otherSocket, errRefused, at(11)), CheckRspamdDown, "rspamd", at(11))
	for i := range pingUp - 1 {
		if got := h.Ping(otherSocket, nil, at(20+i)); len(got) != 0 {
			t.Fatalf("new socket recovered early: %+v", got)
		}
	}
	if got := h.Ping(testSocket, errRefused, at(30)); len(got) != 0 {
		t.Fatalf("stale failure reported %+v", got)
	}
	assertHealthFinding(t, h.Ping(otherSocket, nil, at(31)), CheckRspamdRecovered, "", at(31))
	if active := h.Active(); len(active) != 0 {
		t.Fatalf("recovery left active findings: %+v", active)
	}
}

// Alert text counts in words a reader expects: one failed scan, and the
// probe counts the tracker uses.
func TestHealthFindingText(t *testing.T) {
	h := enabledHealth()
	got, _ := h.Line(scanErrorLine, at(0))
	if len(got) != 1 || !strings.HasPrefix(got[0].Details, "Exim logged 1 failed scan since ") {
		t.Fatalf("first scan error: %+v", got)
	}
	for i := range pingDown {
		got = h.Ping(testSocket, errRefused, at(i))
	}
	if len(got) != 1 || !strings.HasPrefix(got[0].Details, fmt.Sprintf("%d /ping probes in a row over %s failed.", pingDown, testSocket)) {
		t.Fatalf("down finding: %+v", got)
	}
	for i := range pingUp {
		got = h.Ping(testSocket, nil, at(10+i))
	}
	if len(got) != 1 || got[0].Details != fmt.Sprintf("%d /ping probes in a row over %s succeeded.", pingUp, testSocket) {
		t.Fatalf("recovery finding: %+v", got)
	}
}
