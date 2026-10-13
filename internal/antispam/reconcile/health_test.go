package reconcile

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

const (
	scanOKLine    = `2026-10-13 09:00:00 1xF5ol-00000000SdK-2TMA CSM-ANTISPAM event=scan mode=enforce policy=on result=ok score=0 action="no action" decision=none`
	scanErrorLine = `2026-10-13 09:00:00 1xF5ol-00000000SdK-2TMA CSM-ANTISPAM event=scan mode=enforce policy=on result=error score=none action="unavailable" decision=none`
	// forgedLine is a sender's HELO carrying marker text.
	forgedLine = `2026-10-13 09:00:00 H=(CSM-ANTISPAM event=scan mode=enforce policy=on result=error score=none action="unavailable" decision=none) [192.0.2.1] rejected`
)

var errRefused = errors.New("connection refused")

func enabledHealth() *Health {
	h := &Health{}
	h.SetEnabled(true, "/run/rspamd/csm-normal.sock")
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
	var got []string
	for i, err := range []error{errRefused, errRefused, nil, errRefused, errRefused, errRefused, errRefused, errRefused} {
		got = append(got, checksOf(h.Ping(err, at(i)))...)
	}
	if strings.Join(got, ",") != CheckRspamdDown {
		t.Fatalf("findings %q, want one down after three consecutive failures", got)
	}
	if active := checksOf(h.Active()); strings.Join(active, ",") != CheckRspamdDown {
		t.Fatalf("active %q", active)
	}
}

func TestHealthRecoversAfterTwoSuccesses(t *testing.T) {
	h := enabledHealth()
	for i := range 3 {
		h.Ping(errRefused, at(i))
	}
	var got []string
	for i, err := range []error{nil, errRefused, nil, nil, nil} {
		got = append(got, checksOf(h.Ping(err, at(10+i)))...)
	}
	if strings.Join(got, ",") != CheckRspamdRecovered || len(h.Active()) != 0 {
		t.Fatalf("findings %q, active %+v", got, h.Active())
	}
	// Successes without an outage report nothing.
	if got := h.Ping(nil, at(20)); len(got) != 0 {
		t.Fatalf("recovery without an outage: %+v", got)
	}
}

// One finding identity covers every failed scan; a later success clears it
// and a ping never does (spec section 7).
func TestHealthTracksScanErrors(t *testing.T) {
	h := enabledHealth()
	if got := checksOf(h.Line(scanErrorLine, at(0))); strings.Join(got, ",") != CheckScanError {
		t.Fatalf("first error: %q", got)
	}
	if got := h.Line(scanErrorLine, at(5)); len(got) != 0 {
		t.Fatalf("second error reported again: %+v", got)
	}
	h.Ping(nil, at(6))
	h.Ping(nil, at(7))
	active := h.Active()
	if len(active) != 1 || active[0].Check != CheckScanError || !strings.Contains(active[0].Details, "logged 2 failed scans") ||
		active[0].DedupKey == "" || !active[0].Timestamp.Equal(at(5)) {
		t.Fatalf("active %+v", active)
	}
	h.Line(scanOKLine, at(8))
	if len(h.Active()) != 0 {
		t.Fatalf("success left %+v", h.Active())
	}
}

func TestHealthIgnoresForgedMarkers(t *testing.T) {
	h := enabledHealth()
	if got := h.Line(forgedLine, at(0)); len(got) != 0 || len(h.Active()) != 0 {
		t.Fatalf("forged marker counted: %+v", got)
	}
}

// Disabling forgets every count and active finding without a recovery
// notice, and markers after it are ignored (spec section 7).
func TestHealthDisableResets(t *testing.T) {
	h := enabledHealth()
	for i := range 3 {
		h.Ping(errRefused, at(i))
	}
	h.Line(scanErrorLine, at(4))
	h.SetEnabled(false, "")
	if len(h.Active()) != 0 {
		t.Fatalf("active after disable: %+v", h.Active())
	}
	if got := append(h.Line(scanErrorLine, at(5)), h.Ping(errRefused, at(6))...); len(got) != 0 {
		t.Fatalf("disabled tracking reported %+v", got)
	}
	h.SetEnabled(true, "/run/rspamd/csm-normal.sock")
	if got := append(h.Ping(nil, at(7)), h.Ping(nil, at(8))...); len(got) != 0 || len(h.Active()) != 0 {
		t.Fatalf("recovery reported after a reset: %+v", got)
	}
}

// A new socket is a new probe target: the old outage is forgotten.
func TestHealthForgetsOutageOnSocketChange(t *testing.T) {
	h := enabledHealth()
	for i := range 3 {
		h.Ping(errRefused, at(i))
	}
	h.SetEnabled(true, "/run/rspamd/other.sock")
	if len(h.Active()) != 0 {
		t.Fatalf("outage of the old socket still active: %+v", h.Active())
	}
	h.SetEnabled(true, "/run/rspamd/other.sock")
	for i := range 2 {
		h.Ping(errRefused, at(10+i))
	}
	if got := h.Ping(errRefused, at(12)); strings.Join(checksOf(got), ",") != CheckRspamdDown {
		t.Fatalf("new outage: %+v", got)
	}
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
					h.Ping(errRefused, at(i))
				case 1:
					h.Line(scanErrorLine, at(i))
				case 2:
					h.Active()
				default:
					h.SetEnabled(i%2 == 0, "/run/rspamd/csm-normal.sock")
				}
			}
		}()
	}
	wg.Wait()
}

// Every Exim main-log line reaches Line; lines without a marker must cost
// no allocation.
func TestHealthLineIgnoresOrdinaryLinesCheaply(t *testing.T) {
	h := enabledHealth()
	line := "2026-10-13 09:00:00 1xF5ol-00000000SdK-2TMA <= sender@example.test H=(mail.example.test) [192.0.2.1] P=esmtp S=1234"
	if n := testing.AllocsPerRun(100, func() { h.Line(line, testNow) }); n != 0 {
		t.Fatalf("%v allocations per ordinary line", n)
	}
}
