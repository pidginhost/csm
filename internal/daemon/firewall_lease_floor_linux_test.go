//go:build linux

package daemon

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
)

func TestFirewallStartupValidatesClockBeforeUsingFloor(t *testing.T) {
	at := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	reading := admission.ClockReading{Wall: at, BootID: "0f5e3c2a-1b4d-4e6f-8a9b-0c1d2e3f4a5b", SinceBoot: time.Hour}
	clock, _, err := (admission.Clock{}).Advance(reading)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"missing", "boot", "elapsed", "wall", "backward", "forward"} {
		r, saved := reading, clock
		want := time.Time{}
		switch mode {
		case "missing":
			saved = admission.Clock{}
		case "boot":
			r.BootID = "invalid"
		case "elapsed":
			r.SinceBoot = -time.Second
		case "wall":
			r.Wall = time.Time{}
		case "backward":
			r.Wall = at.Add(-time.Hour)
			r.SinceBoot += time.Minute
			want = at.Add(time.Minute)
		case "forward":
			r.Wall = at.Add(time.Hour)
			r.SinceBoot += time.Minute
			want = at.Add(time.Minute)
		}
		floor, err := provenFirewallLease(saved, r)
		if err == nil || !floor.Equal(want) {
			t.Fatalf("%s: floor %v, error %v; want %v with warning", mode, floor, err, want)
		}
	}
}
