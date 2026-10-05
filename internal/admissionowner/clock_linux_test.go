//go:build linux

package admissionowner

import (
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
)

// The host's own reading is one the ledger accepts, its time since boot is
// the kernel's uptime, and it moves forward between two readings.
func TestHostClockIsAdmissible(t *testing.T) {
	first, err := ReadClock()
	if err != nil {
		t.Fatal(err)
	}
	second, err := ReadClock()
	if err != nil {
		t.Fatal(err)
	}
	if second.BootID != first.BootID || second.SinceBoot < first.SinceBoot || first.SinceBoot <= 0 {
		t.Fatalf("readings %+v then %+v", first, second)
	}
	raw, err := os.ReadFile("/proc/uptime")
	if err != nil {
		t.Fatal(err)
	}
	seconds, err := strconv.ParseFloat(strings.Fields(string(raw))[0], 64)
	if err != nil {
		t.Fatal(err)
	}
	if uptime := time.Duration(seconds * float64(time.Second)); second.SinceBoot < uptime-2*time.Second || second.SinceBoot > uptime+2*time.Second {
		t.Fatalf("time since boot %v, uptime %v", second.SinceBoot, uptime)
	}
	var c admission.Clock
	if _, _, err = c.Advance(first); err != nil {
		t.Fatalf("the ledger refuses the host's reading: %v", err)
	}
}
