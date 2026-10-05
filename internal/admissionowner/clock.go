// Package admissionowner is the daemon's owner of the admission ledger
// (spec 5.4): the one handle on the state database's ledger, and the one
// goroutine that changes it.
package admissionowner

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/admission"
)

// bootIDPath names the kernel's identity of the current boot.
const bootIDPath = "/proc/sys/kernel/random/boot_id"

// readClock samples wall time, the boot identity at path and the time since
// that boot. The ledger validates the identity.
func readClock(path string, wall func() time.Time, sinceBoot func() (time.Duration, error)) (admission.ClockReading, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- a fixed procfs path; tests pass a temporary file.
	if err != nil {
		return admission.ClockReading{}, fmt.Errorf("reading the boot identity: %w", err)
	}
	since, err := sinceBoot()
	if err != nil {
		return admission.ClockReading{}, fmt.Errorf("reading the time since boot: %w", err)
	}
	return admission.ClockReading{Wall: wall(), BootID: strings.TrimSpace(string(data)), SinceBoot: since}, nil
}
