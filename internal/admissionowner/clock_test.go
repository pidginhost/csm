package admissionowner

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
)

// Spec 5.4: a reading carries wall time, the boot's identity and the time
// since that boot, which a same-boot restart keeps counting.
func TestReadClockNamesTheBoot(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "boot_id")
	const boot = "0f5e3c2a-1b4d-4e6f-8a9b-0c1d2e3f4a5b"
	if err := os.WriteFile(path, []byte(boot+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	wall := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	r, err := readClock(path, func() time.Time { return wall }, func() (time.Duration, error) { return 90 * time.Minute, nil })
	if err != nil {
		t.Fatal(err)
	}
	if r != (admission.ClockReading{Wall: wall, BootID: boot, SinceBoot: 90 * time.Minute}) {
		t.Fatalf("reading = %+v", r)
	}
	if _, err = readClock(filepath.Join(dir, "missing"), func() time.Time { return wall }, func() (time.Duration, error) { return time.Minute, nil }); err == nil {
		t.Fatal("a reading without a boot identity was accepted")
	}
	if _, err = readClock(path, func() time.Time { return wall }, func() (time.Duration, error) { return 0, os.ErrPermission }); err == nil {
		t.Fatal("a reading without time since boot was accepted")
	}
}
