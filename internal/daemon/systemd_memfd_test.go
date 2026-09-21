package daemon

import (
	"os"
	"strings"
	"testing"
)

// The realtime YARA retry hands the worker a sealed memfd so it scans the
// event's own bytes rather than reopening a path that may have been replaced.
// systemd 239, which the EL8 target ships, carries memfd_create in none of its
// syscall groups, so the unit has to name it the way it already names
// fanotify_init and pidfd_open. Without it the retry fails on the production
// host and an oversize payload goes unscanned.
func TestSystemdUnitsPermitMemfdCreate(t *testing.T) {
	for _, path := range []string{
		"../../cmd/csm/systemd_unit.go",
		"../../build/packaging/systemd/csm.service",
	} {
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if !strings.Contains(string(body), "memfd_create") {
			t.Errorf("%s does not permit memfd_create, so the realtime oversize retry cannot create its snapshot", path)
		}
	}
}
