package daemon

import (
	"strings"
	"testing"
	"time"
)

// Every other content check honours suppressions.ignore_paths. The dropper
// engine did not, so an operator who excluded a directory still received
// findings from it and had no way to stop them short of disabling the check
// outright -- losing genuine droppers with the noise.
//
// WordPress security plugins rotate their own data files under wp-content,
// which is create-then-unlink by design and indistinguishable from a dropper
// without the path context the operator already supplied.
func TestDropperEngineHonoursIgnorePaths(t *testing.T) {
	ttl := 50 * time.Millisecond
	e, _ := newTestEngine(ttl)
	e.ignorePath = func(p string) bool { return strings.Contains(p, "/wp-content/wflogs/") }

	now := time.Now()

	ignored := "/home/alice/public_html/wp-content/wflogs/config-synced.php"
	if e.admit(newDropperCandidate(now, ignored)) {
		t.Errorf("candidate under an ignored path was admitted: %s", ignored)
	}

	tracked := "/home/alice/public_html/wp-content/uploads/shell.php"
	if !e.admit(newDropperCandidate(now, tracked)) {
		t.Errorf("candidate outside the ignored path was rejected: %s", tracked)
	}
}

// With no matcher configured the engine must behave exactly as before.
func TestDropperEngineWithoutIgnoreMatcherAdmitsEverything(t *testing.T) {
	e, _ := newTestEngine(50 * time.Millisecond)
	now := time.Now()

	if !e.admit(newDropperCandidate(now, "/home/alice/public_html/wp-content/wflogs/config-synced.php")) {
		t.Error("engine with no ignore matcher rejected a candidate")
	}
}

func newDropperCandidate(now time.Time, path string) dropperCandidate {
	return dropperCandidate{
		Path:       path,
		Docroot:    "/home/alice/public_html",
		Observed:   now,
		Birth:      now,
		BirthKnown: true,
		Created:    true,
		Device:     41,
		Inode:      uint64(len(path)),
		Mode:       0o100644,
		Size:       1621,
		PID:        4242,
		UID:        1001,
		Head:       []byte("<?php system($_POST['c']);"),
	}
}
