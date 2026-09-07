package daemon

import (
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
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

func TestDropperSuppressionsApplyToPendingFindings(t *testing.T) {
	for _, suppressAfterProbe := range []bool{false, true} {
		t.Run(map[bool]string{false: "tracked", true: "held"}[suppressAfterProbe], func(t *testing.T) {
			e, got := newTestEngine(time.Minute)
			ignored := false
			e.ignorePath = func(string) bool { return ignored }
			now := time.Now()
			if !e.admit(newDropperCandidate(now, "/home/alice/public_html/test.php")) {
				t.Fatal("initial admission failed")
			}
			future := now.Add(2 * time.Minute)
			if suppressAfterProbe {
				e.probeStep(future, &fakeProber{}, future)
			}
			ignored = true
			e.probeStep(future, &fakeProber{}, future)
			e.probeStep(future.Add(dropperGraceWindow+time.Second), &fakeProber{}, future.Add(dropperGraceWindow+time.Second))
			if len(*got) != 0 {
				t.Fatalf("suppressed pending candidate emitted %d findings", len(*got))
			}
		})
	}
}

func TestDropperPendingBurstFiltersIndividualSuppressedPaths(t *testing.T) {
	e, got := newTestEngine(time.Minute)
	now := time.Now()
	for i := range dropperBurstThreshold {
		path := "/home/alice/public_html/ignored/" + strings.Repeat("x", i+1) + ".php"
		if i == 0 {
			path = "/home/alice/public_html/shell.php"
		}
		if !e.admit(newDropperCandidate(now, path)) {
			t.Fatal("initial admission failed")
		}
	}
	future := now.Add(2 * time.Minute)
	e.probeStep(future, &fakeProber{}, future)
	e.ignorePath = func(path string) bool { return strings.Contains(path, "/ignored/") }
	e.probeStep(future.Add(dropperGraceWindow+time.Second), &fakeProber{}, future.Add(dropperGraceWindow+time.Second))
	if len(*got) != 1 || (*got)[0].path != "/home/alice/public_html/shell.php" || (*got)[0].sev != alert.Critical {
		t.Fatalf("pending burst did not retain only the unsuppressed file: %+v", *got)
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
