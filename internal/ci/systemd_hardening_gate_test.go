package ci

import (
	"bufio"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

const csmUnitPath = "../../build/packaging/systemd/csm.service"

func unitLines(t *testing.T) []string {
	t.Helper()
	f, err := os.Open(csmUnitPath)
	if err != nil {
		t.Fatalf("read %s: %v", csmUnitPath, err)
	}
	defer func() { _ = f.Close() }()

	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		lines = append(lines, strings.TrimSpace(sc.Text()))
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan %s: %v", csmUnitPath, err)
	}
	return lines
}

// In systemd the "~" on SystemCallFilter negates the WHOLE line; it is not a
// per-entry operator. The shipped unit read:
//
//	SystemCallFilter=~@reboot ~@swap ~@module ~@raw-io ~@mount ~@cpu-emulation
//
// so only @reboot was denied. Every later "~@..." parsed as a syscall *name*
// beginning with "~", failed to parse, and was dropped with a warning at
// every single start:
//
//	csm.service:106: Failed to parse system call, ignoring: ~@swap
//	csm.service:106: Failed to parse system call, ignoring: ~@module
//	...
//
// @module, @mount and @raw-io are exactly the groups that matter for a
// security daemon, and they were not blocked on any host. The unit read as
// hardened while the hardening was absent, which is worse than not claiming
// it: nobody re-checks a setting they believe is already on.
func TestUnitDenySyscallGroupsUseOneNegation(t *testing.T) {
	var denyLines []string
	for _, line := range unitLines(t) {
		if strings.HasPrefix(line, "SystemCallFilter=~") {
			denyLines = append(denyLines, line)
		}
	}
	if len(denyLines) == 0 {
		t.Fatal("unit has no SystemCallFilter deny line; the syscall denylist is gone")
	}

	for _, line := range denyLines {
		value := strings.TrimPrefix(line, "SystemCallFilter=")
		entries := strings.Fields(value)
		// The leading "~" belongs to the first entry only.
		for i, entry := range entries {
			if i == 0 {
				if !strings.HasPrefix(entry, "~") {
					t.Errorf("deny line does not start with ~: %q", line)
				}
				continue
			}
			if strings.HasPrefix(entry, "~") {
				t.Errorf("entry %q repeats the ~ prefix; systemd parses it as a syscall name and silently drops it (line: %q)", entry, line)
			}
		}
	}

	// The groups whose absence actually matters. Assert each is denied
	// somewhere, so a future edit cannot quietly drop one.
	joined := strings.Join(denyLines, " ")
	for _, group := range []string{"@reboot", "@swap", "@module", "@raw-io", "@mount", "@cpu-emulation"} {
		if !regexp.MustCompile(`[~ ]` + regexp.QuoteMeta(group) + `(\s|$)`).MatchString(joined) {
			t.Errorf("syscall group %s is no longer denied", group)
		}
	}
}

// CSM competes with the web server and the database it protects. Under CPU
// contention the scanner should lose, and it can only lose if the unit gives
// the kernel a reason to prefer everything else.
func TestUnitYieldsCPUUnderContention(t *testing.T) {
	var weight string
	for _, line := range unitLines(t) {
		if value, ok := strings.CutPrefix(line, "CPUWeight="); ok {
			weight = strings.TrimSpace(value)
		}
		if strings.HasPrefix(line, "CPUQuota=") {
			t.Errorf("unit sets %s: a hard cap delays detection even on an idle host", line)
		}
	}
	if weight == "" {
		t.Fatal("unit sets no CPUWeight, so the scanner competes with the web server on equal terms")
	}
	value, err := strconv.Atoi(weight)
	if err != nil {
		t.Fatalf("CPUWeight=%s is not a number", weight)
	}
	// 100 is the default every other service gets.
	if value >= 100 {
		t.Fatalf("CPUWeight=%d does not yield to the workload CSM protects", value)
	}
}
