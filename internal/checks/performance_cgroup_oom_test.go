package checks

import (
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
)

const cgroupOOMLine = "2026-09-21T10:00:20,521744+03:00 Memory cgroup out of memory: " +
	"Killed process 3554513 (lsphp) total-vm:860524kB, anon-rss:91744kB, file-rss:15724kB, UID:1045"

const hostOOMLine = "2026-09-21T10:00:20,521744+03:00 Out of memory: Killed process 4211 (mysqld) " +
	"total-vm:24800000kB, anon-rss:23900000kB, file-rss:0kB, UID:27"

// A cgroup OOM is one account reaching the memory limit its plan sets, which
// is routine on shared hosting and says nothing about host health. Reporting
// it as Critical alongside a genuine host-wide OOM trains the operator to
// ignore both.
func TestCgroupOOMIsNotCritical(t *testing.T) {
	sev, scoped := classifyOOMLine(cgroupOOMLine)
	if !scoped {
		t.Fatal("a Memory cgroup OOM was not recognised as account-scoped")
	}
	if sev == alert.Critical {
		t.Fatal("an account-scoped cgroup OOM is reported as Critical")
	}
}

// A host-wide OOM keeps its Critical severity: that is real memory exhaustion.
func TestHostOOMStaysCritical(t *testing.T) {
	sev, scoped := classifyOOMLine(hostOOMLine)
	if scoped {
		t.Fatal("a host-wide OOM was misread as account-scoped")
	}
	if sev != alert.Critical {
		t.Fatalf("host-wide OOM severity = %v, want Critical", sev)
	}
}

// The two must not share a dedup identity, or one account hitting its limit
// suppresses the host-wide alert that follows it.
func TestCgroupAndHostOOMDedupSeparately(t *testing.T) {
	a := alert.Finding{Check: "perf_memory", DedupKey: oomDedupKey(cgroupOOMLine)}
	b := alert.Finding{Check: "perf_memory", DedupKey: oomDedupKey(hostOOMLine)}
	if a.Key() == b.Key() {
		t.Fatalf("cgroup and host OOM share dedup key %q", a.Key())
	}
	if !strings.Contains(oomDedupKey(cgroupOOMLine), "lsphp") {
		t.Fatalf("cgroup OOM dedup key lost the victim process: %q", oomDedupKey(cgroupOOMLine))
	}
}
