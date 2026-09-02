package checks

import "testing"

// With the realtime file monitor active the deep tier drops the content
// checks the monitor is assumed to cover. fanotify sees close-after-write
// only: a shell written under a temporary name and renamed into place, or
// written through a bind mount the mount mark does not cover, produces no
// event. The budgeted rolling PHP content scan stays in the reduced tier so
// such files are still met by the YAML rules within a rolling cycle, the way
// the rolling YARA deep scan already stays.
func TestReducedDeepTierKeepsRollingContentScan(t *testing.T) {
	names := map[string]bool{}
	for _, nc := range reducedDeepChecks() {
		names[nc.name] = true
	}
	if !names["yara_deep"] {
		t.Fatal("reduced deep tier lost the rolling YARA scan")
	}
	if !names["php_content"] {
		t.Fatal("reduced deep tier omits the rolling PHP content scan: files renamed into place are never content-scanned while the file monitor is active")
	}
}
