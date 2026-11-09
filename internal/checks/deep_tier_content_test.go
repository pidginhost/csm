package checks

import "testing"

// The deep tier also runs while the realtime file monitor is attached.
// fanotify sees close-after-write only: a shell written under a temporary name
// and renamed into place, or written through a bind mount the mount mark does
// not cover, produces no event. The budgeted rolling PHP content scan and the
// rolling YARA scan are what still meet such files.
func TestDeepTierKeepsRollingContentScan(t *testing.T) {
	names := deepCheckNames()
	if !names["yara_deep"] {
		t.Fatal("deep tier lost the rolling YARA scan")
	}
	if !names["php_content"] {
		t.Fatal("deep tier omits the rolling PHP content scan: files renamed into place are never content-scanned while the file monitor is active")
	}
}
