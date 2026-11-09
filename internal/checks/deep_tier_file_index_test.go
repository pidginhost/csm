package checks

import (
	"slices"
	"testing"
)

// The fanotify mask carries no FAN_MOVED_TO on any kernel and loses FAN_CREATE
// on EL8, so a file renamed into place - how an unpacked archive and most
// droppers land - produces no event at all. The file index is the only check
// that notices such a file, and it also owns the baseline the new-file diff
// runs against, so the deep tier must keep it while the monitor is attached.
func TestDeepTierKeepsFileIndex(t *testing.T) {
	if !deepCheckNames()["file_index"] {
		t.Fatal("deep tier omits the file index: files renamed into place are never indexed while the file monitor is active, and the new-file baseline stops being refreshed")
	}
}

// The deep tier must also purge and merge what the file index emits. Without
// its finding names in the purge list, a run cannot retire a new-file finding
// whose file is gone.
func TestLatestPurgeCheckNamesForDeepCoversFileIndex(t *testing.T) {
	names := LatestPurgeCheckNamesForTier(TierDeep)
	for _, want := range []string{"new_php_in_uploads", "new_webshell_file", "new_php_in_sensitive_dir"} {
		if !slices.Contains(names, want) {
			t.Fatalf("deep purge names missing %q in %v", want, names)
		}
	}
}
