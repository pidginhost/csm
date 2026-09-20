package checks

import (
	"slices"
	"testing"
)

// The reduced deep tier drops the filesystem checks the realtime monitor is
// assumed to cover. The fanotify mask carries no FAN_MOVED_TO on any kernel and
// loses FAN_CREATE on EL8, so a file renamed into place - how an unpacked
// archive and most droppers land - produces no event at all. The file index is
// the only check that notices such a file, and it also owns the baseline the
// new-file diff runs against, so skipping it leaves that baseline frozen for as
// long as the monitor stays attached.
func TestReducedDeepTierKeepsFileIndex(t *testing.T) {
	names := map[string]bool{}
	for _, nc := range reducedDeepChecks() {
		names[nc.name] = true
	}
	if !names["file_index"] {
		t.Fatal("reduced deep tier omits the file index: files renamed into place are never indexed while the file monitor is active, and the new-file baseline stops being refreshed")
	}
}

// The reduced tier must also purge and merge what the file index emits.
// Without its finding names in the reduced purge list, a run in this tier
// cannot retire a new-file finding whose file is gone.
func TestLatestPurgeCheckNamesForReducedDeepCoversFileIndex(t *testing.T) {
	names := LatestPurgeCheckNamesForReducedDeep()
	for _, want := range []string{"new_php_in_uploads", "new_webshell_file", "new_php_in_sensitive_dir"} {
		if !slices.Contains(names, want) {
			t.Fatalf("reduced deep purge names missing %q in %v", want, names)
		}
	}
}
