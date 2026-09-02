package checks

import (
	"slices"
	"testing"
)

// php_content and file_index both emit obfuscated_php and
// suspicious_php_content. Purging those names whenever either check
// completes drops the other check's live findings from the latest set every
// cycle. A name owned by several checks is purged only when all of them ran.
func TestLatestPurgeNamesKeepSharedNamesUntilAllOwnersRan(t *testing.T) {
	fileIndexOnly := latestPurgeCheckNamesForChecks([]namedCheck{{name: "file_index"}})
	for _, shared := range []string{"obfuscated_php", "suspicious_php_content"} {
		if slices.Contains(fileIndexOnly, shared) {
			t.Errorf("%s purged after file_index alone ran; php_content also owns it", shared)
		}
	}
	if !slices.Contains(fileIndexOnly, "new_webshell_file") {
		t.Error("file_index's own finding names must still be purged")
	}

	both := latestPurgeCheckNamesForChecks([]namedCheck{{name: "file_index"}, {name: "php_content"}})
	for _, shared := range []string{"obfuscated_php", "suspicious_php_content"} {
		if !slices.Contains(both, shared) {
			t.Errorf("%s not purged although both owners ran", shared)
		}
	}
}
