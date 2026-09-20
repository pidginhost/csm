package checks

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

// Re-verifying the paths that carry an active finding keeps live detections
// from being retired, but the set of those paths is built from every finding
// name the file index owns, and two of them (obfuscated_php,
// suspicious_php_content) are also emitted by the content scan. An old file the
// content scan flagged is not a new file, so the index must not report it as
// one once the content that drew the original finding is gone. Such a report
// would also renew itself forever, because its own finding puts the path back
// into the re-verified set on the next cycle.
func TestFileIndexDoesNotReportOldContentFlaggedFileAsNew(t *testing.T) {
	cfg, st, uploads := fileIndexLifecycleFixture(t)

	// Establish the baseline with the file already present, so it is not new.
	existing := filepath.Join(uploads, "legacy.php")
	if err := os.WriteFile(existing, []byte("<?php echo 'ready';"), 0600); err != nil {
		t.Fatal(err)
	}
	runFileIndexLifecycleScan(cfg, st)
	runFileIndexLifecycleScan(cfg, st)
	if got := st.LatestFindings(); len(got) != 0 {
		t.Fatalf("baseline cycles produced findings for a clean file: %+v", got)
	}

	// The content scan owns this finding; the file index never called the file
	// new. The content is clean by the time the index re-verifies the path.
	st.SetLatestFindings([]alert.Finding{{
		Check:     "obfuscated_php",
		Severity:  alert.High,
		Message:   "Obfuscated PHP detected: " + existing,
		FilePath:  existing,
		Timestamp: time.Now(),
	}})

	runFileIndexLifecycleScan(cfg, st)

	for _, f := range st.LatestFindings() {
		if f.FilePath == existing && (f.Check == "new_php_in_uploads" || f.Check == "new_php_in_uploads_clean") {
			t.Fatalf("file index reported a file already in its baseline as new: %+v", f)
		}
	}
}
