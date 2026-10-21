package daemon

import (
	"testing"

	"github.com/pidginhost/csm/internal/alert"
)

// Permission findings carry scan details, so their key includes a details
// hash. The initial-scan filter must match the keys the auto-fix returns.
func TestWithoutFixedFindingsMatchesFindingKeys(t *testing.T) {
	fixed := alert.Finding{Check: "world_writable_php", Message: "World-writable PHP file: /home/alice/public_html/a.php", Details: "Mode: -rw-rw-rw-"}
	kept := alert.Finding{Check: "world_writable_php", Message: "World-writable PHP file: /home/alice/public_html/b.php", Details: "Mode: -rw-rw-rw-"}

	got := withoutFixedFindings([]alert.Finding{fixed, kept}, []string{fixed.Key()})

	if len(got) != 1 || got[0].Message != kept.Message {
		t.Fatalf("filtered findings = %+v, want only %q", got, kept.Message)
	}
}
