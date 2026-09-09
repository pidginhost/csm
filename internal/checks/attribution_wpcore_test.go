package checks

import (
	"context"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// A modified core file names its path; the collapsed extraneous-file finding
// has no single path, so it carries the install's owner instead. Both resolve
// to the account that owns the install.
func TestWPCoreIntegrityAttributesByPath(t *testing.T) {
	withAccountHomeRoots(t, "/home")
	wpCoreCheckMocks(t,
		"Warning: File should not exist: wp-includes/blocks/leftover.php\n"+
			"Warning: File doesn't verify against checksum: wp-includes/plugin.php\n")

	findings := coreIntegrityFindings(CheckWPCore(context.Background(), &config.Config{}, nil))
	if len(findings) != 2 {
		t.Fatalf("findings = %d, want one modified file and one collapsed extra: %+v", len(findings), findings)
	}
	seen := expectAttributed(t, findings, "alice")
	requireChecks(t, seen, "wp_core_integrity")
	for _, f := range findings {
		if f.FilePath == "" && f.TenantID != "alice" {
			t.Errorf("collapsed extraneous finding lacks the install owner: %+v", f)
		}
	}

	anchors := []alert.Finding{critical("db_rogue_admin", "bob"), critical("db_rogue_admin", "carol")}
	res := CorrelateFindings(append(anchors, findings...))
	if len(res.Derived) != 1 || res.Derived[0].Check != "coordinated_attack" {
		t.Fatalf("critical core-file output did not aggregate: %+v", res)
	}
	if len(res.Unattributed) != 0 {
		t.Fatalf("unattributed core rows %v", res.Unattributed)
	}
}
