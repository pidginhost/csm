//go:build yara

package checks

import (
	"context"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/yara"
)

// The scheduled YARA sweep names the matched file, so its owner resolves
// from the path and a Critical rule counts toward the aggregate.
func TestYARAScheduledFindingAttributesByPath(t *testing.T) {
	root := t.TempDir()
	withAccountHomeRoots(t, root)
	useRollingStore(t)
	path := writeYARADeepFile(t, root, "alice/public_html/uploads/image.dat", "dormant malware")
	yara.SetActive(&deepYARATestBackend{})
	t.Cleanup(func() { yara.SetActive(nil) })

	findings := CheckYARADeep(context.Background(), &config.Config{AccountRoots: []string{root}}, nil)
	var matches []alert.Finding
	for _, f := range findings {
		if f.Check == "yara_match_scheduled" {
			matches = append(matches, f)
		}
	}
	if len(matches) != 1 || matches[0].FilePath != path {
		t.Fatalf("findings = %+v, want one YARA match for %s", findings, path)
	}
	seen := expectAttributed(t, matches, "alice")
	requireChecks(t, seen, "yara_match_scheduled")

	anchors := []alert.Finding{critical("db_rogue_admin", "bob"), critical("db_rogue_admin", "carol")}
	res := CorrelateFindings(append(anchors, matches...))
	if len(res.Derived) != 1 || res.Derived[0].Check != "coordinated_attack" {
		t.Fatalf("critical YARA output did not aggregate: %+v", res)
	}
	if len(res.Unattributed) != 0 {
		t.Fatalf("unattributed YARA rows %v", res.Unattributed)
	}
}
