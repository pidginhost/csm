package checks

import (
	"context"
	"maps"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

// A suspended account's database user is locked: its installs are skipped
// without leaving the check incomplete, and other accounts are still scanned.
func TestCMSScansSkipSuspendedAccounts(t *testing.T) {
	withAccountHomeRoots(t, "/home", "/var/www/vhosts")
	for _, a := range cmsAdapterCases() {
		t.Run(a.name, func(t *testing.T) {
			files := maps.Clone(a.files)
			files["/var/cpanel/suspended/alice"] = ""
			withCMSConfigOS(t, &twoOwnerCMSOS{files: files})
			withMockCmd(t, &mockCmd{runWithEnv: func(_ string, args []string, _ ...string) ([]byte, error) {
				return maliciousRowsFor(a.name, strings.Join(args, " "), 0), nil
			}})
			ctx, coverage := withIncompleteCheckCollector(context.Background())
			findings := a.run(ctx, &config.Config{}, nil)
			bob := 0
			for _, f := range findings {
				switch f.TenantID {
				case "alice":
					t.Errorf("suspended account scanned: %s %s", f.Check, f.Message)
				case "bob":
					bob++
				}
			}
			if bob == 0 {
				t.Error("active account was not scanned")
			}
			if coverage.contains("db_content_" + a.name) {
				t.Error("skipping a suspended account left the check incomplete")
			}
		})
	}
}
