package checks

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

func TestWPCoreVerificationRequiresCompletionSummary(t *testing.T) {
	for _, tc := range []struct {
		name, output, state string
	}{
		{"truncated", "Warning: File doesn't verify against checksum: wp-includes/version.php\n", "unverified"},
		{"complete", "Warning: File doesn't verify against checksum: wp-includes/version.php\nError: WordPress installation doesn't verify against checksums.\n", "modified"},
		{"missing_file", "Warning: File should exist: wp-includes/version.php\nError: WordPress installation doesn't verify against checksums.\n", "modified"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := setupPluginStore(t)
			roots, _ := wpCoreQueueFixtures(t, 1)
			refused := refusedCommand(t)
			withMockCmd(t, &mockCmd{runContext: func(context.Context, string, ...string) ([]byte, error) {
				return []byte(tc.output), refused
			}})
			for range 2 {
				CheckWPCore(withWPInstallCache(context.Background()), nil, nil)
			}
			rows, err := db.WPVerification("core")
			if err != nil || rows[filepath.Dir(roots[0])].State != tc.state {
				t.Fatalf("wrong checksum completion state: %+v %v", rows, err)
			}
		})
	}
}

func TestWPCoreVerificationDisableAliases(t *testing.T) {
	for _, alias := range []string{"wp_core", "wp_core_integrity"} {
		cfg := &config.Config{DisabledChecks: []string{alias}}
		enabled, disabled := splitDisabledChecks(cfg, []namedCheck{{"wp_core", CheckWPCore}})
		if len(enabled) != 0 || len(disabled) != 1 {
			t.Errorf("%s failed to disable the hosted verification check", alias)
		}
	}
}
