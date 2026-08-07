package checks

import (
	"context"
	"slices"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

// A rolling deep scan on a large host never completes in one run, so its
// names never enter the purge list and every run's scan_incomplete status
// finding accumulates forever. Status findings describe one run's coverage,
// not discovered state: they must be replaced whenever the owning check ran,
// while discovered findings (yara_match_scheduled) still survive incomplete
// runs.

func TestRunParallelPurgesPerRunStatusFindingsOfIncompleteCheck(t *testing.T) {
	findings, purge := runParallel(&config.Config{}, nil, []namedCheck{{
		name: "yara_deep",
		fn: func(ctx context.Context, _ *config.Config, _ *state.Store) []alert.Finding {
			markCheckIncomplete(ctx, "yara_deep")
			return []alert.Finding{{
				Severity: alert.High,
				Check:    "yara_scan_incomplete",
				Message:  "YARA deep scan could not inspect 3 file or directory entries",
			}}
		},
	}}, "test", true)

	if len(findings) != 1 || findings[0].Check != "yara_scan_incomplete" {
		t.Fatalf("findings = %+v, want the emitted yara_scan_incomplete", findings)
	}
	if !slices.Contains(purge, "yara_scan_incomplete") {
		t.Errorf("purge = %v, want yara_scan_incomplete purged for a ran-but-incomplete check", purge)
	}
	if slices.Contains(purge, "yara_match_scheduled") {
		t.Errorf("purge = %v, discovered-state findings of an incomplete check must not be purged", purge)
	}
}

func TestRunParallelCompletedCheckPurgesAllOwnedFindingNames(t *testing.T) {
	_, purge := runParallel(&config.Config{}, nil, []namedCheck{{
		name: "yara_deep",
		fn: func(context.Context, *config.Config, *state.Store) []alert.Finding {
			return nil
		},
	}}, "test", true)

	if !slices.Contains(purge, "yara_scan_incomplete") || !slices.Contains(purge, "yara_match_scheduled") {
		t.Errorf("purge = %v, want both owned finding names for a completed check", purge)
	}
}

func TestRunParallelPerRunPurgeCoversPhpConfigScanIncomplete(t *testing.T) {
	_, purge := runParallel(&config.Config{}, nil, []namedCheck{{
		name: "php_config_changes",
		fn: func(ctx context.Context, _ *config.Config, _ *state.Store) []alert.Finding {
			markCheckIncomplete(ctx, "php_config_changes")
			return nil
		},
	}}, "test", true)

	if !slices.Contains(purge, "php_config_scan_incomplete") {
		t.Errorf("purge = %v, want php_config_scan_incomplete purged for a ran-but-incomplete check", purge)
	}
	if slices.Contains(purge, "php_config_change") {
		t.Errorf("purge = %v, php_config_change must survive an incomplete run", purge)
	}
}
