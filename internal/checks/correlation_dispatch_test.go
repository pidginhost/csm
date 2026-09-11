package checks

import (
	"context"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/state"
)

// Derived aggregates carry no action target. Passing them through every
// automatic response stage with responses enabled must produce no action
// and touch no responder.
func TestDerivedAggregatesNeverDispatchResponses(t *testing.T) {
	withAccountHomeRoots(t, "/home")
	cfg := &config.Config{}
	cfg.StatePath = t.TempDir()
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.BlockIPs = true
	cfg.AutoResponse.KillProcesses = true
	cfg.AutoResponse.QuarantineFiles = true
	cfg.AutoResponse.CleanHtaccess = true
	blocker := &outcomeIPBlocker{outcome: firewall.BlockOutcomeLive}
	swapBlocker(t, blocker)

	res := CorrelateFindings([]alert.Finding{
		critical("webshell", "alice"), critical("webshell", "bob"), critical("db_rogue_admin", "carol"),
	})
	if len(res.Derived) != 2 {
		t.Fatalf("fixture produced %d aggregates, want 2", len(res.Derived))
	}
	aggregates := make([]alert.Finding, len(res.Derived))
	for i, f := range res.Derived {
		f.Timestamp = time.Now()
		aggregates[i] = f
	}

	challenge, block := ChallengeThenBlock(cfg, aggregates)
	if len(challenge) != 0 || len(block) != 0 || blocker.outcomeHits != 0 {
		t.Fatalf("block stage acted on aggregates: challenge=%d block=%d hits=%d", len(challenge), len(block), blocker.outcomeHits)
	}
	if actions := AutoKillProcesses(context.Background(), cfg, aggregates); len(actions) != 0 {
		t.Fatalf("kill stage acted on aggregates: %+v", actions)
	}
	if actions := AutoQuarantineFiles(cfg, aggregates); len(actions) != 0 {
		t.Fatalf("quarantine stage acted on aggregates: %+v", actions)
	}
	if actions := AutoCleanHtaccess(cfg, aggregates); len(actions) != 0 {
		t.Fatalf("htaccess stage acted on aggregates: %+v", actions)
	}
	if actions := AutoVirtualPatchExposedFiles(cfg, aggregates); len(actions) != 0 {
		t.Fatalf("virtual patch stage acted on aggregates: %+v", actions)
	}
}

func TestScanBatchCorrelationRetainsCarriedTimestamps(t *testing.T) {
	withAccountHomeRoots(t, "/home")
	at := time.Now()
	batch := []alert.Finding{
		criticalAt("one", "php_remote_taint", at.Add(-2*time.Hour)),
		criticalAt("two", "php_remote_taint", at.Add(-3*time.Hour)),
		criticalAt("three", "webshell", at),
	}
	batch[0].ScanCarryForward = true
	batch[1].ScanCarryForward = true
	rows, _ := runParallel(&config.Config{}, nil, []namedCheck{{name: "php_taint_deep", fn: func(context.Context, *config.Config, *state.Store) []alert.Finding {
		return batch
	}}}, "test", true)
	counts := checksIn(rows)
	if counts["coordinated_attack"] != 1 || counts["cross_account_malware"] != 0 || len(rows) != 4 {
		t.Fatalf("batch lost carried-forward evidence: %v", counts)
	}
	if !rows[0].Timestamp.Equal(batch[0].Timestamp) || !rows[1].Timestamp.Equal(batch[1].Timestamp) {
		t.Fatal("batch rewrote the age of carried-forward evidence")
	}
}
