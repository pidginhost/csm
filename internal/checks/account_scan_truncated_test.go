package checks

import (
	"context"
	"strings"
	"testing"
	"time"
)

// Per-account aggregation makes the finding actionable: operators can
// see which account tripped the cap and decide whether to raise the
// threshold or trim that account's deadweight files.
func TestAccountScanTruncated_PerAccountFinding(t *testing.T) {
	baseCtx, collector := withAccountScanTruncationCollector(context.Background())
	aliceCtx := ContextWithAccountScope(baseCtx, "alice")
	bobCtx := ContextWithAccountScope(baseCtx, "bob")

	recordAccountScanTruncated(aliceCtx, 100, 50)
	recordAccountScanTruncated(bobCtx, 200, 50)
	recordAccountScanTruncated(aliceCtx, 50, 50)

	findings := collector.findings(time.Now())
	if len(findings) != 2 {
		t.Fatalf("findings count = %d, want 2 (one per account)", len(findings))
	}

	byAccount := map[string]string{}
	for _, f := range findings {
		switch {
		case strings.Contains(f.Message, "alice"):
			byAccount["alice"] = f.Message
		case strings.Contains(f.Message, "bob"):
			byAccount["bob"] = f.Message
		}
	}
	if byAccount["alice"] == "" {
		t.Errorf("no finding mentioned alice; findings = %+v", findings)
	} else if !strings.Contains(byAccount["alice"], "150") {
		t.Errorf("alice finding total wrong: %q", byAccount["alice"])
	}
	if byAccount["bob"] == "" {
		t.Errorf("no finding mentioned bob; findings = %+v", findings)
	} else if !strings.Contains(byAccount["bob"], "200") {
		t.Errorf("bob finding total wrong: %q", byAccount["bob"])
	}
}

// Full-host scans (no account scope) still get a finding so operators
// know the daemon-wide tier truncated. The account label collapses to
// the empty/unscoped marker.
func TestAccountScanTruncated_HostScopeFinding(t *testing.T) {
	ctx, collector := withAccountScanTruncationCollector(context.Background())
	recordAccountScanTruncated(ctx, 42, 100)

	findings := collector.findings(time.Now())
	if len(findings) != 1 {
		t.Fatalf("findings count = %d, want 1", len(findings))
	}
	if !strings.Contains(findings[0].Message, "42") || !strings.Contains(findings[0].Message, "100") {
		t.Errorf("host-scope message missing counts: %q", findings[0].Message)
	}
}

// Two accounts truncated at different caps must each produce their own
// finding so the operator can distinguish which tier was hit. This
// protects against a regression where same-cap aggregation collapses
// distinct accounts into a single line.
func TestAccountScanTruncated_DistinctCapsPerAccount(t *testing.T) {
	baseCtx, collector := withAccountScanTruncationCollector(context.Background())
	aliceCtx := ContextWithAccountScope(baseCtx, "alice")
	bobCtx := ContextWithAccountScope(baseCtx, "bob")

	recordAccountScanTruncated(aliceCtx, 10, 50)
	recordAccountScanTruncated(bobCtx, 20, 100)

	findings := collector.findings(time.Now())
	if len(findings) != 2 {
		t.Fatalf("findings count = %d, want 2", len(findings))
	}
}
