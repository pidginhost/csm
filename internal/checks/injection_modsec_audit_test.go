package checks

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/platform"
)

// CheckModSecAuditLog:
//   - platform.ModSecAuditLogPaths empty → nil
//   - log file missing → nil
//   - log lines with no 403/MODSEC markers → nil
//   - one IP with ≥20 blocked hits → High finding
//   - same IP with <20 hits → no finding
//   - infra IP skipped

// withModSecAuditLog points platform overrides at a log we serve via mockOS.
func withModSecAuditLog(t *testing.T, content string) {
	t.Helper()
	platform.ResetForTest()
	t.Cleanup(platform.ResetForTest)
	platform.SetOverrides(platform.Overrides{
		ModSecAuditLogPaths: []string{"/var/log/modsec/audit.log"},
	})
	tmp := t.TempDir() + "/modsec.log"
	if err := os.WriteFile(tmp, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	withMockOS(t, &mockOS{
		open: func(name string) (*os.File, error) {
			if name == "/var/log/modsec/audit.log" {
				return os.Open(tmp)
			}
			return nil, os.ErrNotExist
		},
	})
}

func TestCheckModSecAuditLogNoPathsReturnsNil(t *testing.T) {
	platform.ResetForTest()
	t.Cleanup(platform.ResetForTest)
	platform.SetOverrides(platform.Overrides{
		ModSecAuditLogPaths: []string{}, // empty
	})
	got := CheckModSecAuditLog(context.Background(), &config.Config{}, nil)
	if got != nil {
		t.Errorf("empty paths should yield nil, got %d findings", len(got))
	}
}

func TestCheckModSecAuditLogMissingFileReturnsNil(t *testing.T) {
	platform.ResetForTest()
	t.Cleanup(platform.ResetForTest)
	platform.SetOverrides(platform.Overrides{
		ModSecAuditLogPaths: []string{"/var/log/modsec/audit.log"},
	})
	withMockOS(t, &mockOS{
		open: func(string) (*os.File, error) { return nil, os.ErrNotExist },
	})
	got := CheckModSecAuditLog(context.Background(), &config.Config{}, nil)
	if got != nil {
		t.Errorf("missing log should yield nil, got %d findings", len(got))
	}
}

func TestCheckModSecAuditLogNoMatchingLinesReturnsEmpty(t *testing.T) {
	// Log content has no 403/MODSEC/Access-denied markers.
	content := "2026-04-14 10:00:00 [core:info] [client 1.2.3.4] request completed normally\n" +
		"2026-04-14 10:00:01 [core:info] [client 5.6.7.8] another benign log line\n"
	withModSecAuditLog(t, content)

	got := CheckModSecAuditLog(context.Background(), &config.Config{}, nil)
	if len(got) != 0 {
		t.Errorf("no ModSec markers should yield no findings, got %+v", got)
	}
}

func TestCheckModSecAuditLogHighVolumeAttackerEmitsHigh(t *testing.T) {
	// Generate 25 blocked lines from the same IP.
	var sb strings.Builder
	for i := 0; i < 25; i++ {
		fmt.Fprintf(&sb, "2026-04-14 10:00:%02d [client 203.0.113.9] [id \"942100\"] [msg \"SQL Injection\"] 403 Access denied MODSEC\n", i)
	}
	withModSecAuditLog(t, sb.String())

	got := CheckModSecAuditLog(context.Background(), &config.Config{}, nil)
	if len(got) != 1 {
		t.Fatalf("expected 1 high-volume finding, got %d: %+v", len(got), got)
	}
	if got[0].Check != "waf_attack_blocked" || got[0].Severity != alert.High {
		t.Errorf("unexpected finding: %+v", got[0])
	}
	if !strings.Contains(got[0].Message, "203.0.113.9") {
		t.Errorf("message should name the attacker: %s", got[0].Message)
	}
}

func TestCheckModSecAuditLogBelowThresholdIgnored(t *testing.T) {
	// Only 10 blocked lines — under the 20-hit threshold.
	var sb strings.Builder
	for i := 0; i < 10; i++ {
		fmt.Fprintf(&sb, "2026-04-14 10:00:%02d [client 203.0.113.9] 403 MODSEC blocked\n", i)
	}
	withModSecAuditLog(t, sb.String())

	got := CheckModSecAuditLog(context.Background(), &config.Config{}, nil)
	if len(got) != 0 {
		t.Errorf("under-threshold should not emit, got %+v", got)
	}
}

func TestCheckModSecAuditLogSkipsInfraIP(t *testing.T) {
	var sb strings.Builder
	for i := 0; i < 25; i++ {
		fmt.Fprintf(&sb, "2026-04-14 10:00:%02d [client 10.0.0.5] 403 MODSEC blocked\n", i)
	}
	withModSecAuditLog(t, sb.String())

	got := CheckModSecAuditLog(context.Background(), &config.Config{InfraIPs: []string{"10.0.0.0/8"}}, nil)
	if len(got) != 0 {
		t.Errorf("infra IP should be skipped, got %+v", got)
	}
}
