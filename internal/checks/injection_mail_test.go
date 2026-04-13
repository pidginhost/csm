package checks

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// =========================================================================
// CheckMailQueue
// =========================================================================

func TestCheckMailQueueCmdError(t *testing.T) {
	withMockCmd(t, &mockCmd{
		run: func(name string, args ...string) ([]byte, error) {
			return nil, fmt.Errorf("exec: not found")
		},
	})
	cfg := &config.Config{}
	cfg.Thresholds.MailQueueWarn = 100
	cfg.Thresholds.MailQueueCrit = 500
	findings := CheckMailQueue(context.Background(), cfg, nil)
	if len(findings) != 0 {
		t.Errorf("cmd error should produce 0 findings, got %d", len(findings))
	}
}

func TestCheckMailQueueNilOutput(t *testing.T) {
	withMockCmd(t, &mockCmd{
		run: func(name string, args ...string) ([]byte, error) {
			return nil, nil
		},
	})
	cfg := &config.Config{}
	cfg.Thresholds.MailQueueWarn = 100
	cfg.Thresholds.MailQueueCrit = 500
	findings := CheckMailQueue(context.Background(), cfg, nil)
	if len(findings) != 0 {
		t.Errorf("nil output should produce 0 findings, got %d", len(findings))
	}
}

func TestCheckMailQueueNonNumericOutput(t *testing.T) {
	withMockCmd(t, &mockCmd{
		run: func(name string, args ...string) ([]byte, error) {
			return []byte("not-a-number\n"), nil
		},
	})
	cfg := &config.Config{}
	cfg.Thresholds.MailQueueWarn = 100
	cfg.Thresholds.MailQueueCrit = 500
	findings := CheckMailQueue(context.Background(), cfg, nil)
	if len(findings) != 0 {
		t.Errorf("non-numeric output should produce 0 findings, got %d", len(findings))
	}
}

func TestCheckMailQueueBelowThreshold(t *testing.T) {
	withMockCmd(t, &mockCmd{
		run: func(name string, args ...string) ([]byte, error) {
			if name == "exim" && len(args) > 0 && args[0] == "-bpc" {
				return []byte("5\n"), nil
			}
			return nil, nil
		},
	})
	cfg := &config.Config{}
	cfg.Thresholds.MailQueueWarn = 100
	cfg.Thresholds.MailQueueCrit = 500
	findings := CheckMailQueue(context.Background(), cfg, nil)
	if len(findings) != 0 {
		t.Errorf("below threshold should produce 0 findings, got %d", len(findings))
	}
}

func TestCheckMailQueueWarning(t *testing.T) {
	withMockCmd(t, &mockCmd{
		run: func(name string, args ...string) ([]byte, error) {
			return []byte("150\n"), nil
		},
	})
	cfg := &config.Config{}
	cfg.Thresholds.MailQueueWarn = 100
	cfg.Thresholds.MailQueueCrit = 500
	findings := CheckMailQueue(context.Background(), cfg, nil)
	if len(findings) != 1 {
		t.Fatalf("warning threshold should produce 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != alert.Warning {
		t.Errorf("severity = %v, want Warning", findings[0].Severity)
	}
	if findings[0].Check != "mail_queue" {
		t.Errorf("check = %q, want mail_queue", findings[0].Check)
	}
	if !strings.Contains(findings[0].Message, "150") {
		t.Errorf("message should contain count 150, got %q", findings[0].Message)
	}
}

func TestCheckMailQueueCritical(t *testing.T) {
	withMockCmd(t, &mockCmd{
		run: func(name string, args ...string) ([]byte, error) {
			return []byte("  600  \n"), nil // whitespace-padded
		},
	})
	cfg := &config.Config{}
	cfg.Thresholds.MailQueueWarn = 100
	cfg.Thresholds.MailQueueCrit = 500
	findings := CheckMailQueue(context.Background(), cfg, nil)
	if len(findings) != 1 {
		t.Fatalf("critical threshold should produce 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != alert.Critical {
		t.Errorf("severity = %v, want Critical", findings[0].Severity)
	}
	if !strings.Contains(findings[0].Message, "600") {
		t.Errorf("message should contain count 600, got %q", findings[0].Message)
	}
	if !strings.Contains(findings[0].Details, "spam") {
		t.Errorf("details should mention spam, got %q", findings[0].Details)
	}
}

func TestCheckMailQueueExactWarnBoundary(t *testing.T) {
	withMockCmd(t, &mockCmd{
		run: func(name string, args ...string) ([]byte, error) {
			return []byte("100\n"), nil
		},
	})
	cfg := &config.Config{}
	cfg.Thresholds.MailQueueWarn = 100
	cfg.Thresholds.MailQueueCrit = 500
	findings := CheckMailQueue(context.Background(), cfg, nil)
	if len(findings) != 1 {
		t.Fatalf("exact warn boundary should produce 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != alert.Warning {
		t.Errorf("severity = %v, want Warning at exact boundary", findings[0].Severity)
	}
}

func TestCheckMailQueueExactCritBoundary(t *testing.T) {
	withMockCmd(t, &mockCmd{
		run: func(name string, args ...string) ([]byte, error) {
			return []byte("500\n"), nil
		},
	})
	cfg := &config.Config{}
	cfg.Thresholds.MailQueueWarn = 100
	cfg.Thresholds.MailQueueCrit = 500
	findings := CheckMailQueue(context.Background(), cfg, nil)
	if len(findings) != 1 {
		t.Fatalf("exact crit boundary should produce 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != alert.Critical {
		t.Errorf("severity = %v, want Critical at exact boundary", findings[0].Severity)
	}
}

func TestCheckMailQueueZeroCount(t *testing.T) {
	withMockCmd(t, &mockCmd{
		run: func(name string, args ...string) ([]byte, error) {
			return []byte("0\n"), nil
		},
	})
	cfg := &config.Config{}
	cfg.Thresholds.MailQueueWarn = 100
	cfg.Thresholds.MailQueueCrit = 500
	findings := CheckMailQueue(context.Background(), cfg, nil)
	if len(findings) != 0 {
		t.Errorf("zero queue should produce 0 findings, got %d", len(findings))
	}
}

// =========================================================================
// CheckMailPerAccount
// =========================================================================

// writeTempLog creates a temp file with the given content and returns an
// open mock that redirects tailFile to the temp file.
func mailLogMock(t *testing.T, content string) *mockOS {
	t.Helper()
	return &mockOS{
		open: func(name string) (*os.File, error) {
			if strings.Contains(name, "exim_mainlog") {
				tmp := t.TempDir() + "/exim_mainlog"
				_ = os.WriteFile(tmp, []byte(content), 0644)
				return os.Open(tmp)
			}
			return nil, os.ErrNotExist
		},
	}
}

func TestCheckMailPerAccountNoLog(t *testing.T) {
	withMockOS(t, &mockOS{})
	findings := CheckMailPerAccount(context.Background(), &config.Config{}, nil)
	if len(findings) != 0 {
		t.Errorf("no log should produce 0 findings, got %d", len(findings))
	}
}

func TestCheckMailPerAccountBelowThreshold(t *testing.T) {
	// 10 outgoing messages from example.com -- below 100 threshold
	var lines string
	for i := 0; i < 10; i++ {
		lines += fmt.Sprintf("2026-04-13 10:%02d:00 1abc%02d-000abc-XX <= alice@example.com H=relay U=mailnull\n", i, i)
	}
	withMockOS(t, mailLogMock(t, lines))

	findings := CheckMailPerAccount(context.Background(), &config.Config{}, nil)
	if len(findings) != 0 {
		t.Errorf("below threshold should produce 0 findings, got %d", len(findings))
	}
}

func TestCheckMailPerAccountAboveThreshold(t *testing.T) {
	// 120 outgoing messages from spammer.com
	var lines string
	for i := 0; i < 120; i++ {
		lines += fmt.Sprintf("2026-04-13 10:00:%02d 1abc%03d-000abc-XX <= spam@spammer.com H=relay U=mailnull\n", i%60, i)
	}
	withMockOS(t, mailLogMock(t, lines))

	findings := CheckMailPerAccount(context.Background(), &config.Config{}, nil)
	if len(findings) != 1 {
		t.Fatalf("above threshold should produce 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != alert.High {
		t.Errorf("severity = %v, want High", findings[0].Severity)
	}
	if findings[0].Check != "mail_per_account" {
		t.Errorf("check = %q, want mail_per_account", findings[0].Check)
	}
	if !strings.Contains(findings[0].Message, "spammer.com") {
		t.Errorf("message should contain domain, got %q", findings[0].Message)
	}
	if !strings.Contains(findings[0].Message, "120") {
		t.Errorf("message should contain count, got %q", findings[0].Message)
	}
}

func TestCheckMailPerAccountMultipleDomains(t *testing.T) {
	// 110 from bad.com (above threshold) + 50 from good.com (below threshold)
	var lines string
	for i := 0; i < 110; i++ {
		lines += fmt.Sprintf("2026-04-13 10:00:00 1x%03d-0-XX <= spammer@bad.com H=h U=u\n", i)
	}
	for i := 0; i < 50; i++ {
		lines += fmt.Sprintf("2026-04-13 10:00:00 1y%03d-0-XX <= legit@good.com H=h U=u\n", i)
	}
	withMockOS(t, mailLogMock(t, lines))

	findings := CheckMailPerAccount(context.Background(), &config.Config{}, nil)
	if len(findings) != 1 {
		t.Fatalf("should flag only bad.com, got %d findings", len(findings))
	}
	if !strings.Contains(findings[0].Message, "bad.com") {
		t.Errorf("message should reference bad.com, got %q", findings[0].Message)
	}
}

func TestCheckMailPerAccountBothDomainsAbove(t *testing.T) {
	var lines string
	for i := 0; i < 105; i++ {
		lines += fmt.Sprintf("2026-04-13 10:00:00 1a%03d-0-XX <= user1@domA.com H=h U=u\n", i)
		lines += fmt.Sprintf("2026-04-13 10:00:00 1b%03d-0-XX <= user2@domB.com H=h U=u\n", i)
	}
	withMockOS(t, mailLogMock(t, lines))

	findings := CheckMailPerAccount(context.Background(), &config.Config{}, nil)
	if len(findings) != 2 {
		t.Fatalf("both domains above threshold should produce 2 findings, got %d", len(findings))
	}
	// Verify both domains are represented (map iteration order varies)
	msgs := findings[0].Message + " " + findings[1].Message
	if !strings.Contains(msgs, "domA.com") || !strings.Contains(msgs, "domB.com") {
		t.Errorf("findings should reference both domains, got %q", msgs)
	}
}

func TestCheckMailPerAccountSkipsBounces(t *testing.T) {
	// 200 bounce messages (<>) -- should be ignored
	var lines string
	for i := 0; i < 200; i++ {
		lines += fmt.Sprintf("2026-04-13 10:00:00 1x%03d-0-XX <= <> R=bounce T=remote\n", i)
	}
	withMockOS(t, mailLogMock(t, lines))

	findings := CheckMailPerAccount(context.Background(), &config.Config{}, nil)
	if len(findings) != 0 {
		t.Errorf("bounces should be ignored, got %d findings", len(findings))
	}
}

func TestCheckMailPerAccountSkipsNonOutgoing(t *testing.T) {
	// Lines without " <= " should be ignored (delivery lines use " => ")
	var lines string
	for i := 0; i < 200; i++ {
		lines += fmt.Sprintf("2026-04-13 10:00:00 1x%03d-0-XX => alice@example.com R=local T=local\n", i)
	}
	withMockOS(t, mailLogMock(t, lines))

	findings := CheckMailPerAccount(context.Background(), &config.Config{}, nil)
	if len(findings) != 0 {
		t.Errorf("delivery lines (=>) should be ignored, got %d findings", len(findings))
	}
}

func TestCheckMailPerAccountSkipsNoAtSign(t *testing.T) {
	// Sender with no @ sign should be ignored
	var lines string
	for i := 0; i < 200; i++ {
		lines += fmt.Sprintf("2026-04-13 10:00:00 1x%03d-0-XX <= localuser H=h U=u\n", i)
	}
	withMockOS(t, mailLogMock(t, lines))

	findings := CheckMailPerAccount(context.Background(), &config.Config{}, nil)
	if len(findings) != 0 {
		t.Errorf("senders without @ should be ignored, got %d findings", len(findings))
	}
}

func TestCheckMailPerAccountExactThreshold(t *testing.T) {
	// Exactly 100 messages -- at threshold boundary (>= 100)
	var lines string
	for i := 0; i < 100; i++ {
		lines += fmt.Sprintf("2026-04-13 10:00:00 1x%03d-0-XX <= user@boundary.com H=h U=u\n", i)
	}
	withMockOS(t, mailLogMock(t, lines))

	findings := CheckMailPerAccount(context.Background(), &config.Config{}, nil)
	if len(findings) != 1 {
		t.Fatalf("exact threshold (100) should produce 1 finding, got %d", len(findings))
	}
	if !strings.Contains(findings[0].Message, "boundary.com") {
		t.Errorf("message should reference boundary.com, got %q", findings[0].Message)
	}
}

func TestCheckMailPerAccountEmptyLog(t *testing.T) {
	withMockOS(t, mailLogMock(t, ""))

	findings := CheckMailPerAccount(context.Background(), &config.Config{}, nil)
	if len(findings) != 0 {
		t.Errorf("empty log should produce 0 findings, got %d", len(findings))
	}
}

func TestCheckMailPerAccountMixedLines(t *testing.T) {
	// Mix of outgoing, delivery, and irrelevant lines.
	// Keep total under 500 lines so tailFile captures everything.
	var lines string
	// 110 outgoing from flagged.com
	for i := 0; i < 110; i++ {
		lines += fmt.Sprintf("2026-04-13 10:00:00 1x%03d-0-XX <= user@flagged.com H=h U=u\n", i)
	}
	// Interleaved delivery and status lines (200 total)
	for i := 0; i < 100; i++ {
		lines += "2026-04-13 10:00:00 Completed\n"
		lines += "2026-04-13 10:00:00 1y000-0-XX => local@flagged.com R=local\n"
	}
	withMockOS(t, mailLogMock(t, lines))

	findings := CheckMailPerAccount(context.Background(), &config.Config{}, nil)
	if len(findings) != 1 {
		t.Fatalf("mixed lines should produce 1 finding, got %d", len(findings))
	}
	if !strings.Contains(findings[0].Message, "110") {
		t.Errorf("count should be 110, got %q", findings[0].Message)
	}
}
