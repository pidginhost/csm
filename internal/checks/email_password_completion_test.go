package checks

import (
	"context"
	"net/http"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

func TestEmailPasswordIncompleteScanPreservesFindingsAndRetries(t *testing.T) {
	db := withTestStore(t)
	withWeakPasswords(t, []string{"fixture-secret-123"})
	withTestHIBP(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	path := t.TempDir() + "/shadow"
	withMockOS(t, &mockOS{
		glob: func(string) ([]string, error) { return []string{"/home/alice/etc/example.test/shadow"}, nil },
		open: func(string) (*os.File, error) { return os.Open(path) },
	})
	s := newCrontabTestStore(t)
	s.SetLatestFindings([]alert.Finding{{Check: "email_weak_password", Severity: alert.Critical, Message: "prior weak password"}})
	cfg := &config.Config{}
	cfg.EmailProtection.PasswordCheckIntervalMin = 1440
	const key = "email:pwaudit:alice:mailbox@example.test"
	for _, stored := range []string{"{UNKNOWN}private-fixture", "$6$rounds=1000001$salt$" + strings.Repeat("a", 86), "{SHA}invalid"} {
		// Each hash type is exercised on its own run, so the interval the
		// previous iteration stamped must not skip this one.
		if err := db.SetEmailPWLastRefresh(time.Time{}); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("mailbox:"+stored+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
		oldFP := hashFingerprint(stored)
		if err := db.SetMetaString(key, oldFP); err != nil {
			t.Fatal(err)
		}
		findings, purge := runParallel(cfg, s, []namedCheck{{"email_weak_password", CheckEmailPasswords}}, "deep", true)
		StoreLatestScanFindings(s, purge, findings)
		got := s.LatestFindings()
		counts := make(map[string]int)
		for _, f := range got {
			counts[f.Check]++
		}
		if len(got) != 2 || counts["email_weak_password"] != 1 || counts["email_password_audit_incomplete"] != 1 {
			t.Fatalf("incomplete scan lost prior findings or accumulated status rows: %+v", got)
		}
		if db.GetMetaString(key) != oldFP {
			t.Fatal("incomplete scan recorded successful verification")
		}
		// These three hashes are unauditable by construction, not transient.
		// Rerunning cannot change the outcome, so the scan stamps its refresh
		// and honours the interval instead of redoing every mailbox next
		// cycle; the warning above is what keeps them visible.
		if db.GetEmailPWLastRefresh().IsZero() {
			t.Fatal("a scan whose only failures are unauditable hashes did not stamp its refresh, so the whole mailbox set is re-verified every cycle")
		}
		for cycle := 0; cycle < 2; cycle++ {
			ctx, gaps := WithCoverageGaps(context.Background())
			findings, purge := runParallelWithContext(ctx, cfg, s, []namedCheck{{"email_weak_password", CheckEmailPasswords}}, "deep", true)
			if len(findings) != 0 || len(purge) != 0 {
				t.Fatalf("skipped cycle returned findings=%+v purge=%v", findings, purge)
			}
			if !gaps.Snapshot().IncompleteChecks["email_password_audit_incomplete"] {
				t.Fatal("skipped warning is not protected by scan coverage")
			}
			StoreLatestScanFindingsWithCoverage(s, purge, findings, gaps.Snapshot())
			if latest := s.LatestFindings(); !reflect.DeepEqual(latest, got) {
				t.Fatalf("skipped cycle changed findings: got %+v, want %+v", latest, got)
			}
		}
	}
	if err := db.SetEmailPWLastRefresh(time.Time{}); err != nil {
		t.Fatal(err)
	}
	// A supported hash must be retried even if an earlier version cached it.
	const recovered = "{PLAIN}fixture-secret-123"
	if err := os.WriteFile(path, []byte("mailbox:"+recovered+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := db.SetMetaString(key, hashFingerprint(recovered)); err != nil {
		t.Fatal(err)
	}
	findings, purge := runParallel(cfg, s, []namedCheck{{"email_weak_password", CheckEmailPasswords}}, "deep", true)
	StoreLatestScanFindings(s, purge, findings)
	got := s.LatestFindings()
	if len(got) != 1 || got[0].Check != "email_weak_password" || got[0].Mailbox != "mailbox@example.test" {
		t.Fatalf("recovery did not replace old state with confirmed weakness: %+v", got)
	}
	if db.GetMetaString(key) != "v2:"+hashFingerprint(recovered) || db.GetEmailPWLastRefresh().IsZero() {
		t.Fatal("complete scan failed to record verification")
	}
}

func TestEmailPasswordUnsupportedHashDoesNotPreventOtherMailboxes(t *testing.T) {
	withTestStore(t)
	withWeakPasswords(t, []string{"fixture-secret-123"})
	withTestHIBP(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	path := t.TempDir() + "/shadow"
	if err := os.WriteFile(path, []byte("unknown:{UNKNOWN}private-fixture\nknown:{PLAIN}fixture-secret-123\n"), 0600); err != nil {
		t.Fatal(err)
	}
	withMockOS(t, &mockOS{
		glob: func(string) ([]string, error) { return []string{"/home/alice/etc/example.test/shadow"}, nil },
		open: func(string) (*os.File, error) { return os.Open(path) },
	})
	ctx, incomplete := withIncompleteCheckCollector(context.Background())
	findings := CheckEmailPasswords(ctx, &config.Config{}, nil)
	counts := make(map[string]int)
	for _, f := range findings {
		counts[f.Check]++
	}
	if len(findings) != 2 || counts["email_weak_password"] != 1 || counts["email_password_audit_incomplete"] != 1 || !incomplete.contains("email_weak_password") {
		t.Fatalf("partial audit returned %+v", findings)
	}
}
