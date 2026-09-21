package checks

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// Several checks carry their own interval on top of the scan cadence and
// return nothing on the cycles in between. Returning nothing without saying so
// reads to the runner as "ran, found nothing", which is a completed check --
// so the purge retires everything the check found on the cycle that did look.
// A weak mailbox password therefore disappears from the latest set for the
// whole interval and comes back when the check next runs.
func TestEmailPasswordIntervalSkipKeepsEarlierFindings(t *testing.T) {
	db := withTestStore(t)
	withMockOS(t, &mockOS{
		glob:    func(string) ([]string, error) { return nil, nil },
		open:    func(string) (*os.File, error) { return nil, os.ErrNotExist },
		readDir: func(string) ([]os.DirEntry, error) { return nil, os.ErrNotExist },
	})
	st := newCrontabTestStore(t)
	st.SetLatestFindings([]alert.Finding{{
		Check:    "email_weak_password",
		Severity: alert.Critical,
		Message:  "weak password for mailbox@example.test",
	}})

	// The check completed recently, so this cycle falls inside its interval.
	if err := db.SetEmailPWLastRefresh(time.Now()); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{}
	cfg.EmailProtection.PasswordCheckIntervalMin = 1440
	findings, purge := runParallel(cfg, st, []namedCheck{
		{"email_weak_password", CheckEmailPasswords},
	}, "deep", true)
	StoreLatestScanFindings(st, purge, findings)

	if !containsFindingCheck(st.LatestFindings(), "email_weak_password") {
		t.Fatalf("a cycle skipped by the check's own interval retired the earlier finding: %+v", st.LatestFindings())
	}
}

// The forwarder audit carries the same interval and had the same gap.
func TestForwarderIntervalSkipDeclaresSkippedScope(t *testing.T) {
	db := withTestStore(t)
	withMockOS(t, &mockOS{
		glob:    func(string) ([]string, error) { return nil, nil },
		open:    func(string) (*os.File, error) { return nil, os.ErrNotExist },
		readDir: func(string) ([]os.DirEntry, error) { return nil, os.ErrNotExist },
	})
	if err := db.SetMetaString("email:fwd_last_refresh", time.Now().Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{}
	cfg.EmailProtection.PasswordCheckIntervalMin = 1440
	ctx, collector := withIncompleteCheckCollector(context.Background())
	CheckForwarders(ctx, cfg, nil)

	if !collector.contains("email_forwarder_audit") {
		t.Fatal("a cycle skipped by the forwarder interval reported complete, so the runner may retire forwarder findings it never looked at")
	}
}
