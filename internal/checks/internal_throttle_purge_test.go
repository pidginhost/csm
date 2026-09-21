package checks

import (
	"context"
	"os"
	"reflect"
	"slices"
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

// Repeated skips must not leak completion state into a later real scan.
func TestInternalThrottleEventuallyRetiresFindings(t *testing.T) {
	for _, owner := range []namedCheck{
		{"email_weak_password", CheckEmailPasswords},
		{"email_forwarder_audit", CheckForwarders},
	} {
		for _, resume := range []string{"expired", "forced", "disabled"} {
			t.Run(owner.name+"/"+resume, func(t *testing.T) {
				db := withTestStore(t)
				withMockOS(t, &mockOS{
					glob:    func(string) ([]string, error) { return nil, nil },
					open:    func(string) (*os.File, error) { return nil, os.ErrNotExist },
					readDir: func(string) ([]os.DirEntry, error) { return nil, os.ErrNotExist },
				})
				// Exercise the runner reservation as well as the internal interval.
				previousThrottle, hadThrottle := checkThrottleMin[owner.name]
				checkThrottleMin[owner.name] = 60
				t.Cleanup(func() {
					if hadThrottle {
						checkThrottleMin[owner.name] = previousThrottle
					} else {
						delete(checkThrottleMin, owner.name)
					}
				})
				previousForce := ForceAll
				ForceAll = false
				t.Cleanup(func() { ForceAll = previousForce })
				stamp := func(at time.Time) {
					t.Helper()
					if err := db.SetEmailPWLastRefresh(at); err != nil {
						t.Fatal(err)
					}
					if err := db.SetMetaString("email:fwd_last_refresh", at.Format(time.RFC3339)); err != nil {
						t.Fatal(err)
					}
				}
				stamp(time.Now())
				st := newCrontabTestStore(t)
				var prior []alert.Finding
				for _, check := range runnerFindingNames[owner.name] {
					prior = append(prior, alert.Finding{Check: check, Severity: alert.Warning, Message: "prior finding"})
				}
				st.SetLatestFindings(prior)
				prior = st.LatestFindings()
				cfg := &config.Config{}
				cfg.EmailProtection.PasswordCheckIntervalMin = 1440
				ctx, gaps := WithCoverageGaps(context.Background())
				for cycle := 0; cycle < 3; cycle++ {
					findings, purge := runParallelWithContext(ctx, cfg, st, []namedCheck{owner}, "deep", true)
					if len(findings) != 0 || len(purge) != 0 {
						t.Fatalf("skip returned findings=%+v purge=%v", findings, purge)
					}
					StoreLatestScanFindingsWithCoverage(st, purge, findings, gaps.Snapshot())
					if got := st.LatestFindings(); !reflect.DeepEqual(got, prior) {
						t.Fatalf("skip changed prior findings: %+v", got)
					}
				}
				switch resume {
				case "expired":
					stamp(time.Now().Add(-48 * time.Hour))
				case "forced":
					ForceAll = true
				case "disabled":
					cfg.DisabledChecks = []string{owner.name}
				}
				findings, purge := runParallelWithContext(ctx, cfg, st, []namedCheck{owner}, "deep", true)
				for _, check := range runnerFindingNames[owner.name] {
					if !slices.Contains(purge, check) || gaps.Snapshot().IncompleteChecks[check] {
						t.Fatalf("completed check did not release %s: purge=%v coverage=%+v", check, purge, gaps.Snapshot())
					}
				}
				StoreLatestScanFindingsWithCoverage(st, purge, findings, gaps.Snapshot())
				if got := st.LatestFindings(); len(got) != 0 {
					t.Fatalf("completed scan retained findings: %+v", got)
				}
			})
		}
	}
}
