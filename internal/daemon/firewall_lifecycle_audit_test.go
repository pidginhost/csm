package daemon

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/blockdigest"
	"github.com/pidginhost/csm/internal/challenge"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/state"
	"github.com/pidginhost/csm/internal/store"
)

type lifecycleAuditBlocker struct {
	applyWiringBlocker
	outcome firewall.BlockOutcome
	err     error
}

func (b *lifecycleAuditBlocker) DurableActionsEnabled() bool { return true }
func (b *lifecycleAuditBlocker) BlockIPRequest(firewall.ActionRequest, *firewall.ScanAdmission) (firewall.BlockOutcome, error) {
	return b.outcome, b.err
}

func lifecycleAuditDaemon(t *testing.T, outcome firewall.BlockOutcome, resultErr error) (*Daemon, *store.DB, *int) {
	t.Helper()
	cfg, _ := applyWiringSetup(t)
	checks.SetIPBlocker(&lifecycleAuditBlocker{outcome: outcome, err: resultErr})
	db, err := store.Open(cfg.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	previousDB := store.Global()
	store.SetGlobal(db)
	t.Cleanup(func() {
		store.SetGlobal(previousDB)
		_ = db.Close()
	})
	history, err := state.Open(cfg.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	d := New(cfg, history, nil, "")
	d.blockDigest = blockdigest.New(blockdigest.Options{SendOn: "any", Interval: time.Hour, MinBlock: 1})
	dispatched := new(int)
	previousHook := alert.CentralHook
	alert.SetCentralHook(func(alert.Finding) { *dispatched++ })
	t.Cleanup(func() { alert.SetCentralHook(previousHook) })
	return d, db, dispatched
}

func TestIncidentVerifiedAuditFailureRetainsOutcomeAndEvidence(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		live bool
	}{
		{name: "verified", err: firewall.ErrActionAuditPending, live: true},
		{name: "unknown", err: firewall.ErrActionUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, db, dispatched := lifecycleAuditDaemon(t, firewall.BlockOutcomeLive, tc.err)
			live, err := d.applyIncidentSprayBlock("203.0.113.81", "incident: observed abuse", time.Hour, "finding-incident")
			if live != tc.live || !errors.Is(err, tc.err) {
				t.Fatalf("live=%t err=%v, want live=%t and %v", live, err, tc.live, tc.err)
			}
			want := 0
			if tc.live {
				want = 1
			}
			if _, total := db.ReadHistory(10, 0); total != want {
				t.Fatalf("history total=%d, want %d", total, want)
			}
			if digest := d.blockDigest.Drain(); digest.Total != want || *dispatched != want {
				t.Fatalf("digest=%d dispatch=%d, want %d", digest.Total, *dispatched, want)
			}
		})
	}
}

func TestChallengeVerifiedAuditFailureRetainsEvidence(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want int
	}{
		{name: "verified", err: firewall.ErrActionAuditPending, want: 1},
		{name: "unknown", err: firewall.ErrActionUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, db, dispatched := lifecycleAuditDaemon(t, firewall.BlockOutcomeLive, tc.err)
			d.ipList = challenge.NewIPList(t.TempDir())
			d.ipList.Add("203.0.113.82", "observed abuse", -time.Minute)
			before := challengeEscalatedCount()
			stderr := captureAppliedBlockStderr(t, func() { d.escalateExpiredChallenges(time.Hour) })
			if !strings.Contains(stderr, tc.err.Error()) {
				t.Fatalf("degraded action error was hidden: %q", stderr)
			}
			if _, total := db.ReadHistory(10, 0); total != tc.want {
				t.Fatalf("history total=%d, want %d", total, tc.want)
			}
			if digest := d.blockDigest.Drain(); digest.Total != tc.want || *dispatched != tc.want {
				t.Fatalf("digest=%d dispatch=%d, want %d", digest.Total, *dispatched, tc.want)
			}
			if got := challengeEscalatedCount() - before; got != tc.want {
				t.Fatalf("live challenge escalations=%d, want %d", got, tc.want)
			}
		})
	}
}
