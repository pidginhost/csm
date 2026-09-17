package checks

import (
	"errors"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

func TestAutoBlockRetryPolicyWithdrawalIsNotLoss(t *testing.T) {
	cfg := autoBlockQueueFixture(t, func() error { t.Error("withdrawn evidence reached firewall"); return nil })
	cfg.AutoResponse.BlockCpanelLogins = false
	seed := &blockState{}
	for _, check := range []string{"", "ftp_login", "cpanel_file_upload_realtime", "webmail_login_realtime", "api_auth_failure_realtime", "mail_account_compromised"} {
		seed.Pending = append(seed.Pending, pendingIP{IP: "192.0.2.140", Reason: "old decision", Check: check, Severity: alert.High, QueuedAt: time.Now()})
	}
	if err := writeBlockState(cfg.StatePath, seed); err != nil {
		t.Fatal(err)
	}
	restoreWrite := failRetryWrite(t, cfg.StatePath)
	if actions := AutoBlockIPs(cfg, nil); len(actions) != 0 {
		t.Fatalf("policy withdrawal created actions: %+v", actions)
	}
	pending, candidates := retryQueueRows(t, time.Now())
	if pending.Depth != 6 || pending.InFlight != 0 || pending.DroppedTotal != 0 || pending.Reason != "state_io" || candidates.Depth != 0 || candidates.InFlight != 0 || candidates.DroppedTotal != 0 {
		t.Fatalf("failed withdrawal persistence lost ownership: pending=%+v candidates=%+v", pending, candidates)
	}
	restoreWrite()
	if actions := AutoBlockIPs(cfg, nil); len(actions) != 0 {
		t.Fatalf("retained withdrawal created actions: %+v", actions)
	}
	pending, candidates = retryQueueRows(t, time.Now())
	if pending.Depth != 0 || pending.InFlight != 0 || pending.DroppedTotal != 0 || pending.Status != "ok" || candidates.DroppedTotal != 0 {
		t.Fatalf("expected policy refusal became protection loss: pending=%+v candidates=%+v", pending, candidates)
	}
	actual, err := readBlockState(cfg.StatePath)
	if err != nil || len(actual.Pending) != 0 || len(actual.IPs) != 0 || actual.BlocksThisHour != 0 {
		t.Fatalf("withdrawal changed block policy: state=%+v err=%v", actual, err)
	}
}

// A post-rename readback must distinguish records with the same address and
// timestamp but different eligibility. The refused record cannot own the retry.
func TestAutoBlockRetryIdentityIncludesEligibility(t *testing.T) {
	for _, difference := range []string{"check", "severity"} {
		t.Run(difference, func(t *testing.T) {
			calls := 0
			cfg := autoBlockQueueFixture(t, func() error { calls++; return errors.New("synthetic block failure") })
			now := time.Now().Truncate(time.Second)
			allowed := pendingIP{IP: "192.0.2.141", Reason: "eligible", Check: "mail_account_compromised", Severity: alert.Critical, QueuedAt: now}
			refused := allowed
			refused.Reason = "withdrawn"
			if difference == "check" {
				refused.Check = "ftp_login"
			} else {
				refused.Severity = alert.High
			}
			if err := writeBlockState(cfg.StatePath, &blockState{Pending: []pendingIP{refused, allowed}}); err != nil {
				t.Fatal(err)
			}
			previous := persistAutoBlockState
			t.Cleanup(func() { persistAutoBlockState = previous })
			persistAutoBlockState = func(path string, state *blockState) error {
				if err := writeBlockState(path, state); err != nil {
					return err
				}
				return errors.New("synthetic post-rename failure")
			}
			AutoBlockIPs(cfg, nil)
			pending, candidates := retryQueueRows(t, time.Now())
			if calls != 1 || pending.Depth != 1 || pending.InFlight != 0 || pending.DroppedTotal != 0 || candidates.DroppedTotal != 0 {
				t.Fatalf("readback confused refused and retained evidence: calls=%d pending=%+v candidates=%+v", calls, pending, candidates)
			}
			actual, err := readBlockState(cfg.StatePath)
			if err != nil || len(actual.Pending) != 1 || actual.Pending[0].Check != allowed.Check || actual.Pending[0].Severity != allowed.Severity || !actual.Pending[0].QueuedAt.Equal(now) {
				t.Fatalf("eligible wire record changed: state=%+v err=%v", actual, err)
			}
			persistAutoBlockState = previous
			SetIPBlocker(retryQueueBlocker{block: func(string) error { calls++; return nil }})
			actions := AutoBlockIPs(cfg, nil)
			pending, candidates = retryQueueRows(t, time.Now())
			if calls != 2 || len(actions) != 1 || pending.Depth != 0 || pending.DroppedTotal != 0 || candidates.DroppedTotal != 0 {
				t.Fatalf("eligible retry failed to complete: calls=%d actions=%d pending=%+v candidates=%+v", calls, len(actions), pending, candidates)
			}
		})
	}
}
