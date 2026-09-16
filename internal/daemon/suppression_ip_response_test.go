package daemon

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/attackdb"
	"github.com/pidginhost/csm/internal/challenge"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
	"github.com/pidginhost/csm/internal/store"
)

// Suppression rules mute notifications and stop file, process and account
// remediation for a false positive. They must not switch off IP enforcement:
// a check-wide rule written to keep brute-force alerts out of the mailbox
// left every brute-forcing address unblocked. An IP false positive is
// handled by allowlisting that address, not by muting the whole check.

const suppressedDetailsMarker = "suppressed-finding-details-marker"

type webhookRecorder struct {
	mu     sync.Mutex
	bodies []string
}

func (r *webhookRecorder) delivered(marker string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, b := range r.bodies {
		if strings.Contains(b, marker) {
			return true
		}
	}
	return false
}

func suppressionResponseSetup(t *testing.T) (*config.Config, *applyWiringBlocker, *webhookRecorder) {
	t.Helper()
	previousActive := config.Active()
	config.SetActive(nil)
	t.Cleanup(func() { config.SetActive(previousActive) })
	previousStore := store.Global()
	store.SetGlobal(nil)
	t.Cleanup(func() { store.SetGlobal(previousStore) })
	previousBlockedIPsFunc := alert.BlockedIPsFunc
	alert.BlockedIPsFunc = nil
	t.Cleanup(func() { alert.BlockedIPsFunc = previousBlockedIPsFunc })

	cfg, blocker := applyWiringSetup(t)
	cfg.AutoResponse.MaxBlocksPerHour = 100
	dryRun := false
	cfg.AutoResponse.DryRun = &dryRun
	cfg.Alerts.MaxPerHour = 100

	rec := &webhookRecorder{}
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(req.Body)
		rec.mu.Lock()
		rec.bodies = append(rec.bodies, string(body))
		rec.mu.Unlock()
	}))
	t.Cleanup(srv.Close)
	cfg.Alerts.Webhook.Enabled = true
	cfg.Alerts.Webhook.URL = srv.URL
	cfg.Alerts.Webhook.Type = "generic"
	return cfg, blocker, rec
}

func suppressionTestDaemon(t *testing.T, cfg *config.Config, rules []state.SuppressionRule) *Daemon {
	t.Helper()
	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if rules != nil {
		if err := st.SaveSuppressions(rules); err != nil {
			t.Fatal(err)
		}
	}
	return New(cfg, st, nil, "")
}

func smtpBruteForceFinding(ip string) alert.Finding {
	return alert.Finding{
		Severity:  alert.Critical,
		Check:     "smtp_bruteforce",
		Message:   "SMTP brute force from " + ip + ": 5 failed auths in 10m0s",
		Details:   suppressedDetailsMarker,
		SourceIP:  ip,
		Timestamp: time.Now(),
	}
}

func blockedIPs(b *applyWiringBlocker) []string {
	var ips []string
	for _, c := range b.calls {
		ips = append(ips, c.ip)
	}
	return ips
}

func checkWideSuppression(check string) []state.SuppressionRule {
	return []state.SuppressionRule{{ID: "r1", Check: check, Reason: "Visible in web UI only", CreatedAt: time.Now()}}
}

func TestDispatchBatchBlocksSuppressedBruteForceSource(t *testing.T) {
	cfg, blocker, rec := suppressionResponseSetup(t)
	d := suppressionTestDaemon(t, cfg, checkWideSuppression("smtp_bruteforce"))

	d.dispatchBatch([]alert.Finding{smtpBruteForceFinding("192.0.2.23")})

	if got := blockedIPs(blocker); len(got) != 1 || got[0] != "192.0.2.23" {
		t.Fatalf("suppressed brute-force source was not blocked: block calls %v", got)
	}
	if rec.delivered(suppressedDetailsMarker) {
		t.Fatal("suppressed finding was still delivered to the webhook")
	}
}

// Control for the webhook assertion above: without a rule the same finding is
// delivered, so a missing marker proves suppression and not a dead sink.
func TestDispatchBatchDeliversUnsuppressedBruteForceFinding(t *testing.T) {
	cfg, blocker, rec := suppressionResponseSetup(t)
	d := suppressionTestDaemon(t, cfg, nil)

	d.dispatchBatch([]alert.Finding{smtpBruteForceFinding("192.0.2.24")})

	if got := blockedIPs(blocker); len(got) != 1 || got[0] != "192.0.2.24" {
		t.Fatalf("unsuppressed brute-force source was not blocked: block calls %v", got)
	}
	if !rec.delivered(suppressedDetailsMarker) {
		t.Fatal("unsuppressed finding never reached the webhook")
	}
}

func TestDispatchBatchRecordsSuppressedAttackInThreatDB(t *testing.T) {
	cfg, _, _ := suppressionResponseSetup(t)
	db := attackdb.NewForTest(nil)
	previous := attackdb.Global()
	attackdb.SetGlobal(db)
	t.Cleanup(func() { attackdb.SetGlobal(previous) })
	d := suppressionTestDaemon(t, cfg, checkWideSuppression("smtp_bruteforce"))

	d.dispatchBatch([]alert.Finding{smtpBruteForceFinding("192.0.2.25")})

	rec := db.LookupIP("192.0.2.25")
	if rec == nil || rec.EventCount != 1 || rec.AttackCounts[attackdb.AttackBruteForce] != 1 {
		t.Fatalf("suppressed attack was not recorded in the threat database: %+v", rec)
	}
}

func TestDispatchBatchChallengeRoutesSuppressedSource(t *testing.T) {
	cfg, _, _ := suppressionResponseSetup(t)
	cfg.Challenge.Enabled = true
	d := suppressionTestDaemon(t, cfg, checkWideSuppression("wp_login_bruteforce"))
	d.ipList = challenge.NewIPList(t.TempDir())
	previous := checks.GetChallengeIPList()
	checks.SetChallengeIPList(d.ipList)
	t.Cleanup(func() { checks.SetChallengeIPList(previous) })

	d.dispatchBatch([]alert.Finding{{
		Severity:  alert.High,
		Check:     "wp_login_bruteforce",
		Message:   "WordPress login brute force from 192.0.2.26",
		SourceIP:  "192.0.2.26",
		Timestamp: time.Now(),
	}})

	if !d.ipList.Contains("192.0.2.26") {
		t.Fatal("suppressed brute-force source was not routed to the challenge")
	}
}

func TestInitialScanBlocksSuppressedBruteForceSource(t *testing.T) {
	cfg, blocker, rec := suppressionResponseSetup(t)
	d := suppressionTestDaemon(t, cfg, checkWideSuppression("smtp_bruteforce"))

	newFindings, _ := d.respondToInitialScan(cfg, []alert.Finding{smtpBruteForceFinding("192.0.2.27")})

	if got := blockedIPs(blocker); len(got) != 1 || got[0] != "192.0.2.27" {
		t.Fatalf("suppressed brute-force source was not blocked at startup: block calls %v", got)
	}
	for _, f := range newFindings {
		if f.Check == "smtp_bruteforce" {
			t.Fatal("suppressed finding was kept for startup alerting")
		}
	}
	if rec.delivered(suppressedDetailsMarker) {
		t.Fatal("suppressed finding was delivered during the startup scan")
	}
}
