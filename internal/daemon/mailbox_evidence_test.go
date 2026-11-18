package daemon

import (
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/store"
)

// evidenceCase stands in for a cPanel host with a mailbox CSM can suspend
// and returns the uapi calls made.
func evidenceCase(t *testing.T) (*store.DB, *[][]string) {
	t.Helper()
	db := withMailboxStore(t)
	withMailBackendHost(t, true)
	withUserdomains(t, "victim.example: cpuser\n")
	t.Cleanup(checks.SetAccountOwnerLookupForTest(func(domain string) (string, bool) {
		return "cpuser", domain == "victim.example"
	}))
	calls := stubMailboxActions(t, func([]string) ([]byte, error) { return uapiOK() })
	stubAccountHold(t, true)
	captureActionRecords(t)
	return db, calls
}

func dryRunConfig() *config.Config {
	cfg := &config.Config{}
	cfg.AutoResponse.Enabled = true
	dry := true
	cfg.AutoResponse.DryRun = &dry
	return cfg
}

func newCountry(country string, at time.Time) mailboxSignal {
	return mailboxSignal{kind: signalNewCountry, key: country, at: at,
		detail: "webmail login from " + country + " (203.0.113.7)"}
}

func onlyIncident(t *testing.T, findings []alert.Finding) alert.Finding {
	t.Helper()
	if len(findings) != 1 {
		t.Fatalf("findings = %+v, want exactly one incident", findings)
	}
	f := findings[0]
	if f.Check != "email_mailbox_compromise" || f.Severity != alert.Critical ||
		f.Mailbox != "real@victim.example" || f.Domain != "victim.example" {
		t.Fatalf("incident = %+v", f)
	}
	return f
}

func TestMailboxEvidence_BelowThresholdOnlyRecords(t *testing.T) {
	db, calls := evidenceCase(t)
	at := time.Now()

	if got := observeMailboxSignal(eximAutoHoldConfig(), "Real@Victim.example", newCountry("DE", at)); len(got) != 0 {
		t.Fatalf("one new country reported %+v, want only evidence", got)
	}
	if len(*calls) != 0 {
		t.Fatalf("uapi calls = %v, want none below the threshold", *calls)
	}
	e, err := db.UpdateMailboxEvidence("real@victim.example", func(*store.MailboxEvidence) {})
	if err != nil || len(e.Signals) != 1 || e.ReportedAt != nil || !e.LastNewCountry.Equal(at) {
		t.Fatalf("ledger = %+v, %v", e, err)
	}
}

func TestMailboxEvidence_SuspendsOnceAndReportsOnce(t *testing.T) {
	_, calls := evidenceCase(t)
	cfg := eximAutoHoldConfig()
	at := time.Now()

	observeMailboxSignal(cfg, "real@victim.example", newCountry("DE", at.Add(-3*time.Hour)))
	f := onlyIncident(t, observeMailboxSignal(cfg, "real@victim.example", newCountry("BR", at)))
	if !strings.HasPrefix(f.Message, "Suspended mailbox real@victim.example: compromise evidence scored 4") {
		t.Fatalf("message = %q", f.Message)
	}
	for _, want := range []string{"webmail login from DE (203.0.113.7)", "webmail login from BR (203.0.113.7)", "Email page, Suspended tab"} {
		if !strings.Contains(f.Details, want) {
			t.Fatalf("details missing %q:\n%s", want, f.Details)
		}
	}
	if f.TenantID != "cpuser" {
		t.Fatalf("tenant = %q, want the mailbox's cPanel account", f.TenantID)
	}
	if len(*calls) != 2 {
		t.Fatalf("uapi calls = %v, want one suspension (login and outgoing)", *calls)
	}

	// More evidence of the same incident adds to the ledger, never a second
	// report or response.
	for _, s := range []mailboxSignal{
		newCountry("US", at.Add(time.Minute)),
		{kind: signalForgedSender, key: "other.example", at: at.Add(2 * time.Minute), detail: "sent as x@other.example"},
	} {
		if got := observeMailboxSignal(cfg, "real@victim.example", s); len(got) != 0 {
			t.Fatalf("repeat reported %+v", got)
		}
	}
	if len(*calls) != 2 {
		t.Fatalf("uapi calls after repeats = %v, want still one suspension", *calls)
	}
}

func TestMailboxEvidence_DryRunAndDisabledReportWouldSuspendOnce(t *testing.T) {
	for name, cfg := range map[string]*config.Config{
		"dry-run":  dryRunConfig(),
		"disabled": {},
	} {
		t.Run(name, func(t *testing.T) {
			_, calls := evidenceCase(t)
			at := time.Now()
			observeMailboxSignal(cfg, "real@victim.example", newCountry("DE", at.Add(-time.Hour)))
			f := onlyIncident(t, observeMailboxSignal(cfg, "real@victim.example", newCountry("BR", at)))
			if !strings.HasPrefix(f.Message, "Would suspend mailbox real@victim.example") {
				t.Fatalf("message = %q", f.Message)
			}
			if got := observeMailboxSignal(cfg, "real@victim.example", newCountry("US", at)); len(got) != 0 {
				t.Fatalf("repeat reported %+v", got)
			}
			if len(*calls) != 0 {
				t.Fatalf("uapi calls = %v, want none", *calls)
			}
		})
	}
}

func TestMailboxEvidence_Score(t *testing.T) {
	now := time.Now()
	sig := func(kind, key string, first time.Time) store.MailboxSignal {
		return store.MailboxSignal{Kind: kind, Key: key, First: first, Last: now, Count: 1}
	}
	cases := []struct {
		name string
		e    store.MailboxEvidence
		want int
	}{
		{"one country", store.MailboxEvidence{Signals: []store.MailboxSignal{sig(signalNewCountry, "DE", now)}}, 2},
		{"two countries a day apart", store.MailboxEvidence{Signals: []store.MailboxSignal{
			sig(signalNewCountry, "DE", now.Add(-25*time.Hour)), sig(signalNewCountry, "BR", now)}}, 2},
		{"two countries within a day", store.MailboxEvidence{Signals: []store.MailboxSignal{
			sig(signalNewCountry, "DE", now.Add(-23*time.Hour)), sig(signalNewCountry, "BR", now)}}, 4},
		{"forged sender once per kind", store.MailboxEvidence{Signals: []store.MailboxSignal{
			sig(signalForgedSender, "a.example", now), sig(signalForgedSender, "b.example", now)}}, 3},
		{"bulk and reputation", store.MailboxEvidence{Signals: []store.MailboxSignal{
			sig(signalBulkRecipients, "", now), sig(signalReputation, "192.0.2.1", now)}}, 3},
		{"redirect alone", store.MailboxEvidence{Signals: []store.MailboxSignal{
			sig(signalRedirect, "x@freemail.example", now.Add(-90*24*time.Hour))}}, 2},
		{"redirect after a foreign login", store.MailboxEvidence{
			LastNewCountry: now.Add(-25 * 24 * time.Hour),
			Signals:        []store.MailboxSignal{sig(signalRedirect, "x@freemail.example", now.Add(-2*24*time.Hour))}}, 3},
		{"redirect long after a foreign login", store.MailboxEvidence{
			LastNewCountry: now.Add(-80 * 24 * time.Hour),
			Signals:        []store.MailboxSignal{sig(signalRedirect, "x@freemail.example", now.Add(-20*24*time.Hour))}}, 2},
	}
	for _, c := range cases {
		if got := mailboxEvidenceScore(c.e); got != c.want {
			t.Errorf("%s: score = %d, want %d", c.name, got, c.want)
		}
	}
}

func TestMailboxEvidence_ExpiredEvidenceEndsTheIncident(t *testing.T) {
	db, calls := evidenceCase(t)
	cfg := dryRunConfig()
	at := time.Now()
	observeMailboxSignal(cfg, "real@victim.example", newCountry("DE", at))
	onlyIncident(t, observeMailboxSignal(cfg, "real@victim.example", newCountry("BR", at)))

	if err := pruneMailboxEvidence(db, at.Add(8*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	e, err := db.UpdateMailboxEvidence("real@victim.example", func(*store.MailboxEvidence) {})
	if err != nil || len(e.Signals) != 0 || e.ReportedAt != nil {
		t.Fatalf("ledger after expiry = %+v, %v; want signals and report gone", e, err)
	}
	if !e.LastNewCountry.Equal(at) {
		t.Fatalf("expiry dropped the last foreign login a redirect is dated against: %+v", e)
	}

	// New evidence after the old incident expired is a new incident.
	observeMailboxSignal(cfg, "real@victim.example", newCountry("DE", time.Now()))
	onlyIncident(t, observeMailboxSignal(cfg, "real@victim.example", newCountry("BR", time.Now())))
	if len(*calls) != 0 {
		t.Fatalf("dry-run acted: %v", *calls)
	}
}

func TestMailboxEvidence_StaleSignalDoesNotCount(t *testing.T) {
	db, _ := evidenceCase(t)
	cfg := dryRunConfig()
	old := time.Now().Add(-8 * 24 * time.Hour)
	observeMailboxSignal(cfg, "real@victim.example", newCountry("DE", old))
	if got := observeMailboxSignal(cfg, "real@victim.example", newCountry("BR", old)); len(got) != 0 {
		t.Fatalf("replayed week-old evidence reported %+v", got)
	}
	e, err := db.UpdateMailboxEvidence("real@victim.example", func(*store.MailboxEvidence) {})
	if err != nil || len(e.Signals) != 0 {
		t.Fatalf("ledger = %+v, %v; want stale signals dropped", e, err)
	}
}

func TestMailboxEvidence_ReleaseForgetsEvidence(t *testing.T) {
	db, _ := evidenceCase(t)
	cfg := eximAutoHoldConfig()
	at := time.Now()
	observeMailboxSignal(cfg, "real@victim.example", newCountry("DE", at))
	onlyIncident(t, observeMailboxSignal(cfg, "real@victim.example", newCountry("BR", at)))

	if err := releaseMailboxSuspension(store.MailboxSuspensionID("cpanel", "real@victim.example"), "admin"); err != nil {
		t.Fatal(err)
	}
	e, err := db.UpdateMailboxEvidence("real@victim.example", func(*store.MailboxEvidence) {})
	if err != nil || len(e.Signals) != 0 || e.ReportedAt != nil || !e.LastNewCountry.IsZero() {
		t.Fatalf("ledger after release = %+v, %v; want empty", e, err)
	}
}

func TestMailboxEvidence_RedirectNamedInIncident(t *testing.T) {
	_, _ = evidenceCase(t)
	cfg := eximAutoHoldConfig()
	at := time.Now()
	observeMailboxSignal(cfg, "real@victim.example", mailboxSignal{
		kind: signalRedirect, key: "x@freemail.example", at: at, since: at.Add(-48 * time.Hour),
		detail: "Sieve script /home/cpuser/mail/victim.example/real/sieve/roundcube.sieve redirects all mail to x@freemail.example",
	})
	f := onlyIncident(t, observeMailboxSignal(cfg, "real@victim.example", newCountry("DE", at)))
	if !strings.Contains(f.Details, "/home/cpuser/mail/victim.example/real/sieve/roundcube.sieve redirects all mail to x@freemail.example") ||
		!strings.Contains(f.Details, "remove it after review") {
		t.Fatalf("details = %s", f.Details)
	}
}

func TestMailboxEvidence_IgnoresNonMailboxSubjects(t *testing.T) {
	_, calls := evidenceCase(t)
	for _, subject := range []string{"", "cpuser", "victim.example"} {
		if got := observeMailboxSignal(eximAutoHoldConfig(), subject, newCountry("DE", time.Now())); len(got) != 0 {
			t.Fatalf("subject %q reported %+v", subject, got)
		}
	}
	if len(*calls) != 0 {
		t.Fatalf("uapi calls = %v", *calls)
	}
}

func TestPruneSenderHistoryExpiresMailboxEvidence(t *testing.T) {
	db, _ := evidenceCase(t)
	at := time.Now()
	observeMailboxSignal(dryRunConfig(), "real@victim.example", newCountry("DE", at))
	pruneSenderHistory(at.Add(8 * 24 * time.Hour))
	e, err := db.UpdateMailboxEvidence("real@victim.example", func(*store.MailboxEvidence) {})
	if err != nil || len(e.Signals) != 0 {
		t.Fatalf("ledger after the daily prune = %+v, %v; want expired signals gone", e, err)
	}
}

func TestMailboxCompromiseFindingCarriesTenant(t *testing.T) {
	evidenceCase(t)
	at := time.Now()
	observeMailboxSignal(dryRunConfig(), "real@victim.example", newCountry("DE", at))
	f := onlyIncident(t, observeMailboxSignal(dryRunConfig(), "real@victim.example", newCountry("BR", at)))
	if f.TenantID != "cpuser" || len(f.Claims) != 1 || f.Claims[0].Value != "real@victim.example" {
		t.Fatalf("tenant = %q, claims = %+v; want the owning account and the mailbox claim", f.TenantID, f.Claims)
	}
}

func TestMailboxEvidence_RotatingKeysStayBounded(t *testing.T) {
	db, _ := evidenceCase(t)
	at := time.Now()
	for i := range 3 * mailboxSignalKeysPerKind {
		observeMailboxSignal(dryRunConfig(), "real@victim.example", mailboxSignal{
			kind: signalForgedSender, key: strings.Repeat("x", i+1) + ".example", at: at,
			detail: strings.Repeat("d", 4096),
		})
	}
	e, err := db.UpdateMailboxEvidence("real@victim.example", func(*store.MailboxEvidence) {})
	if err != nil || len(e.Signals) != mailboxSignalKeysPerKind {
		t.Fatalf("signals = %d, %v; want the per-kind cap %d", len(e.Signals), err, mailboxSignalKeysPerKind)
	}
	total := 0
	for _, s := range e.Signals {
		total += s.Count
		if len(s.Detail) > 303 {
			t.Fatalf("detail kept %d bytes", len(s.Detail))
		}
	}
	if total != 3*mailboxSignalKeysPerKind {
		t.Fatalf("counted %d sightings, want every one", total)
	}
}
