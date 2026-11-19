package daemon

import (
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/actionlog"
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
	e, err := db.GetMailboxEvidence("real@victim.example")
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
		return store.MailboxSignal{Kind: kind, Key: key, First: first, Last: first, Count: 1}
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
	e, err := db.GetMailboxEvidence("real@victim.example")
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
	e, err := db.GetMailboxEvidence("real@victim.example")
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
	e, err := db.GetMailboxEvidence("real@victim.example")
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
	for _, subject := range []string{"", "cpuser", "victim.example", "@victim.example", "missing@", "one@two@victim.example"} {
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
	e, err := db.GetMailboxEvidence("real@victim.example")
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
	e, err := db.GetMailboxEvidence("real@victim.example")
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

func TestMailboxEvidence_QueuedBeforeRelease(t *testing.T) {
	db, _ := evidenceCase(t)
	row := cpanelRow("real@victim.example", store.AppliedSuspendLogin)
	putRows(t, db, row)
	at := time.Now()
	cfg := eximAutoHoldConfig()
	observeMailboxSignal(cfg, row.Subject, newCountry("DE", at))
	entered, finish := make(chan struct{}), make(chan struct{})
	withLifecycleBackend(t, lifecycleBackend{
		suspendFn: func(mailboxCompromise) (store.MailboxSuspension, error) { return row, nil },
		releaseFn: func(store.MailboxSuspension, string) error {
			close(entered)
			<-finish
			return nil
		},
	})
	released := make(chan error, 1)
	go func() { released <- releaseMailboxSuspension(row.ID, "admin") }()
	<-entered
	done := make(chan []alert.Finding, 1)
	var returned atomic.Bool
	go func() {
		done <- observeMailboxSignal(cfg, row.Subject, newCountry("BR", at))
		returned.Store(true)
	}()
	waitMailLifecycle(t, row.ID, returned.Load)
	close(finish)
	if err := <-released; err != nil {
		t.Fatal(err)
	}
	if got := <-done; len(got) != 0 {
		t.Errorf("reported evidence cleared by release: %+v", got)
	}
	observeMailboxSignal(cfg, row.Subject, newCountry("BR", at))
	if got := observeMailboxSignal(cfg, row.Subject, newCountry("DE", time.Now())); len(got) != 0 {
		t.Errorf("used a pre-release observation: %+v", got)
	}
}

func TestMailboxEvidence_ConcurrentDryRun(t *testing.T) {
	_, calls := evidenceCase(t)
	sink := captureActionRecords(t)
	cfg, at := dryRunConfig(), time.Now()
	const mailbox = "real@victim.example"
	observeMailboxSignal(cfg, mailbox, newCountry("DE", at))
	const workers = 12
	start := make(chan struct{})
	done := make(chan []alert.Finding, workers)
	for range workers {
		go func() {
			<-start
			done <- observeMailboxSignal(cfg, mailbox, newCountry("BR", at))
		}()
	}
	close(start)
	var findings []alert.Finding
	for range workers {
		findings = append(findings, (<-done)...)
	}
	onlyIncident(t, findings)
	if len(*calls) != 0 || len(sink.records) != 1 || sink.records[0].Result != actionlog.DryRun || sink.records[0].Target != mailbox {
		t.Fatalf("calls=%v, audit=%+v", *calls, sink.records)
	}
}

func TestMailboxEvidence_DescribesAppliedRestrictions(t *testing.T) {
	for _, tc := range []struct {
		part, want string
		err        error
	}{
		{store.AppliedSuspendLogin, "Only logins", nil},
		{store.AppliedSuspendOutgoing, "Only outgoing", nil},
		{store.AppliedHoldOutgoing, "account", nil},
		{store.AppliedDisableSignIn, "Sessions", nil},
		{"", "already restricted", errMailAlreadyRestricted},
		{"", "Could not suspend", errors.New("unavailable")},
	} {
		t.Run(tc.want, func(t *testing.T) {
			evidenceCase(t)
			cfg, at := eximAutoHoldConfig(), time.Now()
			row := cpanelRow("real@victim.example", tc.part)
			withLifecycleBackend(t, lifecycleBackend{suspendFn: func(mailboxCompromise) (store.MailboxSuspension, error) { return row, tc.err }})
			observeMailboxSignal(cfg, row.Subject, newCountry("DE", at))
			f := onlyIncident(t, observeMailboxSignal(cfg, row.Subject, newCountry("BR", at)))
			if !strings.Contains(f.Message+" "+f.Details, tc.want) || tc.err != nil && strings.Contains(f.Details, "Suspended tab") {
				t.Errorf("incorrect response: %+v", f)
			}
		})
	}
}

func TestMailboxEvidence_OldRedirectBeforeLogin(t *testing.T) {
	db, _ := evidenceCase(t)
	at := time.Now()
	mailbox := "real@victim.example"
	_, err := db.UpdateMailboxEvidence(mailbox, func(e *store.MailboxEvidence) { e.LastNewCountry = at.Add(-10 * 24 * time.Hour) })
	if err != nil {
		t.Fatal(err)
	}
	observeMailboxSignal(dryRunConfig(), mailbox, mailboxSignal{kind: signalRedirect, key: "other.example", at: at, since: at.Add(-20 * 24 * time.Hour)})
	if got := observeMailboxSignal(dryRunConfig(), mailbox, mailboxSignal{kind: signalReputation, at: at}); len(got) != 0 {
		t.Errorf("redirect predating login raised incident: %+v", got)
	}
}

func TestMailboxEvidence_BoundsInputAndKeepsAccurateDetails(t *testing.T) {
	db, _ := evidenceCase(t)
	mailbox := "real@victim.example"
	at := time.Now()
	cfg := dryRunConfig()
	for i := range mailboxSignalKeysPerKind + 3 {
		key := strings.Repeat("a", i+600) + ".example"
		observeMailboxSignal(cfg, mailbox, mailboxSignal{kind: signalForgedSender, key: key, at: at, detail: key[:i+1]})
	}
	observeMailboxSignal(cfg, mailbox, mailboxSignal{kind: "unknown", at: at})
	e, err := db.GetMailboxEvidence(mailbox)
	if err != nil {
		t.Fatal(err)
	}
	if len(e.Signals) != mailboxSignalKeysPerKind {
		t.Fatalf("stored %d signals", len(e.Signals))
	}
	for _, s := range e.Signals {
		if s.Kind != signalForgedSender || len(s.Key) > 320 || s.Key != "" && s.Count != 1 {
			t.Errorf("misattributed or unbounded signal: kind=%s key bytes=%d count=%d", s.Kind, len(s.Key), s.Count)
		}
	}
}

func TestMailboxEvidence_HighVolumeExemptsOnlySendingPatterns(t *testing.T) {
	evidenceCase(t)
	mailbox := "real@victim.example"
	at := time.Now()
	cfg := dryRunConfig()
	cfg.EmailProtection.HighVolumeSenders = []string{strings.ToUpper(mailbox)}
	for _, kind := range []string{signalForgedSender, signalBulkRecipients, signalReputation} {
		if got := observeMailboxSignal(cfg, mailbox, mailboxSignal{kind: kind, at: at}); len(got) != 0 {
			t.Fatalf("%s raised %+v", kind, got)
		}
	}
	observeMailboxSignal(cfg, mailbox, newCountry("DE", at))
	onlyIncident(t, observeMailboxSignal(cfg, mailbox, newCountry("BR", at)))
}

func TestMailboxEvidence_StalwartResolvesOnlyForLiveIncidents(t *testing.T) {
	evidenceCase(t)
	cfg := dryRunConfig()
	clients := stalwartHost(t, func() *config.Config { return cfg }, &fakeStalwart{})
	withMailBackendHost(t, true)
	mailbox := "real@victim.example"
	at := time.Now()
	observeMailboxSignal(cfg, mailbox, newCountry("DE", at))
	onlyIncident(t, observeMailboxSignal(cfg, mailbox, newCountry("BR", at)))
	if *clients != 0 {
		t.Fatalf("read-only evidence made %d mail server requests", *clients)
	}
}

func TestMailboxEvidence_LaterCountrySightingsFormPair(t *testing.T) {
	evidenceCase(t)
	at := time.Now()
	cfg := dryRunConfig()
	mailbox := "real@victim.example"
	for _, s := range []mailboxSignal{newCountry("DE", at.Add(-6*24*time.Hour)), newCountry("BR", at.Add(-3*24*time.Hour)), newCountry("DE", at.Add(-2*24*time.Hour+time.Minute))} {
		if got := observeMailboxSignal(cfg, mailbox, s); len(got) != 0 {
			t.Fatalf("observations outside a day reported %+v", got)
		}
	}
	onlyIncident(t, observeMailboxSignal(cfg, mailbox, newCountry("BR", at.Add(-2*24*time.Hour))))
}

func TestMailboxEvidence_RedirectBetweenForeignLogins(t *testing.T) {
	now := time.Now()
	mailbox := "real@victim.example"
	db, _ := evidenceCase(t)
	cfg := dryRunConfig()
	observeMailboxSignal(cfg, mailbox, newCountry("DE", now.Add(-6*24*time.Hour)))
	observeMailboxSignal(cfg, mailbox, newCountry("BR", now))
	f := onlyIncident(t, observeMailboxSignal(cfg, mailbox, mailboxSignal{kind: signalRedirect, at: now, since: now.Add(-3 * 24 * time.Hour)}))
	if !strings.Contains(f.Message, "scored 5") {
		t.Errorf("earlier foreign login lost from score: %s", f.Message)
	}
	if err := pruneMailboxEvidence(db, now.Add(48*time.Hour)); err != nil {
		t.Fatal(err)
	}
	e, err := db.GetMailboxEvidence(mailbox)
	if err != nil || mailboxEvidenceScore(e) != 5 {
		t.Errorf("prune lost confirmed redirect timing: %+v, %v", e, err)
	}
}

func TestMailboxEvidence_ReleaseAdviceRequiresStoredSuspension(t *testing.T) {
	db, _ := evidenceCase(t)
	row := cpanelRow("real@victim.example", store.AppliedSuspendLogin)
	withLifecycleBackend(t, lifecycleBackend{suspendFn: func(mailboxCompromise) (store.MailboxSuspension, error) {
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
		return row, nil
	}})
	cfg, at := eximAutoHoldConfig(), time.Now()
	observeMailboxSignal(cfg, row.Subject, newCountry("DE", at))
	f := onlyIncident(t, observeMailboxSignal(cfg, row.Subject, newCountry("BR", at)))
	if !strings.Contains(f.Message, "Suspended") || !strings.Contains(f.Details, "action log") || strings.Contains(f.Details, "Suspended tab") {
		t.Errorf("unrecorded restriction: %+v", f)
	}
}

func TestMailboxEvidence_ReleasePredatingLedger(t *testing.T) {
	db, _ := evidenceCase(t)
	cfg := eximAutoHoldConfig()
	row := cpanelRow("real@victim.example", store.AppliedSuspendLogin)
	at := time.Now().Add(-time.Hour)
	row.ReleasedAt = &at
	putRows(t, db, row)
	observeMailboxSignal(cfg, row.Subject, newCountry("DE", at))
	if got := observeMailboxSignal(cfg, row.Subject, newCountry("BR", time.Now())); len(got) != 0 {
		t.Fatalf("used evidence from before the stored release: %+v", got)
	}
}

func TestMailboxEvidence_AcceptsMailboxPunctuation(t *testing.T) {
	db, _ := evidenceCase(t)
	mailbox := "support/help@victim.example"
	observeMailboxSignal(dryRunConfig(), mailbox, newCountry("DE", time.Now()))
	e, err := db.GetMailboxEvidence(mailbox)
	if err != nil || len(e.Signals) != 1 {
		t.Fatalf("mailbox evidence = %+v, %v", e, err)
	}
}

func TestMailboxEvidence_GroupedRedirectBonusExpires(t *testing.T) {
	now := time.Now()
	e := store.MailboxEvidence{LastNewCountry: now.Add(-31 * 24 * time.Hour)}
	old := now.Add(-6 * 24 * time.Hour)
	recordMailboxSignal(&e, mailboxSignal{kind: signalRedirect, key: "first", since: old, at: old})
	dateMailboxRedirects(&e)
	for i := range mailboxSignalKeysPerKind + 4 {
		recordMailboxSignal(&e, mailboxSignal{kind: signalRedirect, key: strings.Repeat("b", i+1), since: now.Add(-60 * 24 * time.Hour), at: now})
	}
	if got := mailboxEvidenceScore(e); got != 3 {
		t.Fatalf("before expiry: score=%d", got)
	}
	expireMailboxEvidence(&e, now.Add(2*24*time.Hour))
	if got := mailboxEvidenceScore(e); got != 2 {
		t.Fatalf("retained expired redirect bonus: score=%d", got)
	}
}

func TestMailboxEvidence_StalwartReleaseDatesAddressReset(t *testing.T) {
	db, _ := evidenceCase(t)
	row := stalwartRow("real@victim.example", "account-id")
	putRows(t, db, row)
	withLifecycleBackend(t, lifecycleBackend{
		backend:  "stalwart",
		activeFn: func([]store.MailboxSuspension) (map[string]bool, error) { return map[string]bool{row.ID: false}, nil },
	})
	addressID := evidenceAddressLock(row.Backend, row.Subject)
	unlock := lockMailResponse(addressID)
	done := make(chan error, 1)
	go func() { _, err := listMailboxSuspensions(); done <- err }()
	waitMailLifecycle(t, addressID, func() bool { return false })
	at := time.Now()
	unlock()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	rec := storedRow(t, db, row.ID)
	if rec.ReleasedAt == nil || rec.ReleasedAt.Before(at) {
		t.Fatalf("release cutoff predates evidence reset: %+v", rec)
	}
}
