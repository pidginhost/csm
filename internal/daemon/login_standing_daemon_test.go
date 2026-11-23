package daemon

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/store"
)

// withMailboxResponseStanding points mailbox response at s for one test.
func withMailboxResponseStanding(t *testing.T, s *loginStanding) {
	t.Helper()
	prev := mailboxResponseStanding.Load()
	mailboxResponseStanding.Store(s)
	t.Cleanup(func() { mailboxResponseStanding.Store(prev) })
}

// Only the trackers that read the services' own logs share the index; the
// file readers keep none, so log-file lines never earn or consult standing.
func TestNewWiresLoginStanding(t *testing.T) {
	prev := mailboxResponseStanding.Load()
	t.Cleanup(func() { mailboxResponseStanding.Store(prev) })
	d := New(&config.Config{}, nil, nil, "")
	if d.loginStanding == nil {
		t.Fatal("no login standing index")
	}
	if d.mailAuthTracker.standing != d.loginStanding || d.smtpAuthTracker.standing != d.loginStanding {
		t.Fatal("the trusted trackers do not share the daemon's index")
	}
	if d.fileMailAuthTracker.standing != nil || d.fileSMTPAuthTracker.standing != nil {
		t.Fatal("a log-file tracker holds login standing")
	}
	if mailboxResponseStanding.Load() != d.loginStanding {
		t.Fatal("mailbox response does not revoke the daemon's index")
	}
}

// Standing survives a restart through the store, and a revocation reaches
// the store before the next start.
func TestLoginStandingSurvivesRestart(t *testing.T) {
	withGlobalStore(t, func(*store.DB) {
		clock := &staticClock{t: standingBase}
		start := func() *Daemon {
			d := &Daemon{loginStanding: newLoginStanding(clock.Now)}
			d.loadLoginStanding()
			return d
		}
		a := start()
		earnStanding(t, a.loginStanding, standingIP, standingBox, otherBox)
		a.persistLoginStanding()

		b := start()
		if !b.loginStanding.Has(standingIP, standingBox, standingBase) || !b.loginStanding.Has(standingIP, otherBox, standingBase) {
			t.Fatal("standing did not survive a restart")
		}
		b.loginStanding.Revoke(standingBox)
		b.persistLoginStanding()

		c := start()
		if c.loginStanding.Has(standingIP, standingBox, standingBase) {
			t.Fatal("a revoked mailbox regained standing after a restart")
		}
		if !c.loginStanding.Has(standingIP, otherBox, standingBase) {
			t.Fatal("revocation removed another mailbox")
		}
	})
}

// Mailbox response acts on a mailbox it believes compromised: that belief
// withdraws the mailbox's standing from every address, whatever the
// response mode does on the mail server.
func TestMailboxResponseRevokesStanding(t *testing.T) {
	dryRun, live := true, false
	for _, tc := range []struct {
		name string
		cfg  func() *config.Config
	}{
		{"enabled", eximAutoHoldConfig},
		{"dry run", func() *config.Config {
			cfg := &config.Config{}
			cfg.AutoResponse.Enabled = true
			cfg.AutoResponse.DryRun = &dryRun
			return cfg
		}},
		{"auto_response disabled", func() *config.Config {
			cfg := &config.Config{}
			cfg.AutoResponse.DryRun = &live
			return cfg
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withMailboxStore(t)
			withMailBackendHost(t, true)
			withUserdomains(t, "example.com: cpuser\n")
			stubMailboxActions(t, func([]string) ([]byte, error) { return uapiOK() })
			stubAccountHold(t, true)
			captureActionRecords(t)
			clock := &staticClock{t: standingBase}
			s := newLoginStanding(clock.Now)
			withMailboxResponseStanding(t, s)
			earnStanding(t, s, standingIP, standingBox, otherBox)
			earnStanding(t, s, "198.51.100.1", standingBox)

			respondToCompromise(tc.cfg(), sendingCompromise(standingBox, time.Now()))
			if hasRow(s, standingIP, standingBox) || hasRow(s, "198.51.100.1", standingBox) {
				t.Fatal("mailbox response left standing on the mailbox")
			}
			if !hasRow(s, standingIP, otherBox) {
				t.Fatal("mailbox response revoked another mailbox")
			}
		})
	}
}

func TestLoginStandingShutdownSavesLateChanges(t *testing.T) {
	withGlobalStore(t, func(db *store.DB) {
		clock := &staticClock{t: standingBase}
		d := &Daemon{loginStanding: newLoginStanding(clock.Now)}
		d.loadLoginStanding()
		earnStanding(t, d.loginStanding, standingIP, standingBox)
		d.persistLoginStanding()
		// Log readers and response can finish after the periodic saver exits.
		earnStanding(t, d.loginStanding, standingIP, otherBox)
		d.loginStanding.Revoke(standingBox)
		d.flushPendingAlertsOnShutdown()
		saved, err := db.LoadLoginStanding()
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := saved[standingIP+" "+otherBox]; !ok || len(saved) != 1 {
			t.Fatalf("shutdown did not save the late login and revocation: %+v", saved)
		}
	})
}

func TestLoginStandingSaveFailureRetriesCurrentState(t *testing.T) {
	dir := t.TempDir()
	db, restore := openTestBoltStore(t, dir)
	t.Cleanup(restore)
	clock := &staticClock{t: standingBase}
	d := &Daemon{loginStanding: newLoginStanding(clock.Now)}
	d.loadLoginStanding()
	earnStanding(t, d.loginStanding, standingIP, standingBox, otherBox)
	d.persistLoginStanding()
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	const newIP = "198.51.100.1"
	earnStanding(t, d.loginStanding, newIP, otherBox)
	d.persistLoginStanding() // Closed store: the extracted changes must be retried.
	d.loginStanding.Revoke(standingBox)
	reopened, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	store.SetGlobal(reopened)
	d.persistLoginStanding()
	saved, err := reopened.LoadLoginStanding()
	if err != nil {
		t.Fatal(err)
	}
	_, oldLogin := saved[standingIP+" "+otherBox]
	_, newLogin := saved[newIP+" "+otherBox]
	if len(saved) != 2 || !oldLogin || !newLogin {
		t.Fatalf("retry lost a login or restored revoked standing: %+v", saved)
	}
}

// Scored compromise evidence suspends a mailbox without going through
// respondToCompromise; it withdraws the mailbox's standing the same way.
func TestMailboxEvidenceRevokesStanding(t *testing.T) {
	for name, cfg := range map[string]*config.Config{
		"enabled":  eximAutoHoldConfig(),
		"dry-run":  dryRunConfig(),
		"disabled": {},
	} {
		t.Run(name, func(t *testing.T) {
			evidenceCase(t)
			clock := &staticClock{t: standingBase}
			s := newLoginStanding(clock.Now)
			withMailboxResponseStanding(t, s)
			const box = "real@victim.example"
			earnStanding(t, s, standingIP, box, otherBox)
			earnStanding(t, s, "198.51.100.1", box)
			at := time.Now()
			observeMailboxSignal(cfg, box, newCountry("DE", at.Add(-3*time.Hour)))
			onlyIncident(t, observeMailboxSignal(cfg, box, newCountry("BR", at)))
			if hasRow(s, standingIP, box) || hasRow(s, "198.51.100.1", box) {
				t.Fatal("a mailbox CSM declared compromised kept its standing")
			}
			if !hasRow(s, standingIP, otherBox) {
				t.Fatal("the response revoked another mailbox")
			}
		})
	}
}
