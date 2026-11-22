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
