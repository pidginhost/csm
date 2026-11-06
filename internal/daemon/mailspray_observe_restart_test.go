package daemon

import (
	"testing"
	"time"
)

// A saved observe advisory keeps its original window after restart, including
// when only the successful login changed since the last save. Enabling
// enforcement must still allow blocks each suppression period.
func TestMailSprayObserveCompromiseRestart(t *testing.T) {
	for _, save := range []string{"full", "incremental"} {
		for _, mode := range []string{"observe", "enforce"} {
			t.Run(save+"/"+mode, func(t *testing.T) {
				openStoreForTest(t)
				cfg := testSprayConfig()
				cfg.Mode = sprayObserve
				m, clock := newTestSpray(cfg)
				const ip, mailbox, missing = "192.0.2.1", "c@example.com", "nobody@example.com"
				ageTrust(t, m, clock, ip, "a@example.com")
				corroborate(t, m, missing)
				wantNoVerdict(t, m.Failure(ip, missing, mailboxMissing))
				if save == "incremental" {
					(&Daemon{mailSpray: m}).persistMailSpray()
				}
				clean, v := m.Success(ip, mailbox)
				if clean {
					t.Fatal("suspect login earned trust")
				}
				wantRule(t, v, sprayRuleCompromise, true)
				firstAlert := clock.Now()
				(&Daemon{mailSpray: m}).persistMailSpray()
				m = newMailSpray(cfg, clock.Now)
				(&Daemon{mailSpray: m}).loadMailSpray()
				cfg.Mode = parseSprayMode(mode)
				m.SetConfig(cfg)
				for range 2 {
					clock.advance(cfg.Suppression + time.Minute)
					clean, v = m.Success(ip, mailbox)
					if clean {
						t.Fatal("restart let a suspect login earn trust")
					}
					if cfg.Mode == sprayEnforce {
						wantRule(t, v, sprayRuleCompromise, true)
					} else {
						wantNoVerdict(t, v)
					}
				}
				if cfg.Mode == sprayEnforce {
					return
				}
				clock.advance(firstAlert.Add(cfg.Window).Sub(clock.Now()))
				for _, from := range []string{"198.51.100.1", "203.0.113.1", ip} {
					m.Failure(from, missing, mailboxMissing)
				}
				if clean, v = m.Success(ip, mailbox); clean || v != nil {
					t.Fatalf("at the window boundary got (%v, %+v), want (false, nil)", clean, v)
				}
				clock.advance(time.Second)
				clean, v = m.Success(ip, mailbox)
				if clean {
					t.Fatal("suspect login earned trust after the advisory expired")
				}
				wantRule(t, v, sprayRuleCompromise, true)
			})
		}
	}
}
