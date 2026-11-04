package daemon

import (
	"fmt"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

// Cracks beyond the per-key name cap still deny new trust after release,
// including when all named cracks have expired and only overflow remains.
func TestOperatorReleaseKeepsOverflowCracks(t *testing.T) {
	for _, release := range []string{"192.0.2.7", ""} {
		t.Run("release="+release, func(t *testing.T) {
			for _, stage := range []string{"release", "restart", "named expiry", "overflow expiry"} {
				t.Run(stage, func(t *testing.T) {
					d, clock := releaseDaemon(t)
					m := d.mailSpray
					const ip, cracked = "192.0.2.7", "overflow@example.com"
					ageTrust(t, m, clock, ip, "good@example.com")
					for i := range maxSprayNamesPerIP {
						m.RevokeTrust(ip, fmt.Sprintf("cracked%d@example.com", i))
					}
					clock.advance(m.cfg.Window / 2)
					m.RevokeTrust(ip, cracked)
					sprayBlock(t, m, ip)

					d.operatorReleased(release)

					if !m.TrustedAll(ip, []string{"good@example.com"}) {
						t.Fatal("release discarded unrelated login trust")
					}
					if stage == "named expiry" || stage == "overflow expiry" {
						clock.advance(m.cfg.Window/2 + time.Second)
						m.Purge()
					}
					if stage == "overflow expiry" {
						clock.advance(m.cfg.Window / 2)
						m.Purge()
					}
					if stage != "release" {
						m = restartSpray(t, m, clock)
					}
					clean, v := m.Success(ip, cracked)
					if want := stage == "overflow expiry"; clean != want || (want && v != nil) {
						t.Fatalf("trust after %s: clean=%v verdict=%+v, want clean=%v", stage, clean, v, want)
					}
				})
			}
		})
	}
}

// Releases reset rate counters under every spelling used by the log readers.
// A flush does the same for all addresses without losing successful logins.
func TestOperatorReleaseRestartsFailureCounters(t *testing.T) {
	for _, tc := range []struct {
		name    string
		release string
		aliases []string
	}{
		{"ipv4", "192.0.2.7", []string{"192.0.2.7", "::ffff:192.0.2.7"}},
		{"ipv6", "2001:db8:1::a", []string{"2001:DB8:1::A", "2001:db8:1:0::a"}},
		{"flush", "", []string{"192.0.2.7", "2001:DB8:1::A"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, _ := releaseDaemon(t)
			const other = "198.51.100.9"
			addresses := append(append([]string(nil), tc.aliases...), other)
			for _, ip := range addresses {
				d.mailAuthTracker.RecordSuccess(ip, "good@example.com")
			}
			for _, ip := range addresses {
				for range 4 {
					if got := d.smtpAuthTracker.Record(ip, "bad@example.com"); len(got) != 0 {
						t.Fatalf("SMTP setup for %s: %+v", ip, got)
					}
					if got := d.mailAuthTracker.Record(ip, "bad@example.com"); len(got) != 0 {
						t.Fatalf("IMAP setup for %s: %+v", ip, got)
					}
				}
			}

			d.operatorReleased(tc.release)

			for _, ip := range addresses {
				released := tc.release == "" || ip != other
				if !released {
					if len(d.smtpAuthTracker.ips[ip].times) != 4 || len(d.mailAuthTracker.ips[ip].times) != 4 {
						t.Fatal("release erased another address's counters")
					}
					continue
				}
				if got := d.smtpAuthTracker.Record(ip, "bad@example.com"); len(got) != 0 {
					t.Errorf("first SMTP failure after release for %s: %+v", ip, got)
				}
				if got := d.mailAuthTracker.Record(ip, "bad@example.com"); len(got) != 0 {
					t.Errorf("first IMAP failure after release for %s: %+v", ip, got)
				}
				smtp, imap := d.smtpAuthTracker.ips[ip], d.mailAuthTracker.ips[ip]
				if len(smtp.times) != 1 || len(smtp.slowTimes) != 1 || len(imap.times) != 1 || len(imap.slowTimes) != 1 {
					t.Errorf("%s counts = SMTP %d/%d, IMAP %d/%d; want 1 each", ip,
						len(smtp.times), len(smtp.slowTimes), len(imap.times), len(imap.slowTimes))
				}
				if len(imap.succ) != 1 || len(imap.successAccounts["good@example.com"]) != 1 || imap.goodLast["good@example.com"].IsZero() {
					t.Errorf("%s lost successful login history", ip)
				}
			}
		})
	}
}

// A delayed MTA reply must not revive rejected mailbox names from before a
// release. Outage marks still apply to new replies after the release.
func TestOperatorReleaseDiscardsPendingFailures(t *testing.T) {
	for _, release := range []string{"192.0.2.7", ""} {
		t.Run("release="+release, func(t *testing.T) {
			d, clock := releaseDaemon(t)
			tr := d.smtpAuthTracker
			const ip, alias, other = "192.0.2.7", "::ffff:192.0.2.7", "198.51.100.9"
			for _, addr := range []string{ip, alias, other} {
				tr.NoteDovecotRejection(addr, "a@example.com", mailboxMissing, clock.Now())
				tr.NoteDovecotRejection(addr, "b@example.com", mailboxMissing, clock.Now())
			}
			tr.NoteAuthTrouble(ip)
			d.operatorReleased(release)
			for _, addr := range []string{ip, alias, other} {
				_, _, names, paired := tr.PairMTAFailure(addr, "", clock.Now(), true)
				if release != "" && addr == other {
					if !paired || len(names) != 2 {
						t.Errorf("another address lost pending failures: paired=%v names=%v", paired, names)
					}
				} else if paired || len(names) != 0 || len(tr.pendingVerdicts[addr]) != 0 {
					t.Errorf("released %s retained pending failures: paired=%v names=%v", addr, paired, names)
				}
			}
			tr.NoteDovecotRejection(ip, "new@example.com", mailboxMissing, clock.Now())
			if _, _, names, paired := tr.PairMTAFailure(ip, "", clock.Now(), true); paired || len(names) != 0 {
				t.Fatal("release cleared the outage guard")
			}
		})
	}
}

// The IMAP log-error outage gate, like the SMTP probe gate, must take
// precedence over a saved repeat marker.
func TestMailSprayMarkerIgnoresIMAPOutage(t *testing.T) {
	d, clock := releaseDaemon(t)
	const ip = "192.0.2.7"
	sprayBlock(t, d.mailSpray, ip)
	clock.advance(8 * 24 * time.Hour)
	for range mailBackendDegradedThreshold {
		d.mailAuthTracker.RecordBackendFailure()
	}
	if got := d.mailAuthTracker.Record(ip, "bad@example.com"); len(got) != 0 {
		t.Fatalf("outage failure raised findings: %+v", got)
	}
	clock.advance(d.mailAuthTracker.window + time.Second)
	got := d.mailAuthTracker.Record(ip, "bad@example.com")
	if len(got) != 1 || got[0].Check != "mail_bruteforce" || got[0].Severity != alert.Critical || got[0].BlockTTL != markerSprayConfig().BlockTTL {
		t.Fatalf("post-outage repeat = %+v, want one spray block", got)
	}
}
