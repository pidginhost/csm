package daemon

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/blockdigest"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/incident"
	"github.com/pidginhost/csm/internal/reporting"
)

// The cause's customer must be excluded before counting and sampling a
// subnet, even when that login falls outside the displayed examples.
func TestCustomerBlockSubnetExcludesOwnCauseBeforeSampling(t *testing.T) {
	for _, causeIndex := range []int{0, 6} {
		t.Run(fmt.Sprintf("cause_at_%d", causeIndex), func(t *testing.T) {
			at := time.Now().Add(-time.Hour)
			d := &Daemon{knownCustomers: newKnownCustomers(time.Now)}
			var customers []blockdigest.CustomerHit
			for i := range 7 {
				ip := fmt.Sprintf("198.51.100.%d", i+1)
				account := fmt.Sprintf("user%d@example.com", i+1)
				loginAt := at.Add(time.Duration(i) * time.Minute)
				d.knownCustomers.Note(ip, knownCustomerIMAP, account, loginAt, syslogFed)
				customers = append(customers, blockdigest.CustomerHit{IP: ip, Kind: knownCustomerIMAP, Account: account, At: loginAt})
			}
			own := customers[causeIndex]
			finding := alert.Finding{Check: "mail_account_compromised", Severity: alert.Critical,
				SourceIP: own.IP, Mailbox: own.Account, Timestamp: own.At,
				Message: "Mail account compromise: " + own.Account + " from " + own.IP}
			cause := alert.CauseOf(finding)
			notice := alert.Finding{Check: "auto_block", Severity: alert.Critical, Cause: &cause,
				Message: "AUTO-NETBLOCK: 198.51.100.0/24 blocked"}
			blocks := d.customerBlocks([]alert.Finding{finding, notice})
			if len(blocks) != 1 {
				t.Fatalf("customer blocks = %+v, want the other customers alerted", blocks)
			}
			b := blocks[0]
			if len(b.Hits) != 5 || b.More != 1 {
				t.Fatalf("customer block = %+v, want five examples and one more customer", b)
			}
			position := 0
			for i := len(customers) - 1; i >= 0 && position < len(b.Hits); i-- {
				if i == causeIndex {
					continue
				}
				if b.Hits[position] != customers[i] {
					t.Errorf("example %d = %+v, want %+v", position, b.Hits[position], customers[i])
				}
				position++
			}
		})
	}
}

// A block that lands in a later batch than the compromise it answers, from
// a queued retry, the incident correlator or central intelligence, skips the
// compromised login as a same-batch block does: the compromise email
// already named it. A later block of the address for another check alerts.
func TestCustomerBlockSkipsOwnCauseFromLaterBatch(t *testing.T) {
	const ip, mailbox = "203.0.113.40", "office@example.com"
	compromise := alert.Finding{Severity: alert.Critical, Check: "mail_account_compromised", SourceIP: ip, Mailbox: mailbox, Timestamp: time.Now(),
		Message: "Mail account compromise: successful login for " + mailbox + " from " + ip + " after recent auth failures"}
	incidentBlock := func(t *testing.T, d *Daemon, root alert.Finding) {
		t.Helper()
		if _, err := d.applyIncidentBlock(ip, "incident: account compromise", time.Hour, "", incident.PreparedRoot{Finding: root}, admission.EntryIncidentSpray); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		name   string
		block  func(*testing.T, *Daemon, *customerTestBlocker)
		alerts int
	}{
		{"queued retry", func(t *testing.T, d *Daemon, b *customerTestBlocker) {
			b.fail = 1
			d.dispatchBatch([]alert.Finding{compromise})
			if b.IsBlocked(ip) {
				t.Fatal("the failed attempt blocked")
			}
			d.dispatchBatch([]alert.Finding{smtpBruteFrom("198.51.100.9")})
		}, 0},
		{"incident", func(t *testing.T, d *Daemon, b *customerTestBlocker) {
			d.dispatchBatch([]alert.Finding{compromise})
			_ = b.UnblockIP(ip)
			incidentBlock(t, d, compromise)
		}, 0},
		{"central intelligence", func(t *testing.T, d *Daemon, b *customerTestBlocker) {
			d.dispatchBatch([]alert.Finding{compromise})
			_ = b.UnblockIP(ip)
			store := centralStoreWith(t, []reporting.ScoredEntry{{IP: ip, Score: 95, Classes: []reporting.Class{reporting.ClassBruteforce}, LastSeen: time.Now().UTC()}})
			action, ok := d.planCentralAction(store, reporting.ActionBlockIfLocalCorroborated, 80, func(string) bool { return false }, compromise)
			if !ok || action.decision != reporting.DecisionBlock {
				t.Fatalf("central plan = %+v (%v), want a block", action, ok)
			}
			if err := d.performCentralAction(action); err != nil {
				t.Fatal(err)
			}
		}, 0},
		{"incident for another check", func(t *testing.T, d *Daemon, b *customerTestBlocker) {
			d.dispatchBatch([]alert.Finding{compromise})
			_ = b.UnblockIP(ip)
			incidentBlock(t, d, alert.Finding{Severity: alert.Critical, Check: "mail_bruteforce", Message: "Mail auth brute force from " + ip, SourceIP: ip, Timestamp: time.Now()})
		}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, _, blocker, capture := customerBlockSetup(t)
			d.knownCustomers.Note(ip, knownCustomerIMAP, mailbox, time.Now().Add(-time.Minute), syslogFed)
			tc.block(t, d, blocker)
			if !blocker.IsBlocked(ip) {
				t.Fatalf("%s not blocked", ip)
			}
			if n, hooks := len(capture.customerEmails()), len(capture.events("customer_block")); n != tc.alerts || hooks != tc.alerts {
				t.Fatalf("customer emails = %d, webhooks = %d, want %d each", n, hooks, tc.alerts)
			}
		})
	}
}

// A cause without its own timestamp still counts in its batch, and a cause
// is forgotten once its login could no longer be a known customer.
func TestBlockCausesKeepByDispatchTime(t *testing.T) {
	var c blockCauses
	now := time.Now()
	cause := alert.Finding{Check: "mail_account_compromised", SourceIP: "203.0.113.41", Mailbox: "office@example.com"}
	c.note(cause, now)
	if _, ok := c.lookup(alert.FindingID(cause), now); !ok {
		t.Fatal("cause without a timestamp not found in its batch")
	}
	later := now.Add(knownCustomerTTL)
	if _, ok := c.lookup(alert.FindingID(cause), later); ok {
		t.Fatal("cause still found after the known-customer window")
	}
	c.note(alert.Finding{Check: "ftp_login_after_bruteforce", SourceIP: "203.0.113.42", Timestamp: later}, later)
	if n := len(c.byID); n != 1 {
		t.Fatalf("kept causes = %d, want the expired one pruned", n)
	}
}

type customerNetblockTestBlocker struct {
	*customerTestBlocker
}

func (b *customerNetblockTestBlocker) BlockSubnet(cidr, reason string, ttl time.Duration) error {
	return b.BlockIP(cidr, reason, ttl)
}

func (b *customerNetblockTestBlocker) IsSubnetBlocked(cidr string) bool {
	return b.IsBlocked(cidr)
}

// A range escalation can answer an earlier compromise using only its
// finding ID. The compromised login is omitted, but other customers in
// the range must still receive the false-positive alert.
func TestCustomerNetblockSkipsOwnCauseFromLaterBatch(t *testing.T) {
	d, cfg, blocker, capture := customerBlockSetup(t)
	checks.SetIPBlocker(&customerNetblockTestBlocker{blocker})
	live := false
	cfg.AutoResponse.DryRun = &live
	const ownIP, otherIP, subnet = "198.51.100.30", "198.51.100.40", "198.51.100.0/24"
	const ownAccount, otherAccount = "compromised@example.com", "customer@example.com"
	at := time.Now().Add(-time.Minute)
	d.knownCustomers.Note(ownIP, knownCustomerIMAP, ownAccount, at, syslogFed)
	d.knownCustomers.Note(otherIP, knownCustomerIMAP, otherAccount, at, syslogFed)
	compromise := alert.Finding{Severity: alert.Critical, Check: "mail_account_compromised", SourceIP: ownIP,
		Mailbox: ownAccount, Timestamp: time.Now(), Message: "Mail account compromise: " + ownAccount + " from " + ownIP}
	for _, f := range []alert.Finding{smtpBruteFrom("198.51.100.10"), smtpBruteFrom("198.51.100.20"), compromise} {
		d.dispatchBatch([]alert.Finding{f})
		if !blocker.IsBlocked(f.SourceIP) {
			t.Fatalf("address block did not apply: %s", f.SourceIP)
		}
	}
	capture.reset()
	cfg.AutoResponse.NetBlock = true
	cfg.AutoResponse.NetBlockThreshold = config.DefaultNetBlockThreshold
	actions := checks.AutoBlockIPs(cfg, []alert.Finding{smtpBruteFrom("203.0.113.9")})
	if !blocker.IsBlocked(subnet) {
		t.Fatal("range block did not apply")
	}
	var found bool
	for _, f := range actions {
		kind, target, _ := blockTarget(f)
		if kind == "AUTO-NETBLOCK" && target == subnet {
			found = true
			if f.Cause == nil || f.Cause.FindingID != alert.FindingID(compromise) || f.Cause.Check != "" {
				t.Fatalf("range block cause = %+v, want only the earlier compromise ID", f.Cause)
			}
		}
	}
	if !found {
		t.Fatal("range block notice missing from actions")
	}
	d.dispatchBatch(actions)
	hooks := capture.events("customer_block")
	if len(capture.customerEmails()) != 1 || len(hooks) != 1 || len(hooks[0].CSM.CustomerBlocks) != 1 {
		t.Fatalf("customer emails = %d, webhooks = %+v, want one range alert", len(capture.customerEmails()), hooks)
	}
	b := hooks[0].CSM.CustomerBlocks[0]
	if b.Target != subnet || b.More != 0 || len(b.Hits) != 1 || b.Hits[0].IP != otherIP || b.Hits[0].Account != otherAccount {
		t.Fatalf("customer block = %+v, want only the other customer", b)
	}
}

// Concurrent observers retain each cause without mixing up accounts or
// suppressing blocks whose check disagrees with the remembered cause.
func TestCustomerBlockConcurrentCauseObservers(t *testing.T) {
	d, _, _, capture := customerBlockSetup(t)
	const workers = 20
	var wg sync.WaitGroup
	for i := range workers {
		ip := fmt.Sprintf("192.0.2.%d", i+1)
		account := fmt.Sprintf("customer%d@example.com", i+1)
		d.knownCustomers.Note(ip, knownCustomerIMAP, account, time.Now(), syslogFed)
		wg.Go(func() {
			cause := alert.Finding{Check: "mail_account_compromised", Severity: alert.Critical,
				SourceIP: ip, Mailbox: account, Timestamp: time.Now(), Message: "Mail account compromise: " + account + " from " + ip}
			d.observeBlocks([]alert.Finding{cause})
			id := alert.FindingID(cause)
			notice := alert.Finding{Check: "auto_block", Severity: alert.Critical,
				Message: "AUTO-BLOCK: " + ip + " blocked", Cause: &alert.Cause{FindingID: id}}
			other := notice
			other.Cause = &alert.Cause{FindingID: id, Check: "smtp_bruteforce"}
			d.observeBlocks([]alert.Finding{notice, other})
		})
	}
	wg.Wait()
	hooks := capture.events("customer_block")
	if len(hooks) != workers || len(capture.customerEmails()) != workers {
		t.Fatalf("emails = %d, webhooks = %d, want %d each", len(capture.customerEmails()), len(hooks), workers)
	}
	seen := make(map[string]bool)
	for _, p := range hooks {
		blocks := p.CSM.CustomerBlocks
		if len(blocks) != 1 || blocks[0].Check != "smtp_bruteforce" || len(blocks[0].Hits) != 1 {
			t.Fatalf("customer blocks = %+v, want only the unrelated block", blocks)
		}
		b := blocks[0]
		if b.Hits[0].IP != b.Target || seen[b.Target] {
			t.Fatalf("customer block = %+v, duplicate or wrong address", b)
		}
		seen[b.Target] = true
	}
}
