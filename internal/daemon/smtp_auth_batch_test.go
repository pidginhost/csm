package daemon

import (
	"fmt"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

// Withheld batches must be retired even when another reply arrives after
// recovery. A backend reply cannot identify which pending name it belongs to.
func TestPairingAmbiguousBatchStaysDiscardedAfterTrouble(t *testing.T) {
	const ip = "203.0.113.123"
	for _, trouble := range []string{"server reply", "process warning", "backend probe"} {
		t.Run(trouble, func(t *testing.T) {
			d, clock := newPairingDaemon(t, sprayTestConfig("enforce"))
			feed(d, clock,
				"dovecot: auth: sql(alice@example.net,"+ip+"): Password mismatch",
				"dovecot: auth: sql(bob@example.net,"+ip+"): Password mismatch")
			down := trouble == "backend probe"
			d.smtpAuthTracker.SetBackendDownCheck(func() bool { return down })
			switch trouble {
			case "server reply":
				feed(d, clock, "postfix/smtpd[98]: warning: unknown["+ip+"]: SASL LOGIN authentication failed: Temporary authentication failure")
			case "process warning":
				feed(d, clock,
					"postfix/smtpd[98]: warning: SASL: Couldn't send handshake: Broken pipe",
					"postfix/smtpd[98]: warning: unknown["+ip+"]: SASL LOGIN authentication failed: (reason unavailable)")
			case "backend probe":
				feed(d, clock, fmt.Sprintf(postfixFailFmt, ip, "alice@example.net"))
			}
			down = false
			got := feed(d, clock, fmt.Sprintf(postfixFailFmt, ip, "bob@example.net"))
			if hasCheckFinding(got, "smtp_bruteforce") || len(sprayEvidence(d, ip)) != 0 {
				t.Fatalf("withheld names became evidence after recovery: findings=%+v evidence=%+v", got, sprayEvidence(d, ip))
			}
			feed(d, clock,
				"dovecot: auth: sql(carol@example.net,"+ip+"): Password mismatch",
				fmt.Sprintf(postfixFailFmt, ip, "carol@example.net"))
			if ev := sprayEvidence(d, ip); len(ev) != 1 || ev["carol@example.net"].count != 1 {
				t.Fatalf("fresh rejection after recovery = %+v, want only carol", ev)
			}
		})
	}
}

// Every name must satisfy the receipt and source-time pairing bounds, even
// if a different name in the same batch is still eligible.
func TestPairingAmbiguousBatchBoundsEveryName(t *testing.T) {
	const ip = "203.0.113.124"
	for _, boundary := range []string{"receipt", "source expired", "source future"} {
		t.Run(boundary, func(t *testing.T) {
			d, clock := newPairingDaemon(t, sprayTestConfig("enforce"))
			tr := d.smtpAuthTracker
			at := clock.Now()
			switch boundary {
			case "receipt":
				tr.NoteDovecotRejection(ip, "old@example.net", mailboxExists, time.Time{})
				clock.advance(20 * time.Second)
				tr.NoteDovecotRejection(ip, "live@example.net", mailboxExists, time.Time{})
				clock.advance(11 * time.Second)
			case "source expired":
				tr.NoteDovecotRejection(ip, "old@example.net", mailboxExists, at.Add(-time.Minute))
				tr.NoteDovecotRejection(ip, "live@example.net", mailboxExists, at.Add(-time.Second))
			case "source future":
				tr.NoteDovecotRejection(ip, "live@example.net", mailboxExists, at.Add(-time.Second))
				tr.NoteDovecotRejection(ip, "old@example.net", mailboxExists, at.Add(time.Second))
			}
			line := clock.Now().Format(time.RFC3339) + " mail postfix/smtpd[99]: warning: unknown[" + ip + "]: SASL LOGIN authentication failed: (reason unavailable)"
			got := d.handleMailLine(line, alert.Observation{}, d.currentCfg())
			if hasCheckFinding(got, "smtp_bruteforce") {
				t.Fatalf("out-of-window name caused a block: %+v", got)
			}
			if ev := sprayEvidence(d, ip); len(ev) != 1 || ev["live@example.net"].count != 1 {
				t.Fatalf("paired evidence = %+v, want only the live rejection", ev)
			}
			if boundary == "source future" {
				clock.advance(2 * time.Second)
				line = clock.Now().Format(time.RFC3339) + " mail postfix/smtpd[99]: warning: unknown[" + ip + "]: SASL LOGIN authentication failed: (reason unavailable)"
				d.handleMailLine(line, alert.Observation{}, d.currentCfg())
				if ev := sprayEvidence(d, ip); len(ev) != 2 || ev["live@example.net"].count != 1 || ev["old@example.net"].count != 1 {
					t.Fatalf("later reply lost its eligible rejection or repeated the earlier one: %+v", ev)
				}
			}
		})
	}
}

// More passdb answers can arrive while a batch still has replies pending.
// A name already fed by that batch must not be counted again.
func TestPairingAmbiguousBatchCountsRepeatedNameOnce(t *testing.T) {
	const ip = "203.0.113.125"
	d, clock := newPairingDaemon(t, sprayTestConfig("enforce"))
	feed(d, clock,
		"dovecot: auth: sql(alice@example.net,"+ip+"): Password mismatch",
		"dovecot: auth: sql(bob@example.net,"+ip+"): Password mismatch",
		fmt.Sprintf(postfixFailFmt, ip, "alice@example.net"),
		"dovecot: auth: passwd-file(alice@example.net,"+ip+"): Password mismatch",
		fmt.Sprintf(postfixFailFmt, ip, "bob@example.net"),
		fmt.Sprintf(postfixFailFmt, ip, "alice@example.net"))
	if ev := sprayEvidence(d, ip); len(ev) != 2 || ev["alice@example.net"].count != 1 || ev["bob@example.net"].count != 1 {
		t.Fatalf("batch repeated a name: %+v", ev)
	}
}

// Pairing and recording use separate lock acquisitions. A rejection read
// between them belongs to the next reply, not the already claimed one.
func TestPairingAmbiguousBatchClaimIsSnapshot(t *testing.T) {
	const ip = "203.0.113.126"
	d, clock := newPairingDaemon(t, sprayTestConfig("enforce"))
	tr := d.smtpAuthTracker
	tr.NoteDovecotRejection(ip, "alice@example.net", mailboxExists, clock.Now())
	tr.NoteDovecotRejection(ip, "bob@example.net", mailboxExists, clock.Now())
	_, _, batch, ok := tr.PairMTAFailure(ip, "smtpd[99]", clock.Now(), true)
	if !ok || batch == nil {
		t.Fatal("two pending names did not form an ambiguous pair")
	}
	clock.advance(time.Second)
	tr.NoteDovecotRejection(ip, "carol@example.net", mailboxExists, clock.Now())
	tr.RecordAmbiguousFailure(ip, batch, alert.Observation{})
	if ev := sprayEvidence(d, ip); len(ev) != 2 || ev["alice@example.net"].count != 1 || ev["bob@example.net"].count != 1 {
		t.Fatalf("claimed batch changed after pairing: %+v", ev)
	}
	_, _, batch, ok = tr.PairMTAFailure(ip, "smtpd[99]", clock.Now(), true)
	if !ok || batch == nil {
		t.Fatal("remaining ambiguous reply was lost")
	}
	tr.RecordAmbiguousFailure(ip, batch, alert.Observation{})
	if ev := sprayEvidence(d, ip); len(ev) != 3 || ev["carol@example.net"].count != 1 || ev["alice@example.net"].count != 1 || ev["bob@example.net"].count != 1 {
		t.Fatalf("next reply did not count only the new name: %+v", ev)
	}
}

// A buffered rejection later than the current reply is still part of the
// ambiguous outage batch, and must not become evidence after probe recovery.
func TestPairingAmbiguousBatchProbeDiscardsLaterSourceTime(t *testing.T) {
	const ip = "203.0.113.127"
	d, clock := newPairingDaemon(t, sprayTestConfig("enforce"))
	tr := d.smtpAuthTracker
	down := true
	tr.SetBackendDownCheck(func() bool { return down })
	tr.NoteDovecotRejection(ip, "alice@example.net", mailboxExists, clock.Now())
	tr.NoteDovecotRejection(ip, "bob@example.net", mailboxExists, clock.Now().Add(time.Second))
	failure := func() {
		line := clock.Now().Format(time.RFC3339) + " mail postfix/smtpd[99]: warning: unknown[" + ip + "]: SASL LOGIN authentication failed: (reason unavailable)"
		d.handleMailLine(line, alert.Observation{}, d.currentCfg())
	}
	failure()
	down = false
	clock.advance(time.Second)
	failure()
	if ev := sprayEvidence(d, ip); len(ev) != 0 {
		t.Fatalf("probe recovery restored an outage batch name: %+v", ev)
	}
	if calls := smtpCalls(d); calls != 2 {
		t.Fatalf("SMTP failures = %d, want both replies counted", calls)
	}
}

// Duplicate answers may fill the reply queue, but must not displace a
// distinct name whose rejection is still within the pairing bounds.
func TestPairingAmbiguousBatchRetainsNamesAtQueueCapacity(t *testing.T) {
	const ip = "203.0.113.128"
	d, clock := newPairingDaemon(t, sprayTestConfig("enforce"))
	tr := d.smtpAuthTracker
	tr.NoteDovecotRejection(ip, "alice@example.net", mailboxExists, clock.Now())
	for range smtpAuthPairMaxPending {
		tr.NoteDovecotRejection(ip, "bob@example.net", mailboxExists, clock.Now())
	}
	feed(d, clock, "postfix/smtpd[99]: warning: unknown["+ip+"]: SASL LOGIN authentication failed: (reason unavailable)")
	if ev := sprayEvidence(d, ip); len(ev) != 2 || ev["alice@example.net"].count != 1 || ev["bob@example.net"].count != 1 {
		t.Fatalf("queue capacity lost a live rejected name: %+v", ev)
	}
}

// A later duplicate must not hide a rejection that can pair with the
// current reply, even when the duplicate's source time is still in the future.
func TestPairingAmbiguousBatchKeepsEarlierEligibleDuplicate(t *testing.T) {
	const ip = "203.0.113.129"
	d, clock := newPairingDaemon(t, sprayTestConfig("enforce"))
	tr := d.smtpAuthTracker
	tr.NoteDovecotRejection(ip, "alice@example.net", mailboxExists, clock.Now())
	tr.NoteDovecotRejection(ip, "bob@example.net", mailboxExists, clock.Now())
	tr.NoteDovecotRejection(ip, "alice@example.net", mailboxExists, clock.Now().Add(time.Second))
	line := clock.Now().Format(time.RFC3339) + " mail postfix/smtpd[99]: warning: unknown[" + ip + "]: SASL LOGIN authentication failed: (reason unavailable)"
	d.handleMailLine(line, alert.Observation{}, d.currentCfg())
	if ev := sprayEvidence(d, ip); len(ev) != 2 || ev["alice@example.net"].count != 1 || ev["bob@example.net"].count != 1 {
		t.Fatalf("later duplicate hid earlier evidence: %+v", ev)
	}
}

// Continuous overlapping requests can keep a batch alive indefinitely.
// Consumed names must not hide fresh failures after their pairing window.
func TestPairingAmbiguousBatchRearmsAfterPairWindow(t *testing.T) {
	const ip = "203.0.113.130"
	d, clock := newPairingDaemon(t, sprayTestConfig("enforce"))
	tr := d.smtpAuthTracker
	reject := func(name string) {
		tr.NoteDovecotRejection(ip, name, mailboxExists, time.Time{})
	}
	pair := func() {
		_, _, names, ok := tr.PairMTAFailure(ip, "smtpd[99]", time.Time{}, true)
		if !ok || names == nil {
			t.Fatal("overlapping requests lost their ambiguous batch")
		}
		tr.RecordAmbiguousFailure(ip, names, alert.Observation{})
	}
	reject("alice@example.net")
	reject("bob@example.net")
	pair()
	for range 3 {
		clock.advance(smtpAuthPairWindow / 3)
		reject("bob@example.net")
		pair()
	}
	clock.advance(time.Second)
	reject("alice@example.net")
	pair()
	if ev := sprayEvidence(d, ip); len(ev) != 2 || ev["alice@example.net"].count != 2 || ev["bob@example.net"].count != 1 {
		t.Fatalf("consumed name hid a new failure after its window: %+v", ev)
	}
}

// Reopening a name for a new rejection must not make older, already
// consumed duplicates eligible for a buffered reply that precedes it.
func TestPairingAmbiguousBatchRenewalKeepsConsumedDuplicatesOut(t *testing.T) {
	const ip = "203.0.113.131"
	d, clock := newPairingDaemon(t, sprayTestConfig("enforce"))
	tr := d.smtpAuthTracker
	pair := func() {
		_, _, names, ok := tr.PairMTAFailure(ip, "smtpd[99]", clock.Now(), true)
		if !ok || names == nil {
			t.Fatal("overlapping requests lost their ambiguous batch")
		}
		tr.RecordAmbiguousFailure(ip, names, alert.Observation{})
	}
	tr.NoteDovecotRejection(ip, "alice@example.net", mailboxExists, clock.Now())
	tr.NoteDovecotRejection(ip, "bob@example.net", mailboxExists, clock.Now())
	pair()
	clock.advance(smtpAuthPairWindow)
	tr.NoteDovecotRejection(ip, "alice@example.net", mailboxExists, clock.Now())
	pair()
	clock.advance(time.Second)
	tr.NoteDovecotRejection(ip, "alice@example.net", mailboxExists, clock.Now().Add(2*time.Second))
	pair()
	if ev := sprayEvidence(d, ip); len(ev) != 2 || ev["alice@example.net"].count != 1 || ev["bob@example.net"].count != 1 {
		t.Fatalf("new rejection revived a consumed duplicate: %+v", ev)
	}
	clock.advance(2 * time.Second)
	pair()
	if ev := sprayEvidence(d, ip); len(ev) != 2 || ev["alice@example.net"].count != 2 || ev["bob@example.net"].count != 1 {
		t.Fatalf("new rejection did not count with its later reply: %+v", ev)
	}
}
