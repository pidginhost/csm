package daemon

import (
	"maps"
	"slices"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
)

// releaseDaemon shares one enforce mode spray memory between both trackers.
func releaseDaemon(t *testing.T) (*Daemon, *staticClock) {
	t.Helper()
	m, clock := newTestSpray(markerSprayConfig())
	d := &Daemon{mailSpray: m, smtpAuthTracker: newTestTracker(t, clock), mailAuthTracker: newTestMailTracker(t, clock)}
	d.smtpAuthTracker.SetSpray(m)
	d.mailAuthTracker.SetSpray(m)
	return d, clock
}

// An operator release drops the address's marker, verdict cadence and
// failure evidence, and its short-window failure counts. Login trust and
// IMAP good standing describe mailboxes, not the block, so they stay.
func TestOperatorReleaseClearsSprayKeepsTrust(t *testing.T) {
	d, clock := releaseDaemon(t)
	m := d.mailSpray
	const ip = "192.0.2.7"
	ageTrust(t, m, clock, ip, "t@example.com")
	d.mailAuthTracker.RecordSuccess(ip, "t@example.com")
	for range 2 {
		d.mailAuthTracker.Record(ip, "x@example.com")
	}
	sprayBlock(t, m, ip)
	for range 4 {
		if f := d.smtpAuthTracker.RecordTemporaryFailure(ip, "", alert.Observation{}); f != nil {
			t.Fatalf("setup SMTP failure = %+v, want none below the per-IP bar", f)
		}
	}

	d.operatorReleased(ip)

	if _, ok := m.blocks[ip]; ok {
		t.Fatal("marker survived the release")
	}
	if e := m.ips[ip]; e == nil || len(e.failed) != 0 || len(e.sources) != 0 || !e.verdictAt.IsZero() {
		t.Fatalf("evidence after release = %+v, want no failures, cadence or verdict", e)
	}
	// Not suppressed and no marker: one untrusted failure stays below the bar.
	wantNoVerdict(t, m.Failure(ip, "n@example.com", mailboxExists))
	// The trusted mailbox is still excused, so it does not make a second name.
	wantNoVerdict(t, m.Failure(ip, "t@example.com", mailboxExists))
	if !m.TrustedAll(ip, []string{"t@example.com"}) {
		t.Fatal("release dropped login trust")
	}

	for i := range 4 {
		if f := d.smtpAuthTracker.RecordTemporaryFailure(ip, "", alert.Observation{}); f != nil {
			t.Fatalf("SMTP failure %d after release = %+v, want the per-IP count restarted", i+1, f)
		}
	}
	e := d.mailAuthTracker.ips[ip]
	if e == nil || len(e.times) != 0 || len(e.failedAccounts) != 0 || len(e.slowTimes) != 0 || !e.suppressed.IsZero() {
		t.Fatalf("IMAP failures after release = %+v, want none", e)
	}
	if _, ok := e.goodLast["t@example.com"]; !ok || len(e.succ) == 0 {
		t.Fatalf("IMAP good standing after release = %v %v, want kept", e.goodLast, e.succ)
	}

	// A daemon without mail tracking ignores releases.
	(&Daemon{}).operatorReleased(ip)
	(&Daemon{}).operatorReleased("")
}

// Review focus 6: releasing one address of a /64 clears the /64's failure
// evidence and that address's marker. A sibling's marker stays: it stands
// for the sibling's own block.
func TestOperatorReleaseIPv6KeepsSiblingMarkers(t *testing.T) {
	d, clock := releaseDaemon(t)
	m := d.mailSpray
	cfg := markerSprayConfig()
	const a, b, c, key = "2001:db8:1::a", "2001:db8:1::b", "2001:db8:1::c", "2001:db8:1::/64"
	ageTrust(t, m, clock, a, "t@example.com")
	m.RevokeTrust("2001:db8:1::d", "r@example.com")
	sprayBlock(t, m, a)
	wantRule(t, m.Failure(b, "c@example.com", mailboxExists), sprayRuleBreadth, true)

	d.operatorReleased("2001:DB8:1::A")

	e := m.ips[key]
	if _, ok := m.blocks[a]; ok {
		t.Fatal("released address kept its marker")
	}
	if _, ok := m.blocks[b]; !ok || !slices.Equal(slices.Sorted(maps.Keys(m.blocksByKey[key])), []string{b}) {
		t.Fatalf("sibling markers = %v %v, want %s kept", m.blocks, m.blocksByKey, b)
	}
	if _, ok := e.sources[a]; ok {
		t.Fatal("released address kept its verdict cadence")
	}
	if _, ok := e.sources[b]; !ok {
		t.Fatal("sibling lost its verdict cadence")
	}
	if len(e.failed) != 0 {
		t.Fatalf("/64 failures after release = %v, want none", e.failed)
	}
	if _, ok := e.revoked["r@example.com"]; !ok || !m.TrustedAll(a, []string{"t@example.com"}) {
		t.Fatal("release dropped the /64's crack record or trust")
	}

	clock.advance(cfg.Suppression)
	wantNoVerdict(t, m.Failure(c, "n@example.com", mailboxExists))
	wantNoVerdict(t, m.Failure(a, "n@example.com", mailboxExists))
	wantRule(t, m.Failure(b, "n@example.com", mailboxExists), sprayRuleRepeat, true)
}

// The next save deletes the released marker and rewrites its evidence key
// without touching the sibling's marker.
func TestOperatorReleasePersists(t *testing.T) {
	db := openStoreForTest(t)
	d, _ := releaseDaemon(t)
	m := d.mailSpray
	const a, b = "2001:db8:1::a", "2001:db8:1::b"
	sprayBlock(t, m, a)
	wantRule(t, m.Failure(b, "c@example.com", mailboxExists), sprayRuleBreadth, true)
	d.persistMailSpray()
	bucketMatches(t, db, m)

	d.operatorReleased(a)

	delta, full := m.ExportChanges()
	put, ok := delta.Put.IPs["2001:db8:1::/64"]
	if full || !slices.Equal(delta.DeleteBlocked, []string{a}) || len(delta.Put.Blocked) != 0 || !ok ||
		len(delta.Put.IPs) != 1 || len(delta.DeleteIPs) != 0 {
		t.Fatalf("delta after release = full %v %+v, want blk:%s deleted and the /64 rewritten", full, delta, a)
	}
	if _, kept := put.Sources[b]; len(put.Failed) != 0 || !kept || len(put.Sources) != 1 {
		t.Fatalf("saved /64 = %+v, want no failures and only %s's cadence", put, b)
	}
	m.RetryChanges(delta, full)
	d.persistMailSpray()
	bucketMatches(t, db, m)
}

// A flush releases every address: markers, failure evidence, cadence and
// corroboration go in one full rewrite; trust and crack records stay.
func TestOperatorFlushClearsAllSprayMarkers(t *testing.T) {
	db := openStoreForTest(t)
	d, clock := releaseDaemon(t)
	m := d.mailSpray
	ageTrust(t, m, clock, "192.0.2.7", "t@example.com")
	m.RevokeTrust("192.0.2.8", "r@example.com")
	sprayBlock(t, m, "192.0.2.7")
	sprayBlock(t, m, "2001:db8:1::a")
	corroborate(t, m, "gone@example.com")
	d.persistMailSpray()
	if len(m.blocks) != 2 || len(m.names) == 0 {
		t.Fatalf("setup: markers %v, names %v", m.blocks, m.names)
	}

	d.operatorReleased("")

	if len(m.blocks)+len(m.blocksByKey)+len(m.names) != 0 {
		t.Fatalf("after flush: markers %v %v, names %v, want none", m.blocks, m.blocksByKey, m.names)
	}
	for key, e := range m.ips {
		if len(e.failed) != 0 || len(e.sources) != 0 || !e.untracked.IsZero() || !e.verdictAt.IsZero() || !e.observedAt.IsZero() {
			t.Fatalf("evidence of %s after flush = %+v, want none", key, e)
		}
	}
	if e := m.ips["192.0.2.8"]; e == nil || e.revoked["r@example.com"].IsZero() {
		t.Fatal("flush dropped a crack record")
	}
	if !m.TrustedAll("192.0.2.7", []string{"t@example.com"}) {
		t.Fatal("flush dropped login trust")
	}
	delta, full := m.ExportChanges()
	if !full {
		t.Fatalf("save after flush = %+v, want a full rewrite", delta)
	}
	m.RetryChanges(delta, full)
	d.persistMailSpray()
	bucketMatches(t, db, m)
}
