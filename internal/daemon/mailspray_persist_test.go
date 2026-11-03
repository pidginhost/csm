package daemon

import (
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/store"
)

// restartSpray saves m through a real store and loads it into a fresh
// detector with the same config and clock, as a daemon restart does.
func restartSpray(t *testing.T, m *mailSpray, clock *staticClock) *mailSpray {
	t.Helper()
	openStoreForTest(t)
	(&Daemon{mailSpray: m}).persistMailSpray()
	next := newMailSpray(m.cfg, clock.Now)
	(&Daemon{mailSpray: next}).loadMailSpray()
	return next
}

func TestDaemonMailSprayRestartKeepsEvidenceAndTrust(t *testing.T) {
	m, clock := newTestSpray(testSprayConfig())
	const ip = "192.0.2.10"
	ageTrust(t, m, clock, ip, "a@example.com", "r@example.com")
	m.RevokeTrust(ip, "r@example.com")
	wantNoVerdict(t, m.Failure(ip, "b@example.com", mailboxExists))
	clock.advance(time.Hour)

	m = restartSpray(t, m, clock)
	if !m.TrustedAll(ip, []string{"a@example.com"}) {
		t.Fatalf("aged trust did not survive the restart")
	}
	if m.TrustedAll(ip, []string{"r@example.com"}) {
		t.Fatalf("revoked trust came back after the restart")
	}
	wantRule(t, m.Failure(ip, "c@example.com", mailboxExists), sprayRuleBreadth, true)
}

// Load and Export must carry every field of one IP unchanged.
func TestMailSprayLoadExportKeepsEveryField(t *testing.T) {
	m, clock := newTestSpray(testSprayConfig())
	at := func(h int) time.Time { return clock.Now().Add(time.Duration(h) * time.Hour) }
	want := store.MailSprayState{
		IPs: map[string]store.MailSprayIP{
			"192.0.2.1": {
				Failed: map[string]store.MailSprayFailure{
					"a@example.com":      {First: at(-50), Last: at(-2), Count: 4, Exist: uint8(mailboxExists)},
					"nobody@example.com": {First: at(-3), Last: at(-3), Count: 1, Exist: uint8(mailboxMissing)},
					"":                   {First: at(-5), Last: at(-4), Count: 2},
				},
				WeakAlerted:     map[string]time.Time{"w@example.com": at(-6)},
				Untracked:       at(-7),
				SuppressedUntil: at(1),
				CompromiseUntil: at(2),
				VerdictAt:       at(-2),
				LastSeen:        at(-1),
			},
		},
		Trust: map[string]map[string]store.GoodSourcePair{
			"192.0.2.1":   {"t@example.com": {First: at(-100), Last: at(-8)}},
			"203.0.113.5": {"u@example.com": {First: at(-9), Last: at(-9)}},
		},
		Networks: map[string]map[string]time.Time{
			"nobody@example.com": {"192.0.0.0/16": at(-3), "2001:db8::/32": at(-10)},
		},
	}
	m.Load(want)
	if got := m.Export(); !reflect.DeepEqual(got, want) {
		t.Fatalf("Load then Export:\n got %+v\nwant %+v", got, want)
	}
}

// 4d needs the first failure time: a restart must not restart the spread.
func TestMailSprayRestartKeepsFirstFailureTime(t *testing.T) {
	m, clock := newTestSpray(testSprayConfig())
	const ip = "192.0.2.20"
	wantNoVerdict(t, m.Failure(ip, "a@example.com", mailboxExists))
	clock.advance(25 * time.Hour)
	wantNoVerdict(t, m.Failure(ip, "a@example.com", mailboxExists))

	m = restartSpray(t, m, clock)
	clean, v := m.Success(ip, "a@example.com")
	if !clean {
		t.Fatalf("login after a stale password was not clean")
	}
	wantRule(t, v, sprayRuleSingleMailboxSuccess, false)
}

func TestMailSprayRestartKeepsSuppressionAndAdvisoryDedupe(t *testing.T) {
	m, clock := newTestSpray(testSprayConfig())
	const ip = "192.0.2.30"
	wantNoVerdict(t, m.Failure(ip, "x@example.com", mailboxExists))
	wantRule(t, m.Failure(ip, "y@example.com", mailboxExists), sprayRuleBreadth, true)
	_, v := m.Success(ip, "a@example.com")
	wantRule(t, v, sprayRuleWeakCompromise, false)

	m = restartSpray(t, m, clock)
	wantNoVerdict(t, m.Failure(ip, "z@example.com", mailboxExists))
	if clean, got := m.Success(ip, "b@example.com"); clean || got != nil {
		t.Fatalf("login inside the compromise suppression = (%v, %+v), want (false, nil)", clean, got)
	}

	clock.advance(61 * time.Minute)
	if clean, got := m.Success(ip, "a@example.com"); clean || got != nil {
		t.Fatalf("repeat advisory for a = (%v, %+v), want (false, nil)", clean, got)
	}
	_, v = m.Success(ip, "c@example.com")
	wantRule(t, v, sprayRuleWeakCompromise, false)
}

func TestMailSprayRestartKeepsTrustOnlyIP(t *testing.T) {
	m, clock := newTestSpray(testSprayConfig())
	const ip = "192.0.2.40"
	ageTrust(t, m, clock, ip, "a@example.com")

	m = restartSpray(t, m, clock)
	if m.Size() != 0 || m.TrustSize() != 1 {
		t.Fatalf("after restart evidence=%d trust=%d, want 0 and 1", m.Size(), m.TrustSize())
	}
	if !m.TrustedAll(ip, []string{"a@example.com"}) {
		t.Fatalf("trust-only IP lost its trust")
	}
}

// A name refused at the per-IP cap still blocks new trust after a restart,
// even once the stored names have aged out.
func TestMailSprayRestartUntrackedBlocksTrust(t *testing.T) {
	m, clock := newTestSpray(testSprayConfig())
	const ip = "192.0.2.50"
	for i := range maxSprayNamesPerIP {
		m.Failure(ip, fmt.Sprintf("n%d@example.com", i), mailboxExists)
	}
	clock.advance(24 * time.Hour)
	m.Failure(ip, "over@example.com", mailboxExists)
	clock.advance(6*24*time.Hour + time.Hour)
	m.Purge()
	if e := m.ips[ip]; e == nil || len(e.failed) != 0 || e.untracked.IsZero() {
		t.Fatalf("setup: want only the refused name left, got %+v", e)
	}

	m = restartSpray(t, m, clock)
	if clean, _ := m.Success(ip, "a@example.com"); clean {
		t.Fatalf("login after a refused name earned trust after the restart")
	}
	if m.TrustSize() != 0 {
		t.Fatalf("trust records = %d, want 0", m.TrustSize())
	}
}

func TestMailSprayRestartKeepsCorroboration(t *testing.T) {
	m, clock := newTestSpray(testSprayConfig())
	const missing = "nobody@example.com"
	corroborate(t, m, missing)

	m = restartSpray(t, m, clock)
	v := m.Failure("192.0.2.1", missing, mailboxMissing)
	wantRule(t, v, sprayRuleMissingMailbox, true)
	if v.Networks != 3 {
		t.Fatalf("networks = %d, want 3", v.Networks)
	}
}

func TestMailSprayLoadDropsExpiredAndCaps(t *testing.T) {
	cfg := testSprayConfig()
	m, clock := newTestSpray(cfg)
	now := clock.Now()
	old := now.Add(-cfg.Window - time.Minute)
	recent := now.Add(-time.Hour)

	st := store.MailSprayState{
		IPs: map[string]store.MailSprayIP{
			"192.0.2.1": {
				Failed: map[string]store.MailSprayFailure{
					"old@example.com": {First: old, Last: old, Count: 1},
					"new@example.com": {Last: recent, Count: 0, Exist: 9},
				},
				WeakAlerted: map[string]time.Time{"old@example.com": old, "new@example.com": recent},
				Untracked:   old,
				LastSeen:    recent,
			},
			"192.0.2.2": {
				Failed:      map[string]store.MailSprayFailure{"a@example.com": {First: old, Last: old, Count: 3}},
				WeakAlerted: map[string]time.Time{"a@example.com": old},
				Untracked:   old,
				VerdictAt:   recent,
				LastSeen:    recent,
			},
			"192.0.2.3": {Failed: map[string]store.MailSprayFailure{}, WeakAlerted: map[string]time.Time{}, LastSeen: recent},
		},
		Trust: map[string]map[string]store.GoodSourcePair{
			"192.0.2.1": {
				"old@example.com":  {First: old.Add(-time.Hour), Last: old},
				"new@example.com":  {First: recent, Last: recent},
				"bad@example.com":  {First: recent, Last: recent.Add(-time.Minute)},
				"zero@example.com": {Last: recent},
			},
		},
		Networks: map[string]map[string]time.Time{
			"nobody@example.com": {"192.0.0.0/16": old, "203.0.0.0/16": recent},
			"gone@example.com":   {"192.0.0.0/16": old},
		},
	}
	// Over every per-IP and per-name cap.
	full := store.MailSprayIP{Failed: map[string]store.MailSprayFailure{}, WeakAlerted: map[string]time.Time{}, LastSeen: recent}
	for i := range maxSprayNamesPerIP + 8 {
		ts := recent.Add(time.Duration(i) * time.Second)
		full.Failed[fmt.Sprintf("n%02d@example.com", i)] = store.MailSprayFailure{First: ts, Last: ts, Count: 1}
		full.WeakAlerted[fmt.Sprintf("w%02d@example.com", i)] = ts
	}
	st.IPs["192.0.2.4"] = full
	st.Trust["192.0.2.4"] = map[string]store.GoodSourcePair{}
	for i := range maxSprayTrustPerIP + 8 {
		ts := recent.Add(time.Duration(i) * time.Second)
		st.Trust["192.0.2.4"][fmt.Sprintf("t%03d@example.com", i)] = store.GoodSourcePair{First: ts, Last: ts}
	}
	for i := range maxSprayTrustIPsPerMailbox + 8 {
		ts := recent.Add(time.Duration(i) * time.Second)
		st.Trust[fmt.Sprintf("198.51.100.%d", i)] = map[string]store.GoodSourcePair{"shared@example.com": {First: ts, Last: ts}}
	}
	st.Networks["many@example.com"] = map[string]time.Time{}
	for i := range maxSprayNetworksPerName + 8 {
		st.Networks["many@example.com"][fmt.Sprintf("10.%d.0.0/16", i)] = recent.Add(time.Duration(i) * time.Second)
	}

	m.Load(st)

	e := m.ips["192.0.2.1"]
	if e == nil || len(e.failed) != 1 || len(e.weakAlerted) != 1 || !e.untracked.IsZero() {
		t.Fatalf("192.0.2.1 after load = %+v, want only the recent name and advisory", e)
	}
	if f := e.failed["new@example.com"]; !f.first.Equal(recent) || f.count != 1 || f.exist != mailboxExistenceUnknown {
		t.Fatalf("damaged failure loaded as %+v, want first=last, count 1, unknown existence", f)
	}
	for _, ip := range []string{"192.0.2.2", "192.0.2.3"} {
		if m.ips[ip] != nil {
			t.Fatalf("%s has no evidence in the window but was loaded", ip)
		}
	}
	if mbs := m.trustByIP["192.0.2.1"]; len(mbs) != 1 {
		t.Fatalf("192.0.2.1 trust after load = %v, want only new@example.com", mbs)
	}
	if !m.TrustedAll("192.0.2.1", []string{"new@example.com"}) {
		t.Fatalf("recent aged trust was not loaded")
	}

	e = m.ips["192.0.2.4"]
	if len(e.failed) != maxSprayNamesPerIP || e.untracked.IsZero() {
		t.Fatalf("names over the cap: %d stored, untracked %v; want %d and a refusal", len(e.failed), e.untracked, maxSprayNamesPerIP)
	}
	if len(e.weakAlerted) != maxSprayNamesPerIP {
		t.Fatalf("advisory records = %d, want %d", len(e.weakAlerted), maxSprayNamesPerIP)
	}
	if _, ok := e.weakAlerted[fmt.Sprintf("w%02d@example.com", maxSprayNamesPerIP+7)]; !ok {
		t.Fatalf("the newest advisory record was not kept")
	}
	if n := len(m.trustByIP["192.0.2.4"]); n != maxSprayTrustPerIP {
		t.Fatalf("trust per IP = %d, want %d", n, maxSprayTrustPerIP)
	}
	if n := len(m.trustByMailbox["shared@example.com"]); n != maxSprayTrustIPsPerMailbox {
		t.Fatalf("trust per mailbox = %d, want %d", n, maxSprayTrustIPsPerMailbox)
	}
	if !m.TrustedAll(fmt.Sprintf("198.51.100.%d", maxSprayTrustIPsPerMailbox+7), []string{"shared@example.com"}) {
		t.Fatalf("the newest trust on the shared mailbox was not kept")
	}
	if n := m.names["nobody@example.com"]; n == nil || len(n.networks) != 1 || !n.last.Equal(recent) {
		t.Fatalf("nobody@example.com after load = %+v, want the recent network only", n)
	}
	if m.names["gone@example.com"] != nil {
		t.Fatalf("a name tried only before the window was loaded")
	}
	if n := len(m.names["many@example.com"].networks); n != maxSprayNetworksPerName {
		t.Fatalf("networks per name = %d, want %d", n, maxSprayNetworksPerName)
	}
}

func TestMailSprayLoadEvictsToMaxIPsByRank(t *testing.T) {
	cfg := testSprayConfig()
	cfg.MaxIPs = 4
	m, clock := newTestSpray(cfg)
	now := clock.Now()
	one := func(seen time.Time) store.MailSprayIP {
		return store.MailSprayIP{
			Failed:   map[string]store.MailSprayFailure{"a@example.com": {First: seen, Last: seen, Count: 1}},
			LastSeen: seen,
		}
	}
	st := store.MailSprayState{
		IPs:   map[string]store.MailSprayIP{},
		Trust: map[string]map[string]store.GoodSourcePair{},
	}
	for i := range 6 {
		ts := now.Add(time.Duration(i-60) * time.Minute)
		st.IPs[fmt.Sprintf("198.51.100.%d", i)] = one(ts)
		st.Trust[fmt.Sprintf("203.0.113.%d", i)] = map[string]store.GoodSourcePair{"a@example.com": {First: ts, Last: ts}}
	}
	verdict := one(now.Add(-time.Hour))
	verdict.VerdictAt = now.Add(-time.Hour)
	st.IPs["192.0.2.1"] = verdict
	repeat := one(now.Add(-time.Hour))
	repeat.Failed["a@example.com"] = store.MailSprayFailure{First: now.Add(-2 * time.Hour), Last: now.Add(-time.Hour), Count: 2}
	st.IPs["192.0.2.2"] = repeat
	st.Networks = map[string]map[string]time.Time{}
	for i := range maxSprayCorroborationNames + 10 {
		st.Networks[fmt.Sprintf("n%05d@example.com", i)] = map[string]time.Time{"192.0.0.0/16": now}
	}

	m.Load(st)

	if m.Size() > cfg.MaxIPs || m.TrustSize() > cfg.MaxIPs {
		t.Fatalf("after load evidence=%d trust=%d, cap %d", m.Size(), m.TrustSize(), cfg.MaxIPs)
	}
	for _, ip := range []string{"192.0.2.1", "192.0.2.2", "198.51.100.5"} {
		if m.ips[ip] == nil {
			t.Fatalf("%s was evicted ahead of older one-shot evidence", ip)
		}
	}
	if !m.TrustedAll("203.0.113.5", []string{"a@example.com"}) {
		t.Fatalf("the newest trust record was evicted")
	}
	if n := len(m.names); n > maxSprayCorroborationNames {
		t.Fatalf("corroboration names = %d, cap %d", n, maxSprayCorroborationNames)
	}
}

func TestMailSprayLoadIgnoredWhenDisabled(t *testing.T) {
	cfg := testSprayConfig()
	cfg.Window = 0
	m, clock := newTestSpray(cfg)
	now := clock.Now()
	m.Load(store.MailSprayState{
		IPs: map[string]store.MailSprayIP{"192.0.2.1": {
			Failed:   map[string]store.MailSprayFailure{"a@example.com": {First: now, Last: now, Count: 1}},
			LastSeen: now,
		}},
		Trust:    map[string]map[string]store.GoodSourcePair{"192.0.2.1": {"b@example.com": {First: now, Last: now}}},
		Networks: map[string]map[string]time.Time{"c@example.com": {"192.0.0.0/16": now}},
	})
	if m.Size() != 0 || m.TrustSize() != 0 || len(m.names) != 0 {
		t.Fatalf("disabled detector loaded evidence=%d trust=%d names=%d", m.Size(), m.TrustSize(), len(m.names))
	}
}
