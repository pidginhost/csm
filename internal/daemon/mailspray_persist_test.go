package daemon

import (
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strings"
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
	m, clock := newTestSpray(markerSprayConfig())
	at := func(h int) time.Time { return clock.Now().Add(time.Duration(h) * time.Hour) }
	want := store.MailSprayState{
		IPs: map[string]store.MailSprayIP{
			"192.0.2.1": {
				Failed: map[string]store.MailSprayFailure{
					"a@example.com":      {First: at(-50), Last: at(-2), Count: 4, Exist: uint8(mailboxExists)},
					"nobody@example.com": {First: at(-3), Last: at(-3), Count: 1, Exist: uint8(mailboxMissing)},
					"":                   {First: at(-5), Last: at(-4), Count: 2},
				},
				WeakAlerted:   map[string]time.Time{"w@example.com": at(-6)},
				Revoked:       map[string]time.Time{"r@example.com": at(-11)},
				Sources:       map[string]store.MailSpraySource{"192.0.2.1": {SuppressedUntil: clock.Now().Add(30 * time.Minute), CompromiseUntil: clock.Now().Add(45 * time.Minute)}},
				Untracked:     at(-7),
				VerdictAt:     at(-2),
				ObservedAt:    at(-3),
				ObservedNames: 2,
				LastSeen:      at(-1),
			},
			"2001:db8:1:2::/64": {
				Failed: map[string]store.MailSprayFailure{"a@example.com": {First: at(-4), Last: at(-2), Count: 2}},
				Sources: map[string]store.MailSpraySource{
					"2001:db8:1:2::a": {SuppressedUntil: clock.Now().Add(20 * time.Minute)},
					"2001:db8:1:2::b": {CompromiseUntil: clock.Now().Add(40 * time.Minute)},
				},
				LastSeen: at(-2),
			},
		},
		Trust: map[string]map[string]store.GoodSourcePair{
			"192.0.2.1":   {"t@example.com": {First: at(-100), Last: at(-8)}},
			"203.0.113.5": {"u@example.com": {First: at(-9), Last: at(-9)}},
		},
		Networks: map[string]map[string]time.Time{
			"nobody@example.com": {"192.0.0.0/16": at(-3), "2001:db8::/32": at(-10)},
		},
		Blocked: map[string]time.Time{"192.0.2.1": at(20 * 24), "2001:db8:1:2::a": at(-30)},
	}
	loadSpraySnapshot(t, m, want)
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
				Revoked:     map[string]time.Time{"old@example.com": old},
				Untracked:   old,
				ObservedAt:  old,
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
	full := store.MailSprayIP{
		Failed:        map[string]store.MailSprayFailure{},
		WeakAlerted:   map[string]time.Time{},
		Revoked:       map[string]time.Time{},
		ObservedAt:    recent,
		ObservedNames: 99,
		LastSeen:      recent,
	}
	for i := range maxSprayNamesPerIP + 8 {
		ts := recent.Add(time.Duration(i) * time.Second)
		full.Failed[fmt.Sprintf("n%02d@example.com", i)] = store.MailSprayFailure{First: ts, Last: ts, Count: 1}
		full.WeakAlerted[fmt.Sprintf("w%02d@example.com", i)] = ts
		full.Revoked[fmt.Sprintf("r%02d@example.com", i)] = ts
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

	loadSpraySnapshot(t, m, st)

	e := m.ips["192.0.2.1"]
	if e == nil || len(e.failed) != 1 || len(e.weakAlerted) != 1 || len(e.revoked) != 0 || !e.untracked.IsZero() || !e.observedAt.IsZero() {
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
	if len(e.revoked) != maxSprayNamesPerIP {
		t.Fatalf("revocation records = %d, want %d", len(e.revoked), maxSprayNamesPerIP)
	}
	if e.observedNames != maxSprayNamesPerIP {
		t.Fatalf("observed names = %d, want capped at %d", e.observedNames, maxSprayNamesPerIP)
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

	loadSpraySnapshot(t, m, st)

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

// Load admits entries without checking them against the eviction floors,
// so it leaves the floors clear.
func TestMailSprayLoadClearsEvictionFloor(t *testing.T) {
	cfg := testSprayConfig()
	cfg.MaxIPs = 4
	m, clock := newTestSpray(cfg)
	seen := clock.Now().Add(-time.Hour)
	st := store.MailSprayState{IPs: map[string]store.MailSprayIP{}}
	for i := range cfg.MaxIPs + 1 {
		e := store.MailSprayIP{
			Failed:   map[string]store.MailSprayFailure{"a@example.com": {First: seen, Last: seen, Count: 1}},
			LastSeen: seen,
		}
		if i < cfg.MaxIPs {
			e.VerdictAt = seen
		}
		st.IPs[fmt.Sprintf("192.0.2.%d", i+1)] = e
	}
	loadSpraySnapshot(t, m, st)
	if m.Size() != cfg.MaxIPs || m.ipFloor != 0 {
		t.Fatalf("after load %d IPs, floor %d; want %d IPs, floor 0", m.Size(), m.ipFloor, cfg.MaxIPs)
	}
}

func TestMailSprayLoadIgnoredWhenDisabled(t *testing.T) {
	cfg := testSprayConfig()
	cfg.Window = 0
	m, clock := newTestSpray(cfg)
	now := clock.Now()
	loadSpraySnapshot(t, m, store.MailSprayState{
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

// A time after now is damage, from a bad bucket or a clock stepped back
// across the restart. It must not create trust, silence verdicts or pin
// state past the window.
func TestMailSprayLoadDistrustsFutureTimes(t *testing.T) {
	cfg := testSprayConfig()
	future := func(now time.Time) store.MailSprayState {
		later := now.Add(365 * 24 * time.Hour)
		return store.MailSprayState{
			IPs: map[string]store.MailSprayIP{"192.0.2.2": {
				Failed:      map[string]store.MailSprayFailure{"x@example.com": {First: later, Last: later, Count: 1}},
				WeakAlerted: map[string]time.Time{"w@example.com": later},
				Revoked:     map[string]time.Time{"r@example.com": later},
				Sources:     map[string]store.MailSpraySource{"192.0.2.2": {SuppressedUntil: later, CompromiseUntil: later}},
				Untracked:   later,
				VerdictAt:   later,
				ObservedAt:  later,
				LastSeen:    later,
			}},
			Trust: map[string]map[string]store.GoodSourcePair{"192.0.2.1": {
				"a@example.com": {First: now.Add(-24 * time.Hour), Last: later},
				"b@example.com": {First: later, Last: later},
			}},
			Networks: map[string]map[string]time.Time{
				"nobody@example.com": {"198.51.0.0/16": later, "203.0.0.0/16": later},
			},
		}
	}

	m, clock := newTestSpray(cfg)
	now := clock.Now()
	loadSpraySnapshot(t, m, future(now))
	if m.TrustSize() != 0 || m.TrustedAll("192.0.2.1", []string{"a@example.com"}) {
		t.Fatalf("a trust record from the future was loaded")
	}
	e := m.ips["192.0.2.2"]
	if e == nil {
		t.Fatalf("future evidence was dropped instead of clamped")
	}
	f := e.failed["x@example.com"]
	for name, got := range map[string]time.Time{
		"failure first": f.first, "failure last": f.last, "untracked": e.untracked,
		"verdict": e.verdictAt, "observed": e.observedAt, "last seen": e.lastSeen, "advisory": e.weakAlerted["w@example.com"],
		"revoked": e.revoked["r@example.com"],
	} {
		if !got.Equal(now) {
			t.Errorf("%s = %v, want clamped to %v", name, got, now)
		}
	}
	src := e.sources["192.0.2.2"]
	for name, got := range map[string]time.Time{"suppression": src.blockUntil, "compromise suppression": src.compromiseUntil} {
		if want := now.Add(cfg.Suppression); !got.Equal(want) {
			t.Errorf("%s = %v, want capped at %v", name, got, want)
		}
	}

	if len(m.names) != 0 {
		t.Fatal("future networks were loaded as present corroboration")
	}

	// Verdicts resume once the capped suppression ends.
	clock.advance(cfg.Suppression + time.Minute)
	wantRule(t, m.Failure("192.0.2.2", "y@example.com", mailboxExists), sprayRuleBreadth, true)
	_, v := m.Success("192.0.2.2", "c@example.com")
	wantRule(t, v, sprayRuleWeakCompromise, false)

	// Purge expires everything a window after the load, and the future
	// networks no longer count toward the missing-name rule.
	m, clock = newTestSpray(cfg)
	loadSpraySnapshot(t, m, future(clock.Now()))
	clock.advance(cfg.Window + time.Minute)
	m.Purge()
	if m.Size() != 0 || m.TrustSize() != 0 || len(m.names) != 0 {
		t.Fatalf("after a window: evidence=%d trust=%d names=%d, want all expired", m.Size(), m.TrustSize(), len(m.names))
	}
	wantNoVerdict(t, m.Failure("192.0.2.3", "nobody@example.com", mailboxMissing))
}

// IPv6 evidence is saved under its /64. Each address keeps its own verdict
// suppression across a restart.
func TestMailSprayIPv6EvidenceSurvivesRestart(t *testing.T) {
	m, clock := newTestSpray(testSprayConfig())
	const a, b = "2001:db8:1:2::a", "2001:db8:1:2::b"
	wantNoVerdict(t, m.Failure(a, "a@example.com", mailboxExists))
	wantRule(t, m.Failure(a, "b@example.com", mailboxExists), sprayRuleBreadth, true)
	want := m.Export()
	if _, ok := want.IPs["2001:db8:1:2::/64"]; !ok || len(want.IPs) != 1 {
		t.Fatalf("saved evidence keys = %v, want the /64", slices.Collect(maps.Keys(want.IPs)))
	}

	m = restartSpray(t, m, clock)
	if got := m.Export(); !reflect.DeepEqual(got, want) {
		t.Fatalf("restart changed the memory:\n got %+v\nwant %+v", got, want)
	}
	wantNoVerdict(t, m.Failure(a, "c@example.com", mailboxExists))
	wantRule(t, m.Failure(b, "d@example.com", mailboxExists), sprayRuleBreadth, true)
}

// Older state keyed IPv6 evidence by address; it folds into the /64. Only
// keys the detector could have written are loaded.
func TestMailSprayLoadEvidenceKeys(t *testing.T) {
	m, clock := newTestSpray(testSprayConfig())
	now := clock.Now()
	entry := func(name string) store.MailSprayIP {
		return store.MailSprayIP{
			Failed:   map[string]store.MailSprayFailure{name: {First: now, Last: now, Count: 1}},
			LastSeen: now,
		}
	}
	loadSpraySnapshot(t, m, store.MailSprayState{IPs: map[string]store.MailSprayIP{
		"2001:db8:1:2::a":    entry("a@example.com"),
		"2001:db8:1:2::b":    entry("b@example.com"),
		"2001:db8:1:2::/64":  entry("c@example.com"),
		"192.0.2.1":          entry("d@example.com"),
		"2001:db8:1:3::1/64": entry("x@example.com"),
		"2001:db8:1:4::/48":  entry("x@example.com"),
		"2001:DB8:1:5::/64":  entry("x@example.com"),
		"192.0.2.0/24":       entry("x@example.com"),
		"192.0.2.0/32":       entry("x@example.com"),
	}})
	if m.Size() != 2 {
		t.Fatalf("evidence entries = %v, want the /64 and the IPv4 address", slices.Collect(maps.Keys(m.ips)))
	}
	e := m.ips["2001:db8:1:2::/64"]
	if e == nil || len(e.failed) != 3 {
		t.Fatalf("/64 evidence = %+v, want the failures of both addresses and the /64", e)
	}
	if f := m.ips["192.0.2.1"]; f == nil || len(f.failed) != 1 {
		t.Fatalf("IPv4 evidence = %+v", f)
	}
}

func TestMailSprayLoadNormalisesKeys(t *testing.T) {
	m, clock := newTestSpray(testSprayConfig())
	now := clock.Now()
	t0, t1, t2 := now.Add(-3*time.Hour), now.Add(-2*time.Hour), now.Add(-time.Hour)
	// Untrimmed names, as a damaged bucket could hold them.
	const failedSpaced, weakSpaced = " a@example.com", "w@example.com "
	loadSpraySnapshot(t, m, store.MailSprayState{
		IPs: map[string]store.MailSprayIP{
			"not-an-ip": {Failed: map[string]store.MailSprayFailure{"a@example.com": {First: t1, Last: t1, Count: 1}}, LastSeen: t1},
			"192.0.2.5": {
				Failed: map[string]store.MailSprayFailure{
					"A@Example.com": {First: t1, Last: t2, Count: 1, Exist: uint8(mailboxExists)},
					failedSpaced:    {First: t0, Last: t1, Count: 3, Exist: uint8(mailboxMissing)},
				},
				WeakAlerted: map[string]time.Time{"W@Example.com": t0, weakSpaced: t1},
				LastSeen:    t2,
			},
		},
		Trust: map[string]map[string]store.GoodSourcePair{
			"not-an-ip": {"a@example.com": {First: t0, Last: t1}},
			"192.0.2.5": {
				"T@Example.com": {First: t0, Last: t1},
				"t@example.com": {First: t1, Last: t2},
			},
		},
		Networks: map[string]map[string]time.Time{
			"Nobody@Example.com": {"198.51.0.0/16": t1, "bogus": t1, "10.0.0.0/8": t1, "192.0.2.0/16": t1},
			"nobody@example.com": {"203.0.0.0/16": t2},
		},
	})

	if m.Size() != 1 || m.TrustSize() != 1 || len(m.names) != 1 {
		t.Fatalf("loaded evidence=%d trust=%d names=%d, want 1 each", m.Size(), m.TrustSize(), len(m.names))
	}
	e := m.ips["192.0.2.5"]
	if f := e.failed["a@example.com"]; len(e.failed) != 1 || !f.first.Equal(t0) || !f.last.Equal(t2) || f.count != 3 || f.exist != mailboxExists {
		t.Fatalf("merged failures = %+v, want one name first t0, last t2, count 3, exists", e.failed)
	}
	if at := e.weakAlerted["w@example.com"]; len(e.weakAlerted) != 1 || !at.Equal(t1) {
		t.Fatalf("merged advisories = %v, want w@example.com at t1", e.weakAlerted)
	}
	if tr := m.trust[sprayTrustKey{"192.0.2.5", "t@example.com"}]; !tr.first.Equal(t0) || !tr.last.Equal(t2) {
		t.Fatalf("merged trust = %+v, want first t0, last t2", tr)
	}
	if n := m.names["nobody@example.com"]; n == nil || len(n.networks) != 2 || !n.last.Equal(t2) {
		t.Fatalf("merged corroboration = %+v, want two networks, last t2", n)
	}
}

// A crack revoked before the restart still cannot earn trust after it.
func TestMailSprayRestartKeepsRevokedTrust(t *testing.T) {
	m, clock := newTestSpray(testSprayConfig())
	const ip = "192.0.2.60"
	ageTrust(t, m, clock, ip, "a@example.com")
	m.RevokeTrust(ip, "a@example.com")

	m = restartSpray(t, m, clock)
	if clean, _ := m.Success(ip, "a@example.com"); clean {
		t.Fatalf("a revoked mailbox earned trust again after the restart")
	}
	if m.TrustSize() != 0 {
		t.Fatalf("trust records = %d, want 0", m.TrustSize())
	}
}

// bucketMatches fails the test unless the store holds exactly m's memory.
func bucketMatches(t *testing.T, db *store.DB, m *mailSpray) {
	t.Helper()
	got, err := loadSavedSpray(db)
	if err != nil {
		t.Fatalf("LoadMailSpray: %v", err)
	}
	if want := m.Export(); !reflect.DeepEqual(got, want) {
		t.Fatalf("bucket differs from memory:\n got %+v\nwant %+v", got, want)
	}
}

func TestMailSprayDeltaSaveWritesOnlyChangedKeys(t *testing.T) {
	db := openStoreForTest(t)
	m, clock := newTestSpray(testSprayConfig())
	d := &Daemon{mailSpray: m}
	for _, ip := range []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"} {
		m.Failure(ip, "a@example.com", mailboxExists)
	}
	ageTrust(t, m, clock, "203.0.113.1", "t@example.com")
	if !m.full {
		t.Fatalf("the first save is not a full snapshot")
	}
	d.persistMailSpray()
	bucketMatches(t, db, m)

	clock.advance(time.Minute)
	m.Failure("192.0.2.1", "b@example.com", mailboxExists)
	delta, full := m.ExportChanges()
	if full || len(delta.Put.IPs) != 1 || len(delta.Put.Trust) != 0 || len(delta.Put.Networks) != 0 ||
		len(delta.DeleteIPs)+len(delta.DeleteTrust)+len(delta.DeleteNames) != 0 {
		t.Fatalf("delta after one failure = full %v %+v, want only 192.0.2.1", full, delta)
	}
	if _, ok := delta.Put.IPs["192.0.2.1"]; !ok {
		t.Fatalf("delta misses the changed IP: %+v", delta)
	}
	m.RetryChanges(delta, full)

	// A sentinel written behind the detector's back survives a delta save,
	// so the save did not rewrite the bucket.
	sentinel := clock.Now().Add(-time.Hour)
	if err := db.ApplyMailSprayDelta(store.MailSprayDelta{Put: store.MailSprayState{
		IPs: map[string]store.MailSprayIP{"192.0.2.2": {LastSeen: sentinel}},
	}}); err != nil {
		t.Fatalf("writing sentinel: %v", err)
	}
	d.persistMailSpray()
	got, err := loadSavedSpray(db)
	if err != nil {
		t.Fatalf("LoadMailSpray: %v", err)
	}
	if !got.IPs["192.0.2.2"].LastSeen.Equal(sentinel) {
		t.Fatalf("an unchanged IP was rewritten by a delta save")
	}
	if len(got.IPs["192.0.2.1"].Failed) != 2 {
		t.Fatalf("changed IP not saved: %+v", got.IPs["192.0.2.1"])
	}
}

func TestMailSprayDeltaSaveDeletesDroppedKeys(t *testing.T) {
	db := openStoreForTest(t)
	cfg := testSprayConfig()
	cfg.MaxIPs = 20
	m, clock := newTestSpray(cfg)
	d := &Daemon{mailSpray: m}
	for i := range cfg.MaxIPs {
		m.Failure(fmt.Sprintf("192.0.2.%d", i), "a@example.com", mailboxExists)
		clock.advance(time.Second)
	}
	corroborate(t, m, "nobody@example.com")
	ageTrust(t, m, clock, "203.0.113.50", "t@example.com")
	d.persistMailSpray()
	bucketMatches(t, db, m)

	// Eviction: a new IP pushes the oldest one-shots out.
	m.Failure("192.0.2.199", "a@example.com", mailboxExists)
	if m.ips["192.0.2.0"] != nil {
		t.Fatalf("setup: the oldest one-shot was not evicted")
	}
	d.persistMailSpray()
	bucketMatches(t, db, m)

	// Purge: everything ages out, keys go from the bucket.
	clock.advance(cfg.Window + time.Minute)
	m.Purge()
	d.persistMailSpray()
	bucketMatches(t, db, m)
	if got, err := loadSavedSpray(db); err != nil || len(got.IPs)+len(got.Trust)+len(got.Networks) != 0 {
		t.Fatalf("after purge the bucket holds %+v, %v; want nothing", got, err)
	}
}

// Forgetting outage failures can leave a saved entry with no records. Purge
// drops it from memory and must drop its key from the bucket too.
func TestMailSprayPurgeDeletesEmptiedEntry(t *testing.T) {
	db := openStoreForTest(t)
	m, clock := newTestSpray(testSprayConfig())
	d := &Daemon{mailSpray: m}
	const ip = "192.0.2.9"
	m.Failure(ip, "a@example.com", mailboxExists)
	clock.advance(time.Minute)
	m.ForgetRecentFailures(ip, clock.Now().Add(-time.Hour))
	d.persistMailSpray()
	if got, err := loadSavedSpray(db); err != nil {
		t.Fatalf("LoadMailSpray: %v", err)
	} else if saved, ok := got.IPs[ip]; !ok || saved.Failed != nil {
		t.Fatalf("setup: bucket = %+v; want the emptied entry saved", got)
	}

	m.Purge()
	delta, full := m.ExportChanges()
	if full || !slices.Equal(delta.DeleteIPs, []string{ip}) {
		t.Fatalf("delta after purge = full %v %+v, want a delete of %s", full, delta, ip)
	}
	m.RetryChanges(delta, full)
	d.persistMailSpray()
	bucketMatches(t, db, m)
}

func TestMailSprayFailedSaveRetries(t *testing.T) {
	db := openStoreForTest(t)
	m, clock := newTestSpray(testSprayConfig())
	d := &Daemon{mailSpray: m}
	m.Failure("192.0.2.9", "a@example.com", mailboxExists)
	d.persistMailSpray()

	// A delete and two writes, all lost to the failed save.
	clock.advance(testSprayConfig().Window + time.Minute)
	m.Purge()
	m.Failure("192.0.2.1", "b@example.com", mailboxExists)
	ageTrust(t, m, clock, "203.0.113.1", "t@example.com")
	closed, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	_ = closed.Close()
	store.SetGlobal(closed)
	d.persistMailSpray()
	store.SetGlobal(db)

	d.persistMailSpray()
	bucketMatches(t, db, m)
}

// A full snapshot followed by deltas restores exactly the live memory. Each
// interval changes some keys through one path only, so a path that forgets
// to mark its key leaves the bucket behind.
func TestMailSprayRestartFromSnapshotAndDeltas(t *testing.T) {
	db := openStoreForTest(t)
	m, clock := newTestSpray(testSprayConfig())
	d := &Daemon{mailSpray: m}
	save := func() {
		t.Helper()
		d.persistMailSpray()
		bucketMatches(t, db, m)
	}
	start := clock.Now()
	ageTrust(t, m, clock, "192.0.2.1", "a@example.com", "r@example.com")
	m.Failure("192.0.2.2", "x@example.com", mailboxExists)
	m.Failure("192.0.2.4", "old@example.com", mailboxExists)
	m.Failure("2001:db8::1", "nobody@example.com", mailboxMissing)
	for i := range maxSprayNamesPerIP + 1 { // the last name overflows
		m.Failure("192.0.2.5", fmt.Sprintf("n%d@example.com", i), mailboxExists)
	}
	save()

	clock.advance(25 * time.Hour)
	m.RevokeTrust("192.0.2.1", "r@example.com")
	m.Failure("192.0.2.2", "x@example.com", mailboxExists)
	m.Failure("192.0.2.2", "y@example.com", mailboxExists)
	m.Success("192.0.2.2", "c@example.com")
	m.Failure("192.0.2.4", "new@example.com", mailboxExists)
	m.Failure("198.51.100.1", "nobody@example.com", mailboxMissing)
	for i := range maxSprayNamesPerIP {
		m.Failure("192.0.2.5", fmt.Sprintf("n%d@example.com", i), mailboxExists)
	}
	save()

	// Logins only: a weak advisory and an aged trust refresh.
	clock.advance(2 * time.Hour)
	if _, v := m.Success("192.0.2.2", "d@example.com"); v == nil {
		t.Fatalf("setup: no advisory for d@example.com")
	}
	if clean, _ := m.Success("192.0.2.1", "a@example.com"); !clean {
		t.Fatalf("setup: aged trust did not refresh")
	}
	save()

	// Purge only: the first interval's records age out, the rest stay.
	clock.t = start.Add(testSprayConfig().Window + 12*time.Minute)
	m.Purge()
	if e := m.ips["192.0.2.4"]; e == nil || len(e.failed) != 1 {
		t.Fatalf("setup: want a partial purge of 192.0.2.4, got %+v", e)
	}
	if e := m.ips["192.0.2.5"]; e == nil || !e.untracked.IsZero() || len(e.failed) != maxSprayNamesPerIP {
		t.Fatalf("setup: want only the overflow marker of 192.0.2.5 purged, got %+v", e)
	}
	if n := m.names["nobody@example.com"]; n == nil || len(n.networks) != 1 {
		t.Fatalf("setup: want a partial purge of nobody@example.com, got %+v", n)
	}
	save()

	next := newMailSpray(m.cfg, clock.Now)
	next.ExportChanges() // a detector that already saved
	(&Daemon{mailSpray: next}).loadMailSpray()
	if got, want := next.Export(), m.Export(); !reflect.DeepEqual(got, want) {
		t.Fatalf("restart from snapshot and deltas:\n got %+v\nwant %+v", got, want)
	}
	if _, full := next.ExportChanges(); !full {
		t.Fatalf("the first save after a load is not a full snapshot")
	}
}

// Attacker churn of one-shot IPs between saves must neither grow the change
// set nor force a rewrite of idle evidence: the delta holds only what the
// churn actually changed.
func TestMailSprayChurnKeepsSavesSmall(t *testing.T) {
	cfg := testSprayConfig()
	cfg.MaxIPs = 20
	m, clock := newTestSpray(cfg)
	stable := make([]string, 10)
	for i := range stable {
		stable[i] = fmt.Sprintf("192.0.2.%d", i)
		m.Failure(stable[i], "a@example.com", mailboxExists)
		wantRule(t, m.Failure(stable[i], "b@example.com", mailboxExists), sprayRuleBreadth, true)
	}
	m.ExportChanges()

	for i := range 10 * cfg.MaxIPs {
		clock.advance(time.Second)
		m.Failure(fmt.Sprintf("2001:db8:%x::1", i), "a@example.com", mailboxExists)
		if n := len(m.ipChanges.dirty); n > cfg.MaxIPs {
			t.Fatalf("change set holds %d IPs, pool %d", n, cfg.MaxIPs)
		}
	}
	delta, full := m.ExportChanges()
	if full {
		t.Fatalf("churn forced a full rewrite")
	}
	for _, ip := range stable {
		if _, ok := delta.Put.IPs[ip]; ok || slices.Contains(delta.DeleteIPs, ip) {
			t.Fatalf("idle %s was rewritten by churn", ip)
		}
	}
	if len(delta.DeleteIPs) != 0 {
		t.Fatalf("deletes for IPs never saved: %v", delta.DeleteIPs)
	}
}

// Saves that keep failing under churn keep the bookkeeping bounded, and the
// first save that works brings the bucket back in line.
func TestMailSprayChangeSetBoundedWhileSavesFail(t *testing.T) {
	db := openStoreForTest(t)
	cfg := testSprayConfig()
	cfg.MaxIPs = 10
	m, clock := newTestSpray(cfg)
	d := &Daemon{mailSpray: m}
	for i := range cfg.MaxIPs {
		m.Failure(fmt.Sprintf("192.0.2.%d", i), "a@example.com", mailboxExists)
	}
	d.persistMailSpray()

	closed, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	_ = closed.Close()
	store.SetGlobal(closed)
	for round := range 5 {
		for i := range 3 * cfg.MaxIPs {
			clock.advance(time.Second)
			m.Failure(fmt.Sprintf("2001:db8:%x:%x::1", round, i), "a@example.com", mailboxExists)
		}
		d.persistMailSpray()
		if n, s := len(m.ipChanges.dirty), len(m.ipChanges.saved); n > 2*cfg.MaxIPs || s > 2*cfg.MaxIPs {
			t.Fatalf("round %d: change set %d, saved set %d, bound %d", round, n, s, 2*cfg.MaxIPs)
		}
	}
	store.SetGlobal(db)
	d.persistMailSpray()
	bucketMatches(t, db, m)
}

// Turning the detector off drops its memory, and the next save drops the
// saved copy too, so a later restart with it on starts clean.
func TestMailSprayDisableEmptiesBucketOnNextSave(t *testing.T) {
	db := openStoreForTest(t)
	m, clock := newTestSpray(testSprayConfig())
	d := &Daemon{mailSpray: m}
	m.Failure("192.0.2.1", "a@example.com", mailboxExists)
	ageTrust(t, m, clock, "203.0.113.1", "t@example.com")
	d.persistMailSpray()
	d.persistMailSpray() // now in delta mode

	off := testSprayConfig()
	off.Window = 0
	m.SetConfig(off)
	d.persistMailSpray()
	if got, err := loadSavedSpray(db); err != nil || len(got.IPs)+len(got.Trust)+len(got.Networks) != 0 {
		t.Fatalf("after disabling the bucket holds %+v, %v; want nothing", got, err)
	}
}

func TestMailSprayFutureNetworksCannotCorroborate(t *testing.T) {
	m, clock := newTestSpray(testSprayConfig())
	loadSpraySnapshot(t, m, store.MailSprayState{Networks: map[string]map[string]time.Time{
		"missing@example.com": {
			"198.51.0.0/16": clock.Now().Add(time.Hour),
			"203.0.0.0/16":  clock.Now().Add(time.Hour),
		},
	}})
	wantNoVerdict(t, m.Failure("192.0.2.1", "missing@example.com", mailboxMissing))
	if got := m.networkCount(m.names["missing@example.com"], clock.Now()); got != 1 {
		t.Fatalf("network count = %d, want only the live observation", got)
	}
}

func TestMailSprayLoadRevocationOverridesTrust(t *testing.T) {
	m, clock := newTestSpray(testSprayConfig())
	const ip = "192.0.2.1"
	st := store.MailSprayState{
		IPs:   map[string]store.MailSprayIP{ip: {Revoked: map[string]time.Time{}}},
		Trust: map[string]map[string]store.GoodSourcePair{ip: {}},
	}
	// Include revocations beyond the name cap: losing a name must not keep
	// its conflicting trust. The unrelated mailbox must remain trusted.
	for i := range maxSprayNamesPerIP + 1 {
		mb := fmt.Sprintf("r%d@example.com", i)
		st.IPs[ip].Revoked[mb] = clock.Now()
		st.Trust[ip][mb] = store.GoodSourcePair{First: clock.Now().Add(-time.Hour), Last: clock.Now()}
	}
	st.Trust[ip]["clean@example.com"] = store.GoodSourcePair{First: clock.Now().Add(-time.Hour), Last: clock.Now()}
	loadSpraySnapshot(t, m, st)
	for i := range maxSprayNamesPerIP + 1 {
		mb := fmt.Sprintf("r%d@example.com", i)
		if m.TrustedAll(ip, []string{mb}) {
			t.Errorf("revoked %s retained trust", mb)
		}
		if clean, _ := m.Success(ip, mb); clean {
			t.Errorf("revoked %s earned trust", mb)
		}
	}
	if !m.TrustedAll(ip, []string{"clean@example.com"}) {
		t.Fatal("unrelated aged trust was lost")
	}
}

// A saved revocation under a /64 key drops the mailbox's trust for every
// address of the /64, as the live crack did.
func TestMailSprayLoadRevocationCovers64(t *testing.T) {
	m, clock := newTestSpray(testSprayConfig())
	now := clock.Now()
	aged := store.GoodSourcePair{First: now.Add(-time.Hour), Last: now}
	loadSpraySnapshot(t, m, store.MailSprayState{
		IPs: map[string]store.MailSprayIP{"2001:db8:1:2::/64": {Revoked: map[string]time.Time{"l@example.com": now}, LastSeen: now}},
		Trust: map[string]map[string]store.GoodSourcePair{
			"2001:db8:1:2::a": {"l@example.com": aged, "o@example.com": aged},
			"2001:db8:1:3::a": {"l@example.com": aged},
		},
	})
	if m.TrustedAll("2001:db8:1:2::a", []string{"l@example.com"}) {
		t.Fatal("saved revocation left trust in the /64")
	}
	if !m.TrustedAll("2001:db8:1:2::a", []string{"o@example.com"}) || !m.TrustedAll("2001:db8:1:3::a", []string{"l@example.com"}) {
		t.Fatal("saved revocation dropped unrelated trust")
	}
}

func TestMailSprayFailedDeltaAfterConfigShrinkStaysBounded(t *testing.T) {
	db := openStoreForTest(t)
	cfg := testSprayConfig()
	m, clock := newTestSpray(cfg)
	d := &Daemon{mailSpray: m}
	for i := range 20 {
		m.Failure(fmt.Sprintf("192.0.2.%d", i), "a@example.com", mailboxExists)
	}
	d.persistMailSpray()
	clock.advance(cfg.Window + time.Minute)
	m.Purge()
	delta, full := m.ExportChanges()
	if full || len(delta.DeleteIPs) != 20 {
		t.Fatal("setup did not export all deletes")
	}
	cfg.MaxIPs = 1
	m.SetConfig(cfg)
	m.RetryChanges(delta, full)
	if len(m.ipChanges.saved) > 2*cfg.MaxIPs || len(m.ipChanges.dirty) > 2*cfg.MaxIPs {
		t.Fatalf("retry after shrink left saved=%d dirty=%d", len(m.ipChanges.saved), len(m.ipChanges.dirty))
	}
	d.persistMailSpray()
	bucketMatches(t, db, m)
}

func TestMailSprayLoadedCountsCannotOverflow(t *testing.T) {
	m, clock := newTestSpray(testSprayConfig())
	const ip = "192.0.2.1"
	maxInt := int(^uint(0) >> 1)
	loadSpraySnapshot(t, m, store.MailSprayState{IPs: map[string]store.MailSprayIP{ip: {
		Failed: map[string]store.MailSprayFailure{
			"a@example.com": {First: clock.Now(), Last: clock.Now(), Count: maxInt},
			"b@example.com": {First: clock.Now(), Last: clock.Now(), Count: 1},
		},
		LastSeen: clock.Now(),
	}}})
	if got := m.ipRank(m.ips[ip], clock.Now()); got != sprayRankRepeat {
		t.Errorf("rank = %d, want repeated failures", got)
	}
	m.Failure(ip, "a@example.com", mailboxExists)
	if got := m.ips[ip].failed["a@example.com"].count; got != maxInt {
		t.Fatalf("failure counter = %d, want saturated at %d", got, maxInt)
	}
}

func TestMailSprayLoadRejectsScopedAddresses(t *testing.T) {
	m, clock := newTestSpray(testSprayConfig())
	// IPv6 zones are not remote log identities and have no length bound.
	ip := "2001:db8::1%" + strings.Repeat("z", 4096)
	loadSpraySnapshot(t, m, store.MailSprayState{
		IPs: map[string]store.MailSprayIP{ip: {
			Failed: map[string]store.MailSprayFailure{"a@example.com": {First: clock.Now(), Last: clock.Now(), Count: 1}},
		}},
		Trust: map[string]map[string]store.GoodSourcePair{ip: {
			"t@example.com": {First: clock.Now().Add(-time.Hour), Last: clock.Now()},
		}},
	})
	if m.Size() != 0 || m.TrustSize() != 0 {
		t.Fatalf("scoped address retained evidence=%d trust=%d", m.Size(), m.TrustSize())
	}
}

func TestMailSprayLargestLiveEntriesSurviveRestart(t *testing.T) {
	m, clock := newTestSpray(testSprayConfig())
	// Control bytes occupy six JSON bytes each, so exercise the entry limit
	// with full maps of the longest, most expensive mailbox keys.
	mailbox := func(i int) string {
		return fmt.Sprintf("%03d", i) + strings.Repeat("\x00", maxSprayMailboxBytes-3)
	}
	for i := range maxSprayTrustPerIP {
		m.Success("192.0.2.1", mailbox(i))
	}
	for i := range maxSprayNamesPerIP {
		m.Failure("192.0.2.2", mailbox(i), mailboxMissing)
		m.Success("192.0.2.2", mailbox(maxSprayNamesPerIP+i))
		m.RevokeTrust("192.0.2.2", mailbox(2*maxSprayNamesPerIP+i))
		clock.advance(m.cfg.Suppression + time.Second)
	}
	e := m.ips["192.0.2.2"]
	if m.TrustSize() != maxSprayTrustPerIP || len(e.failed) != maxSprayNamesPerIP ||
		len(e.weakAlerted) != maxSprayNamesPerIP || len(e.revoked) != maxSprayNamesPerIP {
		t.Fatal("setup did not fill every per-address map")
	}
	want := m.Export()
	next := restartSpray(t, m, clock)
	if got := next.Export(); !reflect.DeepEqual(got, want) {
		t.Fatal("maximum-sized live entries did not survive persistence")
	}
}

func loadSavedSpray(db *store.DB) (store.MailSprayState, error) {
	st := store.MailSprayState{
		IPs:      make(map[string]store.MailSprayIP),
		Trust:    make(map[string]map[string]store.GoodSourcePair),
		Networks: make(map[string]map[string]time.Time),
		Blocked:  make(map[string]time.Time),
	}
	err := db.LoadMailSpray(maxSprayEntryBytes, func(part store.MailSprayState) {
		maps.Copy(st.IPs, part.IPs)
		maps.Copy(st.Trust, part.Trust)
		maps.Copy(st.Networks, part.Networks)
		maps.Copy(st.Blocked, part.Blocked)
	})
	return st, err
}

// Mutations made after export must survive both successful and failed writes.
func TestMailSprayChangesDuringSave(t *testing.T) {
	for _, snapshot := range []bool{false, true} {
		for _, fail := range []bool{false, true} {
			for _, remove := range []bool{false, true} {
				t.Run(fmt.Sprintf("snapshot=%v/fail=%v/remove=%v", snapshot, fail, remove), func(t *testing.T) {
					db := openStoreForTest(t)
					m, clock := newTestSpray(testSprayConfig())
					d := &Daemon{mailSpray: m}
					m.Failure("192.0.2.1", "a@example.com", mailboxMissing)
					m.Success("203.0.113.1", "t@example.com")
					if !snapshot {
						d.persistMailSpray()
						m.Failure("192.0.2.1", "a@example.com", mailboxMissing)
						m.Success("203.0.113.1", "t@example.com")
					}
					delta, full := m.ExportChanges()
					if full != snapshot || delta.Empty() {
						t.Fatal("setup exported the wrong save kind")
					}
					if remove {
						clock.advance(m.cfg.Window + time.Minute)
						m.Purge()
					} else {
						clock.advance(time.Minute)
						m.Failure("192.0.2.1", "b@example.com", mailboxExists)
						m.Failure("198.51.100.1", "a@example.com", mailboxMissing)
						m.Success("203.0.113.1", "t@example.com")
					}
					if fail {
						m.RetryChanges(delta, full)
					} else if full {
						if err := db.SaveMailSpray(delta.Put); err != nil {
							t.Fatal(err)
						}
					} else if err := db.ApplyMailSprayDelta(delta); err != nil {
						t.Fatal(err)
					}
					d.persistMailSpray()
					bucketMatches(t, db, m)
					if delta, full = m.ExportChanges(); full || !delta.Empty() {
						t.Fatal("successful save left pending changes")
					}
				})
			}
		}
	}
}

func TestMailSprayStreamingLoadCapsEachPoolDuringReplay(t *testing.T) {
	cfg := testSprayConfig()
	cfg.MaxIPs = 4
	m, clock := newTestSpray(cfg)
	now := clock.Now()
	err := m.Load(func(visit func(store.MailSprayState)) error {
		for i := range 2 * cfg.MaxIPs {
			ip := fmt.Sprintf("192.0.2.%d", i)
			at := now.Add(-time.Duration(i) * time.Minute)
			visit(store.MailSprayState{Trust: map[string]map[string]store.GoodSourcePair{
				ip: {"t@example.com": {First: at, Last: at}},
			}})
			if len(m.trust) > cfg.MaxIPs || len(m.trustByIP) > cfg.MaxIPs || len(m.trustByMailbox) > cfg.MaxIPs {
				t.Fatal("trust exceeded its cap during replay")
			}
		}
		for i := range 2 * cfg.MaxIPs {
			ip := fmt.Sprintf("192.0.2.%d", i)
			visit(store.MailSprayState{IPs: map[string]store.MailSprayIP{ip: {
				Failed: map[string]store.MailSprayFailure{"a@example.com": {First: now, Last: now, Count: 1}}, LastSeen: now,
			}}})
			if len(m.ips) > cfg.MaxIPs {
				t.Fatal("evidence exceeded its cap during replay")
			}
		}
		for i := range maxSprayCorroborationNames + 1 {
			visit(store.MailSprayState{Networks: map[string]map[string]time.Time{
				fmt.Sprintf("n%d@example.com", i): {"192.0.0.0/16": now},
			}})
			if len(m.names) > maxSprayCorroborationNames {
				t.Fatal("corroboration exceeded its cap during replay")
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := m.trust[sprayTrustKey{"192.0.2.0", "t@example.com"}]; !ok {
		t.Fatal("out-of-order replay discarded the newest trust")
	}
	if m.Size() != cfg.MaxIPs || m.TrustSize() != cfg.MaxIPs || len(m.names) != maxSprayCorroborationNames*95/100 {
		t.Fatalf("load unexpectedly lost state: evidence=%d trust=%d names=%d", m.Size(), m.TrustSize(), len(m.names))
	}
}

func loadSpraySnapshot(t *testing.T, m *mailSpray, st store.MailSprayState) {
	t.Helper()
	if err := m.Load(func(visit func(store.MailSprayState)) error {
		visit(st)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// A new marker is saved under its own key; Purge expiry deletes it; a failed
// save writes and deletes it again.
func TestMailSprayMarkerDeltaSave(t *testing.T) {
	db := openStoreForTest(t)
	cfg := markerSprayConfig()
	m, clock := newTestSpray(cfg)
	d := &Daemon{mailSpray: m}
	sprayBlock(t, m, "192.0.2.7")
	d.persistMailSpray()
	bucketMatches(t, db, m)

	clock.advance(time.Hour)
	const ip = "2001:db8:1::a"
	sprayBlock(t, m, ip)
	delta, full := m.ExportChanges()
	if end, ok := delta.Put.Blocked[ip]; full || !ok || !end.Equal(clock.Now().Add(cfg.BlockTTL)) ||
		len(delta.Put.Blocked) != 1 || len(delta.DeleteBlocked) != 0 {
		t.Fatalf("delta after a new marker = full %v %+v, want only blk:%s", full, delta, ip)
	}
	m.RetryChanges(delta, full)
	d.persistMailSpray()
	bucketMatches(t, db, m)

	clock.advance(cfg.BlockTTL + cfg.Window + time.Minute)
	m.Purge()
	delta, full = m.ExportChanges()
	slices.Sort(delta.DeleteBlocked)
	if full || !slices.Equal(delta.DeleteBlocked, []string{"192.0.2.7", ip}) {
		t.Fatalf("delta after expiry = full %v %+v, want both markers deleted", full, delta)
	}
	m.RetryChanges(delta, full)
	d.persistMailSpray()
	bucketMatches(t, db, m)
	if got, err := loadSavedSpray(db); err != nil || len(got.Blocked) != 0 {
		t.Fatalf("after expiry the bucket holds markers %v, %v", got.Blocked, err)
	}
}

func TestMailSprayLoadMarkers(t *testing.T) {
	cfg := markerSprayConfig()
	m, clock := newTestSpray(cfg)
	now := clock.Now()
	blocked := map[string]time.Time{
		"not-an-ip":        now,
		"2001:db8::1%eth0": now,
		"192.0.2.1":        now.Add(-cfg.Window - time.Minute), // past end + window
		"192.0.2.2":        now.Add(365 * 24 * time.Hour),
		"192.0.2.3":        now.Add(-time.Hour),
	}
	for i := range maxSprayNamesPerIP + 4 {
		blocked[fmt.Sprintf("2001:db8:1::%x", i+1)] = now.Add(time.Duration(i) * time.Minute)
	}
	loadSpraySnapshot(t, m, store.MailSprayState{Blocked: blocked})
	for _, ip := range []string{"not-an-ip", "2001:db8::1%eth0", "192.0.2.1"} {
		if _, ok := m.blocks[ip]; ok {
			t.Errorf("marker of %s loaded", ip)
		}
	}
	if got := m.blocks["192.0.2.2"]; !got.Equal(now.Add(cfg.BlockTTL)) {
		t.Errorf("future marker end = %v, want clamped to %v", got, now.Add(cfg.BlockTTL))
	}
	if got := m.blocks["192.0.2.3"]; !got.Equal(now.Add(-time.Hour)) {
		t.Errorf("ended marker in the window = %v, want kept", got)
	}
	if n := len(m.blocksByKey["2001:db8:1::/64"]); n != maxSprayNamesPerIP {
		t.Errorf("/64 markers = %d, want %d", n, maxSprayNamesPerIP)
	}
	for i := range 4 {
		if _, ok := m.blocks[fmt.Sprintf("2001:db8:1::%x", i+1)]; ok {
			t.Errorf("soonest-ending marker %d of the /64 kept", i+1)
		}
	}
	wantRule(t, m.Failure("192.0.2.3", "a@example.com", mailboxExists), sprayRuleRepeat, true)

	// A second load replaces the first, within the global cap.
	big := make(map[string]time.Time, maxSprayMarkers+1)
	for i := range maxSprayMarkers + 1 {
		big[fmt.Sprintf("2001:db8:%x:%x::1", i>>16, i&0xffff)] = now.Add(time.Duration(i) * time.Second)
	}
	loadSpraySnapshot(t, m, store.MailSprayState{Blocked: big})
	if n := len(m.blocks); n > maxSprayMarkers || n != len(m.blocksByKey) {
		t.Errorf("markers = %d, index keys = %d, cap %d", n, len(m.blocksByKey), maxSprayMarkers)
	}
	if _, ok := m.blocks["192.0.2.3"]; ok {
		t.Errorf("a marker of the first load survived the second")
	}
}

func TestMailSprayMarkerPersists(t *testing.T) {
	m, clock := newTestSpray(markerSprayConfig())
	ips := []string{"192.0.2.7", "2001:db8:1::a"}
	for _, ip := range ips {
		sprayBlock(t, m, ip)
	}
	want := m.Export()
	if len(want.Blocked) != len(ips) {
		t.Fatalf("setup: markers %v", want.Blocked)
	}
	m = restartSpray(t, m, clock)
	if got := m.Export(); !reflect.DeepEqual(got, want) {
		t.Fatalf("restart changed the memory:\n got %+v\nwant %+v", got, want)
	}
	clock.advance(8 * 24 * time.Hour)
	for _, ip := range ips {
		wantRule(t, m.Failure(ip, "c@example.com", mailboxExists), sprayRuleRepeat, true)
	}
}

// Saved address keys load under the canonical form. Spellings of one
// address merge, the later time winning whatever the visit order.
func TestMailSprayLoadCanonicalisesAddresses(t *testing.T) {
	cfg := markerSprayConfig()
	m, clock := newTestSpray(cfg)
	now := clock.Now()
	early, late := now.Add(-2*time.Hour), now.Add(-time.Hour)
	entry := func(src string, until time.Time) store.MailSprayIP {
		return store.MailSprayIP{
			Failed:   map[string]store.MailSprayFailure{"a@example.com": {First: early, Last: early, Count: 1}},
			Sources:  map[string]store.MailSpraySource{src: {SuppressedUntil: until}},
			LastSeen: early,
		}
	}
	visits := []store.MailSprayState{
		{
			IPs:     map[string]store.MailSprayIP{"2001:db8:1::/64": entry("2001:db8:1:0::a", now.Add(20*time.Minute))},
			Trust:   map[string]map[string]store.GoodSourcePair{"2001:db8:1:0::b": {"t@example.com": {First: early, Last: late}}},
			Blocked: map[string]time.Time{"2001:db8:1:0::a": late},
		},
		{
			IPs:     map[string]store.MailSprayIP{"2001:db8:1::/64": entry("2001:DB8:1::A", now.Add(10*time.Minute))},
			Trust:   map[string]map[string]store.GoodSourcePair{"2001:DB8:1::B": {"t@example.com": {First: early, Last: early}}},
			Blocked: map[string]time.Time{"2001:DB8:1::A": early},
		},
	}
	if err := m.Load(func(visit func(store.MailSprayState)) error {
		for _, st := range visits {
			visit(st)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	const a, b = "2001:db8:1::a", "2001:db8:1::b"
	if end, ok := m.blocks[a]; len(m.blocks) != 1 || !ok || !end.Equal(late) {
		t.Errorf("markers = %v, want %s ending %v", m.blocks, a, late)
	}
	if src, ok := m.ips["2001:db8:1::/64"].sources[a]; len(m.ips["2001:db8:1::/64"].sources) != 1 || !ok || !src.blockUntil.Equal(now.Add(20*time.Minute)) {
		t.Errorf("sources = %v, want %s suppressed until the later time", m.ips["2001:db8:1::/64"].sources, a)
	}
	if tr, ok := m.trust[sprayTrustKey{b, "t@example.com"}]; m.TrustSize() != 1 || !ok || !tr.last.Equal(late) {
		t.Errorf("trust = %v, want %s last seen at the later time", m.trust, b)
	}
}
