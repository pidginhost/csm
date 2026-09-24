package admission

import (
	"reflect"
	"testing"
	"time"
)

type rootSpec struct {
	p      *Producer
	check  string
	target string
	age    time.Duration
	cursor string
	sev    Severity
	intel  time.Duration // intel expiry after observation; reputation only
}

func mintRoot(t *testing.T, now time.Time, s rootSpec) Evidence {
	t.Helper()
	target, err := CanonicalAddress(s.target, v6)
	if err != nil {
		target = mustPrefix(t, s.target)
	}
	if s.sev == 0 {
		s.sev = SeverityHigh
	}
	in := EvidenceInput{
		Check:       s.check,
		FindingID:   "0123456789abcdef",
		Severity:    s.sev,
		Observation: ObservationRef{Stream: string(s.p.ID()), Cursor: s.cursor, Version: 1},
		ObservedAt:  now.Add(-s.age),
		Parser:      ParserRef{Name: "fixture", Version: 1},
		Target:      target,
	}
	if s.intel != 0 {
		in.Intel = &IntelRef{Source: "feed", Expires: in.ObservedAt.Add(s.intel)}
	}
	e, err := s.p.Mint(in)
	if err != nil {
		t.Fatalf("mint %s: %v", s.check, err)
	}
	return e
}

func TestAssessClasses(t *testing.T) {
	tp := newTestProducers(t)
	now := t0
	addr := mustAddr(t, "192.0.2.1")
	ssh := func(age time.Duration, cursor string) rootSpec {
		return rootSpec{p: tp.ssh, check: "ssh_brute", target: "192.0.2.1", age: age, cursor: cursor}
	}
	rep := func(age time.Duration) rootSpec {
		return rootSpec{p: tp.reputation, check: "reputation", target: "192.0.2.1", age: age, cursor: "r", intel: 30 * time.Hour}
	}
	cases := []struct {
		name               string
		roots              []rootSpec
		class              Class
		direct, corrobated bool
	}{
		{"local root", []rootSpec{ssh(time.Minute, "a")}, ClassC2, false, false},
		{"reputation alone", []rootSpec{rep(time.Minute)}, ClassC1, false, false},
		{"local plus reputation", []rootSpec{ssh(time.Minute, "a"), rep(time.Minute)}, ClassC3, false, true},
		{"local plus reputation 23h old", []rootSpec{ssh(time.Minute, "a"), rep(23 * time.Hour)}, ClassC3, false, true},
		{"local plus reputation past lookback", []rootSpec{ssh(time.Minute, "a"), rep(24 * time.Hour)}, ClassC2, false, false},
		{"fresh reputation plus stale local", []rootSpec{rep(time.Minute), ssh(20*time.Hour, "a")}, ClassC1, false, false},
		{"two roots of one family", []rootSpec{ssh(time.Minute, "a"), ssh(time.Minute, "b")}, ClassC2, false, false},
		{"same request in access log and WAF", []rootSpec{
			{p: tp.http, check: "http_scan", target: "192.0.2.1", age: time.Minute, cursor: "a"},
			{p: tp.http, check: "waf_escalation", target: "192.0.2.1", age: time.Minute, cursor: "b"},
		}, ClassC2, false, false},
		{"derived history never corroborates", []rootSpec{ssh(time.Minute, "a"),
			{p: tp.derived, check: "threat_score", target: "192.0.2.1", age: time.Minute, cursor: "t"}}, ClassC2, false, false},
		{"two local families", []rootSpec{ssh(time.Minute, "a"),
			{p: tp.mail, check: "mail_brute", target: "192.0.2.1", age: 3 * time.Hour, cursor: "m"}}, ClassC3, false, true},
		{"direct compromise", []rootSpec{{p: tp.mail, check: "mail_takeover", target: "192.0.2.1", age: time.Minute, cursor: "m"}}, ClassC3, true, false},
		{"direct compromise with support", []rootSpec{{p: tp.mail, check: "mail_takeover", target: "192.0.2.1", age: time.Minute, cursor: "m"}, ssh(time.Minute, "a")}, ClassC3, true, false},
	}
	for _, tc := range cases {
		var roots []Evidence
		for _, s := range tc.roots {
			roots = append(roots, mintRoot(t, now, s))
		}
		a, err := Assess(addr, roots, now)
		if err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		if a.Tier.Class != tc.class || a.DirectC3 != tc.direct || a.Corroborated != tc.corrobated {
			t.Errorf("%s: class %s direct %v corroborated %v, want %s %v %v", tc.name, a.Tier.Class, a.DirectC3, a.Corroborated, tc.class, tc.direct, tc.corrobated)
		}
		if a.Reserved() != (tc.direct || tc.corrobated) {
			t.Errorf("%s: Reserved() = %v", tc.name, a.Reserved())
		}
	}
}

// The same log line read by two producers is one observation, even across
// families.
func TestAssessSameObservationAcrossFamiliesIsOneRoot(t *testing.T) {
	tp := newTestProducers(t)
	addr := mustAddr(t, "192.0.2.1")
	in := sshInput(t)
	in.Observation = ObservationRef{Stream: "shared", Cursor: "offset=1", Version: 1}
	a, _ := tp.ssh.Mint(in)
	in.Check = "mail_brute"
	in.Observation.Version = 2
	b, err := tp.mail.Mint(in)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Assess(addr, []Evidence{a, b}, t0)
	if err != nil || got.Corroborated || got.Tier.Class != ClassC2 {
		t.Errorf("one observation corroborated itself: %+v %v", got, err)
	}
}

func TestAssessFreshnessBoundaries(t *testing.T) {
	tp := newTestProducers(t)
	addr := mustAddr(t, "192.0.2.1")
	root := mintRoot(t, t0, rootSpec{p: tp.ssh, check: "ssh_brute", target: "192.0.2.1", cursor: "a"})
	if _, err := Assess(addr, []Evidence{root}, t0.Add(RootFreshness-time.Nanosecond)); err != nil {
		t.Errorf("a root is stale before two hours: %v", err)
	}
	_, err := Assess(addr, []Evidence{root}, t0.Add(RootFreshness))
	wantReason(t, "root at two hours", err, ReasonStale)
	intel := mintRoot(t, t0, rootSpec{p: tp.reputation, check: "reputation", target: "192.0.2.1", cursor: "r", intel: 30 * time.Minute})
	_, err = Assess(addr, []Evidence{intel}, t0.Add(30*time.Minute))
	wantReason(t, "intel past its own expiry", err, ReasonStale)
	_, err = Assess(addr, []Evidence{root}, t0.Add(-2*time.Second))
	wantReason(t, "future-dated root", err, ReasonInvalid)
	if _, err := Assess(addr, []Evidence{root}, t0.Add(-500*time.Millisecond)); err != nil {
		t.Errorf("sub-second skew refused: %v", err)
	}
}

func TestAssessTimesAndSeverity(t *testing.T) {
	tp := newTestProducers(t)
	addr := mustAddr(t, "192.0.2.1")
	now := t0
	early := mintRoot(t, now, rootSpec{p: tp.ssh, check: "ssh_brute", target: "192.0.2.1", age: 90 * time.Minute, cursor: "a", sev: SeverityWarning})
	late := mintRoot(t, now, rootSpec{p: tp.ssh, check: "ssh_brute", target: "192.0.2.1", age: 10 * time.Minute, cursor: "b", sev: SeverityHigh})
	oldCritical := mintRoot(t, now, rootSpec{p: tp.mail, check: "mail_brute", target: "192.0.2.1", age: 23*time.Hour + 30*time.Minute, cursor: "m", sev: SeverityCritical})
	a, err := Assess(addr, []Evidence{late, early, oldCritical, late}, now)
	if err != nil {
		t.Fatal(err)
	}
	if a.Tier != (Tier{ClassC3, SeverityHigh}) || !a.Corroborated {
		t.Errorf("tier = %+v corroborated %v; a stale Critical support root must raise class but not severity", a.Tier, a.Corroborated)
	}
	if want := now.Add(-10 * time.Minute).Add(RootFreshness); !a.EvidenceExpiry.Equal(want) {
		t.Errorf("EvidenceExpiry = %v, want %v", a.EvidenceExpiry, want)
	}
	if want := now.Add(-(23*time.Hour + 30*time.Minute)).Add(SupportLookback); !a.ReassessBy.Equal(want) {
		t.Errorf("ReassessBy = %v, want the support root's lookback end %v", a.ReassessBy, want)
	}
	if len(a.Roots) != 3 || a.Roots[0] >= a.Roots[1] || a.Roots[1] >= a.Roots[2] {
		t.Errorf("roots = %v, want three sorted unique IDs", a.Roots)
	}
}

func TestAssessRefusals(t *testing.T) {
	tp := newTestProducers(t)
	addr := mustAddr(t, "192.0.2.1")
	root := mintRoot(t, t0, rootSpec{p: tp.ssh, check: "ssh_brute", target: "192.0.2.1", cursor: "a"})
	other := mintRoot(t, t0, rootSpec{p: tp.ssh, check: "ssh_brute", target: "192.0.2.9", cursor: "b"})
	_, err := Assess(addr, nil, t0)
	wantReason(t, "no roots", err, ReasonInvalid)
	_, err = Assess(addr, []Evidence{root, other}, t0)
	wantReason(t, "root for another address", err, ReasonInvalid)
	_, err = Assess(addr, []Evidence{{}}, t0)
	wantReason(t, "zero evidence", err, ReasonInvalid)
	_, err = Assess(Target{}, []Evidence{root}, t0)
	wantReason(t, "zero target", err, ReasonInvalid)
	_, err = Assess(mustService(t, "192.0.2.1", "tcp", 22), []Evidence{root}, t0)
	wantReason(t, "service target", err, ReasonUnsupportedContainment)
	many := make([]Evidence, MaxRoots+1)
	for i := range many {
		many[i] = root
	}
	_, err = Assess(addr, many, t0)
	wantReason(t, "too many roots", err, ReasonInvalid)
	in := sshInput(t)
	in.Observation.Cursor = "a"
	in.Observation.Stream = "sshd_log"
	in.Parser = ParserRef{Name: "fixture", Version: 1}
	in.FindingID = "fedcba9876543210"
	twin, err := tp.ssh.Mint(in)
	if err != nil {
		t.Fatal(err)
	}
	if twin.ID() != root.ID() || twin.Equal(root) {
		t.Fatal("fixture does not build a conflicting twin")
	}
	_, err = Assess(addr, []Evidence{root, twin}, t0)
	wantReason(t, "conflicting twin", err, ReasonInvalid)
}

func TestAssessPrefixTargets(t *testing.T) {
	tp := newTestProducers(t)
	net := mustPrefix(t, "198.51.100.0/24")
	inside := mintRoot(t, t0, rootSpec{p: tp.ssh, check: "ssh_brute", target: "198.51.100.7", cursor: "a"})
	insideRep := mintRoot(t, t0, rootSpec{p: tp.reputation, check: "reputation", target: "198.51.100.8", cursor: "r", intel: time.Hour})
	summary := mintRoot(t, t0, rootSpec{p: tp.mail, check: "mail_brute", target: "198.51.100.0/24", cursor: "m"})
	outside := mintRoot(t, t0, rootSpec{p: tp.ssh, check: "ssh_brute", target: "203.0.113.7", cursor: "b"})
	a, err := Assess(net, []Evidence{inside, insideRep, summary}, t0)
	if err != nil || a.Tier.Class != ClassC2 || a.Corroborated {
		t.Errorf("prefix assessment = %+v %v; want C2 and no range corroboration", a, err)
	}
	_, err = Assess(net, []Evidence{inside, outside}, t0)
	wantReason(t, "root outside the prefix", err, ReasonInvalid)
	_, err = Assess(mustAddr(t, "198.51.100.7"), []Evidence{summary}, t0)
	wantReason(t, "prefix root for an address", err, ReasonInvalid)
}

func TestAssessReputationSupportExpires(t *testing.T) {
	tp := newTestProducers(t)
	addr := mustAddr(t, "192.0.2.1")
	local := mintRoot(t, t0, rootSpec{p: tp.ssh, check: "ssh_brute", target: "192.0.2.1", cursor: "a"})
	support := mintRoot(t, t0, rootSpec{p: tp.reputation, check: "reputation", target: "192.0.2.1", age: 3 * time.Hour, cursor: "r", intel: 3*time.Hour + time.Minute})
	a, err := Assess(addr, []Evidence{local, support}, t0)
	if err != nil || a.Tier.Class != ClassC3 || !a.Corroborated || !a.ReassessBy.Equal(t0.Add(time.Minute)) || !a.EvidenceExpiry.Equal(t0.Add(RootFreshness)) {
		t.Fatalf("before intel expiry: %+v %v", a, err)
	}
	a, err = Assess(addr, []Evidence{local, support}, t0.Add(time.Minute))
	if err != nil || a.Tier.Class != ClassC2 || a.Corroborated || a.Reserved() {
		t.Fatalf("expired intel supported a raise: %+v %v", a, err)
	}
}

func TestAssessSupportNeverRefreshesLocalRoot(t *testing.T) {
	tp := newTestProducers(t)
	addr := mustAddr(t, "192.0.2.1")
	local := mintRoot(t, t0, rootSpec{p: tp.ssh, check: "ssh_brute", target: "192.0.2.1", age: RootFreshness - time.Minute, cursor: "a"})
	support := mintRoot(t, t0, rootSpec{p: tp.mail, check: "mail_brute", target: "192.0.2.1", age: 3 * time.Hour, cursor: "m"})
	a, err := Assess(addr, []Evidence{local, support}, t0)
	if err != nil || a.Tier.Class != ClassC3 || !a.EvidenceExpiry.Equal(t0.Add(time.Minute)) || !a.ReassessBy.Equal(t0.Add(time.Minute)) {
		t.Fatalf("support changed the fresh root deadline: %+v %v", a, err)
	}
	_, err = Assess(addr, []Evidence{local, support}, t0.Add(time.Minute))
	wantReason(t, "local root expired", err, ReasonStale)
}

func TestAssessReputationFeedsDoNotMultiplyRoots(t *testing.T) {
	tp := newTestProducers(t)
	addr := mustAddr(t, "192.0.2.1")
	one := mintRoot(t, t0, rootSpec{p: tp.reputation, check: "reputation", target: "192.0.2.1", cursor: "r1", intel: time.Hour})
	two := mintRoot(t, t0, rootSpec{p: tp.reputation, check: "reputation", target: "192.0.2.1", cursor: "r2", intel: time.Hour})
	a, err := Assess(addr, []Evidence{one, two}, t0)
	if err != nil || a.Tier.Class != ClassC1 || a.Corroborated || a.Reserved() {
		t.Fatalf("shared upstream feeds raised class: %+v %v", a, err)
	}
	local := mintRoot(t, t0, rootSpec{p: tp.ssh, check: "ssh_brute", target: "192.0.2.1", cursor: "a"})
	mail := mintRoot(t, t0, rootSpec{p: tp.mail, check: "mail_brute", target: "192.0.2.1", cursor: "m"})
	a, err = Assess(addr, []Evidence{one, two, local, mail}, t0)
	if err != nil || a.Tier.Class != ClassC3 || !a.Corroborated || a.DirectC3 {
		t.Fatalf("multiple supports must raise only once: %+v %v", a, err)
	}
}

func TestAssessIgnoresOrderingAndIdenticalDuplicates(t *testing.T) {
	tp := newTestProducers(t)
	addr := mustAddr(t, "192.0.2.1")
	local := mintRoot(t, t0, rootSpec{p: tp.ssh, check: "ssh_brute", target: "192.0.2.1", age: time.Hour, cursor: "local"})
	mail := mintRoot(t, t0, rootSpec{p: tp.mail, check: "mail_brute", target: "192.0.2.1", age: 23*time.Hour + 30*time.Minute, cursor: "mail", sev: SeverityCritical})
	reputation := mintRoot(t, t0, rootSpec{p: tp.reputation, check: "reputation", target: "192.0.2.1", age: 3 * time.Hour, cursor: "rep", intel: 3*time.Hour + time.Minute})
	direct := mintRoot(t, t0, rootSpec{p: tp.mail, check: "mail_takeover", target: "192.0.2.1", cursor: "direct", sev: SeverityWarning})
	for _, roots := range [][]Evidence{{local, mail, reputation}, {local, mail, reputation, direct}} {
		want, err := Assess(addr, roots, t0)
		if err != nil || want.Tier != (Tier{ClassC3, SeverityHigh}) || want.DirectC3 != (len(roots) == 4) || want.Corroborated == want.DirectC3 {
			t.Fatalf("unexpected baseline assessment: %+v %v", want, err)
		}
		var permute func(int)
		permute = func(i int) {
			if i == len(roots) {
				// Every duplicate count through the input bound must preserve
				// the complete assessment, including deadlines and sorted IDs.
				input := append([]Evidence(nil), roots...)
				for len(input) <= MaxRoots {
					got, err := Assess(addr, input, t0)
					if err != nil || !reflect.DeepEqual(got, want) {
						t.Fatalf("ordering or duplication changed assessment: %+v %v; want %+v", got, err, want)
					}
					input = append(input, roots[len(input)%len(roots)])
				}
				return
			}
			for j := i; j < len(roots); j++ {
				roots[i], roots[j] = roots[j], roots[i]
				permute(i + 1)
				roots[i], roots[j] = roots[j], roots[i]
			}
		}
		permute(0)
	}
}
