package admission

import (
	"bytes"
	"crypto/sha256"
	"math"
	"strings"
	"testing"
	"time"
)

// testPolicies is a registry fixture, not the production table.
var testPolicies = map[string]Policy{
	"ssh_brute":      {Family: FamilySSH, Basis: BasisLocal},
	"http_scan":      {Family: FamilyHTTP, Basis: BasisLocal},
	"waf_escalation": {Family: FamilyHTTP, Basis: BasisLocal},
	"mail_brute":     {Family: FamilyMail, Basis: BasisLocal},
	"mail_takeover":  {Family: FamilyMail, Basis: BasisCompromise},
	"reputation":     {Family: FamilyReputation, Basis: BasisIntel},
	"threat_score":   {Family: FamilyDerived, Basis: BasisIntel},
	"login_audit":    {},
}

func testLookup(check string) (string, Policy, bool) {
	if check == "ssh_brute_legacy" {
		check = "ssh_brute"
	}
	p, ok := testPolicies[check]
	return check, p, ok
}

var t0 = time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)

type testProducers struct {
	reg                                         *Registry
	ssh, http, mail, reputation, derived, spare *Producer
}

func newTestProducers(t *testing.T) testProducers {
	t.Helper()
	reg, err := NewRegistry(testLookup)
	if err != nil {
		t.Fatal(err)
	}
	must := func(spec ProducerSpec) *Producer {
		p, err := reg.Register(spec)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	tp := testProducers{reg: reg}
	tp.ssh = must(ProducerSpec{ID: "sshd_log", Entry: EntryScan, Observation: ObservationLogCursor, Checks: []string{"ssh_brute"}})
	tp.http = must(ProducerSpec{ID: "access_log", Entry: EntryScan, Observation: ObservationLogCursor, Checks: []string{"waf_escalation", "http_scan"}})
	tp.mail = must(ProducerSpec{ID: "mail_log", Entry: EntryScan, Observation: ObservationLogCursor, Checks: []string{"mail_brute", "mail_takeover"}})
	tp.reputation = must(ProducerSpec{ID: "reputation_scan", Entry: EntryScan, Observation: ObservationScanPass, Checks: []string{"reputation"}})
	tp.derived = must(ProducerSpec{ID: "threat_scan", Entry: EntryScan, Observation: ObservationScanPass, Checks: []string{"threat_score"}})
	tp.spare = must(ProducerSpec{ID: "incident", Entry: EntryIncident, Observation: ObservationEventSeq, Checks: []string{"ssh_brute"}})
	return tp
}

func sshInput(t *testing.T) EvidenceInput {
	return EvidenceInput{
		Check:       "ssh_brute",
		FindingID:   "0123456789abcdef",
		Severity:    SeverityHigh,
		Observation: ObservationRef{Stream: "secure:dev=2049,ino=77", Cursor: "offset=4096", Version: 1},
		ObservedAt:  t0,
		Parser:      ParserRef{Name: "sshd", Version: 1},
		Target:      mustAddr(t, "192.0.2.1"),
	}
}

func TestRegisterRefusesUnsafeProducers(t *testing.T) {
	reg, _ := NewRegistry(testLookup)
	good := ProducerSpec{ID: "p", Entry: EntryScan, Observation: ObservationLogCursor, Checks: []string{"ssh_brute"}}
	if _, err := reg.Register(good); err != nil {
		t.Fatal(err)
	}
	many := make([]string, maxProducerChecks+1)
	for i := range many {
		many[i] = "ssh_brute"
	}
	bad := map[string]ProducerSpec{
		"duplicate ID":           good,
		"uppercase ID":           {ID: "P2", Entry: EntryScan, Observation: ObservationLogCursor, Checks: []string{"ssh_brute"}},
		"no entry":               {ID: "p2", Observation: ObservationLogCursor, Checks: []string{"ssh_brute"}},
		"no observation kind":    {ID: "p2", Entry: EntryScan, Checks: []string{"ssh_brute"}},
		"no checks":              {ID: "p2", Entry: EntryScan, Observation: ObservationLogCursor},
		"too many checks":        {ID: "p2", Entry: EntryScan, Observation: ObservationLogCursor, Checks: many},
		"unregistered check":     {ID: "p2", Entry: EntryScan, Observation: ObservationLogCursor, Checks: []string{"nope"}},
		"alias instead of name":  {ID: "p2", Entry: EntryScan, Observation: ObservationLogCursor, Checks: []string{"ssh_brute_legacy"}},
		"check without evidence": {ID: "p2", Entry: EntryScan, Observation: ObservationLogCursor, Checks: []string{"login_audit"}},
		"repeated check":         {ID: "p2", Entry: EntryScan, Observation: ObservationLogCursor, Checks: []string{"ssh_brute", "ssh_brute"}},
	}
	for name, spec := range bad {
		if _, err := reg.Register(spec); err == nil {
			t.Errorf("%s: registered", name)
		}
	}
	reg.Seal()
	if _, err := reg.Register(ProducerSpec{ID: "late", Entry: EntryScan, Observation: ObservationLogCursor, Checks: []string{"http_scan"}}); err == nil {
		t.Error("a sealed registry accepted a producer")
	}
	if _, err := NewRegistry(nil); err == nil {
		t.Error("a registry without a lookup was created")
	}
}

func TestMintBindsProducerEntryAndPolicy(t *testing.T) {
	tp := newTestProducers(t)
	in := sshInput(t)
	in.Check = "ssh_brute_legacy"
	e, err := tp.ssh.Mint(in)
	if err != nil {
		t.Fatal(err)
	}
	if e.Producer() != "sshd_log" || e.Entry() != EntryScan || e.Check() != "ssh_brute" || e.Family() != FamilySSH || e.Basis() != BasisLocal {
		t.Errorf("minted %+v", e.rec)
	}
	if !e.ObservedAt().Equal(t0) || e.ObservedAt().Location() != time.UTC || e.Target().Key() != "ip:192.0.2.1" || !e.Owner().IsHost() {
		t.Errorf("minted time/target/owner wrong: %v %q %q", e.ObservedAt(), e.Target().Key(), e.Owner().Key())
	}
	if _, err := tp.http.Mint(sshInput(t)); err == nil {
		t.Error("a producer minted a check it does not publish")
	}
	if err := tp.reg.Validate(e); err != nil {
		t.Errorf("fresh evidence does not validate: %v", err)
	}
	if spare, _ := tp.spare.Mint(sshInput(t)); spare.Entry() != EntryIncident || spare.ID() == e.ID() {
		t.Error("evidence is not bound to its producer's entry and identity")
	}
}

func TestMintWithoutRegisteredProducerRefuses(t *testing.T) {
	for name, p := range map[string]*Producer{"nil": nil, "zero": {}} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("unissued producer panicked: %v", r)
				}
			}()
			e, err := p.Mint(sshInput(t))
			wantReason(t, "unissued producer", err, ReasonPolicy)
			if !e.Equal(Evidence{}) {
				t.Error("unissued producer returned evidence")
			}
		})
	}
}

func TestRegistrationErrorsNeverEchoInput(t *testing.T) {
	const marker = "untrusted_marker"
	good := ProducerSpec{ID: marker, Entry: EntryScan, Observation: ObservationLogCursor, Checks: []string{"ssh_brute"}}
	cases := map[string]func(*Registry, *ProducerSpec){
		"invalid ID":      func(_ *Registry, s *ProducerSpec) { s.ID += "/" },
		"entry":           func(_ *Registry, s *ProducerSpec) { s.Entry = 0 },
		"observation":     func(_ *Registry, s *ProducerSpec) { s.Observation = 0 },
		"no checks":       func(_ *Registry, s *ProducerSpec) { s.Checks = nil },
		"unknown check":   func(_ *Registry, s *ProducerSpec) { s.Checks = []string{marker} },
		"no evidence":     func(_ *Registry, s *ProducerSpec) { s.Checks = []string{"login_audit"} },
		"duplicate check": func(_ *Registry, s *ProducerSpec) { s.Checks = []string{"ssh_brute", "ssh_brute"} },
		"sealed registry": func(r *Registry, _ *ProducerSpec) { r.Seal() },
		"duplicate producer": func(r *Registry, _ *ProducerSpec) {
			if _, err := r.Register(good); err != nil {
				t.Fatal(err)
			}
		},
		"invalid policy": func(r *Registry, _ *ProducerSpec) {
			r.lookup = func(check string) (string, Policy, bool) {
				return check, Policy{Family: FamilyReputation, Basis: BasisCompromise}, true
			}
		},
	}
	for name, setup := range cases {
		r, err := NewRegistry(testLookup)
		if err != nil {
			t.Fatal(err)
		}
		spec := good
		setup(r, &spec)
		if _, err := r.Register(spec); err == nil || strings.Contains(err.Error(), marker) {
			t.Errorf("%s: expected a refusal without input text, got %v", name, err)
		}
	}
}

func TestMintRefusesMalformedInput(t *testing.T) {
	tp := newTestProducers(t)
	prefix := mustPrefix(t, "198.51.100.0/24")
	svc := mustService(t, "192.0.2.1", "tcp", 22)
	mutate := map[string]func(*EvidenceInput){
		"short finding ID":     func(in *EvidenceInput) { in.FindingID = "0123" },
		"uppercase finding":    func(in *EvidenceInput) { in.FindingID = "0123456789ABCDEF" },
		"no severity":          func(in *EvidenceInput) { in.Severity = 0 },
		"no stream":            func(in *EvidenceInput) { in.Observation.Stream = "" },
		"spaced cursor":        func(in *EvidenceInput) { in.Observation.Cursor = "a b" },
		"long stream":          func(in *EvidenceInput) { in.Observation.Stream = strings.Repeat("s", 129) },
		"version 0":            func(in *EvidenceInput) { in.Observation.Version = 0 },
		"no time":              func(in *EvidenceInput) { in.ObservedAt = time.Time{} },
		"pre-epoch time":       func(in *EvidenceInput) { in.ObservedAt = time.Unix(-5, 0) },
		"unrepresentable time": func(in *EvidenceInput) { in.ObservedAt = time.Date(1400, 1, 1, 0, 0, 0, 0, time.UTC) },
		"no parser":            func(in *EvidenceInput) { in.Parser = ParserRef{} },
		"no target":            func(in *EvidenceInput) { in.Target = Target{} },
		"service target":       func(in *EvidenceInput) { in.Target = svc },
		"intel on local root":  func(in *EvidenceInput) { in.Intel = &IntelRef{Source: "feed", Expires: t0.Add(time.Hour)} },
	}
	for name, m := range mutate {
		in := sshInput(t)
		m(&in)
		if _, err := tp.ssh.Mint(in); err == nil {
			t.Errorf("%s: minted", name)
		} else if _, ok := ReasonOf(err); !ok {
			t.Errorf("%s: refusal without a reason: %v", name, err)
		}
	}
	in := sshInput(t)
	in.Target = prefix
	if _, err := tp.ssh.Mint(in); err != nil {
		t.Errorf("prefix evidence refused: %v", err)
	}
	rep := sshInput(t)
	rep.Check = "reputation"
	if _, err := tp.reputation.Mint(rep); err == nil {
		t.Error("reputation evidence without intel was minted")
	}
	rep.Intel = &IntelRef{Source: "feed", Expires: t0}
	if _, err := tp.reputation.Mint(rep); err == nil {
		t.Error("intel expiring at the observation was accepted")
	}
	rep.Intel.Expires = time.Date(2700, 1, 1, 0, 0, 0, 0, time.UTC)
	if _, err := tp.reputation.Mint(rep); err == nil {
		t.Error("unrepresentable intel expiry was accepted")
	}
	rep.Intel.Expires = t0.Add(time.Hour)
	if e, err := tp.reputation.Mint(rep); err != nil {
		t.Errorf("valid reputation evidence refused: %v", err)
	} else if ref, ok := e.Intel(); !ok || ref.Source != "feed" || !ref.Expires.Equal(t0.Add(time.Hour)) {
		t.Errorf("Intel() = %+v %v", ref, ok)
	}
}

func TestEvidenceIDFollowsTheObservation(t *testing.T) {
	tp := newTestProducers(t)
	a, _ := tp.ssh.Mint(sshInput(t))
	re := sshInput(t)
	re.FindingID = "fedcba9876543210"
	re.Severity = SeverityCritical
	b, _ := tp.ssh.Mint(re)
	if a.ID() != b.ID() {
		t.Error("a re-report of the same observation changed the evidence ID")
	}
	if a.Equal(b) {
		t.Error("records with different finding links compare equal")
	}
	for name, m := range map[string]func(*EvidenceInput){
		"cursor":  func(in *EvidenceInput) { in.Observation.Cursor = "offset=8192" },
		"version": func(in *EvidenceInput) { in.Observation.Version = 2 },
		"target":  func(in *EvidenceInput) { in.Target = mustAddr(t, "192.0.2.2") },
	} {
		in := sshInput(t)
		m(&in)
		c, err := tp.ssh.Mint(in)
		if err != nil || c.ID() == a.ID() {
			t.Errorf("changing the %s kept evidence ID %s (%v)", name, a.ID(), err)
		}
	}
	if !strings.HasPrefix(string(a.ID()), "ev_") || len(a.ID()) != 35 {
		t.Errorf("evidence ID %q is malformed", a.ID())
	}
}

func TestValidateRefusesPolicyDrift(t *testing.T) {
	tp := newTestProducers(t)
	e, _ := tp.ssh.Mint(sshInput(t))
	testPolicies["ssh_brute"] = Policy{Family: FamilySSH, Basis: BasisCompromise}
	defer func() { testPolicies["ssh_brute"] = Policy{Family: FamilySSH, Basis: BasisLocal} }()
	err := tp.reg.Validate(e)
	wantReason(t, "policy drift", err, ReasonPolicy)
	other, _ := NewRegistry(testLookup)
	wantReason(t, "foreign registry", other.Validate(e), ReasonPolicy)
}

func TestEvidenceRoundTripsAndRefusesTampering(t *testing.T) {
	tp := newTestProducers(t)
	inv, _ := NewInventory(map[string]uint64{"alice": 4}, nil)
	in := sshInput(t)
	in.Owner = inv.Resolve(Claim{ClaimAccount, "alice"})
	e, err := tp.ssh.Mint(in)
	if err != nil {
		t.Fatal(err)
	}
	data, err := e.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	back, err := UnmarshalEvidence(data)
	if err != nil || !back.Equal(e) || back.Owner().Key() != "acct:alice#4" {
		t.Fatalf("round trip = %+v %v", back.rec, err)
	}
	reseal := func(body string) []byte {
		out := append([]byte{'E', evidenceVersion}, body...)
		sum := sha256.Sum256(out)
		return append(out, sum[:8]...)
	}
	body := string(data[2 : len(data)-8])
	flipped := append([]byte(nil), data...)
	flipped[10] ^= 1
	cases := map[string][]byte{
		"truncated":      data[:5],
		"flipped byte":   flipped,
		"future version": append([]byte{'E', 2}, data[2:]...),
		"unknown field":  reseal(strings.Replace(body, `{"producer"`, `{"x":1,"producer"`, 1)),
		"trailing value": reseal(body + "{}"),
		"trailing close": reseal(body + "}"),
		"leading space":  reseal(" " + body),
		"trailing space": reseal(body + "\n"),
		"spaced":         reseal(strings.Replace(body, `"entry":1`, `"entry": 1`, 1)),
		"duplicate key":  reseal(strings.Replace(body, `"entry":1`, `"entry":1,"entry":1`, 1)),
		"case alias":     reseal(strings.Replace(body, `"entry":1`, `"Entry":1`, 1)),
		"escaped key":    reseal(strings.Replace(body, `"entry":1`, `"\u0065ntry":1`, 1)),
		"omitted zero":   reseal(strings.Replace(body, `"entry":1`, `"intel_expires":0,"entry":1`, 1)),
		"null optional":  reseal(strings.Replace(body, `"entry":1`, `"intel_source":null,"entry":1`, 1)),
		"no family":      reseal(strings.Replace(body, `"family":4`, `"family":0`, 1)),
		"host with gen":  reseal(strings.Replace(body, `"owner_account":"alice",`, ``, 1)),
		"mapped target":  reseal(strings.Replace(body, `"ip:192.0.2.1"`, `"ip:::ffff:192.0.2.1"`, 1)),
		"oversized":      reseal(strings.Replace(body, `"sshd"`, `"`+strings.Repeat("p", MaxEvidenceBytes)+`"`, 1)),
	}
	for name, b := range cases {
		if _, err := UnmarshalEvidence(b); err == nil {
			t.Errorf("%s: decoded", name)
		}
	}
	if bytes.Contains(data, []byte("0123456789abcdef")) == false {
		t.Error("encoding lost the finding link")
	}
}

func TestEvidenceTimeNanosecondBoundaries(t *testing.T) {
	tp := newTestProducers(t)
	latest := time.Unix(0, math.MaxInt64)
	for _, observed := range []time.Time{time.Unix(0, 1), latest} {
		in := sshInput(t)
		in.ObservedAt = observed
		e, err := tp.ssh.Mint(in)
		if err != nil || !e.ObservedAt().Equal(observed) {
			t.Fatalf("representable observation changed: %v", err)
		}
		data, err := e.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		back, err := UnmarshalEvidence(data)
		if err != nil || !back.Equal(e) {
			t.Fatalf("representable observation did not round-trip: %v", err)
		}
	}
	in := sshInput(t)
	in.Check = "reputation"
	in.Intel = &IntelRef{Source: "feed", Expires: latest}
	e, err := tp.reputation.Mint(in)
	if err != nil {
		t.Fatal(err)
	}
	if intel, ok := e.Intel(); !ok || !intel.Expires.Equal(latest) {
		t.Fatal("representable intel expiry changed")
	}
	for _, outside := range []time.Time{latest.Add(time.Nanosecond), time.Unix(0, math.MinInt64).Add(-time.Nanosecond)} {
		in := sshInput(t)
		in.ObservedAt = outside
		_, err := tp.ssh.Mint(in)
		wantReason(t, "unrepresentable observation", err, ReasonInvalid)
		in.ObservedAt = t0
		in.Check = "reputation"
		in.Intel = &IntelRef{Source: "feed", Expires: outside}
		_, err = tp.reputation.Mint(in)
		wantReason(t, "unrepresentable intel expiry", err, ReasonInvalid)
	}
}

func TestEvidenceSameIDDoesNotAuthorizeReplacement(t *testing.T) {
	tp := newTestProducers(t)
	in := sshInput(t)
	original, err := tp.ssh.Mint(in)
	if err != nil {
		t.Fatal(err)
	}
	inv := testInventory(t)
	for name, mutate := range map[string]func(*EvidenceInput){
		"finding":  func(in *EvidenceInput) { in.FindingID = "fedcba9876543210" },
		"severity": func(in *EvidenceInput) { in.Severity = SeverityCritical },
		"owner":    func(in *EvidenceInput) { in.Owner = inv.Resolve(Claim{ClaimAccount, "alice"}) },
		"time":     func(in *EvidenceInput) { in.ObservedAt = in.ObservedAt.Add(time.Minute) },
		"parser":   func(in *EvidenceInput) { in.Parser.Version++ },
	} {
		changed := in
		mutate(&changed)
		other, err := tp.ssh.Mint(changed)
		if err != nil {
			t.Fatal(err)
		}
		data, err := other.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := UnmarshalEvidence(data)
		if err != nil || !decoded.Equal(other) || decoded.ID() != original.ID() || decoded.Equal(original) {
			t.Errorf("%s: expected valid encoding but an immutable-record conflict: %v", name, err)
		}
	}
}

func TestRegistryRejectsRenamedEvidence(t *testing.T) {
	renamed := false
	lookup := func(check string) (string, Policy, bool) {
		name, p, ok := testLookup(check)
		if renamed && name == "ssh_brute" {
			name = "ssh_brute_new"
		}
		return name, p, ok
	}
	reg, err := NewRegistry(lookup)
	if err != nil {
		t.Fatal(err)
	}
	p, err := reg.Register(ProducerSpec{ID: "ssh", Entry: EntryScan, Observation: ObservationLogCursor, Checks: []string{"ssh_brute"}})
	if err != nil {
		t.Fatal(err)
	}
	e, err := p.Mint(sshInput(t))
	if err != nil {
		t.Fatal(err)
	}
	renamed = true
	wantReason(t, "canonical policy name changed", reg.Validate(e), ReasonPolicy)
}

func TestObservationKindValuesAreFrozen(t *testing.T) {
	for name, pair := range map[string][2]uint8{"ObservationLogCursor": {uint8(ObservationLogCursor), 1}, "ObservationEventSeq": {uint8(ObservationEventSeq), 2}, "ObservationScanPass": {uint8(ObservationScanPass), 3}} {
		if pair[0] != pair[1] {
			t.Errorf("%s = %d, frozen at %d", name, pair[0], pair[1])
		}
	}
}

// A Critical-only check keeps its advisory findings out of admission: a
// below-floor record is never minted, and one minted before the floor was
// raised stops validating.
func TestSeverityFloorKeepsAdvisoryFindingsOutOfEvidence(t *testing.T) {
	floor := SeverityCritical
	lookup := func(check string) (string, Policy, bool) {
		if check != "mail_takeover" {
			return testLookup(check)
		}
		return check, Policy{Family: FamilyMail, Basis: BasisCompromise, MinSeverity: floor}, true
	}
	reg, err := NewRegistry(lookup)
	if err != nil {
		t.Fatal(err)
	}
	p, err := reg.Register(ProducerSpec{ID: "mail_log", Entry: EntryScan, Observation: ObservationLogCursor, Checks: []string{"mail_takeover"}})
	if err != nil {
		t.Fatal(err)
	}
	in := sshInput(t)
	in.Check = "mail_takeover"
	for _, sev := range []Severity{SeverityWarning, SeverityHigh} {
		in.Severity = sev
		e, mintErr := p.Mint(in)
		wantReason(t, "advisory "+sev.String()+" finding", mintErr, ReasonPolicy)
		if !e.Equal(Evidence{}) {
			t.Errorf("%s: below-floor finding returned evidence", sev)
		}
	}
	in.Severity = SeverityCritical
	critical, err := p.Mint(in)
	if err != nil {
		t.Fatal(err)
	}
	if validateErr := reg.Validate(critical); validateErr != nil {
		t.Errorf("Critical evidence does not validate: %v", validateErr)
	}
	a, err := Assess(mustAddr(t, "192.0.2.1"), []Evidence{critical}, t0)
	if err != nil || !a.DirectC3 {
		t.Errorf("Critical compromise evidence = %+v %v, want direct C3", a, err)
	}

	floor = 0
	in.Severity = SeverityHigh
	high, err := p.Mint(in)
	if err != nil {
		t.Fatalf("a check without a floor refused a High finding: %v", err)
	}
	floor = SeverityCritical
	wantReason(t, "floor raised after minting", reg.Validate(high), ReasonPolicy)
	if err := reg.Validate(critical); err != nil {
		t.Errorf("raising the floor refused evidence at the floor: %v", err)
	}
}

func TestRegisterRefusesUnknownSeverityFloor(t *testing.T) {
	reg, err := NewRegistry(func(check string) (string, Policy, bool) {
		return check, Policy{Family: FamilyMail, Basis: BasisLocal, MinSeverity: SeverityCritical + 1}, true
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reg.Register(ProducerSpec{ID: "mail_log", Entry: EntryScan, Observation: ObservationLogCursor, Checks: []string{"mail_brute"}}); err == nil {
		t.Error("a check with an unknown severity floor registered")
	}
}

// The ledger stores these bytes under this ID. A change to the field names,
// field order, checksum or ID derivation must be a deliberate format change
// with a new version, never a side effect of a refactor.
func TestEvidenceEncodingAndIDAreFrozen(t *testing.T) {
	tp := newTestProducers(t)
	inv, err := NewInventory(map[string]uint64{"alice": 4}, nil)
	if err != nil {
		t.Fatal(err)
	}
	in := sshInput(t)
	in.Check = "reputation"
	in.Owner = inv.Resolve(Claim{ClaimAccount, "alice"})
	in.Intel = &IntelRef{Source: "feed", Expires: t0.Add(time.Hour)}
	e, err := tp.reputation.Mint(in)
	if err != nil {
		t.Fatal(err)
	}
	const body = `{"producer":"reputation_scan","entry":1,"check":"reputation","family":7,"basis":1,` +
		`"finding_id":"0123456789abcdef","severity":2,"stream":"secure:dev=2049,ino=77","cursor":"offset=4096",` +
		`"version":1,"observed_at":1790251200000000000,"parser":"sshd","parser_version":1,"target":"ip:192.0.2.1",` +
		`"owner_account":"alice","owner_generation":4,"intel_source":"feed","intel_expires":1790254800000000000}`
	want := append([]byte("E\x01"+body), 0xf8, 0x3a, 0xfb, 0x6f, 0xd3, 0x61, 0x55, 0x6c)
	got, err := e.MarshalBinary()
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("encoding = %q %v, want %q", got, err, want)
	}
	if e.ID() != "ev_0420f53c6c1a4fbd02004e9f379171f8" {
		t.Errorf("ID() = %s", e.ID())
	}
	back, err := UnmarshalEvidence(want)
	if err != nil || !back.Equal(e) {
		t.Errorf("golden record does not decode: %v", err)
	}
}

// The populated golden cannot detect a change to optional-field omission.
// Host-owned local evidence must keep its encoding across upgrades too.
func TestHostEvidenceEncodingAndIDAreFrozen(t *testing.T) {
	tp := newTestProducers(t)
	e, err := tp.ssh.Mint(sshInput(t))
	if err != nil {
		t.Fatal(err)
	}
	const body = `{"producer":"sshd_log","entry":1,"check":"ssh_brute","family":4,"basis":2,` +
		`"finding_id":"0123456789abcdef","severity":2,"stream":"secure:dev=2049,ino=77","cursor":"offset=4096",` +
		`"version":1,"observed_at":1790251200000000000,"parser":"sshd","parser_version":1,"target":"ip:192.0.2.1"}`
	want := append([]byte("E\x01"+body), 0xd6, 0xcd, 0x71, 0x50, 0x35, 0x24, 0xa5, 0x42)
	got, err := e.MarshalBinary()
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("encoding = %q %v, want %q", got, err, want)
	}
	if e.ID() != "ev_0c35e7a857527c0fb5c4bcb1030c7704" {
		t.Errorf("ID() = %s", e.ID())
	}
	back, err := UnmarshalEvidence(want)
	if err != nil || !back.Equal(e) {
		t.Errorf("golden record does not decode: %v", err)
	}
}

// A record that differs from the original only in its finding is a later
// report of the same observation; any other difference is a conflict.
func TestEvidenceSameExceptFinding(t *testing.T) {
	tp := newTestProducers(t)
	in := sshInput(t)
	original, err := tp.ssh.Mint(in)
	if err != nil {
		t.Fatal(err)
	}
	if !original.SameExceptFinding(original) {
		t.Fatal("a record is the same as itself")
	}
	inv := testInventory(t)
	for name, tc := range map[string]struct {
		mutate func(*EvidenceInput)
		same   bool
	}{
		"finding":  {func(in *EvidenceInput) { in.FindingID = "fedcba9876543210" }, true},
		"severity": {func(in *EvidenceInput) { in.Severity = SeverityCritical }, false},
		"owner":    {func(in *EvidenceInput) { in.Owner = inv.Resolve(Claim{ClaimAccount, "alice"}) }, false},
		"time":     {func(in *EvidenceInput) { in.ObservedAt = in.ObservedAt.Add(time.Minute) }, false},
		"parser":   {func(in *EvidenceInput) { in.Parser.Version++ }, false},
	} {
		changed := in
		tc.mutate(&changed)
		other, err := tp.ssh.Mint(changed)
		if err != nil {
			t.Fatal(err)
		}
		if got := original.SameExceptFinding(other); got != tc.same || other.SameExceptFinding(original) != tc.same {
			t.Errorf("%s: SameExceptFinding = %v, want %v", name, got, tc.same)
		}
	}
}
