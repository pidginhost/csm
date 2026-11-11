package admission

import (
	"errors"
	"testing"
)

// Persisted in refusal summaries: append, never renumber.
func TestCauseVocabulary(t *testing.T) {
	for _, w := range []struct {
		c    Cause
		n    uint8
		name string
	}{
		{CauseNoObservation, 1, "no_observation"},
		{CauseKindNotAllowed, 2, "kind_not_allowed"},
		{CauseTargetMismatch, 3, "target_mismatch"},
		{CauseUnreachable, 4, "unreachable"},
		{CauseProxyPeer, 5, "proxy_peer"},
		{CauseRewrittenLog, 6, "rewritten_log"},
	} {
		if uint8(w.c) != w.n || w.c.String() != w.name || !w.c.Valid() {
			t.Errorf("cause %d = %q valid %v, want %d %q", uint8(w.c), w.c.String(), w.c.Valid(), w.n, w.name)
		}
	}
	if Cause(0).Valid() || Cause(7).Valid() {
		t.Error("cause 0 or 7 is valid")
	}
}

func TestCauseOfAnAttributionRefusal(t *testing.T) {
	err := error(&Error{Reason: ReasonAttribution, Cause: CauseKindNotAllowed, Detail: "x"})
	if CauseOf(err) != CauseKindNotAllowed || CauseOf(errors.Join(errors.New("wrap"), err)) != CauseKindNotAllowed {
		t.Fatal("the cause of an attribution refusal is lost")
	}
	// A cause only narrows an attribution refusal.
	stray := &Error{Reason: ReasonPolicy, Cause: CauseKindNotAllowed, Detail: "x"}
	if CauseOf(stray) != 0 || CauseOf(refuse(ReasonPolicy, "x")) != 0 || CauseOf(errors.New("plain")) != 0 || CauseOf(nil) != 0 {
		t.Fatal("a refusal without a cause names one")
	}
}

// A kind the producer declares and its check accepts mints. The record
// keeps no kind of its own, so its encoding is unchanged (the frozen
// goldens mint with a declared kind).
func TestMintAcceptsADeclaredKind(t *testing.T) {
	tp := newTestProducers(t)
	e, err := tp.ssh.Mint(sshInput(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := tp.reg.Validate(e); err != nil {
		t.Fatal(err)
	}
}

func TestMintRefusesAnUndeclaredKind(t *testing.T) {
	tp := newTestProducers(t)
	for _, kind := range []Attribution{AttributionUnknown, AttributionHTTPPeer, AttributionDerived, 9} {
		in := sshInput(t)
		in.Attribution = kind
		_, err := tp.ssh.Mint(in)
		if r, _ := ReasonOf(err); r != ReasonAttribution || CauseOf(err) != CauseKindNotAllowed {
			t.Errorf("%s: %v, want an attribution refusal naming the kind", kind, err)
		}
	}
	// The row accepts a trusted chain; this producer never declared one.
	in := sshInput(t)
	in.Check, in.Attribution = "http_scan", AttributionTrustedHTTPChain
	if _, err := tp.http.Mint(in); CauseOf(err) != CauseKindNotAllowed {
		t.Errorf("an undeclared kind the row accepts: %v", err)
	}
}

// Declarations are fixed per build: a record whose producer now declares no
// kind, as one an earlier build minted for it, is refused on use.
func TestValidateRefusesAKindTheProducerNoLongerDeclares(t *testing.T) {
	tp := newTestProducers(t)
	e, err := tp.ssh.Mint(sshInput(t))
	if err != nil {
		t.Fatal(err)
	}
	later, err := NewRegistry(testLookup)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := later.Register(ProducerSpec{ID: "sshd_log", Entry: EntryScan, Observation: ObservationLogCursor, Checks: []string{"ssh_brute"}, Claims: []ClaimKind{ClaimAccount}}); err != nil {
		t.Fatal(err)
	}
	if err := later.Validate(e); CauseOf(err) != CauseKindNotAllowed {
		t.Fatalf("validate under a producer that declares nothing: %v", err)
	}
}

// A policy change applies to evidence minted before it, as the family and
// basis already do: the record keeps no kind, so its producer's every kind
// must stay accepted.
func TestValidateRefusesAKindTheRowNoLongerAccepts(t *testing.T) {
	row := Policy{Family: FamilyHTTP, Basis: BasisLocal, Attribution: Attributions(AttributionHTTPPeer, AttributionTrustedHTTPChain)}
	reg, err := NewRegistry(func(check string) (string, Policy, bool) { return check, row, check == "http_scan" })
	if err != nil {
		t.Fatal(err)
	}
	p, err := reg.Register(ProducerSpec{ID: "access_log", Entry: EntryScan, Observation: ObservationLogCursor,
		Checks: []string{"http_scan"}, Attribution: Attributions(AttributionHTTPPeer, AttributionTrustedHTTPChain)})
	if err != nil {
		t.Fatal(err)
	}
	in := sshInput(t)
	in.Check, in.Attribution = "http_scan", AttributionTrustedHTTPChain
	e, err := p.Mint(in)
	if err != nil {
		t.Fatal(err)
	}
	row.Attribution = Attributions(AttributionHTTPPeer)
	if err := reg.Validate(e); CauseOf(err) != CauseKindNotAllowed {
		t.Fatalf("validate after the row narrowed: %v", err)
	}
	if _, err := p.Mint(in); CauseOf(err) != CauseKindNotAllowed {
		t.Fatalf("mint after the row narrowed: %v", err)
	}
}

func TestMintKindDoesNotChangeStoredEvidence(t *testing.T) {
	reg := newRegistryWith(t, map[string]Policy{
		"http_scan": {Family: FamilyHTTP, Basis: BasisLocal, Attribution: Attributions(AttributionHTTPPeer, AttributionTrustedHTTPChain)},
	})
	p, err := reg.Register(ProducerSpec{ID: "http_fixture", Entry: EntryScan, Observation: ObservationLogCursor,
		Checks: []string{"http_scan"}, Attribution: Attributions(AttributionHTTPPeer, AttributionTrustedHTTPChain)})
	if err != nil {
		t.Fatal(err)
	}
	in := sshInput(t)
	in.Check, in.Attribution = "http_scan", AttributionHTTPPeer
	peer, err := p.Mint(in)
	if err != nil {
		t.Fatal(err)
	}
	in.Attribution = AttributionTrustedHTTPChain
	chain, err := p.Mint(in)
	if err != nil {
		t.Fatal(err)
	}
	peerBytes, err := peer.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	chainBytes, err := chain.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if string(peerBytes) != string(chainBytes) || peer.ID() != chain.ID() || !peer.Equal(chain) {
		t.Fatal("mint-only attribution changed stored evidence or its identity")
	}
}
