package checks

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// A queued block of an address that became a trusted proxy, or a known edge
// its root may have seen relaying, is no longer a block to run: the mint
// would refuse it now. A session peer at an edge address keeps its block,
// as the mint keeps it, and a challenge is not a block.
func TestBlocksAProxy(t *testing.T) {
	withKnownProxyPrefixes(t, "198.51.100.0/24")
	SetASNLookup(nil)
	cfg := &config.Config{}
	cfg.WebServer.TrustedProxies = []string{"192.0.2.0/24"}
	httpRoot := realRoot(t, httpPeerFinding("203.0.113.9"))
	ssh := httpPeerFinding("203.0.113.9")
	ssh.Check, ssh.Attribution = "ssh_login_unknown_ip", admission.AttributionPeer
	ssh.Observation.Producer = string(ProducerSSHJournal)
	sshRoot := realRoot(t, ssh)
	block := func(kind admission.Kind, ip string) admission.Candidate {
		target, err := admission.CanonicalAddress(ip, admission.Caps{IPv6: true})
		if err != nil {
			t.Fatal(err)
		}
		return admission.Candidate{Key: admission.CandidateKey{Kind: kind, Target: target}, Entry: admission.EntryScan}
	}
	for _, tc := range []struct {
		name  string
		c     admission.Candidate
		roots []admission.Evidence
		want  bool
	}{
		{"trusted proxy", block(admission.KindBlockIP, "192.0.2.7"), []admission.Evidence{sshRoot}, true},
		{"edge seen over HTTP", block(admission.KindBlockIP, "198.51.100.7"), []admission.Evidence{sshRoot, httpRoot}, true},
		{"edge seen as a session peer", block(admission.KindBlockIP, "198.51.100.7"), []admission.Evidence{sshRoot}, false},
		{"edge with unreadable roots", block(admission.KindBlockIP, "198.51.100.7"), nil, false},
		{"ordinary address", block(admission.KindBlockIP, "203.0.113.9"), []admission.Evidence{httpRoot}, false},
		{"challenge of an edge", block(admission.KindChallenge, "198.51.100.7"), []admission.Evidence{httpRoot}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := BlocksAProxy(cfg, tc.c, func() []admission.Evidence { return tc.roots }); got != tc.want {
				t.Fatalf("BlocksAProxy = %v, want %v", got, tc.want)
			}
		})
	}
}

// Reading roots costs a ledger read per candidate: only an edge address
// reads them.
func TestBlocksAProxyReadsRootsOnlyForAnEdge(t *testing.T) {
	withKnownProxyPrefixes(t, "198.51.100.0/24")
	SetASNLookup(nil)
	target, err := admission.CanonicalAddress("203.0.113.9", admission.Caps{IPv6: true})
	if err != nil {
		t.Fatal(err)
	}
	c := admission.Candidate{Key: admission.CandidateKey{Kind: admission.KindBlockIP, Target: target}, Entry: admission.EntryScan}
	BlocksAProxy(&config.Config{}, c, func() []admission.Evidence {
		t.Fatal("roots read for an ordinary address")
		return nil
	})
}

// The queue recheck never refuses a root the mint accepts at the same
// address, and refuses exactly what the mint now refuses as a proxy edge.
// The oracle is the mint itself, for every producer and every attribution
// it reads.
func TestQueuedProxyRecheckMatchesEveryProducer(t *testing.T) {
	withHTTPRewrite(t, HTTPRewrite{State: RewriteNone})
	withKnownProxyPrefixes(t)
	SetASNLookup(nil)
	const ip = "198.51.100.30"
	target, err := admission.CanonicalAddress(ip, admission.Caps{IPv6: true})
	if err != nil {
		t.Fatal(err)
	}
	c := admission.Candidate{Key: admission.CandidateKey{Kind: admission.KindBlockIP, Target: target}, Entry: admission.EntryScan}
	kinds := []admission.Attribution{admission.AttributionPeer, admission.AttributionHTTPPeer, admission.AttributionTrustedHTTPChain, admission.AttributionSocketDestination, admission.AttributionDerived}
	mintable := 0
	for _, p := range ProducerTable() {
		any := false
		for _, kind := range kinds {
			if !p.Spec.Attribution.Has(kind) {
				continue
			}
			any = true
			t.Run(string(p.Spec.ID)+"/"+kind.String(), func(t *testing.T) {
				f := alert.Finding{
					Severity: alert.Critical, Check: p.Spec.Checks[0], SourceIP: ip, Attribution: kind,
					Observation: alert.Observation{Producer: string(p.Spec.ID), Stream: "f:1:2", Cursor: "0:0123456789abcdef", ObservedAt: time.Now()},
				}
				if kind == admission.AttributionDerived {
					f.Intel = &admission.IntelRef{Source: "feed", Expires: f.Observation.ObservedAt.Add(time.Hour)}
				}
				withKnownProxyPrefixes(t)
				_, _, err := AdmissionEvidence(f)
				// A syslog file line names no one who connected.
				if ProducerWritableLog(p.Spec.ID) {
					if admission.CauseOf(err) != admission.CauseWritableLog {
						t.Fatalf("a writable log producer minted: %v", err)
					}
					return
				}
				if kind == admission.AttributionTrustedHTTPChain {
					if admission.CauseOf(err) != admission.CauseUnreachable {
						t.Fatalf("a proxied client minted: %v", err)
					}
					return
				}
				if err != nil {
					t.Fatalf("the producer mints nothing from this test finding: %v", err)
				}
				root := realRoot(t, f)
				withKnownProxyPrefixes(t, "198.51.100.0/24")
				_, _, edgeErr := AdmissionEvidence(f)
				refused := admission.CauseOf(edgeErr) == admission.CauseProxyPeer
				if got := BlocksAProxy(&config.Config{}, c, func() []admission.Evidence { return []admission.Evidence{root} }); got != refused {
					t.Fatalf("recheck refuses %v, the mint refuses as an edge %v (%v)", got, refused, edgeErr)
				}
				mintable++
			})
		}
		if !any && p.Spec.ID != ProducerPHPRelaySpool {
			t.Errorf("%s reads no address attribution", p.Spec.ID)
		}
		if p.Spec.ID == ProducerPHPRelaySpool && any {
			t.Errorf("%s now reads an address attribution: classify it", p.Spec.ID)
		}
	}
	if mintable == 0 {
		t.Fatal("no producer minted a root")
	}
}

// The recheck reads roots, not the candidate's entry: an HTTP root at an
// edge ends the block through every entry, a session root alone keeps it,
// and a mix ends it in either order. A changed reverse-proxy ASN list, a
// trusted proxy without readable roots and a prefix target are covered too.
func TestQueuedProxyRecheckAcrossEntriesAndRoots(t *testing.T) {
	withHTTPRewrite(t, HTTPRewrite{State: RewriteNone})
	withKnownProxyPrefixes(t)
	SetASNLookup(nil)
	httpRoot := realRoot(t, httpPeerFinding("203.0.113.31"))
	ssh := httpPeerFinding("203.0.113.31")
	ssh.Check, ssh.Attribution = "ssh_login_unknown_ip", admission.AttributionPeer
	ssh.Observation.Producer = string(ProducerSSHJournal)
	sshRoot := realRoot(t, ssh)
	target, err := admission.CanonicalAddress("203.0.113.31", admission.Caps{IPv6: true})
	if err != nil {
		t.Fatal(err)
	}
	withKnownProxyPrefixes(t, "203.0.113.0/24")
	roots := func(r ...admission.Evidence) func() []admission.Evidence {
		return func() []admission.Evidence { return r }
	}
	for _, entry := range []admission.Entry{admission.EntryScan, admission.EntryIncident, admission.EntryIncidentSpray, admission.EntryCentral, admission.EntryChallengeTimeout} {
		c := admission.Candidate{Key: admission.CandidateKey{Kind: admission.KindBlockIP, Target: target}, Entry: entry}
		for _, tc := range []struct {
			name  string
			roots func() []admission.Evidence
			want  bool
		}{
			{"http", roots(httpRoot), true},
			{"session", roots(sshRoot), false},
			{"session then http", roots(sshRoot, httpRoot), true},
			{"http then session", roots(httpRoot, sshRoot), true},
		} {
			if got := BlocksAProxy(&config.Config{}, c, tc.roots); got != tc.want {
				t.Errorf("%v/%s: recheck = %v, want %v", entry, tc.name, got, tc.want)
			}
		}
	}
	withKnownProxyPrefixes(t)
	c := admission.Candidate{Key: admission.CandidateKey{Kind: admission.KindBlockIP, Target: target}, Entry: admission.EntryScan}
	SetASNLookup(func(string) (uint, string) { return 64512, "Edge" })
	cfg := &config.Config{}
	cfg.Thresholds.HTTPASNCrawlReverseProxyASNs = []uint{64512}
	if !BlocksAProxy(cfg, c, roots(httpRoot)) {
		t.Error("an address in a listed reverse-proxy network keeps its queued block")
	}
	if BlocksAProxy(&config.Config{}, c, roots(httpRoot)) {
		t.Error("an emptied reverse-proxy list still ends the queued block")
	}
	SetASNLookup(nil)
	proxy := &config.Config{}
	proxy.WebServer.TrustedProxies = []string{"203.0.113.31"}
	if !BlocksAProxy(proxy, c, roots()) {
		t.Error("a trusted proxy with unreadable roots keeps its queued block")
	}
	prefix, err := admission.CanonicalPrefix("203.0.113.0/24", admission.Caps{IPv6: true})
	if err != nil {
		t.Fatal(err)
	}
	subnet := admission.Candidate{Key: admission.CandidateKey{Kind: admission.KindBlockSubnet, Target: prefix}, Entry: admission.EntryMailSubnet}
	if BlocksAProxy(proxy, subnet, roots(httpRoot)) {
		t.Error("a prefix target is tested as an address block")
	}
}
