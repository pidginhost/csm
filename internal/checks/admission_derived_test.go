package checks

import (
	"slices"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/firewall"
)

func wpBruteForce(ip string) alert.Finding {
	at := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	return alert.Finding{
		Check: "wp_login_bruteforce", Severity: alert.Critical, SourceIP: ip, Message: "brute force", Timestamp: at,
		Observation: alert.Observation{Producer: string(ProducerAccessLog), Stream: "access", Cursor: "offset=7", ObservedAt: at},
	}
}

// Rulings R7: a block a derived path applies is handed to admission with
// the root it carries and through its own entry, after the same switches
// the legacy block honours; a derived block without a root, or a permanent
// one, is handed over without a root and refused there.
func TestApplyBlockAsksAdmissionThroughItsEntry(t *testing.T) {
	a := withAdmission(t)
	applyBlockTestSetup(t, &outcomeStubBlocker{outcome: firewall.BlockOutcomeLive})
	cfg := pendingTestConfig(t)
	root := realRoot(t, wpBruteForce("203.0.113.50"), "203.0.113.50")
	for _, req := range []ApplyBlockRequest{
		{IP: "203.0.113.50", TTL: time.Hour, Source: BlockSourceChallenge, Root: root, Entry: admission.EntryChallengeTimeout},
		{IP: "203.0.113.51", TTL: time.Hour, Source: BlockSourceIncident, Entry: admission.EntryIncident},
		{IP: "203.0.113.50", TTL: 0, Source: BlockSourceIncident, Root: root, Entry: admission.EntryIncident},
	} {
		if _, err := ApplyBlock(cfg, req); err != nil {
			t.Fatal(err)
		}
	}
	cfg.AutoResponse.BlockIPs = false
	if _, err := ApplyBlock(cfg, ApplyBlockRequest{IP: "203.0.113.52", TTL: time.Hour, Source: BlockSourceCentral, Root: root, Entry: admission.EntryCentral}); err == nil {
		t.Fatal("blocked with block_ips off")
	}
	want := []respondCall{
		{kind: admission.KindBlockIP, check: "wp_login_bruteforce", target: "ip:203.0.113.50", cursor: "offset=7", via: admission.EntryChallengeTimeout, rooted: true},
		{kind: admission.KindBlockIP, via: admission.EntryIncident},
		{kind: admission.KindBlockIP, via: admission.EntryIncident},
	}
	if got := a.responses(); !sameResponses(got, want) {
		t.Fatalf("responses = %+v, want %+v", got, want)
	}
}

// A routed challenge keeps the root it was answered with, so its timeout
// can answer the same observation again; a list without that capability,
// or a finding admission could not mint, keeps none.
func TestChallengeRouteKeepsItsRootForTheTimeout(t *testing.T) {
	a := withAdmission(t)
	a.mint = func(f alert.Finding, target string) admission.Evidence { return realRoot(t, f, target) }
	withBlocker(t)
	list := &rootedIPList{mockIPList: mockIPList{ips: map[string]bool{}}, roots: map[string]admission.Evidence{}}
	withChallengeList(t, list)
	cfg := liveAutoBlockConfig(t)
	cfg.Challenge.Enabled = true
	f := wpBruteForce("203.0.113.60")
	ChallengeRouteIPs(cfg, []alert.Finding{f})
	if root, ok := list.roots["203.0.113.60"]; !ok || !root.Equal(realRoot(t, f, f.SourceIP)) {
		t.Fatalf("roots = %+v", list.roots)
	}
	a.refuse = true
	g := wpBruteForce("203.0.113.61")
	ChallengeRouteIPs(cfg, []alert.Finding{g})
	if root, ok := list.roots["203.0.113.61"]; !ok || !root.Equal(admission.Evidence{}) {
		t.Fatalf("an unminted finding kept a root: %+v", list.roots)
	}
}

type rootedIPList struct {
	mockIPList
	roots map[string]admission.Evidence
}

func (l *rootedIPList) AddWithRoot(ip, reason string, d time.Duration, findingID string, root admission.Evidence) {
	l.Add(ip, reason, d)
	l.roots[ip] = root
}

// Each derived entry wraps the roots its path answers: a challenge timeout
// the challengeable checks, central intel and incidents any check whose
// address is admissible evidence.
func TestDerivedEntriesWrapTheirPathsRoots(t *testing.T) {
	wraps := map[admission.Entry][]string{}
	for _, spec := range DerivedEntries() {
		wraps[spec.Entry] = spec.Checks
	}
	for _, check := range []string{"wp_login_bruteforce", "xmlrpc_abuse", "http_scanner_profile"} {
		if !slices.Contains(wraps[admission.EntryChallengeTimeout], check) {
			t.Errorf("challenge timeout does not wrap %s", check)
		}
	}
	if slices.Contains(wraps[admission.EntryChallengeTimeout], "pam_bruteforce") {
		t.Error("challenge timeout wraps a check that is never challenged")
	}
	for _, e := range []admission.Entry{admission.EntryCentral, admission.EntryIncident, admission.EntryIncidentSpray} {
		for _, check := range []string{"pam_bruteforce", "wp_login_bruteforce", "mail_bruteforce"} {
			if !slices.Contains(wraps[e], check) {
				t.Errorf("%s does not wrap %s", e, check)
			}
		}
	}
}

// The permanent-promotion path is a separate selected response. It is
// handed over without a root, while legacy promotion still runs normally.
func TestPermanentPromotionAsksAdmissionWithoutARoot(t *testing.T) {
	a := withAdmission(t)
	b := withBlocker(t)
	cfg := pendingTestConfig(t)
	cfg.AutoResponse.PermBlock = true
	cfg.AutoResponse.PermBlockCount = config.MinBlockEscalationCount
	savePermBlockTracker(cfg.StatePath, &permBlockTracker{IPs: map[string][]time.Time{
		"192.0.2.95": {time.Now().Add(-time.Minute)},
	}})
	if _, err := ApplyBlock(cfg, ApplyBlockRequest{IP: "192.0.2.95", TTL: time.Hour, Source: BlockSourceIncident, Entry: admission.EntryIncident}); err != nil {
		t.Fatal(err)
	}
	var got []respondCall
	for _, c := range a.responses() {
		if c.via == admission.EntryPermblock {
			got = append(got, c)
		}
	}
	want := []respondCall{{kind: admission.KindBlockIP, via: admission.EntryPermblock}}
	if !sameResponses(got, want) || len(b.calls) != 2 || b.calls[0].timeout != time.Hour || b.calls[1].timeout != 0 {
		t.Fatalf("promotion responses=%+v legacy calls=%+v", got, b.calls)
	}
}
