package checks

import (
	"fmt"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/alert"
)

// Ruling R8: the registry, not a check name, says which checks feed a
// subnet response and through which entry; a subnet summary never
// authorizes a single-address block and always carries evidence.
func TestSubnetResponsesComeFromTheRegistry(t *testing.T) {
	for check, want := range map[string]admission.Entry{
		"mail_subnet_spray": admission.EntryMailSubnet, "smtp_subnet_spray": admission.EntryMailSubnet,
		"http_asn_crawl": admission.EntryASNCrawl, "mail_bruteforce": 0, "wp_login_bruteforce": 0,
	} {
		if got := ResponsePolicyFor(check).Subnet; got != want {
			t.Errorf("%s subnet entry = %s, want %s", check, got, want)
		}
	}
	for name, p := range map[string]ResponsePolicy{
		"a subnet check that blocks an address": {Subnet: admission.EntryMailSubnet, Block: BlockAlways, Evidence: admission.FamilyMail, Basis: admission.BasisLocal},
		"a subnet check without evidence":       {Subnet: admission.EntryMailSubnet},
		"an entry that is no subnet path":       {Subnet: admission.EntryCentral, Evidence: admission.FamilyMail, Basis: admission.BasisLocal},
	} {
		if err := validateResponsePolicy([]CheckInfo{{Name: "x_check", Response: p}}); err == nil {
			t.Errorf("%s: accepted %+v", name, p)
		}
	}
}

// Every derived entry wraps checks a root producer publishes, under an
// entry other than the scan's, and registers on the production policy.
func TestDerivedEntriesWrapPublishedRoots(t *testing.T) {
	published := map[string]bool{}
	for _, p := range ProducerTable() {
		for _, check := range p.Spec.Checks {
			published[check] = true
		}
	}
	reg, err := admission.NewRegistry(AdmissionPolicy)
	if err != nil {
		t.Fatal(err)
	}
	entries := map[admission.Entry]bool{}
	for _, spec := range DerivedEntries() {
		if spec.Entry == admission.EntryScan || entries[spec.Entry] {
			t.Errorf("%s: entry %s is not a single derived entry", spec.ID, spec.Entry)
		}
		entries[spec.Entry] = true
		for _, check := range spec.Checks {
			if !published[check] {
				t.Errorf("%s wraps %s, which no producer publishes", spec.ID, check)
			}
		}
		if _, err := reg.Register(spec); err != nil {
			t.Errorf("%s: %v", spec.ID, err)
		}
	}
	for _, e := range []admission.Entry{admission.EntryMailSubnet, admission.EntryASNCrawl} {
		if !entries[e] {
			t.Errorf("no producer binds %s", e)
		}
	}
}

func sprayFinding(constituents int) alert.Finding {
	at := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	f := alert.Finding{
		Check: "mail_subnet_spray", Severity: alert.Critical, Message: "Mail password spray", CIDRs: []string{"198.51.100.0/24"},
		Observation: alert.Observation{Producer: string(ProducerMailLog), Stream: "maillog", Cursor: "crossing", ObservedAt: at},
	}
	for i := 0; i < constituents; i++ {
		f.SprayConstituents = append(f.SprayConstituents, alert.SprayConstituent{
			Address: fmt.Sprintf("198.51.100.%d", i+1), LastSeen: at.Add(-time.Duration(constituents-i) * time.Second),
			Observation: alert.Observation{Producer: string(ProducerMailLog), Stream: "maillog", Cursor: fmt.Sprintf("line-%02d", i+1), ObservedAt: at.Add(-time.Duration(constituents-i) * time.Second)},
		})
	}
	return f
}

// A subnet spray asks admission to block its prefix through the mail
// subnet entry, one root per counted address, newest first and at most as
// many as a candidate holds; a prefix the legacy path already blocked is
// still asked for.
func TestMailSprayAsksAdmissionForItsSubnet(t *testing.T) {
	a := withAdmission(t)
	blocker := withBlocker(t)
	withChallengeList(t, nil)
	cfg := liveAutoBlockConfig(t)
	AutoBlockIPs(cfg, []alert.Finding{sprayFinding(admission.MaxRoots + 4)})
	AutoBlockIPs(cfg, []alert.Finding{sprayFinding(1)})
	got := a.responses()
	if len(got) != admission.MaxRoots+1 || len(blocker.blockedSubnet) != 1 {
		t.Fatalf("%d responses, legacy subnets %v", len(got), blocker.blockedSubnet)
	}
	for i, c := range got[:admission.MaxRoots] {
		want := respondCall{kind: admission.KindBlockSubnet, check: "mail_subnet_spray", target: "198.51.100.0/24", cursor: fmt.Sprintf("line-%02d", admission.MaxRoots+4-i), via: admission.EntryMailSubnet, rooted: true}
		if c != want {
			t.Fatalf("response %d = %+v, want %+v", i, c, want)
		}
	}
	if last := got[admission.MaxRoots]; last.cursor != "line-01" || last.target != "198.51.100.0/24" {
		t.Fatalf("already blocked prefix: %+v", last)
	}
}

// A spray recorded before its constituents were kept answers its own
// observation.
func TestMailSprayWithoutConstituentsAnswersItsOwnObservation(t *testing.T) {
	a := withAdmission(t)
	withBlocker(t)
	withChallengeList(t, nil)
	AutoBlockIPs(liveAutoBlockConfig(t), []alert.Finding{sprayFinding(0)})
	want := []respondCall{{kind: admission.KindBlockSubnet, check: "mail_subnet_spray", target: "198.51.100.0/24", cursor: "crossing", via: admission.EntryMailSubnet, rooted: true}}
	if got := a.responses(); !sameResponses(got, want) {
		t.Fatalf("responses = %+v", got)
	}
}

// A Critical crawl asks admission to block each of its subnets through the
// crawl entry; a subnet touching infra space asks for nothing.
func TestCrawlAsksAdmissionPerSubnet(t *testing.T) {
	a := withAdmission(t)
	withBlocker(t)
	withChallengeList(t, nil)
	cfg := liveAutoBlockConfig(t)
	cfg.InfraIPs = []string{"203.0.113.9"}
	AutoBlockIPs(cfg, []alert.Finding{{Check: "http_asn_crawl", Severity: alert.Critical, Message: "crawl", CIDRs: []string{"198.51.100.0/24", "203.0.113.0/24", "192.0.2.0/24"}}})
	want := []respondCall{
		{kind: admission.KindBlockSubnet, check: "http_asn_crawl", target: "198.51.100.0/24", via: admission.EntryASNCrawl, rooted: true},
		{kind: admission.KindBlockSubnet, check: "http_asn_crawl", target: "192.0.2.0/24", via: admission.EntryASNCrawl, rooted: true},
	}
	if got := a.responses(); !sameResponses(got, want) {
		t.Fatalf("responses = %+v", got)
	}
}

// A netblock escalation rests on past blocks, not on a root admission could
// answer: it is handed to admission without one and refused there until
// range corroboration exists (plan 2).
func TestNetblockAsksAdmissionWithoutARoot(t *testing.T) {
	a := withAdmission(t)
	cfg := netblockWindowConfig(t)
	blocker := newNetblockBlocker()
	blocker.live["198.51.100.37"] = struct{}{}
	blocker.live["198.51.100.144"] = struct{}{}
	swapBlocker(t, blocker)
	AutoBlockIPs(cfg, bruteForceFrom("198.51.100.158"))
	var netblock []respondCall
	for _, c := range a.responses() {
		if c.via == admission.EntryNetblock {
			netblock = append(netblock, c)
		}
	}
	if len(blocker.subnets) != 1 || len(netblock) != 1 || netblock[0] != (respondCall{kind: admission.KindBlockSubnet, via: admission.EntryNetblock}) {
		t.Fatalf("legacy subnets %v, netblock responses %+v", blocker.subnets, netblock)
	}
}

// The legacy hourly budget cannot hide later selected crawl subnets
// from admission. Legacy still applies only the first block it can fund.
func TestCrawlAsksAdmissionAfterLegacyBudgetIsSpent(t *testing.T) {
	a := withAdmission(t)
	b := withBlocker(t)
	withChallengeList(t, nil)
	cfg := liveAutoBlockConfig(t)
	cfg.AutoResponse.MaxBlocksPerHour = 1
	cidrs := []string{"192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"}
	AutoBlockIPs(cfg, []alert.Finding{{Check: "http_asn_crawl", Severity: alert.Critical, CIDRs: cidrs}})
	got := a.responses()
	if len(got) != len(cidrs) || len(b.blockedSubnet) != 1 || b.blockedSubnet[0] != cidrs[0] {
		t.Fatalf("responses=%+v legacy subnets=%v", got, b.blockedSubnet)
	}
	for i, c := range got {
		if c.kind != admission.KindBlockSubnet || c.target != cidrs[i] || c.via != admission.EntryASNCrawl {
			t.Fatalf("response %d = %+v", i, c)
		}
	}
}
