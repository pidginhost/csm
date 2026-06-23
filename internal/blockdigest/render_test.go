package blockdigest

import (
	"strings"
	"testing"
	"time"
)

func sampleCollector() *Collector {
	return New(Options{
		Countries: []string{"RO"}, SendOn: "any", Interval: time.Hour, MinBlock: 1,
		Host: "host.example.net", Version: "9.9.9",
		Now: func() time.Time { return time.Unix(0, 0).UTC() },
	})
}

func sampleDigest() Digest {
	return Digest{
		Window: time.Hour, Countries: []string{"RO"},
		Total: 3, CustomerCount: 1, AttackerCount: 2,
		ByCountry:  map[string]int{"RO": 3},
		ByReason:   map[string]int{"ModSecurity escalation": 1, "rule escalation": 1, "unrecognized customer block": 1},
		ByCategory: map[string]int{"modsec": 2, "other": 1},
		Records: []Record{
			{IP: "203.0.113.10", Country: "RO", Reason: "unrecognized customer block", Bucket: BucketCustomer, Category: "other", TS: time.Unix(10, 0).UTC()},
			{IP: "203.0.113.11", Country: "RO", Reason: "ModSecurity escalation: 5+ denies", Bucket: BucketAttacker, Category: "modsec", TS: time.Unix(20, 0).UTC()},
			{IP: "203.0.113.99", Country: "RO", Reason: "rule escalation: 5+ denies", Bucket: BucketAttacker, Category: "modsec", TS: time.Unix(30, 0).UTC()},
		},
	}
}

func TestRenderSubjectHasCounts(t *testing.T) {
	c := sampleCollector()
	s := c.renderSubject(sampleDigest())
	if !strings.Contains(s, "3 watched-country IPs blocked (1 customer-risk)") {
		t.Errorf("subject missing counts: %q", s)
	}
	if !strings.Contains(s, "host.example.net") {
		t.Errorf("subject missing host: %q", s)
	}
}

func TestRenderBodyListsCustomerIPs(t *testing.T) {
	c := sampleCollector()
	b := c.renderBody(sampleDigest())
	if !strings.Contains(b, "203.0.113.10") {
		t.Errorf("body missing customer IPs:\n%s", b)
	}
	if !strings.Contains(b, "RO") {
		t.Errorf("body missing country:\n%s", b)
	}
}

func TestBuildPayloadStructured(t *testing.T) {
	c := sampleCollector()
	p := c.buildPayload("block_digest", sampleDigest())
	if p.Text == "" {
		t.Error("payload text empty")
	}
	if p.CSM.Event != "block_digest" || p.CSM.Host != "host.example.net" || p.CSM.Version != "9.9.9" {
		t.Errorf("csm meta wrong: %+v", p.CSM)
	}
	if p.CSM.Counts.Total != 3 || p.CSM.Counts.Customer != 1 || p.CSM.Counts.Attacker != 2 {
		t.Errorf("counts wrong: %+v", p.CSM.Counts)
	}
	if p.CSM.Counts.ByCategory["modsec"] != 2 || p.CSM.Counts.ByCategory["other"] != 1 {
		t.Errorf("category counts wrong: %+v", p.CSM.Counts.ByCategory)
	}
	if len(p.CSM.Blocks) != 3 {
		t.Errorf("blocks len = %d, want 3", len(p.CSM.Blocks))
	}
	for _, block := range p.CSM.Blocks {
		if block.Category == "" {
			t.Errorf("payload block has empty category: %+v", block)
		}
	}
}

func TestShouldSendGating(t *testing.T) {
	any := New(Options{SendOn: "any", MinBlock: 1})
	cust := New(Options{SendOn: "customer", MinBlock: 1})
	withCust := Digest{Total: 3, CustomerCount: 1}
	noCust := Digest{Total: 3, CustomerCount: 0}
	empty := Digest{Total: 0}
	if !any.shouldSend(withCust) || !any.shouldSend(noCust) {
		t.Error("any should send when total>=min")
	}
	if any.shouldSend(empty) {
		t.Error("any should not send empty when min=1")
	}
	if !cust.shouldSend(withCust) {
		t.Error("customer should send when customer>=min")
	}
	if cust.shouldSend(noCust) {
		t.Error("customer should NOT send when no customer blocks")
	}
	heartbeat := New(Options{SendOn: "any", MinBlock: 0})
	if !heartbeat.shouldSend(empty) {
		t.Error("min_block 0 should send empty heartbeat")
	}
}
