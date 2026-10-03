package alert

import (
	"encoding/json"
	"strings"
	"testing"
)

// The subnets a finding names are part of its public JSON, so the API,
// webhooks, the phpanel queue and history show them; a finding without
// subnets keeps its payload unchanged.
func TestFindingJSONNamesItsCIDRs(t *testing.T) {
	with, err := json.Marshal(Finding{Check: "http_asn_crawl", CIDRs: []string{"198.51.100.0/24", "203.0.113.0/25"}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(with), `"cidrs":["198.51.100.0/24","203.0.113.0/25"]`) {
		t.Fatalf("payload %s, want the cidrs list", with)
	}
	without, err := json.Marshal(Finding{Check: "mail_bruteforce", SourceIP: "192.0.2.5"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(without), "cidrs") {
		t.Fatalf("payload %s names cidrs without any", without)
	}
	var back Finding
	if err := json.Unmarshal(with, &back); err != nil || len(back.CIDRs) != 2 {
		t.Fatalf("decoded %+v (error %v), want both subnets", back, err)
	}
}
