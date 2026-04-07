package modsec

import (
	"os"
	"path/filepath"
	"testing"
)

const testRulesConf = `# CSM Custom ModSecurity Rules

SecRule REQUEST_URI "\.haxor$|\.cgix$" \
    "id:900001,phase:1,deny,status:403,log,msg:'CSM: Blocked LEVIATHAN CGI extension access'"

SecRule REQUEST_URI "/wp-content/uploads/.*\.php" \
    "id:900003,phase:1,deny,status:403,log,msg:'CSM: Blocked PHP execution in uploads directory'"

# Rate limiter - counter rule (pass,nolog)
SecRule REQUEST_URI "/xmlrpc\.php$" \
    "id:900006,phase:1,pass,nolog,\
    setvar:ip.xmlrpc_count=+1,\
    expirevar:ip.xmlrpc_count=600"
SecRule IP:XMLRPC_COUNT "@gt 10" \
    "id:900007,phase:1,deny,status:429,log,msg:'CSM: XML-RPC rate limit exceeded',\
    chain"
SecRule REQUEST_URI "/xmlrpc\.php$"

SecRule REQUEST_URI "/wp-json/wp/v2/users" \
    "id:900112,phase:1,deny,status:403,log,msg:'CSM VP: WordPress user enumeration blocked',\
    chain"
SecRule &REQUEST_HEADERS:Authorization "@eq 0"
`

func TestParseRulesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "modsec2.user.conf")
	if err := os.WriteFile(path, []byte(testRulesConf), 0644); err != nil {
		t.Fatal(err)
	}

	rules, err := ParseRulesFile(path)
	if err != nil {
		t.Fatalf("ParseRulesFile: %v", err)
	}

	// Should find 5 rules total (900001, 900003, 900006, 900007, 900112)
	if len(rules) != 5 {
		t.Fatalf("expected 5 rules, got %d", len(rules))
	}

	// Verify 900001 - simple deny
	r1 := findRule(rules, 900001)
	if r1 == nil {
		t.Fatal("rule 900001 not found")
	}
	if r1.Action != "deny" || r1.StatusCode != 403 || r1.Phase != 1 {
		t.Errorf("900001: action=%s status=%d phase=%d", r1.Action, r1.StatusCode, r1.Phase)
	}
	if r1.Description != "CSM: Blocked LEVIATHAN CGI extension access" {
		t.Errorf("900001 description: %q", r1.Description)
	}
	if r1.IsCounter {
		t.Error("900001 should not be a counter rule")
	}

	// Verify 900006 - counter rule (pass,nolog)
	r6 := findRule(rules, 900006)
	if r6 == nil {
		t.Fatal("rule 900006 not found")
	}
	if !r6.IsCounter {
		t.Error("900006 should be a counter rule (pass,nolog)")
	}
	if r6.Action != "pass" {
		t.Errorf("900006: action=%s, want pass", r6.Action)
	}

	// Verify 900112 - chained deny
	r112 := findRule(rules, 900112)
	if r112 == nil {
		t.Fatal("rule 900112 not found")
	}
	if r112.Action != "deny" || r112.StatusCode != 403 {
		t.Errorf("900112: action=%s status=%d", r112.Action, r112.StatusCode)
	}
	if r112.Description != "CSM VP: WordPress user enumeration blocked" {
		t.Errorf("900112 description: %q", r112.Description)
	}
}

func TestParseRulesFileNotFound(t *testing.T) {
	_, err := ParseRulesFile("/nonexistent/path")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestParseRealConfig(t *testing.T) {
	// Parse the actual CSM modsec config to verify the parser handles all rules
	path := "../../configs/csm_modsec_custom.conf"
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Skip("configs/csm_modsec_custom.conf not found (CI?)")
	}

	rules, err := ParseRulesFile(path)
	if err != nil {
		t.Fatalf("ParseRulesFile: %v", err)
	}

	// Count counter vs visible rules
	counters := 0
	visible := 0
	for _, r := range rules {
		if r.IsCounter {
			counters++
		} else {
			visible++
		}
		// Every rule must have an ID in 900xxx range
		if r.ID < 900000 || r.ID > 900999 {
			t.Errorf("rule ID %d outside CSM range", r.ID)
		}
		// Non-counter rules must have a description
		if !r.IsCounter && r.Description == "" {
			t.Errorf("rule %d missing description", r.ID)
		}
	}

	t.Logf("Parsed %d total rules: %d visible, %d counter", len(rules), visible, counters)

	// The real config has known rules - verify minimum counts
	if len(rules) < 20 {
		t.Errorf("expected at least 20 rules, got %d", len(rules))
	}

	// Verify a few specific known rules exist
	for _, expectedID := range []int{900001, 900005, 900100, 900112, 900116} {
		if findRule(rules, expectedID) == nil {
			t.Errorf("expected rule %d not found", expectedID)
		}
	}
}

func findRule(rules []Rule, id int) *Rule {
	for i := range rules {
		if rules[i].ID == id {
			return &rules[i]
		}
	}
	return nil
}
