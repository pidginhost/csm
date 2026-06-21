package modsec

import (
	"os"
	"path/filepath"
	"strings"
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

// Vendor-format rules: Comodo CWAF pass-action ("triggered" but not blocking),
// OWASP CRS deny rule, LiteSpeed-friendly chained format. These are what
// the rule-action registry needs to classify error_log lines correctly.
const testVendorRulesConf = `# Comodo CWAF informational rule (pass action - logs only, never denies)
SecRule REQUEST_METHOD "!@rx ^(?:GET|HEAD|PROPFIND|OPTIONS)$" \
    "id:210710,chain,msg:'COMODO WAF: Request content type is not allowed by policy.',phase:2,pass,logdata:'%{matched_var_name}=%{matched_var}',t:none,rev:5,severity:2,tag:'CWAF',tag:'Generic'"
SecRule REQUEST_HEADERS:Content-Type "@rx ^([^;\s]+)" \
    "chain,capture"
SecRule TX:0 "!@pmFromFile userdata_wl_content_type" \
    "setvar:'tx.points=+%{tx.points_limit4}',ctl:forceRequestBodyVariable=On,t:none"

# Comodo CWAF inbound-points aggregator (pass)
SecRule TX:INCOMING_POINTS "@ge %{tx.incoming_points_limit}" \
    "id:214930,msg:'COMODO WAF: Inbound Points Exceeded',phase:5,pass,log,noauditlog,t:none,rev:1,severity:2,tag:'CWAF',tag:'FiltersEnd'"

# OWASP CRS-style anomaly enforcement (deny)
SecRule TX:ANOMALY_SCORE "@ge %{tx.inbound_anomaly_score_threshold}" \
    "id:949110,phase:2,deny,t:none,log,msg:'Inbound Anomaly Score Exceeded',severity:2"

# Comodo block-action variant (uses block keyword which inherits SecDefaultAction)
SecRule REQUEST_HEADERS:'/(Content-Length|Transfer-Encoding)/' "," \
    "id:211070,msg:'COMODO WAF: HTTP Request Smuggling Attack.',phase:2,capture,block,t:none,rev:1,severity:2,tag:'CWAF',tag:'Generic'"
`

// TestParseRulesFile_FiltersToCSMRange asserts the legacy entry point still
// scopes results to the 900xxx range that the Web UI rule-management screen
// expects, even though the underlying parser now sees every rule.
func TestParseRulesFile_FiltersToCSMRange(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vendor.conf")
	if err := os.WriteFile(path, []byte(testVendorRulesConf), 0644); err != nil {
		t.Fatal(err)
	}
	rules, err := ParseRulesFile(path)
	if err != nil {
		t.Fatalf("ParseRulesFile: %v", err)
	}
	if len(rules) != 0 {
		t.Errorf("vendor file should yield 0 CSM-range rules, got %d", len(rules))
	}
}

func TestParseRulesFileAll_IncludesVendorRules(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vendor.conf")
	if err := os.WriteFile(path, []byte(testVendorRulesConf), 0644); err != nil {
		t.Fatal(err)
	}

	rules, err := ParseRulesFileAll(path)
	if err != nil {
		t.Fatalf("ParseRulesFileAll: %v", err)
	}

	for _, want := range []struct {
		id     int
		action string
	}{
		{210710, "pass"},
		{214930, "pass"},
		{949110, "deny"},
		{211070, "block"},
	} {
		r := findRule(rules, want.id)
		if r == nil {
			t.Errorf("rule %d not found in parsed vendor rules", want.id)
			continue
		}
		if r.Action != want.action {
			t.Errorf("rule %d: action = %q, want %q", want.id, r.Action, want.action)
		}
	}
}

func TestIsBlockingAction(t *testing.T) {
	cases := map[string]bool{
		"deny":     true,
		"drop":     true,
		"block":    true,
		"redirect": true, // request is diverted - never reaches the upstream app
		"proxy":    true,
		"pause":    true,
		"pass":     false,
		"allow":    false,
		"log":      false, // metadata, not a disposition; caller treats as unknown
		"":         false, // unknown - populated LiteSpeed registry defaults to block
	}
	for action, want := range cases {
		if got := IsBlockingAction(action); got != want {
			t.Errorf("IsBlockingAction(%q) = %v, want %v", action, got, want)
		}
	}
}

// Action tokenisation: regression tests for false matches that the previous
// substring-based detector produced.
func TestParseAction_RejectsLookalikeTokens(t *testing.T) {
	dir := t.TempDir()
	conf := `# "passive" must not match "pass"; the rule has no disposition keyword
SecRule REQUEST_URI "x" "id:800001,phase:1,passive,t:none"
`
	path := filepath.Join(dir, "lookalike.conf")
	if err := os.WriteFile(path, []byte(conf), 0644); err != nil {
		t.Fatal(err)
	}
	rules, err := ParseRulesFileAll(path)
	if err != nil {
		t.Fatalf("ParseRulesFileAll: %v", err)
	}
	r := findRule(rules, 800001)
	if r == nil {
		t.Fatal("rule 800001 not parsed")
	}
	if r.Action != "" {
		t.Errorf("Action = %q, want \"\" (passive is not a disposition)", r.Action)
	}
}

func TestParseAction_IgnoresCommasInsideMsgLiteral(t *testing.T) {
	dir := t.TempDir()
	conf := `SecRule REQUEST_URI "x" "id:800002,phase:1,msg:'Request blocked, denied by policy',pass,t:none"
`
	path := filepath.Join(dir, "msg.conf")
	if err := os.WriteFile(path, []byte(conf), 0644); err != nil {
		t.Fatal(err)
	}
	rules, err := ParseRulesFileAll(path)
	if err != nil {
		t.Fatalf("ParseRulesFileAll: %v", err)
	}
	r := findRule(rules, 800002)
	if r == nil {
		t.Fatal("rule 800002 not parsed")
	}
	if r.Action != "pass" {
		t.Errorf("Action = %q, want pass (commas inside msg must not move the disposition)", r.Action)
	}
}

func TestParseAction_IgnoresEscapedDoubleQuotesInsideMsgLiteral(t *testing.T) {
	dir := t.TempDir()
	conf := `SecRule REQUEST_URI "x" "id:800004,phase:1,msg:'Request \"quoted\" by policy',pass,t:none"
`
	path := filepath.Join(dir, "escaped-quote.conf")
	if err := os.WriteFile(path, []byte(conf), 0644); err != nil {
		t.Fatal(err)
	}
	rules, err := ParseRulesFileAll(path)
	if err != nil {
		t.Fatalf("ParseRulesFileAll: %v", err)
	}
	r := findRule(rules, 800004)
	if r == nil {
		t.Fatal("rule 800004 not parsed")
	}
	if r.Action != "pass" {
		t.Errorf("Action = %q, want pass (escaped double quotes inside msg must not truncate the action list)", r.Action)
	}
}

func TestParseAction_LogOnlyRuleHasNoDisposition(t *testing.T) {
	dir := t.TempDir()
	conf := `SecRule REQUEST_URI "x" "id:800003,phase:1,log,msg:'just record',t:none"
`
	path := filepath.Join(dir, "logonly.conf")
	if err := os.WriteFile(path, []byte(conf), 0644); err != nil {
		t.Fatal(err)
	}
	rules, err := ParseRulesFileAll(path)
	if err != nil {
		t.Fatalf("ParseRulesFileAll: %v", err)
	}
	r := findRule(rules, 800003)
	if r == nil {
		t.Fatal("rule 800003 not parsed")
	}
	if r.Action != "" {
		t.Errorf("Action = %q, want \"\" (log alone inherits SecDefaultAction)", r.Action)
	}
}

func TestParseAction_DisruptiveActionsClassifyAsBlocking(t *testing.T) {
	dir := t.TempDir()
	conf := `SecRule REQUEST_URI "x" "id:800010,phase:1,redirect:'/blocked',log"
SecRule REQUEST_URI "x" "id:800011,phase:1,proxy:'http://sink/',log"
SecRule REQUEST_URI "x" "id:800012,phase:1,pause:5000,log"
SecRule REQUEST_URI "x" "id:800013,phase:1,drop,log"
`
	path := filepath.Join(dir, "disruptive.conf")
	if err := os.WriteFile(path, []byte(conf), 0644); err != nil {
		t.Fatal(err)
	}
	rules, err := ParseRulesFileAll(path)
	if err != nil {
		t.Fatalf("ParseRulesFileAll: %v", err)
	}
	for _, c := range []struct {
		id     int
		action string
	}{
		{800010, "redirect"},
		{800011, "proxy"},
		{800012, "pause"},
		{800013, "drop"},
	} {
		r := findRule(rules, c.id)
		if r == nil {
			t.Errorf("rule %d not parsed", c.id)
			continue
		}
		if r.Action != c.action {
			t.Errorf("rule %d: Action = %q, want %q", c.id, r.Action, c.action)
		}
		if !IsBlockingAction(r.Action) {
			t.Errorf("rule %d: %q should be classified as blocking", c.id, r.Action)
		}
	}
}

func TestParseAction_DenyWinsOverStrayPass(t *testing.T) {
	// Defensive priority: a misconfigured rule that lists both deny and
	// pass must be treated as deny so we never accidentally let a real
	// blocking rule slip through as a warning.
	dir := t.TempDir()
	conf := `SecRule REQUEST_URI "x" "id:800020,phase:1,pass,deny,status:403"
`
	path := filepath.Join(dir, "conflicting.conf")
	if err := os.WriteFile(path, []byte(conf), 0644); err != nil {
		t.Fatal(err)
	}
	rules, err := ParseRulesFileAll(path)
	if err != nil {
		t.Fatalf("ParseRulesFileAll: %v", err)
	}
	r := findRule(rules, 800020)
	if r == nil {
		t.Fatal("rule 800020 not parsed")
	}
	if r.Action != "deny" {
		t.Errorf("Action = %q, want deny (priority must favour the disruptive keyword)", r.Action)
	}
}

// Vendor packs ship assembled rules whose single logical line can exceed the
// default 64 KB scanner token. Before the buffer was enlarged, Scan stopped at
// ErrTooLong and the whole file's rules dropped out of the registry. A rule on
// a >64 KB line must now parse.
func TestParseRulesFileAll_LongMinifiedLineParses(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "big.conf")

	// One SecRule whose regex operand is padded well past 64 KB.
	pad := make([]byte, 100*1024)
	for i := range pad {
		pad[i] = 'a'
	}
	rule := `SecRule REQUEST_URI "@rx ` + string(pad) + `" "id:949110,phase:2,deny,status:403,msg:'big'"` + "\n"
	if err := os.WriteFile(path, []byte(rule), 0644); err != nil {
		t.Fatal(err)
	}

	rules, err := ParseRulesFileAll(path)
	if err != nil {
		t.Fatalf("ParseRulesFileAll on long line: %v", err)
	}
	if findRule(rules, 949110) == nil {
		t.Fatal("rule on >64 KB line was dropped (scanner truncated the file)")
	}
}

func TestParseRulesFileAll_ContinuationLineLimit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "too-big.conf")

	half := strings.Repeat("a", maxModsecLineBytes/2)
	rule := `SecRule REQUEST_URI "@rx ` + half + `\` + "\n" +
		half + `\` + "\n" +
		`a" "id:949111,phase:2,deny,status:403,msg:'too big'"` + "\n"
	if err := os.WriteFile(path, []byte(rule), 0644); err != nil {
		t.Fatal(err)
	}

	if _, err := ParseRulesFileAll(path); err == nil {
		t.Fatal("expected continuation-heavy logical line to be rejected")
	} else if !strings.Contains(err.Error(), "logical modsec line exceeds") {
		t.Fatalf("unexpected error: %v", err)
	}
}
