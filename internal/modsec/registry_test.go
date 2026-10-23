package modsec

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testRegistryComodoConf = `# Comodo CWAF informational pass-action rule (the false-block trigger)
SecRule REQUEST_METHOD "!@rx ^(?:GET|HEAD|PROPFIND|OPTIONS)$" \
    "id:210710,chain,msg:'COMODO WAF: Request content type is not allowed by policy.',phase:2,pass,t:none,rev:5,severity:2,tag:'CWAF',tag:'Generic'"
SecRule REQUEST_HEADERS:Content-Type "@rx ^([^;\s]+)" \
    "chain,capture"
SecRule TX:0 "!@pmFromFile userdata_wl_content_type" \
    "setvar:'tx.points=+%{tx.points_limit4}',ctl:forceRequestBodyVariable=On,t:none"

SecRule TX:INCOMING_POINTS "@ge %{tx.incoming_points_limit}" \
    "id:214930,msg:'COMODO WAF: Inbound Points Exceeded',phase:5,pass,log,noauditlog,t:none,rev:1,severity:2,tag:'CWAF',tag:'FiltersEnd'"
`

const testRegistryCRSConf = `SecRule TX:ANOMALY_SCORE "@ge %{tx.inbound_anomaly_score_threshold}" \
    "id:949110,phase:2,deny,t:none,log,msg:'Inbound Anomaly Score Exceeded',severity:2"
`

const testRegistryCSMConf = `SecRule REQUEST_URI "/wp-content/uploads/.*\.php" \
    "id:900003,phase:1,deny,status:403,log,msg:'CSM: Blocked PHP execution in uploads directory'"
`

func TestBuildRegistry_AggregatesAcrossDirs(t *testing.T) {
	root := t.TempDir()
	comodo := filepath.Join(root, "comodo")
	crs := filepath.Join(root, "crs")
	csm := filepath.Join(root, "csm")
	for _, d := range []string{comodo, crs, csm} {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(comodo, "02_Global_Generic.conf"), []byte(testRegistryComodoConf), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(crs, "REQUEST-949-BLOCKING-EVALUATION.conf"), []byte(testRegistryCRSConf), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(csm, "modsec2.user.conf"), []byte(testRegistryCSMConf), 0644); err != nil {
		t.Fatal(err)
	}

	reg, err := BuildRegistry([]string{comodo, crs, csm})
	if err != nil {
		t.Fatalf("BuildRegistry: %v", err)
	}

	cases := []struct {
		id         int
		wantAction string
		wantBlock  bool
	}{
		{210710, "pass", false},
		{214930, "pass", false},
		{949110, "deny", true},
		{900003, "deny", true},
	}
	for _, c := range cases {
		action, known := reg.Action(c.id)
		if !known {
			t.Errorf("rule %d not in registry", c.id)
			continue
		}
		if action != c.wantAction {
			t.Errorf("rule %d: action %q, want %q", c.id, action, c.wantAction)
		}
		if got := IsBlockingAction(action); got != c.wantBlock {
			t.Errorf("rule %d: IsBlockingAction(%q)=%v, want %v", c.id, action, got, c.wantBlock)
		}
	}

	if _, known := reg.Action(99999999); known {
		t.Error("unknown rule should not be in registry")
	}
}

func TestBuildRegistry_MissingDirIsSoftFailure(t *testing.T) {
	reg, err := BuildRegistry([]string{"/nonexistent/path/that/does/not/exist"})
	if err != nil {
		t.Errorf("missing dir should not error: %v", err)
	}
	if reg == nil {
		t.Fatal("registry should not be nil")
	}
	if reg.Len() != 0 {
		t.Errorf("expected empty registry, got %d entries", reg.Len())
	}
}

// An unreadable file must not discard good rules, but the caller needs to
// know the build was incomplete so it does not cache a partial registry.
func TestBuildRegistry_BrokenSymlinkSkipped(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "good.conf"), []byte(testRegistryCRSConf), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "does-not-exist"), filepath.Join(dir, "broken.conf")); err != nil {
		t.Fatal(err)
	}

	reg, err := BuildRegistry([]string{dir})
	if err == nil {
		t.Error("broken symlink should report an incomplete build")
	}
	if action, known := reg.Action(949110); !known || action != "deny" {
		t.Errorf("rule 949110 from good.conf lost: known=%v action=%q", known, action)
	}
}

func TestBuildRegistryReportsParseErrorsAndContinues(t *testing.T) {
	dir := t.TempDir()
	writeRule(t, filepath.Join(dir, "a_bad.conf"), strings.Repeat("x", maxModsecLineBytes+1))
	writeRule(t, filepath.Join(dir, "b_good.conf"), testRegistryCRSConf)
	reg, err := BuildRegistry([]string{dir})
	if err == nil {
		t.Error("overlong rule did not report an incomplete build")
	}
	if action, known := reg.Action(949110); !known || action != "deny" {
		t.Errorf("good rule lost after parse failure: known=%v action=%q", known, action)
	}
}

func TestBuildRegistry_DuplicateIDLastWriteWinsWithinDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a_first.conf"), []byte(`SecRule REQUEST_URI "x" "id:777777,phase:1,pass"`+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b_second.conf"), []byte(`SecRule REQUEST_URI "x" "id:777777,phase:1,deny,status:403"`+"\n"), 0644); err != nil {
		t.Fatal(err)
	}

	reg, err := BuildRegistry([]string{dir})
	if err != nil {
		t.Fatalf("BuildRegistry: %v", err)
	}
	action, known := reg.Action(777777)
	if !known {
		t.Fatal("rule 777777 not registered")
	}
	if action != "deny" {
		t.Errorf("action = %q, want deny (lexicographically later file wins inside one dir)", action)
	}
}

// TestBuildRegistry_DuplicateIDFirstDirectoryWins encodes the precedence
// contract: dirs is most-specific-first, so an operator override in the
// vendor-config tree must not be silently replaced by a stale rule in a
// system fallback directory walked later.
func TestBuildRegistry_DuplicateIDFirstDirectoryWins(t *testing.T) {
	specific := t.TempDir()
	fallback := t.TempDir()
	if err := os.WriteFile(filepath.Join(specific, "override.conf"), []byte(`SecRule REQUEST_URI "x" "id:777777,phase:1,pass"`+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fallback, "stock.conf"), []byte(`SecRule REQUEST_URI "x" "id:777777,phase:1,deny,status:403"`+"\n"), 0644); err != nil {
		t.Fatal(err)
	}

	reg, err := BuildRegistry([]string{specific, fallback})
	if err != nil {
		t.Fatalf("BuildRegistry: %v", err)
	}
	action, known := reg.Action(777777)
	if !known {
		t.Fatal("rule 777777 not registered")
	}
	if action != "pass" {
		t.Errorf("action = %q, want pass (most-specific directory must win)", action)
	}
}

func TestBuildRegistry_LogOnlyRuleInFirstDirectoryBlocksFallbackAction(t *testing.T) {
	specific := t.TempDir()
	fallback := t.TempDir()
	if err := os.WriteFile(filepath.Join(specific, "metadata.conf"), []byte(`SecRule REQUEST_URI "x" "id:777778,phase:1,log,msg:'inherits default'"`+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fallback, "stock.conf"), []byte(`SecRule REQUEST_URI "x" "id:777778,phase:1,pass"`+"\n"), 0644); err != nil {
		t.Fatal(err)
	}

	reg, err := BuildRegistry([]string{specific, fallback})
	if err != nil {
		t.Fatalf("BuildRegistry: %v", err)
	}
	if action, known := reg.Action(777778); known || action != "" {
		t.Errorf("Action(777778) = (%q,%v), want (\"\",false); fallback pass must not override first-dir unknown", action, known)
	}
}

func TestBuildRegistry_LogOnlyRuleWinsWithinDirectoryWhenLexicallyLater(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a_first.conf"), []byte(`SecRule REQUEST_URI "x" "id:777779,phase:1,pass"`+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b_second.conf"), []byte(`SecRule REQUEST_URI "x" "id:777779,phase:1,log,msg:'inherits default'"`+"\n"), 0644); err != nil {
		t.Fatal(err)
	}

	reg, err := BuildRegistry([]string{dir})
	if err != nil {
		t.Fatalf("BuildRegistry: %v", err)
	}
	if action, known := reg.Action(777779); known || action != "" {
		t.Errorf("Action(777779) = (%q,%v), want (\"\",false); later unknown rule must override earlier pass", action, known)
	}
}

func TestBuildRegistry_NonConfFilesIgnored(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte(testRegistryCRSConf), 0644); err != nil {
		t.Fatal(err)
	}

	reg, err := BuildRegistry([]string{dir})
	if err != nil {
		t.Fatalf("BuildRegistry: %v", err)
	}
	if reg.Len() != 0 {
		t.Errorf("non-.conf file should be ignored, got %d entries", reg.Len())
	}
}

func TestBuildRegistry_RecursesIntoSubdirs(t *testing.T) {
	root := t.TempDir()
	nested := filepath.Join(root, "comodo_litespeed", "rules")
	if err := os.MkdirAll(nested, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nested, "02_Global_Generic.conf"), []byte(testRegistryComodoConf), 0644); err != nil {
		t.Fatal(err)
	}

	reg, err := BuildRegistry([]string{root})
	if err != nil {
		t.Fatalf("BuildRegistry: %v", err)
	}
	if action, known := reg.Action(210710); !known || action != "pass" {
		t.Errorf("nested rule 210710 not picked up: known=%v action=%q", known, action)
	}
}

func TestRegistry_NilAndZeroSafe(t *testing.T) {
	var nilReg *Registry
	if action, known := nilReg.Action(123); known || action != "" {
		t.Errorf("nil registry Action: got (%q,%v), want (\"\",false)", action, known)
	}
	if nilReg.Len() != 0 {
		t.Errorf("nil registry Len = %d, want 0", nilReg.Len())
	}
}

func TestGlobalRegistry_SetGet(t *testing.T) {
	t.Cleanup(ResetGlobalForTest)
	ResetGlobalForTest()
	if Global() != nil {
		t.Fatal("expected nil global at start of test")
	}

	r := &Registry{actions: map[int]string{210710: "pass"}}
	SetGlobal(r)

	got := Global()
	if got == nil {
		t.Fatal("Global returned nil after SetGlobal")
	}
	if action, known := got.Action(210710); !known || action != "pass" {
		t.Errorf("global registry lookup: known=%v action=%q", known, action)
	}
}

// testCRSSetupPass is a synthetic anomaly-scoring setup file. Detection rules
// say block, and block takes the disruptive action of these pass defaults.
const testCRSSetupPass = `# Anomaly scoring mode.
SecDefaultAction "phase:1,log,auditlog,pass"
SecDefaultAction "phase:2,log,auditlog,pass"

# Self-contained mode, commented out.
# SecDefaultAction "phase:1,log,auditlog,deny,status:403"
# SecDefaultAction "phase:2,log,auditlog,deny,status:403"
`

const testCRSDetectionRules = `SecRule ARGS "@rx <script" \
    "id:941100,\
    phase:2,\
    block,\
    capture,\
    t:none,\
    msg:'XSS Attack Detected',\
    setvar:'tx.inbound_anomaly_score=+5'"
SecRule REQUEST_HEADERS:User-Agent "@rx scanner" \
    "id:913100,phase:request,block,log,msg:'Scanner detected'"
SecRule TX:ANOMALY_SCORE "@ge 5" \
    "id:949110,phase:2,deny,t:none,log,msg:'Inbound Anomaly Score Exceeded'"
SecRule ARGS "@rx probe" "id:920100,phase:1,pass,log,msg:'Explicit pass'"
`

func wantRegistryActions(t *testing.T, reg *Registry, want map[int]string) {
	t.Helper()
	for id, action := range want {
		got, known := reg.Action(id)
		if !known || got != action {
			t.Errorf("Action(%d) = (%q,%v), want (%q,true)", id, got, known, action)
		}
	}
}

// block is not a disruptive action of its own: ModSecurity runs the
// disruptive action of the SecDefaultAction for the rule's phase, and pass
// when there is none. Explicit dispositions never change.
func TestBuildRegistry_BlockFollowsThePackSecDefaultAction(t *testing.T) {
	selfContained := `SecDefaultAction "phase:1,log,auditlog,deny,status:403"
SecDefaultAction "phase:2,log,auditlog,deny,status:403"
`
	for _, tc := range []struct {
		name, setup, want string
	}{
		{"anomaly scoring pass defaults", testCRSSetupPass, "pass"},
		{"self-contained deny defaults", selfContained, "deny"},
		{"no SecDefaultAction", "# Setup file without defaults.\n", "pass"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeRule(t, filepath.Join(root, "OWASP3", "crs-setup.conf"), tc.setup)
			writeRule(t, filepath.Join(root, "OWASP3", "rules", "REQUEST-941.conf"), testCRSDetectionRules)
			reg, err := BuildRegistry([]string{root})
			if err != nil {
				t.Fatalf("BuildRegistry: %v", err)
			}
			wantRegistryActions(t, reg, map[int]string{
				941100: tc.want,
				913100: tc.want,
				949110: "deny",
				920100: "pass",
			})
		})
	}
}

func TestBuildRegistry_BlockUsesTheDefaultForItsPhase(t *testing.T) {
	root := t.TempDir()
	writeRule(t, filepath.Join(root, "pack", "setup.conf"), `SecDefaultAction "phase:1,log,deny,status:403"
SecDefaultAction "phase:2,log,pass"
SecDefaultAction "phase:response,log,drop"
`)
	writeRule(t, filepath.Join(root, "pack", "rules", "rules.conf"), `SecRule ARGS "@rx a" "id:1001,phase:1,block"
SecRule ARGS "@rx b" "id:1002,phase:'1',block"
SecRule ARGS "@rx c" "id:1003,phase:2,block"
SecRule ARGS "@rx d" "id:1004,phase:request,block"
SecRule ARGS "@rx e" "id:1005,block,msg:'phase:1 lookalike'"
SecRule ARGS "@rx f" "id:1006,phase:4,block"
SecRule ARGS "@rx g" "id:1007,PHASE:Response,BLOCK"
SecRule ARGS "@rx h" "id:1008,phase:3,block"
SecRule ARGS "@rx i" "id:1009,phase:1,pass"
SecRule ARGS "@rx j" "id:1010,phase:2,deny,status:403"
`)
	reg, err := BuildRegistry([]string{root})
	if err != nil {
		t.Fatalf("BuildRegistry: %v", err)
	}
	wantRegistryActions(t, reg, map[int]string{
		1001: "deny",
		1002: "deny",
		1003: "pass",
		1004: "pass", // phase:request is phase 2
		1005: "pass", // no phase is phase 2; msg text does not set one
		1006: "drop",
		1007: "drop", // phase:response is phase 4
		1008: "pass", // no default for phase 3
		1009: "pass",
		1010: "deny",
	})
}

// CSM cannot see Include order, so a directory's defaults govern its whole
// tree whatever the file names sort as, and the nearest declaring directory
// wins per phase.
func TestBuildRegistry_SecDefaultActionGovernsItsDirectoryTree(t *testing.T) {
	root := t.TempDir()
	// activated_rules/ sorts before crs-setup.conf.
	writeRule(t, filepath.Join(root, "activated_rules", "rules.conf"), `SecRule ARGS "@rx a" "id:3001,phase:2,block"
SecRule ARGS "@rx b" "id:3002,phase:1,block"
`)
	writeRule(t, filepath.Join(root, "crs-setup.conf"), `SecDefaultAction "phase:1,deny,status:403"
SecDefaultAction "phase:2,deny,status:403"
`)
	writeRule(t, filepath.Join(root, "nested", "setup.conf"), `SecDefaultAction "phase:2,pass"`+"\n")
	writeRule(t, filepath.Join(root, "nested", "rules", "rules.conf"), `SecRule ARGS "@rx c" "id:3003,phase:2,block"
SecRule ARGS "@rx d" "id:3004,phase:1,block"
`)
	reg, err := BuildRegistry([]string{root})
	if err != nil {
		t.Fatalf("BuildRegistry: %v", err)
	}
	wantRegistryActions(t, reg, map[int]string{
		3001: "deny",
		3002: "deny",
		3003: "pass", // nested/ declares its own phase 2 default
		3004: "deny", // nested/ has no phase 1 default, root's applies
	})
}

func TestBuildRegistry_SecDefaultActionDoesNotLeak(t *testing.T) {
	deny := `SecDefaultAction "phase:2,log,deny,status:403"` + "\n"
	user := t.TempDir()
	writeRule(t, filepath.Join(user, "modsec2.user.conf"), deny+`SecRule ARGS "@rx a" "id:2001,phase:2,block"`+"\n")
	vendor := t.TempDir()
	// a_pack sorts before b_pack, so a walk-order model would carry its
	// default into the next pack.
	writeRule(t, filepath.Join(vendor, "a_pack", "setup.conf"), deny)
	writeRule(t, filepath.Join(vendor, "a_pack", "rules.conf"), `SecRule ARGS "@rx b" "id:2002,phase:2,block"`+"\n")
	writeRule(t, filepath.Join(vendor, "b_pack", "rules.conf"), `SecRule ARGS "@rx c" "id:2003,phase:2,block"`+"\n")
	other := t.TempDir()
	writeRule(t, filepath.Join(other, "rules.conf"), `SecRule ARGS "@rx d" "id:2004,phase:2,block"`+"\n")

	reg, err := BuildRegistry([]string{user, vendor, other})
	if err != nil {
		t.Fatalf("BuildRegistry: %v", err)
	}
	wantRegistryActions(t, reg, map[int]string{
		2001: "deny",
		2002: "deny",
		2003: "pass", // sibling pack
		2004: "pass", // neither the user file nor a_pack reaches another rule directory
	})
}

func TestBuildRegistry_SecDefaultActionSyntax(t *testing.T) {
	for _, tc := range []struct {
		name, setup, want string
	}{
		{"lower-case directive", `secdefaultaction "phase:2,log,deny,status:403"`, "deny"},
		{"tab and single quotes", "SecDefaultAction\t'phase:2,log,deny,status:403'", "deny"},
		{"unquoted", `SecDefaultAction phase:2,deny,status:403`, "deny"},
		{"continuation and named phase", "SecDefaultAction \\\n    \"phase:request,log,deny,status:403\"", "deny"},
		{"spaces and upper-case actions", `SecDefaultAction "PHASE: 2 , LOG , DENY , status:403"`, "deny"},
		{"quoted phase value", `SecDefaultAction "phase:'2',deny"`, "deny"},
		{"leading whitespace", `    SecDefaultAction "phase:2,deny"`, "deny"},
		{"no phase is phase 2", `SecDefaultAction "deny,status:403"`, "deny"},
		{"later directive wins", "SecDefaultAction \"phase:2,deny\"\nSecDefaultAction \"phase:2,pass\"", "pass"},
		{"commented out", `# SecDefaultAction "phase:2,deny,status:403"`, "pass"},
		{"no disruptive action", `SecDefaultAction "phase:2,log,auditlog"`, "pass"},
		{"block is not a default", `SecDefaultAction "phase:2,block"`, "pass"},
		{"other directive", `SecDefaultActionX "phase:2,deny"`, "pass"},
		{"other phase only", `SecDefaultAction "phase:1,deny"`, "pass"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeRule(t, filepath.Join(root, "setup.conf"), tc.setup+"\n")
			writeRule(t, filepath.Join(root, "rules.conf"), `SecRule ARGS "@rx x" "id:4001,phase:2,block,log"`+"\n")
			reg, err := BuildRegistry([]string{root})
			if err != nil {
				t.Fatalf("BuildRegistry: %v", err)
			}
			wantRegistryActions(t, reg, map[int]string{4001: tc.want})
		})
	}
}
