package modsec

import (
	"os"
	"path/filepath"
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

// TestBuildRegistry_BrokenSymlinkSkipped exercises the per-file I/O-error
// swallow path: a .conf symlink whose target does not exist makes
// ParseRulesFileAll return an open() error. BuildRegistry must keep going
// and still load every rule from the surviving good file in the same
// directory, with no fatal error returned to the caller.
func TestBuildRegistry_BrokenSymlinkSkipped(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "good.conf"), []byte(testRegistryCRSConf), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "does-not-exist"), filepath.Join(dir, "broken.conf")); err != nil {
		t.Fatal(err)
	}

	reg, err := BuildRegistry([]string{dir})
	if err != nil {
		t.Errorf("broken symlink should not surface a fatal error: %v", err)
	}
	if action, known := reg.Action(949110); !known || action != "deny" {
		t.Errorf("rule 949110 from good.conf lost: known=%v action=%q", known, action)
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
