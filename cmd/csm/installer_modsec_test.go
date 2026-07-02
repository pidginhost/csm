package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// modsec2.user.conf is shared with operator-maintained rules, so the
// installer must confine itself to CSM's marker-delimited section. The
// marker lines are an on-disk contract with already-deployed files and
// with internal/checks, so they are spelled out literally here.
const (
	installTestBegin = "# BEGIN CSM Custom ModSecurity Rules (managed by CSM - do not edit inside this block)"
	installTestEnd   = "# END CSM Custom ModSecurity Rules"

	installTestSrcV1 = "# CSM Custom ModSecurity Rules\n" +
		"SecRule REQUEST_URI \"/xmlrpc\\.php$\" \"id:900100,phase:1,deny\"\n"
	installTestSrcV2 = "# CSM Custom ModSecurity Rules\n" +
		"SecRule REQUEST_URI \"/wp-json/wp/v2/users\" \"id:900200,phase:1,deny\"\n"
	installTestOperator = "# Host-scoped CWAF exclusion, operator-maintained\n" +
		"SecRule REQUEST_HEADERS:Host \"@streq shop.example.com\" " +
		"\"id:100001,phase:1,pass,ctl:ruleRemoveById=214930\"\n"
)

// setupModSecDeploy points the installer's modsec source and destination
// paths at a temp tree, mirroring how other installer tests override
// package-level paths (phpShieldEventDir et al).
func setupModSecDeploy(t *testing.T, srcContent string, destContent *string) (destPath string) {
	t.Helper()
	root := t.TempDir()

	src := filepath.Join(root, "configs", "csm_modsec_custom.conf")
	if err := os.MkdirAll(filepath.Dir(src), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(src, []byte(srcContent), 0o644); err != nil {
		t.Fatal(err)
	}

	destDir := filepath.Join(root, "modsec")
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		t.Fatal(err)
	}
	destPath = filepath.Join(destDir, "modsec2.user.conf")
	if destContent != nil {
		if err := os.WriteFile(destPath, []byte(*destContent), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	oldSrc, oldDests := modsecRulesSrcPath, modsecUserConfDests
	modsecRulesSrcPath = src
	modsecUserConfDests = []string{destPath}
	t.Cleanup(func() {
		modsecRulesSrcPath, modsecUserConfDests = oldSrc, oldDests
	})
	return destPath
}

// Re-running the installer over a file holding operator rules plus a legacy
// CSM block (old header, no END marker) must keep the operator rules and
// upgrade the CSM block in place -- the historical behavior overwrote the
// whole file.
func TestDeployModSecRulesPreservesOperatorRules(t *testing.T) {
	existing := installTestOperator + "\n\n" + installTestSrcV1
	dest := setupModSecDeploy(t, installTestSrcV2, &existing)

	(&Installer{}).DeployModSecRules()

	data, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	got := string(data)
	if !strings.HasPrefix(got, installTestOperator) {
		t.Fatalf("operator rules wiped; file now:\n%s", got)
	}
	if !strings.Contains(got, installTestBegin) || !strings.Contains(got, installTestEnd) {
		t.Errorf("missing section delimiters; file now:\n%s", got)
	}
	if !strings.Contains(got, "id:900200") {
		t.Errorf("new CSM rules not deployed; file now:\n%s", got)
	}
	if strings.Contains(got, "id:900100") {
		t.Errorf("legacy CSM rules not removed; file now:\n%s", got)
	}
	if !strings.Contains(got, "modsec2.csm-overrides.conf") {
		t.Errorf("overrides Include not ensured; file now:\n%s", got)
	}
}

// A second install run over an already-current file must not rewrite it:
// content and mtime stay untouched.
func TestDeployModSecRulesUpToDateDoesNotRewrite(t *testing.T) {
	dest := setupModSecDeploy(t, installTestSrcV2, nil)

	inst := &Installer{}
	inst.DeployModSecRules()

	before, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	past := time.Now().Add(-time.Hour)
	if err = os.Chtimes(dest, past, past); err != nil {
		t.Fatal(err)
	}

	inst.DeployModSecRules()

	after, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Errorf("file changed on up-to-date run:\n%s", after)
	}
	info, err := os.Stat(dest)
	if err != nil {
		t.Fatal(err)
	}
	if !info.ModTime().Equal(past) {
		t.Errorf("file rewritten on up-to-date run: mtime %v, want %v", info.ModTime(), past)
	}
}
