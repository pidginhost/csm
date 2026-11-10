package auditd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// auditctl rejects a watch whose parent directory is missing and stops
// there, so one cPanel-only path left every later rule unloaded on hosts
// without cPanel.

func TestRenderRulesDropsOnlyWatchesUnderMissingDirectories(t *testing.T) {
	got := renderRules(func(dir string) bool { return dir != "/var/cpanel/authn" })
	if strings.Contains(got, "/var/cpanel/") {
		t.Fatal("watch under a missing directory was kept")
	}
	want := strings.Replace(rules, "-w /var/cpanel/authn/api_tokens_v2/ -p wa -k csm_whm_api_tokens\n", "", 1)
	if got != want {
		t.Fatalf("other rules changed:\n%s", got)
	}
}

func TestRenderRulesKeepsEveryRuleWhenDirectoriesExist(t *testing.T) {
	if got := renderRules(func(string) bool { return true }); got != rules {
		t.Fatalf("rules changed:\n%s", got)
	}
}

func TestRenderRulesKeepsSyscallRules(t *testing.T) {
	got := renderRules(func(string) bool { return false })
	if strings.Contains(got, "\n-w ") {
		t.Fatal("watch kept although no directory exists")
	}
	if !strings.Contains(got, "-k csm_exec_tmp") || !strings.Contains(got, "-k csm_af_alg_socket") {
		t.Fatal("syscall rules must not depend on directories")
	}
}

func TestPackagedRulesWatchNoCPanelPath(t *testing.T) {
	// The package also installs on hosts without cPanel; the daemon adds
	// cPanel watches where cPanel exists.
	body, err := os.ReadFile(filepath.Join("..", "..", "build", "packaging", "csm.audit.rules"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "/var/cpanel/") || strings.Contains(string(body), "/usr/local/cpanel/") {
		t.Fatal("packaged audit rules watch a cPanel-only path")
	}
}
