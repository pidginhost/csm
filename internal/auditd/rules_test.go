package auditd

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestRulesConstNotEmpty(t *testing.T) {
	if rules == "" {
		t.Fatal("rules constant is empty")
	}
}

func TestRulesContainsShadowWatch(t *testing.T) {
	if !strings.Contains(rules, "/etc/shadow") {
		t.Error("rules should watch /etc/shadow")
	}
}

func TestRulesContainsCronWatch(t *testing.T) {
	if !strings.Contains(rules, "/var/spool/cron") {
		t.Error("rules should watch /var/spool/cron")
	}
}

func TestRulesContainsTmpExecWatch(t *testing.T) {
	if !strings.Contains(rules, "csm_exec_tmp") {
		t.Error("rules should monitor /tmp execution")
	}
}

func TestRulesPathIsAuditDir(t *testing.T) {
	if !strings.HasPrefix(rulesPath, "/etc/audit/") {
		t.Errorf("rulesPath = %q, expected /etc/audit/ prefix", rulesPath)
	}
}

func TestDeployWritesRulesAndReloads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "csm.rules")
	var command []string
	err := deployRules(path, func(name string, args ...string) error {
		command = append([]string{name}, args...)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != rules {
		t.Fatal("deployed audit rules differ from the embedded rules")
	}
	if !slices.Equal(command, []string{"augenrules", "--load"}) {
		t.Fatalf("reload command = %v, want [augenrules --load]", command)
	}
}

func TestRemoveMissingRulesSucceedsWithoutAugenrules(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.rules")
	runCalled := false
	err := removeRules(path, func(string) (string, error) {
		return "", exec.ErrNotFound
	}, func(string, ...string) error {
		runCalled = true
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if runCalled {
		t.Fatal("reload command ran even though augenrules was absent")
	}
}

func TestRemoveReportsReloadFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "csm.rules")
	if err := os.WriteFile(path, []byte(rules), 0o640); err != nil {
		t.Fatal(err)
	}
	want := errors.New("reload failed")
	err := removeRules(path, func(string) (string, error) {
		return "/usr/sbin/augenrules", nil
	}, func(name string, args ...string) error {
		if name != "/usr/sbin/augenrules" || !slices.Equal(args, []string{"--load"}) {
			t.Fatalf("reload command = %s %v", name, args)
		}
		return want
	})
	if !errors.Is(err, want) {
		t.Fatalf("remove error = %v, want reload failure", err)
	}
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Fatalf("rules file remains after removal: %v", statErr)
	}
}

func TestRulesContainsAFAlgSocketWatch(t *testing.T) {
	if !strings.Contains(rules, "-S socket") {
		t.Error("rules should watch the socket() syscall by name; a regression to a different -S would silently disable detection")
	}
	if !strings.Contains(rules, "csm_af_alg_socket") {
		t.Error("rules should watch AF_ALG socket creation (CVE-2026-31431)")
	}
	if !strings.Contains(rules, "a0=38") {
		t.Error("rules should filter on a0=38 (AF_ALG family number)")
	}
	if !strings.Contains(rules, "uid>=1000") {
		t.Error("rules should filter on uid>=1000 so service-launched account workloads are covered")
	}
	if strings.Contains(rules, "auid>=") {
		t.Error("rules should not filter on auid; daemon-launched PHP/cPanel workloads often have unset auid")
	}
	// AF_ALG explicitly does not support socketpair() — the kernel returns
	// ESOCKTNOSUPPORT. Adding a socketpair rule would just produce noise
	// from probing tools without ever firing on the actual exploit, so the
	// rule set should NOT include one.
	if strings.Contains(rules, "-S socketpair") {
		t.Error("rules should not waste an audit slot on socketpair (AF_ALG does not support it)")
	}
}

func TestAFAlgSocketWatchCoversBothArches(t *testing.T) {
	if !strings.Contains(rules, "-F arch=b64 -S socket -F a0=38 -F uid>=1000 -k csm_af_alg_socket") {
		t.Error("rules should include the b64 AF_ALG socket watch line verbatim")
	}
	if !strings.Contains(rules, "-F arch=b32 -S socket -F a0=38 -F uid>=1000 -k csm_af_alg_socket") {
		t.Error("rules should include the b32 AF_ALG socket watch line verbatim — guards against 32-bit ABI exploit evasion")
	}
}
