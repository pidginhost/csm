package auditd

import (
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

func TestDeployReturnsErrorOnDevMachine(t *testing.T) {
	// On non-Linux / dev machines, Deploy should fail because /etc/audit/ doesn't exist.
	// This test exercises the function entry without requiring root/auditd.
	err := Deploy()
	if err == nil {
		// If it somehow succeeded (running as root on Linux), clean up.
		Remove()
	}
	// Either way, the function didn't panic.
}

func TestRemoveDoesNotPanic(t *testing.T) {
	// Remove should not panic even when the file doesn't exist.
	Remove()
}

func TestRulesContainsAFAlgSocketWatch(t *testing.T) {
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
