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
