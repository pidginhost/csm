package daemon

import (
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

func TestBuildPolicyDisabledWhenEnforcementOff(t *testing.T) {
	cfg := &config.Config{}
	p := BuildBPFEnforcementPolicy(cfg)
	if p.Enforce != 0 {
		t.Errorf("Enforce: want 0, got %d", p.Enforce)
	}
}

func TestBuildPolicyHonorsDryRunDefaultTrue(t *testing.T) {
	cfg := &config.Config{}
	cfg.BPFEnforcement.Enabled = true
	cfg.BPFEnforcement.DirectSMTPEgress = true
	cfg.Detection.DirectSMTPEgress.Enabled = true
	cfg.Detection.DirectSMTPEgress.Ports = []int{25, 587}
	p := BuildBPFEnforcementPolicy(cfg)
	if p.Enforce != 1 {
		t.Errorf("Enforce: want 1, got %d", p.Enforce)
	}
	if p.DryRun != 1 {
		t.Errorf("DryRun should default to 1 (safety) when omitted; got %d", p.DryRun)
	}
}

func TestBuildPolicyDryRunFalseFlipsToZero(t *testing.T) {
	cfg := &config.Config{}
	cfg.BPFEnforcement.Enabled = true
	cfg.BPFEnforcement.DirectSMTPEgress = true
	dr := false
	cfg.BPFEnforcement.DryRun = &dr
	cfg.Detection.DirectSMTPEgress.Enabled = true
	cfg.Detection.DirectSMTPEgress.Ports = []int{587}
	p := BuildBPFEnforcementPolicy(cfg)
	if p.DryRun != 0 {
		t.Errorf("DryRun: want 0, got %d", p.DryRun)
	}
}

func TestBuildPolicyPortsCollectedFromDetectorWhenSMTPGate(t *testing.T) {
	cfg := &config.Config{}
	cfg.BPFEnforcement.Enabled = true
	cfg.BPFEnforcement.DirectSMTPEgress = true
	cfg.Detection.DirectSMTPEgress.Enabled = true
	cfg.Detection.DirectSMTPEgress.Ports = []int{25, 465, 587}
	p := BuildBPFEnforcementPolicy(cfg)
	if got, want := len(p.Ports), 3; got != want {
		t.Fatalf("Ports len: want %d, got %d (%v)", want, got, p.Ports)
	}
	for _, want := range []uint16{25, 465, 587} {
		found := false
		for _, q := range p.Ports {
			if q == want {
				found = true
			}
		}
		if !found {
			t.Errorf("port %d missing", want)
		}
	}
}

func TestSafeUIDsFromPasswdParsesRoot(t *testing.T) {
	uids, err := safeUIDsFromPasswd("testdata/passwd_simple")
	if err != nil {
		t.Skipf("fixture not available: %v", err)
	}
	if !uids[0] {
		t.Errorf("root (UID 0) must be in safe_uids")
	}
}

func TestSafeUIDsFromPasswdSkipsHostedAccounts(t *testing.T) {
	uids, err := safeUIDsFromPasswd("testdata/passwd_simple")
	if err != nil {
		t.Skipf("fixture not available: %v", err)
	}
	if uids[1001] {
		t.Errorf("hosted UID 1001 must NOT be in safe_uids (only system + MTA)")
	}
}

func TestSafeUIDsFromPasswdIncludesPostfix(t *testing.T) {
	uids, err := safeUIDsFromPasswd("testdata/passwd_simple")
	if err != nil {
		t.Skipf("fixture not available: %v", err)
	}
	postfixUID := uint32(89)
	if !uids[postfixUID] {
		t.Errorf("postfix UID 89 must be in safe_uids; got %v", uids)
	}
}
