package daemon

import (
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"testing"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/platform"
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
	cfg.AutoResponse.DryRun = &dr
	cfg.BPFEnforcement.DryRun = &dr
	cfg.Detection.DirectSMTPEgress.Enabled = true
	cfg.Detection.DirectSMTPEgress.DryRun = &dr
	cfg.Detection.DirectSMTPEgress.Ports = []int{587}
	p := BuildBPFEnforcementPolicy(cfg)
	if p.DryRun != 0 {
		t.Errorf("DryRun: want 0, got %d", p.DryRun)
	}
}

func TestBuildPolicyGlobalDryRunForcesDryRun(t *testing.T) {
	cfg := &config.Config{}
	cfg.BPFEnforcement.Enabled = true
	cfg.BPFEnforcement.DirectSMTPEgress = true
	falseValue := false
	trueValue := true
	cfg.AutoResponse.DryRun = &trueValue
	cfg.BPFEnforcement.DryRun = &falseValue
	cfg.Detection.DirectSMTPEgress.Enabled = true
	cfg.Detection.DirectSMTPEgress.DryRun = &falseValue
	cfg.Detection.DirectSMTPEgress.Ports = []int{587}
	p := BuildBPFEnforcementPolicy(cfg)
	if p.DryRun != 1 {
		t.Errorf("global dry_run must keep BPF policy in dry-run; got %d", p.DryRun)
	}
}

func TestBuildPolicyDetectorDryRunForcesDryRun(t *testing.T) {
	cfg := &config.Config{}
	cfg.BPFEnforcement.Enabled = true
	cfg.BPFEnforcement.DirectSMTPEgress = true
	falseValue := false
	trueValue := true
	cfg.AutoResponse.DryRun = &falseValue
	cfg.BPFEnforcement.DryRun = &falseValue
	cfg.Detection.DirectSMTPEgress.Enabled = true
	cfg.Detection.DirectSMTPEgress.DryRun = &trueValue
	cfg.Detection.DirectSMTPEgress.Ports = []int{587}
	p := BuildBPFEnforcementPolicy(cfg)
	if p.DryRun != 1 {
		t.Errorf("direct SMTP dry_run must keep BPF policy in dry-run; got %d", p.DryRun)
	}
}

func TestBuildPolicyDisabledWhenDirectSMTPBackendLegacy(t *testing.T) {
	cfg := &config.Config{}
	cfg.BPFEnforcement.Enabled = true
	cfg.BPFEnforcement.DirectSMTPEgress = true
	cfg.Detection.DirectSMTPEgress.Enabled = true
	cfg.Detection.DirectSMTPEgress.Backend = "legacy"
	cfg.Detection.DirectSMTPEgress.Ports = []int{587}
	p := BuildBPFEnforcementPolicy(cfg)
	if p.Enforce != 0 {
		t.Errorf("legacy direct SMTP backend must not produce BPF enforcement policy: %+v", p)
	}
}

func TestBuildPolicyDisabledWhenConnectionTrackerLegacy(t *testing.T) {
	cfg := &config.Config{}
	cfg.Detection.ConnectionTrackerBackend = "legacy"
	cfg.BPFEnforcement.Enabled = true
	cfg.BPFEnforcement.DirectSMTPEgress = true
	cfg.Detection.DirectSMTPEgress.Enabled = true
	cfg.Detection.DirectSMTPEgress.Ports = []int{587}
	p := BuildBPFEnforcementPolicy(cfg)
	if p.Enforce != 0 {
		t.Errorf("legacy connection tracker must not produce BPF enforcement policy: %+v", p)
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
	uids, err := safeUIDsFromPasswd("testdata/passwd_simple", nil)
	if err != nil {
		t.Fatalf("read passwd fixture: %v", err)
	}
	if !uids[0] {
		t.Errorf("root (UID 0) must be in safe_uids")
	}
}

func TestSafeUIDsFromPasswdSkipsHostedAccounts(t *testing.T) {
	uids, err := safeUIDsFromPasswd("testdata/passwd_simple", nil)
	if err != nil {
		t.Fatalf("read passwd fixture: %v", err)
	}
	if uids[1001] {
		t.Errorf("hosted UID 1001 must NOT be in safe_uids (only system + MTA)")
	}
}

func TestSafeUIDsFromPasswdIncludesPostfix(t *testing.T) {
	uids, err := safeUIDsFromPasswd("testdata/passwd_simple", nil)
	if err != nil {
		t.Fatalf("read passwd fixture: %v", err)
	}
	postfixUID := uint32(89)
	if !uids[postfixUID] {
		t.Errorf("postfix UID 89 must be in safe_uids; got %v", uids)
	}
}

func TestSafeUIDsFromPasswdStalwartIdentity(t *testing.T) {
	for _, panel := range []platform.Panel{platform.PanelNone, platform.PanelPlesk, platform.PanelDA, platform.PanelCPanel} {
		for _, user := range []string{"stalwart", "stalwart-mail"} {
			for _, uid := range []uint32{999, 1000, 1001} {
				t.Run(fmt.Sprintf("%s/%s/%d", panel, user, uid), func(t *testing.T) {
					platform.ResetForTest()
					t.Cleanup(platform.ResetForTest)
					if !platform.SetOverrides(platform.Overrides{Panel: &panel}) {
						t.Fatal("set platform override")
					}
					path := filepath.Join(t.TempDir(), "passwd")
					passwd := "root:x:0:0::/root:/bin/sh\n" +
						"postfix:x:2000:2000::/var/spool/postfix:/usr/sbin/nologin\n" +
						"alice:x:2001:2001::/home/alice:/bin/sh\n" +
						fmt.Sprintf("%s:x:%d:%d::/var/lib/stalwart:/usr/sbin/nologin\n", user, uid, uid)
					if err := os.WriteFile(path, []byte(passwd), 0o600); err != nil {
						t.Fatal(err)
					}
					got, err := safeUIDsFromPasswd(path, nil)
					if err != nil {
						t.Fatal(err)
					}
					want := map[uint32]bool{0: true, 2000: true}
					if uid < 1000 {
						want[uid] = true
					}
					if !maps.Equal(got, want) {
						t.Fatalf("safe UIDs = %v, want %v", got, want)
					}
				})
			}
		}
	}
}

func TestSafeUIDsFromPasswdIncludesSMTPAllowUsers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "passwd")
	passwd := "root:x:0:0::/root:/bin/sh\n" +
		"relay:x:1005:1005::/home/relay:/bin/sh\n" +
		"relayx:x:1006:1006::/home/relayx:/bin/sh\n" +
		"Relay:x:1007:1007::/home/Relay:/bin/sh\n" +
		"alice:x:1008:1008::/home/alice:/bin/sh\n"
	if err := os.WriteFile(path, []byte(passwd), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{Firewall: &firewall.FirewallConfig{SMTPAllowUsers: []string{"relay", ""}}}
	got, err := safeUIDsFromPasswd(path, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if want := map[uint32]bool{0: true, 1005: true}; !maps.Equal(got, want) {
		t.Fatalf("safe UIDs = %v, want %v", got, want)
	}
	for _, c := range []*config.Config{nil, {}} {
		got, err := safeUIDsFromPasswd(path, c)
		if err != nil {
			t.Fatal(err)
		}
		if want := map[uint32]bool{0: true}; !maps.Equal(got, want) {
			t.Fatalf("without an allow list, safe UIDs = %v, want %v", got, want)
		}
	}
}
