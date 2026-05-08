package checks

import (
	"net"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/platform"
	"github.com/pidginhost/csm/internal/processctx"
)

func sampleDirectSMTPCfg() *config.Config {
	cfg := &config.Config{}
	cfg.Detection.DirectSMTPEgress.Enabled = true
	cfg.Detection.DirectSMTPEgress.Ports = []int{25, 465, 587}
	return cfg
}

func sampleMTA() platform.MTAIdents {
	return platform.LocalMTAIdentities(platform.Info{OS: platform.OSUbuntu})
}

func TestEvaluateDirectSMTPEgressFiresForHostedAccountToPort587(t *testing.T) {
	cfg := sampleDirectSMTPCfg()
	in := DirectSMTPEgressInput{
		UID: 1001, User: "alice", PID: 4242, Comm: "ncat", Exe: "/usr/bin/ncat",
		DstIP: net.ParseIP("203.0.113.10").To4(), DstPort: 587, MTA: sampleMTA(),
	}
	f, ok := EvaluateDirectSMTPEgress(cfg, in)
	if !ok {
		t.Fatal("expected finding")
	}
	if f.Check != "direct_smtp_egress" {
		t.Errorf("Check: %q", f.Check)
	}
	if f.Severity != alert.High {
		t.Errorf("Severity: want High, got %v", f.Severity)
	}
}

func TestEvaluateDirectSMTPEgressSkipsRoot(t *testing.T) {
	cfg := sampleDirectSMTPCfg()
	in := DirectSMTPEgressInput{
		UID: 0, Comm: "anything",
		DstIP: net.ParseIP("203.0.113.10").To4(), DstPort: 587, MTA: sampleMTA(),
	}
	if _, ok := EvaluateDirectSMTPEgress(cfg, in); ok {
		t.Errorf("root must be skipped")
	}
}

func TestEvaluateDirectSMTPEgressSkipsLoopback(t *testing.T) {
	cfg := sampleDirectSMTPCfg()
	in := DirectSMTPEgressInput{
		UID: 1001, User: "alice", PID: 4242, Comm: "ncat",
		DstIP: net.ParseIP("127.0.0.1"), DstPort: 587, MTA: sampleMTA(),
	}
	if _, ok := EvaluateDirectSMTPEgress(cfg, in); ok {
		t.Errorf("loopback must be skipped")
	}
}

func TestEvaluateDirectSMTPEgressSkipsInfraIPs(t *testing.T) {
	cfg := sampleDirectSMTPCfg()
	cfg.InfraIPs = []string{"203.0.113.10"}
	in := DirectSMTPEgressInput{
		UID: 1001, User: "alice", PID: 4242, Comm: "ncat",
		DstIP: net.ParseIP("203.0.113.10").To4(), DstPort: 587, MTA: sampleMTA(),
	}
	if _, ok := EvaluateDirectSMTPEgress(cfg, in); ok {
		t.Errorf("infra IP must be skipped")
	}
}

func TestEvaluateDirectSMTPEgressSkipsKnownMTAUser(t *testing.T) {
	cfg := sampleDirectSMTPCfg()
	in := DirectSMTPEgressInput{
		UID: 89, User: "postfix", PID: 4242, Comm: "smtpd",
		DstIP: net.ParseIP("203.0.113.10").To4(), DstPort: 587, MTA: sampleMTA(),
	}
	if _, ok := EvaluateDirectSMTPEgress(cfg, in); ok {
		t.Errorf("postfix user must be skipped")
	}
}

func TestEvaluateDirectSMTPEgressSkipsKnownMTAProcess(t *testing.T) {
	cfg := sampleDirectSMTPCfg()
	in := DirectSMTPEgressInput{
		UID: 1001, User: "alice", PID: 4242, Comm: "smtpd",
		DstIP: net.ParseIP("203.0.113.10").To4(), DstPort: 587, MTA: sampleMTA(),
	}
	if _, ok := EvaluateDirectSMTPEgress(cfg, in); ok {
		t.Errorf("smtpd process basename must be skipped even under hosted UID")
	}
}

func TestEvaluateDirectSMTPEgressSkipsNonSMTPPort(t *testing.T) {
	cfg := sampleDirectSMTPCfg()
	in := DirectSMTPEgressInput{
		UID: 1001, User: "alice", PID: 4242, Comm: "ncat",
		DstIP: net.ParseIP("203.0.113.10").To4(), DstPort: 80, MTA: sampleMTA(),
	}
	if _, ok := EvaluateDirectSMTPEgress(cfg, in); ok {
		t.Errorf("port 80 must not fire direct_smtp_egress")
	}
}

func TestEvaluateDirectSMTPEgressDisabledReturnsFalse(t *testing.T) {
	cfg := sampleDirectSMTPCfg()
	cfg.Detection.DirectSMTPEgress.Enabled = false
	in := DirectSMTPEgressInput{
		UID: 1001, User: "alice", PID: 4242, Comm: "ncat",
		DstIP: net.ParseIP("203.0.113.10").To4(), DstPort: 587, MTA: sampleMTA(),
	}
	if _, ok := EvaluateDirectSMTPEgress(cfg, in); ok {
		t.Errorf("disabled detector must not fire")
	}
}

func TestEvaluateDirectSMTPEgressIncludesProcessContextWhenSupplied(t *testing.T) {
	cfg := sampleDirectSMTPCfg()
	pc := &processctx.ProcessContext{
		PID: 4242, UID: 1001, Comm: "ncat", Exe: "/usr/bin/ncat", Account: "alice",
	}
	in := DirectSMTPEgressInput{
		UID: 1001, User: "alice", PID: 4242, Comm: "ncat",
		DstIP: net.ParseIP("203.0.113.10").To4(), DstPort: 587,
		MTA: sampleMTA(), Process: pc,
	}
	f, ok := EvaluateDirectSMTPEgress(cfg, in)
	if !ok {
		t.Fatal("expected finding")
	}
	if f.Process == nil || f.Process.Account != "alice" {
		t.Errorf("Process context must propagate; got %+v", f.Process)
	}
}

func TestEvaluateDirectSMTPEgressLegacyShapeNoCommNoExe(t *testing.T) {
	cfg := sampleDirectSMTPCfg()
	in := DirectSMTPEgressInput{
		UID: 1001, User: "alice", PID: 0, Comm: "", Exe: "",
		DstIP: net.ParseIP("203.0.113.10").To4(), DstPort: 587, MTA: sampleMTA(),
	}
	f, ok := EvaluateDirectSMTPEgress(cfg, in)
	if !ok {
		t.Fatalf("legacy-shape input must still fire (UID + dest port enough)")
	}
	if f.Check != "direct_smtp_egress" {
		t.Errorf("Check: %q", f.Check)
	}
}

func TestEvaluateDirectSMTPEgressLegacyShapeStillSkipsMTAUser(t *testing.T) {
	cfg := sampleDirectSMTPCfg()
	in := DirectSMTPEgressInput{
		UID: 89, User: "postfix", PID: 0, Comm: "", Exe: "",
		DstIP: net.ParseIP("203.0.113.10").To4(), DstPort: 587, MTA: sampleMTA(),
	}
	if _, ok := EvaluateDirectSMTPEgress(cfg, in); ok {
		t.Errorf("postfix UID/user must be skipped even with empty Comm/Exe")
	}
}
