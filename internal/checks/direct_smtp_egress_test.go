package checks

import (
	"net"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/metrics"
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

func TestEvaluateDirectSMTPEgressDoesNotTrustMTAProcessNameUnderHostedUser(t *testing.T) {
	cfg := sampleDirectSMTPCfg()
	in := DirectSMTPEgressInput{
		UID: 1001, User: "alice", PID: 4242, Comm: "smtpd",
		DstIP: net.ParseIP("203.0.113.10").To4(), DstPort: 587, MTA: sampleMTA(),
	}
	if _, ok := EvaluateDirectSMTPEgress(cfg, in); !ok {
		t.Errorf("MTA-looking process basename must not suppress a hosted UID finding")
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

func TestEvaluateDirectSMTPEgressSetsTenantIDFromUser(t *testing.T) {
	cfg := sampleDirectSMTPCfg()
	in := DirectSMTPEgressInput{
		UID: 1001, User: "alice", PID: 4242, Comm: "ncat",
		DstIP: net.ParseIP("203.0.113.10").To4(), DstPort: 587, MTA: sampleMTA(),
	}
	f, ok := EvaluateDirectSMTPEgress(cfg, in)
	if !ok {
		t.Fatal("expected finding")
	}
	if f.TenantID != "alice" {
		t.Errorf("TenantID: want alice, got %q", f.TenantID)
	}
}

func TestEvaluateDirectSMTPEgressUsesProcessAccountForTenantID(t *testing.T) {
	cfg := sampleDirectSMTPCfg()
	in := DirectSMTPEgressInput{
		UID: 1001, User: "php-fpm", PID: 4242, Comm: "ncat",
		DstIP: net.ParseIP("203.0.113.10").To4(), DstPort: 587,
		MTA:     sampleMTA(),
		Process: &processctx.ProcessContext{Account: "alice"},
	}
	f, ok := EvaluateDirectSMTPEgress(cfg, in)
	if !ok {
		t.Fatal("expected finding")
	}
	if f.TenantID != "alice" {
		t.Errorf("TenantID: want process account alice, got %q", f.TenantID)
	}
}

func TestEvaluateDirectSMTPEgressBackendNoneDisables(t *testing.T) {
	cfg := sampleDirectSMTPCfg()
	cfg.Detection.DirectSMTPEgress.Backend = "none"
	in := DirectSMTPEgressInput{
		UID: 1001, User: "alice", PID: 4242, Comm: "ncat",
		DstIP: net.ParseIP("203.0.113.10").To4(), DstPort: 587, MTA: sampleMTA(),
	}
	if _, ok := EvaluateDirectSMTPEgress(cfg, in); ok {
		t.Fatal("backend=none must disable the direct SMTP detector")
	}
}

func TestDirectSMTPEgressBackendEnabledHonorsSpecificBackends(t *testing.T) {
	cfg := sampleDirectSMTPCfg()
	cfg.Detection.DirectSMTPEgress.Backend = "bpf"
	if !DirectSMTPEgressBackendEnabled(cfg, "bpf") {
		t.Fatal("backend=bpf should allow BPF")
	}
	if DirectSMTPEgressBackendEnabled(cfg, "legacy") {
		t.Fatal("backend=bpf must not allow legacy")
	}
	cfg.Detection.DirectSMTPEgress.Backend = "legacy"
	if !DirectSMTPEgressBackendEnabled(cfg, "legacy") {
		t.Fatal("backend=legacy should allow legacy")
	}
	if DirectSMTPEgressBackendEnabled(cfg, "bpf") {
		t.Fatal("backend=legacy must not allow BPF")
	}
}

func TestEvaluateDirectSMTPEgressPortListDoesNotWrap(t *testing.T) {
	cfg := sampleDirectSMTPCfg()
	cfg.Detection.DirectSMTPEgress.Ports = []int{65561}
	in := DirectSMTPEgressInput{
		UID: 1001, User: "alice", PID: 4242, Comm: "ncat",
		DstIP: net.ParseIP("203.0.113.10").To4(), DstPort: 25, MTA: sampleMTA(),
	}
	if _, ok := EvaluateDirectSMTPEgress(cfg, in); ok {
		t.Fatal("invalid configured port 65561 must not wrap to 25")
	}
}

func TestScanProcNetTCPDirectSMTPEgressHonorsLegacyBackend(t *testing.T) {
	withMockPasswd(t, "alice:x:1000:1000::/home/alice:/bin/bash\n")
	cfg := sampleDirectSMTPCfg()
	cfg.Detection.DirectSMTPEgress.Backend = "legacy"
	tcpData := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
		"   0: 0100007F:D6D8 0A7100CB:024B 01 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000 100 0 0 10 0\n"

	findings := scanProcNetTCP(cfg, []byte(tcpData), false)

	if len(findings) != 1 {
		t.Fatalf("findings len = %d, want 1: %+v", len(findings), findings)
	}
	if findings[0].Check != "direct_smtp_egress" {
		t.Fatalf("Check = %q, want direct_smtp_egress", findings[0].Check)
	}
}

func TestScanProcNetTCPDirectSMTPEgressSkipsWhenBackendBPF(t *testing.T) {
	withMockPasswd(t, "alice:x:1000:1000::/home/alice:/bin/bash\n")
	cfg := sampleDirectSMTPCfg()
	cfg.Detection.DirectSMTPEgress.Backend = "bpf"
	tcpData := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
		"   0: 0100007F:D6D8 0A7100CB:024B 01 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000 100 0 0 10 0\n"

	findings := scanProcNetTCP(cfg, []byte(tcpData), false)

	if len(findings) != 0 {
		t.Fatalf("backend=bpf must suppress legacy direct SMTP findings, got %+v", findings)
	}
}

func TestRegisterDirectSMTPEgressMetricsExposesName(t *testing.T) {
	resetDirectSMTPEgressMetricsForTest()
	reg := metrics.NewRegistry()
	RegisterDirectSMTPEgressMetrics(reg)

	var sb strings.Builder
	if err := reg.WriteOpenMetrics(&sb); err != nil {
		t.Fatalf("WriteOpenMetrics: %v", err)
	}
	if !strings.Contains(sb.String(), "csm_direct_smtp_egress_findings_total") {
		t.Errorf("expected csm_direct_smtp_egress_findings_total in output:\n%s", sb.String())
	}
}

func TestDirectSMTPEgressFindingsTotalBumps(t *testing.T) {
	resetDirectSMTPEgressMetricsForTest()
	reg := metrics.NewRegistry()
	RegisterDirectSMTPEgressMetrics(reg)
	BumpDirectSMTPEgressFindings()
	BumpDirectSMTPEgressFindings()

	var sb strings.Builder
	if err := reg.WriteOpenMetrics(&sb); err != nil {
		t.Fatalf("WriteOpenMetrics: %v", err)
	}
	out := sb.String()
	if !strings.Contains(out, "csm_direct_smtp_egress_findings_total 2") {
		t.Errorf("expected counter at 2:\n%s", out)
	}
}
