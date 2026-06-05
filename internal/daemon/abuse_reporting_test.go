package daemon

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"log"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/reporting"
)

func TestClassSetParsesKnownSkipsUnknown(t *testing.T) {
	got := classSet([]string{"bruteforce", "php_relay", "not_a_class", "credential_stuffing"})
	if len(got) != 3 {
		t.Fatalf("classes = %v, want 3 known", got)
	}
	if !got[reporting.ClassBruteforce] || !got[reporting.ClassPHPRelay] || !got[reporting.ClassCredentialStuffing] {
		t.Fatalf("missing expected classes: %v", got)
	}
	if got[reporting.Class("not_a_class")] {
		t.Fatal("unknown class accepted")
	}
}

func TestAbuseReportQueueSizeTracksDefaultSpoolCapacity(t *testing.T) {
	if got := abuseReportQueueSize(abuseReportSpoolDefault); got != abuseReportSpoolDefault {
		t.Fatalf("queue size = %d, want %d", got, abuseReportSpoolDefault)
	}
	if got := abuseReportQueueSize(25); got != 25 {
		t.Fatalf("small queue size = %d, want 25", got)
	}
}

func TestBuildReportTargetsEd25519(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	t.Setenv("CSM_NODE_KEY", hex.EncodeToString(priv))
	got := buildReportTargets([]reportTargetConfig{{
		Name: "central", URL: "https://abuse.example/report", Transport: "ed25519",
		NodeID: "n1", KeyID: "k1", KeyEnv: "CSM_NODE_KEY",
	}})
	if len(got) != 1 {
		t.Fatalf("targets = %d, want 1", len(got))
	}
	if got[0].Transport != reporting.TransportEd25519 || len(got[0].Ed25519Key) != ed25519.PrivateKeySize {
		t.Fatalf("ed25519 target not built: %+v", got[0])
	}
}

func TestBuildReportTargetsHMACWithBearer(t *testing.T) {
	t.Setenv("CSM_REPORT_HMAC", "shared-secret")
	t.Setenv("CSM_REPORT_TOKEN", "bearer-tok")
	got := buildReportTargets([]reportTargetConfig{{
		Name: "priv", URL: "https://collector.internal/report", Transport: "hmac",
		NodeID: "n1", KeyID: "k1", KeyEnv: "CSM_REPORT_HMAC", TokenEnv: "CSM_REPORT_TOKEN",
	}})
	if len(got) != 1 {
		t.Fatalf("targets = %d, want 1", len(got))
	}
	if got[0].Transport != reporting.TransportHMAC || string(got[0].HMACSecret) != "shared-secret" || got[0].BearerToken != "bearer-tok" {
		t.Fatalf("hmac target not built: %+v", got[0])
	}
}

func TestBuildReportTargetsSkipsInvalid(t *testing.T) {
	t.Setenv("BAD_KEY", "not-hex")
	t.Setenv("EMPTY", "")
	t.Setenv("GOOD_HMAC", "shared-secret")
	cases := []reportTargetConfig{
		{Name: "", URL: "https://x/report", Transport: "ed25519", NodeID: "n1", KeyID: "k1", KeyEnv: "BAD_KEY"}, // missing name
		{Name: "insecure", URL: "http://collector.example/report", Transport: "hmac", NodeID: "n1", KeyID: "k1", KeyEnv: "GOOD_HMAC"},
		{Name: "badhex", URL: "https://x/report", Transport: "ed25519", NodeID: "n1", KeyID: "k1", KeyEnv: "BAD_KEY"},
		{Name: "emptyhmac", URL: "https://x/report", Transport: "hmac", NodeID: "n1", KeyID: "k1", KeyEnv: "EMPTY"},
		{Name: "unknowntransport", URL: "https://x/report", Transport: "rot13", NodeID: "n1", KeyID: "k1", KeyEnv: "EMPTY"},
		{Name: "nourl", URL: "", Transport: "hmac", NodeID: "n1", KeyID: "k1", KeyEnv: "EMPTY"},
	}
	if got := buildReportTargets(cases); len(got) != 0 {
		t.Fatalf("expected all invalid targets skipped, got %d: %+v", len(got), got)
	}
}

func TestBuildReportTargetsDoesNotLogKeyMaterial(t *testing.T) {
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })

	secret := "not-a-valid-private-key"
	t.Setenv("CSM_BAD_NODE_KEY", secret)
	_ = buildReportTargets([]reportTargetConfig{{
		Name: "central", URL: "https://abuse.example/report", Transport: "ed25519",
		NodeID: "n1", KeyID: "k1", KeyEnv: "CSM_BAD_NODE_KEY",
	}})
	if strings.Contains(buf.String(), secret) {
		t.Fatal("buildReportTargets logged key material")
	}
}

func TestStartAbuseReportingDisabledClearsStaleHook(t *testing.T) {
	prev := alert.ReportHook
	alert.SetReportHook(func(alert.Finding) {})
	t.Cleanup(func() { alert.SetReportHook(prev) })

	d := New(&config.Config{}, nil, nil, "")
	if loop := d.startAbuseReporting(); loop != nil {
		t.Fatal("disabled reporting returned a loop")
	}
	if alert.ReportHook != nil {
		t.Fatal("disabled reporting left stale hook installed")
	}
}

func TestStartAbuseReportingMisconfiguredClearsStaleHook(t *testing.T) {
	prev := alert.ReportHook
	alert.SetReportHook(func(alert.Finding) {})
	t.Cleanup(func() { alert.SetReportHook(prev) })

	cfg := &config.Config{}
	cfg.Reputation.Report.Enabled = true
	cfg.Reputation.Report.Classes = []string{"bruteforce"}
	d := New(cfg, nil, nil, "")
	if loop := d.startAbuseReporting(); loop != nil {
		t.Fatal("misconfigured reporting returned a loop")
	}
	if alert.ReportHook != nil {
		t.Fatal("misconfigured reporting left stale hook installed")
	}
}

func TestAbuseReportLoopClearsHookAndClosesSpoolOnStop(t *testing.T) {
	prev := alert.ReportHook
	t.Cleanup(func() { alert.SetReportHook(prev) })

	t.Setenv("CSM_REPORT_HMAC", "shared-secret")
	spoolPath := filepath.Join(t.TempDir(), "abuse.db")
	cfg := &config.Config{}
	cfg.Reputation.Report.Enabled = true
	cfg.Reputation.Report.Classes = []string{"bruteforce"}
	cfg.Reputation.Report.SpoolPath = spoolPath
	cfg.Reputation.Report.Targets = []reportTargetConfig{{
		Name: "priv", URL: "https://collector.example/report", Transport: "hmac",
		NodeID: "n1", KeyID: "k1", KeyEnv: "CSM_REPORT_HMAC",
	}}
	d := New(cfg, nil, nil, "")

	loop := d.startAbuseReporting()
	if loop == nil {
		t.Fatal("enabled reporting did not return a loop")
	}
	if alert.ReportHook == nil {
		t.Fatal("enabled reporting did not install hook")
	}

	done := make(chan struct{})
	go func() {
		loop()
		close(done)
	}()

	alert.ReportHook(alert.Finding{
		Check:     "pam_bruteforce",
		Severity:  alert.Critical,
		SourceIP:  "203.0.113.5",
		Timestamp: time.Now(),
	})
	d.stopAbuseReporting()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("abuse report loop did not stop")
	}
	if alert.ReportHook != nil {
		t.Fatal("abuse report loop left hook installed after stop")
	}

	spool, err := reporting.NewSpool(spoolPath, "reports", 10)
	if err != nil {
		t.Fatalf("spool did not close cleanly: %v", err)
	}
	defer func() { _ = spool.Close() }()
	if got := spool.Len(); got != 1 {
		t.Fatalf("spool queued reports = %d, want 1", got)
	}
}

func TestAbuseReportLoopAcceptsReportsAfterDaemonStop(t *testing.T) {
	prev := alert.ReportHook
	t.Cleanup(func() { alert.SetReportHook(prev) })

	t.Setenv("CSM_REPORT_HMAC", "shared-secret")
	spoolPath := filepath.Join(t.TempDir(), "abuse.db")
	cfg := &config.Config{}
	cfg.Reputation.Report.Enabled = true
	cfg.Reputation.Report.Classes = []string{"bruteforce"}
	cfg.Reputation.Report.SpoolPath = spoolPath
	cfg.Reputation.Report.Targets = []reportTargetConfig{{
		Name: "priv", URL: "https://collector.example/report", Transport: "hmac",
		NodeID: "n1", KeyID: "k1", KeyEnv: "CSM_REPORT_HMAC",
	}}
	d := New(cfg, nil, nil, "")

	loop := d.startAbuseReporting()
	if loop == nil {
		t.Fatal("enabled reporting did not return a loop")
	}

	done := make(chan struct{})
	go func() {
		loop()
		close(done)
	}()

	close(d.stopCh)
	if alert.ReportHook == nil {
		t.Fatal("daemon stop cleared report hook before final alert flush")
	}
	alert.ReportHook(alert.Finding{
		Check:     "pam_bruteforce",
		Severity:  alert.Critical,
		SourceIP:  "203.0.113.7",
		Timestamp: time.Now(),
	})
	d.stopAbuseReporting()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("abuse report loop did not stop")
	}

	spool, err := reporting.NewSpool(spoolPath, "reports", 10)
	if err != nil {
		t.Fatalf("spool did not close cleanly: %v", err)
	}
	defer func() { _ = spool.Close() }()
	if got := spool.Len(); got != 1 {
		t.Fatalf("spool queued reports = %d, want 1", got)
	}
}
