package checks

import (
	"net"
	"sync"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

func cfgWithBadASN(enabled bool, blocked, allowed []uint) *config.Config {
	cfg := &config.Config{}
	cfg.Detection.BadASNOutbound.Enabled = enabled
	cfg.Detection.BadASNOutbound.BlockedASNs = blocked
	cfg.Detection.BadASNOutbound.AllowedASNs = allowed
	return cfg
}

func TestBadASNOutbound_BlockedASNFlagged(t *testing.T) {
	cfg := cfgWithBadASN(true, []uint{64500}, nil)
	f, ok := EvaluateBadASNOutbound(cfg, net.ParseIP("203.0.113.9"), 64500, "Bulletproof LLC")
	if !ok {
		t.Fatal("expected finding for blocked ASN 64500")
	}
	if f.Check != "bad_asn_outbound" {
		t.Fatalf("check = %q", f.Check)
	}
	if f.SourceIP != "203.0.113.9" {
		t.Fatalf("SourceIP = %q, want destination IP", f.SourceIP)
	}
	if !f.Timestamp.IsZero() {
		t.Fatal("pure evaluator must not set Timestamp")
	}
}

func TestBadASNOutbound_UnlistedASNNotFlaggedWithoutAllowlist(t *testing.T) {
	cfg := cfgWithBadASN(true, []uint{64500}, nil)
	if _, ok := EvaluateBadASNOutbound(cfg, net.ParseIP("203.0.113.9"), 13335, "Cloudflare"); ok {
		t.Fatal("ASN not in blocklist must not be flagged when no allowlist is set")
	}
}

func TestBadASNOutbound_AllowlistModeFlagsOutsiders(t *testing.T) {
	cfg := cfgWithBadASN(true, nil, []uint{13335, 15169})
	if _, ok := EvaluateBadASNOutbound(cfg, net.ParseIP("203.0.113.9"), 64500, "Bulletproof"); !ok {
		t.Fatal("ASN outside allowlist must be flagged in allowlist mode")
	}
	if _, ok := EvaluateBadASNOutbound(cfg, net.ParseIP("203.0.113.9"), 13335, "Cloudflare"); ok {
		t.Fatal("ASN inside allowlist must not be flagged")
	}
}

func TestBadASNOutbound_DisabledNeverFlags(t *testing.T) {
	cfg := cfgWithBadASN(false, []uint{64500}, nil)
	if _, ok := EvaluateBadASNOutbound(cfg, net.ParseIP("203.0.113.9"), 64500, "Bulletproof"); ok {
		t.Fatal("disabled detector must not flag")
	}
}

func TestBadASNOutbound_UnknownASNSkipped(t *testing.T) {
	// ASN 0 means the lookup found no AS for the IP; classifying it would
	// false-positive every destination outside the ASN database.
	cfg := cfgWithBadASN(true, nil, []uint{13335})
	if _, ok := EvaluateBadASNOutbound(cfg, net.ParseIP("203.0.113.9"), 0, ""); ok {
		t.Fatal("unknown ASN (0) must be skipped")
	}
}

func TestBadASNOutbound_PrivateAndLoopbackSkipped(t *testing.T) {
	cfg := cfgWithBadASN(true, nil, []uint{13335})
	for _, ip := range []string{"10.0.0.5", "192.168.1.2", "127.0.0.1", "::1"} {
		if _, ok := EvaluateBadASNOutbound(cfg, net.ParseIP(ip), 64500, "x"); ok {
			t.Fatalf("private/loopback %s must be skipped", ip)
		}
	}
}

// procNetTCPBadASNRow is a single ESTABLISHED outbound row from a non-root
// uid (1001) to a public destination, reused by the scan wiring tests.
const procNetTCPBadASNRow = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0A0200C0:C350 387100CB:115C 01 00000000:00000000 00:00000000 00000000  1001        0 33333 1 0000000000000000
`

func TestScanProcNetTCPFlagsBadASNOutbound(t *testing.T) {
	cfg := &config.Config{}
	cfg.Detection.BadASNOutbound.Enabled = true
	cfg.Detection.BadASNOutbound.BlockedASNs = []uint{64500}
	SetASNLookup(func(string) (uint, string) { return 64500, "Bulletproof LLC" })
	defer SetASNLookup(nil)

	findings := scanProcNetTCP(cfg, []byte(procNetTCPBadASNRow), false)
	f, ok := findingForCheck(findings, "bad_asn_outbound")
	if !ok {
		t.Fatalf("expected bad_asn_outbound finding; got %+v", findings)
	}
	if f.SourceIP != "203.0.113.56" {
		t.Fatalf("SourceIP = %q, want remote destination IP", f.SourceIP)
	}
	if f.Timestamp.IsZero() {
		t.Fatal("scan wiring must stamp emitted findings")
	}
}

// procNetTCPRootBadASNRow is an ESTABLISHED outbound row owned by root
// (uid 0) -- a post-exploit root process exfiltrating to a bad ASN.
const procNetTCPRootBadASNRow = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0A0200C0:C350 387100CB:115C 01 00000000:00000000 00:00000000 00000000     0        0 33333 1 0000000000000000
`

func TestScanProcNetTCPFlagsRootBadASNOutbound(t *testing.T) {
	cfg := &config.Config{}
	cfg.Detection.BadASNOutbound.Enabled = true
	cfg.Detection.BadASNOutbound.BlockedASNs = []uint{64500}
	SetASNLookup(func(string) (uint, string) { return 64500, "Bulletproof LLC" })
	defer SetASNLookup(nil)

	findings := scanProcNetTCP(cfg, []byte(procNetTCPRootBadASNRow), false)
	if !hasCheck(findings, "bad_asn_outbound") {
		t.Fatalf("root egress to a bad ASN must be flagged; got %+v", findings)
	}
	// The root row must NOT raise the non-root user_outbound finding.
	if hasCheck(findings, "user_outbound_connection") {
		t.Fatalf("root row must not raise user_outbound_connection")
	}
}

// procNetTCPRootBadASNSMTPRow is a root-owned SMTP egress row. Root must
// remain visible to bad_asn_outbound without entering non-root detectors.
const procNetTCPRootBadASNSMTPRow = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0A0200C0:C350 387100CB:024B 01 00000000:00000000 00:00000000 00000000     0        0 33333 1 0000000000000000
`

func TestScanProcNetTCPRootBadASNDoesNotRunNonRootDetectors(t *testing.T) {
	cfg := &config.Config{}
	cfg.Detection.BadASNOutbound.Enabled = true
	cfg.Detection.BadASNOutbound.BlockedASNs = []uint{64500}
	cfg.Detection.DirectSMTPEgress.Enabled = true
	cfg.Detection.DirectSMTPEgress.Backend = "legacy"
	cfg.Detection.DirectSMTPEgress.Ports = []int{25, 465, 587}
	SetASNLookup(func(string) (uint, string) { return 64500, "Bulletproof LLC" })
	defer SetASNLookup(nil)

	findings := scanProcNetTCP(cfg, []byte(procNetTCPRootBadASNSMTPRow), false)
	if !hasCheck(findings, "bad_asn_outbound") {
		t.Fatalf("root egress to a bad ASN must be flagged; got %+v", findings)
	}
	for _, check := range []string{"user_outbound_connection", "direct_smtp_egress"} {
		if hasCheck(findings, check) {
			t.Fatalf("root row must not raise %s; got %+v", check, findings)
		}
	}
}

func TestScanProcNetTCPGoodASNNotFlagged(t *testing.T) {
	cfg := &config.Config{}
	cfg.Detection.BadASNOutbound.Enabled = true
	cfg.Detection.BadASNOutbound.BlockedASNs = []uint{64500}
	SetASNLookup(func(string) (uint, string) { return 13335, "Cloudflare" })
	defer SetASNLookup(nil)

	findings := scanProcNetTCP(cfg, []byte(procNetTCPBadASNRow), false)
	if hasCheck(findings, "bad_asn_outbound") {
		t.Fatalf("good ASN must not flag; got %+v", findings)
	}
}

func TestScanProcNetTCPBadASNDisabledSkipsLookup(t *testing.T) {
	cfg := &config.Config{} // BadASNOutbound.Enabled == false
	called := false
	SetASNLookup(func(string) (uint, string) { called = true; return 64500, "x" })
	defer SetASNLookup(nil)

	findings := scanProcNetTCP(cfg, []byte(procNetTCPBadASNRow), false)
	if hasCheck(findings, "bad_asn_outbound") {
		t.Fatal("disabled detector must not flag")
	}
	if called {
		t.Fatal("disabled detector must not perform ASN lookups")
	}
}

func TestScanProcNetTCPASNLookupConcurrentSet(t *testing.T) {
	cfg := &config.Config{}
	cfg.Detection.BadASNOutbound.Enabled = true
	cfg.Detection.BadASNOutbound.BlockedASNs = []uint{64500}
	t.Cleanup(func() { SetASNLookup(nil) })

	const iterations = 500
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			SetASNLookup(func(string) (uint, string) { return 64500, "Bulletproof LLC" })
			SetASNLookup(nil)
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			_ = scanProcNetTCP(cfg, []byte(procNetTCPBadASNRow), false)
		}
	}()
	wg.Wait()
}

func hasCheck(findings []alert.Finding, check string) bool {
	_, ok := findingForCheck(findings, check)
	return ok
}

func findingForCheck(findings []alert.Finding, check string) (alert.Finding, bool) {
	for _, f := range findings {
		if f.Check == check {
			return f, true
		}
	}
	return alert.Finding{}, false
}
