package daemon

import (
	"slices"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// drainForCheck returns the first finding with the given check name buffered
// on ch, or nil if none is present.
func drainForCheck(ch <-chan alert.Finding, check string) *alert.Finding {
	for {
		select {
		case f := <-ch:
			if f.Check == check {
				out := f
				return &out
			}
		default:
			return nil
		}
	}
}

func TestPAMListenerEmitsCredentialStuffing(t *testing.T) {
	alertCh := make(chan alert.Finding, 8)
	cfg := &config.Config{}
	// Keep the count-based brute trigger quiet so this asserts the
	// distinct-account breadth path specifically.
	cfg.Thresholds.MultiIPLoginThreshold = 100
	cfg.Thresholds.CredStuffingDistinctAccounts = 3

	p := &PAMListener{
		cfg:      cfg,
		alertCh:  alertCh,
		failures: make(map[string]*pamFailureTracker),
		stuffing: newCredentialStuffingDetector(3, 10*time.Minute, nil),
	}

	p.processEvent("FAIL ip=203.0.113.20 user=alice service=sshd")
	p.processEvent("FAIL ip=203.0.113.20 user=bob service=dovecot")
	p.processEvent("FAIL ip=203.0.113.20 user=carol service=sshd")

	got := drainForCheck(alertCh, "credential_stuffing")
	if got == nil {
		t.Fatal("expected credential_stuffing finding after 3 distinct accounts")
	}
	if got.SourceIP != "203.0.113.20" {
		t.Fatalf("SourceIP = %q, want 203.0.113.20", got.SourceIP)
	}
	if got.Severity != alert.High {
		t.Fatalf("Severity = %v, want High", got.Severity)
	}
	if got.Details != "Accounts targeted: alice, bob, carol\nService(s): dovecot, sshd" {
		t.Fatalf("Details = %q, want targeted account list", got.Details)
	}
	if !slices.Equal(got.SprayTargets, []string{"alice", "bob", "carol"}) {
		t.Fatalf("SprayTargets = %v, want [alice bob carol]", got.SprayTargets)
	}
}

func TestSpraySuppressionDefaultChecksAreEmittedByProductionParsers(t *testing.T) {
	defaults := (&config.Config{}).IncidentsSpraySuppressionPerCheck()
	emitted := make(map[string]bool)
	pamTargets := make(map[string]bool)

	for _, f := range parseEximLogLine(`2026-04-11 12:00:00 dovecot_login authenticator failed for H=(mail.example.com) [198.51.100.40]:54321: 535 Incorrect authentication data (set_id=user@example.com)`, &config.Config{}) {
		emitted[f.Check] = true
	}

	alertCh := make(chan alert.Finding, 8)
	cfg := &config.Config{}
	cfg.Thresholds.MultiIPLoginThreshold = 2
	cfg.Thresholds.CredStuffingDistinctAccounts = 3
	p := &PAMListener{
		cfg:      cfg,
		alertCh:  alertCh,
		failures: make(map[string]*pamFailureTracker),
		stuffing: newCredentialStuffingDetector(3, 10*time.Minute, nil),
	}

	p.processEvent("FAIL ip=203.0.113.24 user=alice service=sshd")
	p.processEvent("FAIL ip=203.0.113.24 user=bob service=dovecot")
	p.processEvent("FAIL ip=203.0.113.24 user=carol service=sshd")

	for {
		select {
		case f := <-alertCh:
			emitted[f.Check] = true
			if len(f.SprayTargets) > 0 {
				pamTargets[f.Check] = true
			}
		default:
			for check := range defaults {
				if !emitted[check] {
					t.Fatalf("default spray per_check %q was not emitted by production parser/listener paths; emitted=%v", check, emitted)
				}
			}
			for _, check := range []string{"pam_bruteforce", "credential_stuffing"} {
				if !pamTargets[check] {
					t.Fatalf("%s finding did not carry spray targets", check)
				}
			}
			return
		}
	}
}

func TestPAMListenerRepeatedSingleAccountIsNotStuffing(t *testing.T) {
	alertCh := make(chan alert.Finding, 8)
	cfg := &config.Config{}
	cfg.Thresholds.MultiIPLoginThreshold = 100 // keep brute quiet
	cfg.Thresholds.CredStuffingDistinctAccounts = 3

	p := &PAMListener{
		cfg:      cfg,
		alertCh:  alertCh,
		failures: make(map[string]*pamFailureTracker),
		stuffing: newCredentialStuffingDetector(3, 10*time.Minute, nil),
	}

	// Many failures against ONE account is brute-force depth, not the
	// breadth signal -- no credential_stuffing finding.
	for i := 0; i < 10; i++ {
		p.processEvent("FAIL ip=203.0.113.21 user=root service=sshd")
	}
	if got := drainForCheck(alertCh, "credential_stuffing"); got != nil {
		t.Fatalf("credential_stuffing fired on single-account depth: %+v", got)
	}
}

func TestPAMListenerOKClearsCredentialStuffingState(t *testing.T) {
	alertCh := make(chan alert.Finding, 8)
	cfg := &config.Config{}
	cfg.Thresholds.MultiIPLoginThreshold = 100
	cfg.Thresholds.CredStuffingDistinctAccounts = 3

	p := &PAMListener{
		cfg:      cfg,
		alertCh:  alertCh,
		failures: make(map[string]*pamFailureTracker),
		stuffing: newCredentialStuffingDetector(3, 10*time.Minute, nil),
	}

	p.processEvent("FAIL ip=203.0.113.22 user=alice service=sshd")
	p.processEvent("FAIL ip=203.0.113.22 user=bob service=dovecot")
	p.processEvent("OK ip=203.0.113.22 user=bob service=dovecot")
	p.processEvent("FAIL ip=203.0.113.22 user=carol service=sshd")

	if got := drainForCheck(alertCh, "credential_stuffing"); got != nil {
		t.Fatalf("credential_stuffing retained pre-success accounts: %+v", got)
	}
}

func TestPAMListenerUsesActiveCredentialStuffingThreshold(t *testing.T) {
	prev := config.Active()
	t.Cleanup(func() { config.SetActive(prev) })

	alertCh := make(chan alert.Finding, 8)
	startup := &config.Config{}
	startup.Thresholds.MultiIPLoginThreshold = 100
	startup.Thresholds.CredStuffingDistinctAccounts = 5

	active := &config.Config{}
	active.Thresholds.MultiIPLoginThreshold = 100
	active.Thresholds.CredStuffingDistinctAccounts = 3
	config.SetActive(active)

	p := &PAMListener{
		cfg:             startup,
		alertCh:         alertCh,
		failures:        make(map[string]*pamFailureTracker),
		useActiveConfig: true,
		stuffing:        newCredentialStuffingDetector(5, 10*time.Minute, nil),
	}

	p.processEvent("FAIL ip=203.0.113.23 user=alice service=sshd")
	p.processEvent("FAIL ip=203.0.113.23 user=bob service=dovecot")
	p.processEvent("FAIL ip=203.0.113.23 user=carol service=sshd")

	if got := drainForCheck(alertCh, "credential_stuffing"); got == nil {
		t.Fatal("expected active threshold to lower credential_stuffing trip point")
	}
}

func TestPAMListenerOKClearsFailures(t *testing.T) {
	alertCh := make(chan alert.Finding, 4)
	cfg := &config.Config{}
	cfg.Thresholds.MultiIPLoginThreshold = 2

	p := &PAMListener{
		cfg:      cfg,
		alertCh:  alertCh,
		failures: make(map[string]*pamFailureTracker),
	}

	p.processEvent("FAIL ip=203.0.113.10 user=root service=sshd")
	p.processEvent("OK ip=203.0.113.10 user=root service=sshd")
	p.processEvent("FAIL ip=203.0.113.10 user=root service=sshd")

	select {
	case finding := <-alertCh:
		if finding.Check != "pam_login" {
			t.Fatalf("unexpected finding after reset flow: %+v", finding)
		}
	default:
		t.Fatal("expected pam_login alert after successful login")
	}

	select {
	case finding := <-alertCh:
		t.Fatalf("unexpected extra finding before threshold: %+v", finding)
	default:
	}

	p.processEvent("FAIL ip=203.0.113.10 user=root service=sshd")
	select {
	case finding := <-alertCh:
		if finding.Check != "pam_bruteforce" {
			t.Fatalf("expected pam_bruteforce, got %+v", finding)
		}
		if !slices.Equal(finding.SprayTargets, []string{"root"}) {
			t.Fatalf("SprayTargets = %v, want [root]", finding.SprayTargets)
		}
	default:
		t.Fatal("expected pam_bruteforce finding after second post-reset failure")
	}
}

func TestPAMListenerIgnoresLoopback(t *testing.T) {
	alertCh := make(chan alert.Finding, 2)
	p := &PAMListener{
		cfg:      &config.Config{},
		alertCh:  alertCh,
		failures: make(map[string]*pamFailureTracker),
	}

	p.processEvent("FAIL ip=127.0.0.1 user=root service=sshd")
	p.processEvent("OK ip=127.0.0.1 user=root service=sshd")

	select {
	case finding := <-alertCh:
		t.Fatalf("unexpected finding for loopback event: %+v", finding)
	default:
	}
	if len(p.failures) != 0 {
		t.Fatalf("loopback events should not create failure trackers: %+v", p.failures)
	}
}
