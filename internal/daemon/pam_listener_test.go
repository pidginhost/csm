package daemon

import (
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

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
