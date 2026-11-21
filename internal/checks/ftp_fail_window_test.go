package checks

import (
	"fmt"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// Previously reported sources cannot prevent a new source reaching its threshold.
func TestFTPFailWindowCapacityDoesNotHideNewAttack(t *testing.T) {
	w := NewFTPFailWindow()
	now := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	// Seed a full old tracker without paying for a whole-window sweep per failure.
	for i := range maxTrackedIPs {
		ip := fmt.Sprintf("2001:db8::%x", i+1)
		for range ftpFailThreshold {
			w.t.record(ip, now)
		}
		w.reported[ip] = now
	}
	for i := 1; i <= ftpFailThreshold; i++ {
		count, _, report := w.Failure("203.0.113.77", now, now, &config.Config{})
		if count != i || report != (i == ftpFailThreshold) {
			t.Fatalf("failure %d: count=%d report=%v", i, count, report)
		}
	}
	if _, _, report := w.Failure("203.0.113.77", now, now, nil); report {
		t.Fatal("repeated burst reported twice")
	}
	later := now.Add(31 * time.Minute)
	if count, _, report := w.Failure("203.0.113.77", later, later, nil); count != 1 || report {
		t.Fatalf("expired burst: count=%d report=%v", count, report)
	}
	if len(w.reported) != 0 || len(w.t.Buckets) != 1 {
		t.Fatalf("expired sources retained: reports=%d buckets=%d", len(w.reported), len(w.t.Buckets))
	}
}

// A future event cannot keep compromise history alive past the configured window.
func TestFTPFailWindowLoginHistoryExpires(t *testing.T) {
	w := NewFTPFailWindow()
	cfg := &config.Config{}
	cfg.Thresholds.FTPFailWindowMin = 1
	now := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	for range ftpFailThreshold {
		w.Failure("203.0.113.84", now.Add(24*time.Hour), now, cfg)
	}
	const line = "pure-ftpd: (alice@203.0.113.84) [INFO] alice is now logged in"
	if got, ok := w.LoginFinding(line, now, cfg); !ok || got.Check != "ftp_login_after_bruteforce" || got.Severity != alert.Critical {
		t.Fatalf("fresh history: %+v (%v)", got, ok)
	}
	if got, ok := w.LoginFinding(line, now.Add(2*time.Minute), cfg); !ok || got.Check != "ftp_login" || got.Severity != alert.Warning {
		t.Fatalf("expired history: %+v (%v)", got, ok)
	}
	if _, ok := w.LoginFinding("pure-ftpd: (?@203.0.113.84) [WARNING] Authentication failed for user [alice]", now, cfg); ok {
		t.Fatal("failure accepted as a login")
	}
}
