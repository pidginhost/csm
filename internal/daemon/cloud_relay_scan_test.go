package daemon

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/store"
)

// writeEximFixture renders a sequence of exim acceptance lines at the
// given timestamps to a tempfile and returns its path.
func writeEximFixture(t *testing.T, lines []string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "exim_mainlog")
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return path
}

func eximLine(ts time.Time, sender, ptr, ip, subject string) string {
	return ts.Format("2006-01-02 15:04:05") +
		" 1abc-0000-AB <= " + sender +
		" H=" + ptr + " (helo.example) [" + ip + "]:4321 P=esmtpsa" +
		" X=TLS1.3:TLS_AES_256_GCM_SHA384:256" +
		" A=dovecot_plain:" + sender +
		" S=1024 id=xyz@local" +
		` T="` + subject + `" for victim@example.com`
}

func TestScanRetro_FiresOnPacedSlowBurn(t *testing.T) {
	// Mimic wizard-design.com's actual profile: 20 sends from 1 AWS IP in
	// a 1h cluster. The realtime multi-IP rule would miss this; the
	// volume-burst threshold should catch it on retrospective replay.
	base := time.Now().Add(-2 * time.Hour)
	var lines []string
	for i := 0; i < 18; i++ {
		lines = append(lines, eximLine(
			base.Add(time.Duration(i)*2*time.Minute),
			"info@wizard-design.com",
			"ec2-13-38-71-129.eu-west-3.compute.amazonaws.com",
			"13.38.71.129",
			"BITPANDA LETZTE ERINNERUNG",
		))
	}
	path := writeEximFixture(t, lines)

	withGlobalStore(t, func(*store.DB) {
		cfg := &config.Config{}
		findings := ScanEximHistoryForCloudRelay(cfg, path, time.Now(), 24*time.Hour)
		if len(findings) != 1 {
			t.Fatalf("expected 1 retro finding, got %d: %+v", len(findings), findings)
		}
		f := findings[0]
		if f.Check != "email_cloud_relay_abuse" {
			t.Fatalf("check = %q, want email_cloud_relay_abuse", f.Check)
		}
		if !strings.Contains(f.Message, "RETRO:") {
			t.Fatalf("message should be marked RETRO: %q", f.Message)
		}
		if !strings.Contains(f.Message, "13.38.71.129") {
			t.Fatalf("message must embed source IP for autoblock: %q", f.Message)
		}
	})
}

func TestScanRetro_FiresOnRotatingIPFleet(t *testing.T) {
	// Mimic occonsultingcy.com's actual profile: 10 sends across 5 IPs.
	base := time.Now().Add(-2 * time.Hour)
	ips := []string{"34.26.118.204", "35.237.120.4", "34.26.243.44", "35.185.2.217", "104.196.13.121"}
	var lines []string
	for i := 0; i < 10; i++ {
		ip := ips[i%len(ips)]
		lines = append(lines, eximLine(
			base.Add(time.Duration(i)*3*time.Minute),
			"info@occonsultingcy.com",
			strings.ReplaceAll(ip, ".", "-")+".bc.googleusercontent.com",
			ip,
			"cPanel Service Alert",
		))
	}
	path := writeEximFixture(t, lines)

	withGlobalStore(t, func(*store.DB) {
		cfg := &config.Config{}
		findings := ScanEximHistoryForCloudRelay(cfg, path, time.Now(), 24*time.Hour)
		if len(findings) != 1 {
			t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
		}
	})
}

func TestScanRetro_SilentOnLegitSaaS(t *testing.T) {
	// SmartBill profile: 2 sends from the same AWS IP. Below thresholds.
	// Nylas profile: 2 sends from 2 GCP IPs. Below thresholds.
	base := time.Now().Add(-1 * time.Hour)
	lines := []string{
		eximLine(base, "contact@smartbill-user.example",
			"ec2-34-250-125-227.eu-west-1.compute.amazonaws.com", "34.250.125.227", "Documentul AB1"),
		eximLine(base.Add(30*time.Minute), "contact@smartbill-user.example",
			"ec2-34-250-125-227.eu-west-1.compute.amazonaws.com", "34.250.125.227", "Documentul AB2"),
		eximLine(base, "info@nylas-user.example",
			"13.166.122.34.bc.googleusercontent.com", "34.122.166.13", "Factura"),
		eximLine(base.Add(45*time.Minute), "info@nylas-user.example",
			"88.89.133.34.bc.googleusercontent.com", "34.133.89.88", "Factura"),
	}
	path := writeEximFixture(t, lines)

	withGlobalStore(t, func(*store.DB) {
		cfg := &config.Config{}
		findings := ScanEximHistoryForCloudRelay(cfg, path, time.Now(), 24*time.Hour)
		if len(findings) != 0 {
			t.Fatalf("legit SaaS profile must produce no findings, got %d: %+v", len(findings), findings)
		}
	})
}

func TestScanRetro_RespectsAllowlist(t *testing.T) {
	base := time.Now().Add(-30 * time.Minute)
	var lines []string
	for i := 0; i < 20; i++ {
		lines = append(lines, eximLine(
			base.Add(time.Duration(i)*time.Minute),
			"info@wizard-design.com",
			"ec2-13-38-71-129.eu-west-3.compute.amazonaws.com",
			"13.38.71.129",
			"Whatever",
		))
	}
	path := writeEximFixture(t, lines)

	withGlobalStore(t, func(*store.DB) {
		cfg := &config.Config{}
		cfg.EmailProtection.HighVolumeSenders = []string{"info@wizard-design.com"}
		findings := ScanEximHistoryForCloudRelay(cfg, path, time.Now(), 24*time.Hour)
		if len(findings) != 0 {
			t.Fatalf("allowlisted user must not produce retro findings: %+v", findings)
		}
	})
}

func TestScanRetro_DedupsAcrossReruns(t *testing.T) {
	// First scan fires; second scan over identical data must stay silent
	// until a newer event lands.
	base := time.Now().Add(-30 * time.Minute)
	var lines []string
	for i := 0; i < 18; i++ {
		lines = append(lines, eximLine(
			base.Add(time.Duration(i)*time.Minute),
			"info@example.com",
			"ec2-1-2-3-4.compute-1.amazonaws.com",
			"1.2.3.4",
			"spam",
		))
	}
	path := writeEximFixture(t, lines)

	withGlobalStore(t, func(*store.DB) {
		cfg := &config.Config{}

		first := ScanEximHistoryForCloudRelay(cfg, path, time.Now(), 24*time.Hour)
		if len(first) != 1 {
			t.Fatalf("first scan expected 1 finding, got %d", len(first))
		}

		second := ScanEximHistoryForCloudRelay(cfg, path, time.Now(), 24*time.Hour)
		if len(second) != 0 {
			t.Fatalf("second scan over identical data must be silent, got %d: %+v", len(second), second)
		}

		// A newer event should re-fire the alert.
		newer := eximLine(time.Now().Add(-1*time.Minute),
			"info@example.com",
			"ec2-1-2-3-4.compute-1.amazonaws.com",
			"1.2.3.4",
			"still spamming")
		appended := append([]byte{}, []byte(strings.Join(lines, "\n")+"\n"+newer+"\n")...)
		if err := os.WriteFile(path, appended, 0o600); err != nil {
			t.Fatalf("append fixture: %v", err)
		}
		third := ScanEximHistoryForCloudRelay(cfg, path, time.Now(), 24*time.Hour)
		if len(third) != 1 {
			t.Fatalf("new event should re-fire, got %d", len(third))
		}
	})
}

func TestScanRetro_SkipsLinesOutsideLookback(t *testing.T) {
	// A burst from 3 days ago is outside the 24h lookback — must not fire.
	old := time.Now().Add(-72 * time.Hour)
	var lines []string
	for i := 0; i < 20; i++ {
		lines = append(lines, eximLine(
			old.Add(time.Duration(i)*time.Minute),
			"info@ancient.example",
			"ec2-1-2-3-4.compute-1.amazonaws.com",
			"1.2.3.4",
			"old spam",
		))
	}
	path := writeEximFixture(t, lines)

	withGlobalStore(t, func(*store.DB) {
		cfg := &config.Config{}
		findings := ScanEximHistoryForCloudRelay(cfg, path, time.Now(), 24*time.Hour)
		if len(findings) != 0 {
			t.Fatalf("lines outside lookback must be ignored, got %d: %+v", len(findings), findings)
		}
	})
}

func TestMaxCloudRelayBurst_ReturnsWindowEndNotStart(t *testing.T) {
	// Seven events spaced 2 min apart. The strongest 60-min window
	// covers events 0..6 — operators reading the log want the peak
	// *end* time (last event) so they know when the attack was still
	// active, not when it began.
	base := time.Date(2026, 4, 22, 14, 0, 0, 0, time.UTC)
	events := make([]cloudRelayScanEvent, 7)
	for i := range events {
		events[i] = cloudRelayScanEvent{
			at:  base.Add(time.Duration(i) * 2 * time.Minute),
			ip:  fmt.Sprintf("1.2.3.%d", i),
			ptr: "ec2-x.compute-1.amazonaws.com",
		}
	}
	_, _, bestAt, _ := maxCloudRelayBurst(events)
	want := events[len(events)-1].at
	if !bestAt.Equal(want) {
		t.Fatalf("bestAt = %v, want last-event time %v", bestAt, want)
	}
}

func TestScanRetro_OversizedLineDoesNotAbortScan(t *testing.T) {
	// Put a 500 KB garbage line in the middle of real compromise events.
	// With bufio.Scanner + 256 KB buffer we would hit ErrTooLong and
	// stop the whole scan, missing the events after the garbage line.
	// With the bufio.Reader approach we drain the oversized line and
	// keep going.
	base := time.Now().Add(-2 * time.Hour)
	var lines []string

	// Before: 10 sends from one cloud IP (insufficient on its own).
	for i := 0; i < 10; i++ {
		lines = append(lines, eximLine(
			base.Add(time.Duration(i)*time.Minute),
			"info@victim.example",
			"ec2-1-2-3-4.compute-1.amazonaws.com",
			"1.2.3.4",
			"before-garbage",
		))
	}
	// The pathological line — 500 KB, no newline until the end.
	lines = append(lines, strings.Repeat("X", 500*1024))
	// After: another 10 sends, pushing total to 20 (above volume
	// threshold). If the scanner aborts, these are missed.
	for i := 0; i < 10; i++ {
		lines = append(lines, eximLine(
			base.Add(time.Duration(30+i)*time.Minute),
			"info@victim.example",
			"ec2-1-2-3-4.compute-1.amazonaws.com",
			"1.2.3.4",
			"after-garbage",
		))
	}
	path := writeEximFixture(t, lines)

	withGlobalStore(t, func(*store.DB) {
		cfg := &config.Config{}
		findings := ScanEximHistoryForCloudRelay(cfg, path, time.Now(), 24*time.Hour)
		if len(findings) != 1 {
			t.Fatalf("oversized line must not abort scan — expected 1 finding, got %d", len(findings))
		}
	})
}

func TestExtractSenderFromCloudRelayMessage(t *testing.T) {
	cases := map[string]string{
		"RETRO: account info@example.com sent 42 authenticated messages from 5 cloud-provider IPs (peak 60-min burst) in the last 24 hours - credentials compromised - from 1.2.3.4": "info@example.com",
		"Email account user@site.org sent 15 authenticated messages from 1 cloud-provider IPs in 60 minutes - credentials compromised - from 5.6.7.8":                                "user@site.org",
		"totally unrelated message without the marker": "",
		"account missing-at-sign sent 99 messages":     "",
	}
	for in, want := range cases {
		got := extractSenderFromCloudRelayMessage(in)
		if got != want {
			t.Errorf("extractSenderFromCloudRelayMessage(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseEximTimestamp(t *testing.T) {
	line := "2026-04-22 14:55:43 1wFWBE-000000036n0-1PMK <= ..."
	ts, ok := parseEximTimestamp(line)
	if !ok {
		t.Fatal("expected ok")
	}
	if ts.Year() != 2026 || ts.Month() != 4 || ts.Day() != 22 ||
		ts.Hour() != 14 || ts.Minute() != 55 || ts.Second() != 43 {
		t.Fatalf("unexpected ts: %v", ts)
	}
	if _, ok := parseEximTimestamp("too short"); ok {
		t.Fatal("expected parse failure on short line")
	}
	if _, ok := parseEximTimestamp("not-a-date-here-at-all 12345"); ok {
		t.Fatal("expected parse failure on bad date")
	}
}
