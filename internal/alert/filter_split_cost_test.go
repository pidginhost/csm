package alert

import "testing"

// The split runs on every dispatch. It reads block state only when a finding
// names an address a block could answer, and then once for the whole batch.
func TestSplitByClassLoadsBlockStateOnlyWhenNeeded(t *testing.T) {
	cfg := policyConfig(t)
	loads := 0
	previous := BlockedIPsFunc
	BlockedIPsFunc = func() map[string]bool {
		loads++
		return map[string]bool{"203.0.113.40": true}
	}
	t.Cleanup(func() { BlockedIPsFunc = previous })

	unaddressed := []Finding{
		{Check: "wp_core_integrity", Severity: High, Message: "WordPress core file changed in example.com"},
		{Check: "challenge_route", Severity: Warning, Message: "CHALLENGE: 203.0.113.41 sent to PoW challenge"},
	}
	assertSplit(t, cfg, unaddressed, unaddressed[:1], unaddressed[1:])
	if loads != 0 {
		t.Fatalf("block state loads = %d for a batch no block can answer, want 0", loads)
	}

	addressed := []Finding{
		{Check: "ftp_auth_failure_realtime", Severity: High, SourceIP: "203.0.113.40", Message: "FTP authentication failed from 203.0.113.40"},
		{Check: "http_ua_spoof", Severity: Critical, SourceIP: "203.0.113.40", Message: "User-Agent spoof from 203.0.113.40"},
		{Check: "ftp_auth_failure_realtime", Severity: High, SourceIP: "203.0.113.42", Message: "FTP authentication failed from 203.0.113.42"},
	}
	assertSplit(t, cfg, addressed, addressed[2:], addressed[:2])
	if loads != 1 {
		t.Fatalf("block state loads = %d for one batch, want 1", loads)
	}
}

// A block of a Cloudflare-covered address leaves its web ports open. The
// split reads the Cloudflare ranges once per batch, and only for a web
// finding whose source is blocked.
func TestSplitByClassLoadsCloudflareRangesOnce(t *testing.T) {
	cfg := policyConfig(t)
	previousBlocked := BlockedIPsFunc
	BlockedIPsFunc = func() map[string]bool { return map[string]bool{"203.0.113.40": true, "203.0.113.41": true} }
	t.Cleanup(func() { BlockedIPsFunc = previousBlocked })
	loads := 0
	previousLoad := loadCloudflareRanges
	loadCloudflareRanges = func(statePath string) ([]string, []string) {
		loads++
		if statePath != cfg.StatePath {
			t.Errorf("Cloudflare ranges read from %q, want %q", statePath, cfg.StatePath)
		}
		return []string{"203.0.113.41/32"}, []string{"2001:db8:cf::/48"}
	}
	t.Cleanup(func() { loadCloudflareRanges = previousLoad })
	previousWeb := SetWebTrafficPolicy(func(f Finding) bool { return f.Check == "http_ua_spoof" })
	t.Cleanup(func() { SetWebTrafficPolicy(previousWeb) })

	noBlockedWeb := []Finding{
		{Check: "ftp_auth_failure_realtime", Severity: High, SourceIP: "203.0.113.41", Message: "FTP authentication failed from 203.0.113.41"},
		{Check: "http_ua_spoof", Severity: Critical, SourceIP: "203.0.113.50", Message: "User-Agent spoof from 203.0.113.50"},
	}
	assertSplit(t, cfg, noBlockedWeb, noBlockedWeb[1:], noBlockedWeb[:1])
	if loads != 0 {
		t.Fatalf("Cloudflare loads = %d with no blocked web finding, want 0", loads)
	}

	web := []Finding{
		{Check: "http_ua_spoof", Severity: Critical, SourceIP: "203.0.113.40", Message: "User-Agent spoof from 203.0.113.40"},
		{Check: "http_ua_spoof", Severity: Critical, SourceIP: "203.0.113.41", Message: "User-Agent spoof from 203.0.113.41"},
		{Check: "http_ua_spoof", Severity: Critical, SourceIP: "203.0.113.41", Message: "User-Agent spoof from 203.0.113.41 again"},
		{Check: "ftp_auth_failure_realtime", Severity: High, SourceIP: "203.0.113.41", Message: "FTP authentication failed from 203.0.113.41"},
	}
	assertSplit(t, cfg, web, web[1:3], []Finding{web[0], web[3]})
	if loads != 1 {
		t.Fatalf("Cloudflare loads = %d for one batch, want 1", loads)
	}
}
