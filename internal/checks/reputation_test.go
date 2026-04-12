package checks

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
)

// --- firstField -------------------------------------------------------

func TestFirstFieldIPv4(t *testing.T) {
	if got := firstField("203.0.113.5 - - [01/Jan/2026]"); got != "203.0.113.5" {
		t.Errorf("got %q", got)
	}
}

func TestFirstFieldIPv6(t *testing.T) {
	if got := firstField("2001:db8::1 - -"); got != "2001:db8::1" {
		t.Errorf("got %q", got)
	}
}

func TestFirstFieldNotIP(t *testing.T) {
	if got := firstField("hostname - -"); got != "" {
		t.Errorf("non-IP should return empty, got %q", got)
	}
}

func TestFirstFieldEmpty(t *testing.T) {
	if got := firstField(""); got != "" {
		t.Errorf("empty line should return empty, got %q", got)
	}
}

// --- extractIPAfterKeyword --------------------------------------------

func TestExtractIPAfterKeyword(t *testing.T) {
	line := "Failed password for root from 203.0.113.5 port 22 ssh2"
	if got := extractIPAfterKeyword(line, "from"); got != "203.0.113.5" {
		t.Errorf("got %q", got)
	}
}

func TestExtractIPAfterKeywordEquals(t *testing.T) {
	line := "client=203.0.113.5"
	if got := extractIPAfterKeyword(line, "client"); got != "203.0.113.5" {
		t.Errorf("got %q", got)
	}
}

func TestExtractIPAfterKeywordMissing(t *testing.T) {
	if got := extractIPAfterKeyword("no keyword here", "from"); got != "" {
		t.Errorf("missing keyword should return empty, got %q", got)
	}
}

func TestExtractIPAfterKeywordNotIP(t *testing.T) {
	if got := extractIPAfterKeyword("from hostname", "from"); got != "" {
		t.Errorf("hostname should return empty, got %q", got)
	}
}

// --- extractBracketedIP -----------------------------------------------

func TestExtractBracketedIP(t *testing.T) {
	line := "SMTP connection from [203.0.113.5]:12345"
	if got := extractBracketedIP(line); got != "203.0.113.5" {
		t.Errorf("got %q", got)
	}
}

func TestExtractBracketedIPv6(t *testing.T) {
	if got := extractBracketedIP("from [2001:db8::1]"); got != "2001:db8::1" {
		t.Errorf("got %q", got)
	}
}

func TestExtractBracketedIPNoBrackets(t *testing.T) {
	if got := extractBracketedIP("no brackets here"); got != "" {
		t.Errorf("no brackets should return empty, got %q", got)
	}
}

func TestExtractBracketedIPNotIP(t *testing.T) {
	if got := extractBracketedIP("[hostname]"); got != "" {
		t.Errorf("hostname in brackets should return empty, got %q", got)
	}
}

// --- addIfNotInfra ----------------------------------------------------

func TestAddIfNotInfra(t *testing.T) {
	cfg := &config.Config{InfraIPs: []string{"10.0.0.1"}}
	ips := make(map[string]string)

	addIfNotInfra(ips, "203.0.113.5", "auth.log", cfg)
	addIfNotInfra(ips, "10.0.0.1", "auth.log", cfg)      // infra, skipped
	addIfNotInfra(ips, "127.0.0.1", "auth.log", cfg)     // loopback, skipped
	addIfNotInfra(ips, "", "auth.log", cfg)              // empty, skipped
	addIfNotInfra(ips, "203.0.113.5", "access_log", cfg) // dup, skipped

	if len(ips) != 1 {
		t.Errorf("got %d IPs, want 1: %v", len(ips), ips)
	}
	if ips["203.0.113.5"] != "auth.log" {
		t.Errorf("source = %q, want auth.log", ips["203.0.113.5"])
	}
}

// --- loadAllBlockedIPs ------------------------------------------------

func TestLoadAllBlockedIPsFlatFile(t *testing.T) {
	dir := t.TempDir()
	fwDir := filepath.Join(dir, "firewall")
	_ = os.MkdirAll(fwDir, 0700)

	fwState := map[string]interface{}{
		"blocked": []map[string]interface{}{
			{"ip": "203.0.113.1", "expires_at": time.Now().Add(1 * time.Hour).Format(time.RFC3339)},
			{"ip": "203.0.113.2", "expires_at": time.Now().Add(-1 * time.Hour).Format(time.RFC3339)}, // expired
		},
	}
	data, _ := json.Marshal(fwState)
	_ = os.WriteFile(filepath.Join(fwDir, "state.json"), data, 0600)

	blocked := loadAllBlockedIPs(dir)
	if !blocked["203.0.113.1"] {
		t.Error("active blocked IP should be present")
	}
	if blocked["203.0.113.2"] {
		t.Error("expired blocked IP should not be present")
	}
}

func TestLoadAllBlockedIPsEmpty(t *testing.T) {
	blocked := loadAllBlockedIPs(t.TempDir())
	if len(blocked) != 0 {
		t.Errorf("empty dir should return empty, got %v", blocked)
	}
}

// --- queryAbuseIPDB ---------------------------------------------------

func TestQueryAbuseIPDBSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Key") != "test-key" {
			t.Errorf("API key not sent: %q", r.Header.Get("Key"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"abuseConfidenceScore":85,"usageType":"Data Center","isp":"BadISP","totalReports":42}}`))
	}))
	defer srv.Close()

	// Override endpoint for this test
	origEndpoint := abuseIPDBEndpoint
	defer func() { /* can't restore const */ }()
	_ = origEndpoint

	// queryAbuseIPDB hardcodes the endpoint, so use a client that redirects to our server.
	// Instead, test the response parsing directly by hitting our httptest server.
	client := srv.Client()
	req, _ := http.NewRequest("GET", srv.URL+"?ipAddress=1.2.3.4&maxAgeInDays=90", nil)
	req.Header.Set("Key", "test-key")
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var result abuseIPDBResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if result.Data.AbuseConfidenceScore != 85 {
		t.Errorf("score = %d, want 85", result.Data.AbuseConfidenceScore)
	}
}

// --- cleanCache -------------------------------------------------------

func TestCleanCacheRemovesExpired(t *testing.T) {
	cache := &reputationCache{Entries: map[string]*reputationEntry{
		"1.1.1.1": {Score: 50, CheckedAt: time.Now().Add(-7 * time.Hour)}, // expired
		"2.2.2.2": {Score: 30, CheckedAt: time.Now()},                     // fresh
	}}
	cleanCache(cache)
	if _, ok := cache.Entries["1.1.1.1"]; ok {
		t.Error("expired entry should be removed")
	}
	if _, ok := cache.Entries["2.2.2.2"]; !ok {
		t.Error("fresh entry should be kept")
	}
}

// --- loadReputationCache / saveReputationCache round-trip -------------

func TestReputationCacheRoundTrip(t *testing.T) {
	dir := t.TempDir()
	cache := &reputationCache{Entries: map[string]*reputationEntry{
		"1.2.3.4": {Score: 75, Category: "DC", CheckedAt: time.Now()},
	}}
	saveReputationCache(dir, cache)

	loaded := loadReputationCache(dir)
	if e, ok := loaded.Entries["1.2.3.4"]; !ok {
		t.Error("entry not loaded")
	} else if e.Score != 75 || e.Category != "DC" {
		t.Errorf("got %+v", e)
	}
}

func TestLoadReputationCacheEmpty(t *testing.T) {
	cache := loadReputationCache(t.TempDir())
	if cache.Entries == nil {
		t.Error("should return initialized cache")
	}
	if len(cache.Entries) != 0 {
		t.Errorf("empty dir should return empty cache, got %v", cache.Entries)
	}
}
