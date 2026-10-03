package checks

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/store"
)

func reputationFindingFor(t *testing.T, findings []alert.Finding, ip string) alert.Finding {
	t.Helper()
	for _, f := range findings {
		if f.Check == "ip_reputation" && f.SourceIP == ip {
			return f
		}
	}
	t.Fatalf("no ip_reputation finding for %s in %+v", ip, findings)
	return alert.Finding{}
}

// A reputation finding names the intel it rests on and when that claim
// lapses, as data the admission adapter reads; the public JSON is unchanged.
func TestReputationFindingsCarryTheirIntel(t *testing.T) {
	statePath := t.TempDir()
	restoreThreatDB := SetGlobalThreatDBForTest(statePath)
	t.Cleanup(restoreThreatDB)
	lapse := time.Now().Add(time.Hour).Truncate(time.Second)
	db := GetThreatDB()
	db.badIPs["203.0.113.45"] = "operator list"
	db.badIPExpiry["203.0.113.45"] = lapse
	db.badIPs["203.0.113.46"] = "test-feed"
	db.badIPs["203.0.113.48"] = "test-feed"
	db.badIPExpiry["203.0.113.48"] = time.Now().Add(24 * time.Hour)
	checked := time.Now().Add(-time.Hour).Truncate(time.Second)
	saveReputationCache(statePath, &reputationCache{Entries: map[string]*reputationEntry{
		"203.0.113.47": {Score: 90, Category: "Hacking", CheckedAt: checked},
	}})
	withMockOS(t, mockOSWithAuthLog(t, strings.Join([]string{
		"Apr 14 10:00:00 host sshd[1]: Accepted publickey for root from 203.0.113.45 port 22 ssh2",
		"Apr 14 10:00:01 host sshd[1]: Accepted publickey for root from 203.0.113.46 port 22 ssh2",
		"Apr 14 10:00:02 host sshd[1]: Accepted publickey for root from 203.0.113.47 port 22 ssh2",
		"Apr 14 10:00:03 host sshd[1]: Accepted publickey for root from 203.0.113.48 port 22 ssh2",
	}, "\n")+"\n"))
	before := time.Now()
	findings := CheckIPReputation(context.Background(), &config.Config{StatePath: statePath}, nil)
	after := time.Now()

	lapsing := reputationFindingFor(t, findings, "203.0.113.45")
	if lapsing.Intel == nil || lapsing.Intel.Source != "threatdb:operator_list" || !lapsing.Intel.Expires.Equal(lapse) {
		t.Fatalf("lapsing entry intel %+v, want threatdb:operator_list until %v", lapsing.Intel, lapse)
	}
	feed := reputationFindingFor(t, findings, "203.0.113.46")
	if feed.Intel == nil || feed.Intel.Source != "threatdb:test-feed" ||
		feed.Intel.Expires.Before(before.Add(cacheExpiry)) || feed.Intel.Expires.After(after.Add(cacheExpiry)) {
		t.Fatalf("feed intel %+v, want threatdb:test-feed for one cache period", feed.Intel)
	}
	longLived := reputationFindingFor(t, findings, "203.0.113.48")
	if longLived.Intel == nil || longLived.Intel.Source != "threatdb:test-feed" ||
		longLived.Intel.Expires.Before(before.Add(cacheExpiry)) || longLived.Intel.Expires.After(after.Add(cacheExpiry)) {
		t.Fatalf("long-lived feed intel %+v exceeds one cache period", longLived.Intel)
	}
	cached := reputationFindingFor(t, findings, "203.0.113.47")
	if cached.Intel == nil || cached.Intel.Source != "abuseipdb" || !cached.Intel.Expires.Equal(checked.Add(cacheExpiry)) {
		t.Fatalf("cached intel %+v, want abuseipdb until the cache entry lapses", cached.Intel)
	}
	raw, err := json.Marshal(cached)
	if err != nil || strings.Contains(string(raw), `"intel"`) || strings.Contains(string(raw), `"abuseipdb"`) || strings.Contains(string(raw), `"expires"`) {
		t.Fatalf("public JSON %s (error %v) names the intel", raw, err)
	}
}

func TestIntelSourceIsABoundedToken(t *testing.T) {
	for in, want := range map[string]string{
		"test-feed":             "test-feed",
		"operator list":         "operator_list",
		"tab\tand\nnewline":     "tab_and_newline",
		"del\x7fbyte":           "del_byte",
		"utf8\xc3\xa9":          "utf8__",
		strings.Repeat("a", 90): strings.Repeat("a", 64-len("threatdb:")),
	} {
		if got := intelSource("threatdb:", in); got != "threatdb:"+want {
			t.Errorf("intelSource(%q) = %q, want threatdb:%s", in, got, want)
		}
	}
}

// Every query or fallback branch carries an expiry for its own source.
func TestReputationIntelAcrossQueryPaths(t *testing.T) {
	for _, tc := range []struct {
		name                  string
		status, score, count  int
		upstream, cached, key bool
		cap, used             int
		wantSource            string
	}{
		{name: "fresh abuse", status: 200, score: 90, count: 1, key: true, wantSource: "abuseipdb"},
		{name: "fresh supplemental", status: 200, score: 10, count: 1, key: true, upstream: true, wantSource: "upstream"},
		{name: "cached supplemental", count: 1, cached: true, upstream: true, wantSource: "upstream"},
		{name: "no abuse key", count: 1, upstream: true, wantSource: "upstream"},
		{name: "local quota", count: 1, key: true, upstream: true, cap: 1, used: 1, wantSource: "upstream"},
		{name: "reserved tail", status: 200, score: 10, count: 2, key: true, upstream: true, cap: 1, wantSource: "upstream"},
		{name: "query limit", status: 200, score: 10, count: 6, key: true, upstream: true, wantSource: "upstream"},
		{name: "quota response", status: 429, count: 1, key: true, upstream: true, wantSource: "upstream"},
		{name: "query error", status: 500, count: 1, key: true, upstream: true, wantSource: "upstream"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, db := reputationQueueFixture(t, tc.count)
			t.Cleanup(SetGlobalThreatDBForTest(t.TempDir()))
			if !tc.key {
				cfg.Reputation.AbuseIPDBKey = ""
			}
			if tc.cap > 0 {
				withLowDailyCap(t, tc.cap)
			}
			for i := 0; i < tc.used; i++ {
				db.IncrementAbuseQueryCount(time.Now().UTC().Format("2006-01-02"))
			}
			if tc.cached {
				saveReputationCache(cfg.StatePath, &reputationCache{Entries: map[string]*reputationEntry{
					"198.51.100.1": {Score: 10, CheckedAt: time.Now().Add(-time.Hour)},
				}})
			}
			cfg.Reputation.Upstream.Enabled = tc.upstream
			cfg.Reputation.Upstream.URL = "https://intel.example.test"
			withDefaultHTTPTransport(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = fmt.Fprintf(w, `{"ip":%q,"score":80}`, r.URL.Query().Get("ip"))
			}))
			withReputationQueueTransport(t, roundTripFunc(func(r *http.Request) (*http.Response, error) {
				return reputationQueueResponse(r, tc.status, io.NopCloser(strings.NewReader(fmt.Sprintf(`{"data":{"abuseConfidenceScore":%d}}`, tc.score)))), nil
			}))
			before := time.Now()
			findings := CheckIPReputation(context.Background(), cfg, nil)
			after := time.Now()
			var count int
			for _, f := range findings {
				if f.Check != "ip_reputation" {
					continue
				}
				count++
				if f.Intel == nil || f.Intel.Source != tc.wantSource || f.Intel.Expires.Before(before.Add(cacheExpiry)) || f.Intel.Expires.After(after.Add(cacheExpiry)) {
					t.Fatalf("intel %+v, want %s expiring within the query interval", f.Intel, tc.wantSource)
				}
				if tc.wantSource == "abuseipdb" {
					entry, ok := db.AllReputation()[f.SourceIP]
					if !ok || !f.Intel.Expires.Equal(entry.CheckedAt.Add(cacheExpiry)) {
						t.Fatalf("fresh intel %+v differs from its cache expiry %+v", f.Intel, entry)
					}
				}
			}
			if count != tc.count {
				t.Fatalf("reputation findings %d, want %d", count, tc.count)
			}
		})
	}
}

func TestReputationIntelIgnoresLapsedEvidence(t *testing.T) {
	for _, tc := range []struct {
		name       string
		checkedAgo time.Duration
		cache      bool
		wantSource string
	}{
		{name: "missing cache", wantSource: "upstream"},
		{name: "fresh cache", cache: true, checkedAgo: time.Hour, wantSource: "abuseipdb"},
		{name: "expired cache", cache: true, checkedAgo: 7 * time.Hour, wantSource: "upstream"},
		{name: "future cache", cache: true, checkedAgo: -time.Hour, wantSource: "upstream"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, db := reputationQueueFixture(t, 1)
			t.Cleanup(SetGlobalThreatDBForTest(t.TempDir()))
			threatDB := GetThreatDB()
			threatDB.badIPs["198.51.100.1"] = "expired-list"
			threatDB.badIPExpiry["198.51.100.1"] = time.Now().Add(-time.Hour)
			checked := time.Now().Add(-tc.checkedAgo).Truncate(time.Second)
			if tc.cache {
				if err := db.SetReputation("198.51.100.1", store.ReputationEntry{Score: 90, CheckedAt: checked}); err != nil {
					t.Fatal(err)
				}
			}
			cfg.Reputation.AbuseIPDBKey = ""
			cfg.Reputation.Upstream.Enabled = true
			cfg.Reputation.Upstream.URL = "https://intel.example.test"
			withDefaultHTTPTransport(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = fmt.Fprintf(w, `{"ip":%q,"score":80}`, r.URL.Query().Get("ip"))
			}))
			before := time.Now()
			findings := CheckIPReputation(context.Background(), cfg, nil)
			after := time.Now()
			f := reputationFindingFor(t, findings, "198.51.100.1")
			if f.Intel == nil || f.Intel.Source != tc.wantSource {
				t.Fatalf("intel %+v, want %s instead of lapsed evidence", f.Intel, tc.wantSource)
			}
			if tc.wantSource == "abuseipdb" {
				if !f.Intel.Expires.Equal(checked.Add(6 * time.Hour)) {
					t.Fatalf("cached expiry %v does not match its original lifetime", f.Intel.Expires)
				}
			} else if f.Intel.Expires.Before(before.Add(6*time.Hour)) || f.Intel.Expires.After(after.Add(6*time.Hour)) {
				t.Fatalf("supplemental expiry %v does not match its new lifetime", f.Intel.Expires)
			}
		})
	}
}
