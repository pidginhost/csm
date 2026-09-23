package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/attackdb"
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/state"
	"github.com/pidginhost/csm/internal/store"
)

// timeKey reports whether a JSON key names an instant.
func timeKey(k string) bool {
	switch k {
	case "timestamp", "time", "ts", "created", "started", "finished", "expires", "updated", "from", "to",
		"last_hit", "last_refresh", "last_update", "last_critical", "latest_scan", "last_scan_time",
		"brute_force_window_start":
		return true
	}
	return strings.HasSuffix(k, "_at") || strings.HasSuffix(k, "_seen")
}

// staleTimeKey reports keys the API no longer sends: text the server
// computed from the clock ("5m ago", "1h2m", "24h0m0s") and second copies of
// an instant. Clients compute relative times and format durations themselves.
func staleTimeKey(k string) bool {
	switch k {
	case "time_ago", "expires_in", "uptime", "elapsed", "duration", "oldest_age", "update_interval", "hour":
		return true
	}
	return strings.HasSuffix(k, "_ago") || strings.HasSuffix(k, "_iso")
}

// timeContractProblems walks a JSON body. Every instant is an RFC 3339
// string in UTC ("Z"), and a time that is not set is absent or null, never
// the Go zero time.
func timeContractProblems(body []byte) []string {
	var v any
	if err := json.Unmarshal(body, &v); err != nil {
		return []string{"body is not JSON"}
	}
	var problems []string
	var walk func(path string, v any)
	walk = func(path string, v any) {
		switch x := v.(type) {
		case map[string]any:
			keys := make([]string, 0, len(x))
			for k := range x {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				p := path + "." + k
				if staleTimeKey(k) {
					problems = append(problems, p+" is a server-rendered time; send an instant or *_seconds")
				}
				if _, ok := x[k].(float64); ok && timeKey(k) {
					problems = append(problems, p+" is a number; send an RFC 3339 instant")
				}
				if s, ok := x[k].(string); ok && timeKey(k) {
					ts, err := time.Parse(time.RFC3339Nano, s)
					switch {
					case err != nil:
						problems = append(problems, p+" = "+strconv.Quote(s)+" is not an RFC 3339 instant")
					case !strings.HasSuffix(s, "Z"):
						problems = append(problems, p+" = "+strconv.Quote(s)+" is not in UTC")
					case ts.IsZero():
						problems = append(problems, p+" is the zero time; omit a time that is not set")
					}
				}
				walk(p, x[k])
			}
		case []any:
			for _, e := range x {
				walk(path+"[]", e)
			}
		}
	}
	walk("", v)
	return problems
}

func assertTimeContract(t *testing.T, name string, body []byte) {
	t.Helper()
	for _, p := range timeContractProblems(body) {
		t.Errorf("%s: %s", name, p)
	}
}

type zonedProvider struct {
	*stubComponentsProvider
	at time.Time
}

func (p zonedProvider) StartedAt() time.Time  { return p.at }
func (p zonedProvider) LatestScan() time.Time { return p.at }
func (p zonedProvider) BaselineAt() time.Time { return p.at }

// Every GET route answers instants in one form: RFC 3339 in UTC with
// sub-second precision. Data here is recorded in a +03:00 host zone, the way
// time.Now() stamps it on a server that does not run in UTC.
func TestResponseTimesAreUTCInstants(t *testing.T) {
	zone := time.FixedZone("host", 3*3600)
	at := time.Now().In(zone).Add(-time.Hour).Truncate(time.Millisecond).Add(123 * time.Microsecond)

	s := newUIServer(t)
	db, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	previous := store.Global()
	store.SetGlobal(db)
	t.Cleanup(func() { store.SetGlobal(previous); _ = db.Close() })
	s.sessionNow = func() time.Time { return time.Now().In(zone) }
	s.startTime = at
	s.provider = zonedProvider{stubComponentsProvider: &stubComponentsProvider{
		statuses: map[string]bool{"fanotify": true},
		changed:  map[string]time.Time{"fanotify": at},
	}, at: at}
	s.cfg.Firewall = firewall.DefaultConfig()
	s.cfg.ConfigFile = filepath.Join(t.TempDir(), "csm.yaml")
	if err := os.WriteFile(s.cfg.ConfigFile, []byte("hostname: host.example.test\n"), 0600); err != nil {
		t.Fatal(err)
	}

	shell := alert.Finding{Severity: alert.Critical, Check: "webshell", Message: "shell in /home/alice/public_html/a.php from 203.0.113.9",
		FilePath: "/home/alice/public_html/a.php", Timestamp: at}
	relay := alert.Finding{Severity: alert.High, Check: "email_php_relay_abuse", Message: "relay", Path: "/home/alice/public_html/m.php", Timestamp: at}
	s.store.Update([]alert.Finding{shell})
	s.store.SetLatestFindings([]alert.Finding{shell})
	if err := db.AppendHistory([]alert.Finding{shell, relay, modsecBlock("203.0.113.9", "site.example.com", "/x", "900112", at)}); err != nil {
		t.Fatal(err)
	}
	if err := s.store.SaveSuppressions([]state.SuppressionRule{{ID: "sup-1", Check: "perf_load", Reason: "noise", CreatedAt: at}}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.incidentCorrelator.OnFinding(shell); err != nil {
		t.Fatal(err)
	}
	if err := db.PutScanJob(store.ScanJobRecord{ID: "job-1", Scope: "account", Target: "alice", State: "queued", Created: at}); err != nil {
		t.Fatal(err)
	}
	if err := db.PutDBObjectBackup(store.DBObjectBackup{Account: "alice", Schema: "alice_wp", Kind: "trigger", Name: "t1",
		CreateSQL: "CREATE TRIGGER t1", DroppedAt: at, DroppedBy: "csm"}); err != nil {
		t.Fatal(err)
	}
	seedAttackDB(t, map[string]*attackdb.IPRecord{"203.0.113.9": {IP: "203.0.113.9", ThreatScore: 50, EventCount: 1, FirstSeen: at, LastSeen: at}})
	writeFirewallAudit(t, s.cfg.StatePath, []firewall.AuditEntry{{Timestamp: at, Action: "block", IP: "203.0.113.9", Duration: "24h0m0s"}})
	fwState := firewall.FirewallState{
		Blocked:    []firewall.BlockedEntry{{IP: "203.0.113.9", Reason: "scanner", BlockedAt: at, ExpiresAt: at.Add(48 * time.Hour)}},
		BlockedNet: []firewall.SubnetEntry{{CIDR: "198.51.100.0/24", Reason: "scanner", BlockedAt: at, ExpiresAt: at.Add(48 * time.Hour)}},
		Allowed:    []firewall.AllowedEntry{{IP: "192.0.2.10", Reason: "office", ExpiresAt: at.Add(48 * time.Hour)}},
	}
	raw, _ := json.Marshal(fwState)
	if err := os.MkdirAll(filepath.Join(s.cfg.StatePath, "firewall"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.cfg.StatePath, "firewall", "state.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	qdir := t.TempDir()
	withQuarantineDir(t, qdir)
	meta, _ := json.Marshal(map[string]any{"original_path": "/home/alice/public_html/a.php", "size": 10,
		"quarantined_at": at.Format(time.RFC3339Nano), "reason": "webshell"})
	if err := os.WriteFile(filepath.Join(qdir, "20260922-100000_a.php.meta"), meta, 0600); err != nil {
		t.Fatal(err)
	}

	loginBrowser(t, s, "admin-secret", nil)
	serve := func(method, path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer admin-secret")
		w := httptest.NewRecorder()
		s.httpSrv.Handler.ServeHTTP(w, req)
		return w
	}
	if w := serve("PUT", "/api/v1/prefs/views", `{"page":"findings","name":"mine","params":{"severity":"critical"}}`); w.Code != http.StatusOK {
		t.Fatalf("save view: %d %s", w.Code, w.Body.String())
	}
	s.auditLog(httptest.NewRequest("GET", "/", nil), "block_ip", "203.0.113.9", "seed")

	for _, path := range []string{
		"/api/v1/status", "/api/v1/health", "/api/v1/components",
		"/api/v1/findings", "/api/v1/findings/enriched", "/api/v1/history", "/api/v1/stats",
		"/api/v1/stats/timeline", "/api/v1/finding-detail?check=webshell&message=" + strings.ReplaceAll(shell.Message, " ", "+"),
		"/api/v1/account?name=alice", "/api/v1/quarantine", "/api/v1/blocked-ips", "/api/v1/export",
		"/api/v1/db-object-backups", "/api/v1/scan-jobs",
		"/api/v1/firewall/allowed", "/api/v1/firewall/subnets", "/api/v1/firewall/audit",
		"/api/v1/incident?ip=203.0.113.9", "/api/v1/incidents", "/api/v1/incidents/groups?status=all",
		"/api/v1/modsec/blocks", "/api/v1/modsec/events",
		"/api/v1/threat/top-attackers", "/api/v1/threat/ip?ip=203.0.113.9", "/api/v1/threat/stats",
		"/api/v1/suppressions", "/api/v1/audit", "/api/v1/sessions", "/api/v1/prefs/views",
		"/api/v1/email/groups", "/api/v1/email/relay-abuse", "/api/v1/verified-bots",
		"/api/v1/rules/status", "/api/v1/performance", "/api/v1/threat/db-stats", "/api/v1/hardening",
		"/api/v1/settings/firewall/rollback", "/api/v1/email/deferrals", "/api/v1/email/queue-composition",
		"/api/v1/email/stats", "/api/v1/firewall/check?ip=203.0.113.9", "/api/v1/undo/pending",
		"/api/v1/challenge/stats", "/api/v1/modsec/rules",
	} {
		w := serve("GET", path, "")
		if w.Code != http.StatusOK {
			t.Errorf("%s: status %d %s", path, w.Code, w.Body.String())
			continue
		}
		assertTimeContract(t, path, w.Body.Bytes())
	}
}

// The checker itself: it must catch each form the API used to send.
func TestTimeContractCatchesOldForms(t *testing.T) {
	for _, body := range []string{
		`{"timestamp":"2026-09-22T13:04:05+03:00"}`,
		`{"items":[{"last_seen":"13:04:05"}]}`,
		`{"started":"0001-01-01T00:00:00Z"}`,
		`{"changed_ago":"5m ago"}`,
		`{"time_iso":"2026-09-22T10:04:05Z"}`,
		`{"uptime":"3h2m1s"}`,
		`{"expires_in":"1h2m"}`,
		`{"items":[{"updated":1779743255}]}`,
	} {
		if len(timeContractProblems([]byte(body))) == 0 {
			t.Errorf("checker accepted %s", body)
		}
	}
	good := `{"items":[{"blocked_at":"2026-09-22T10:04:05.000123Z","expires_at":null,"count":3}],"total":1}`
	if p := timeContractProblems([]byte(good)); len(p) != 0 {
		t.Errorf("checker refused a valid body: %v", p)
	}
}
