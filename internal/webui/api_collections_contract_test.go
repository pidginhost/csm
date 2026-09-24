package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/store"
)

// collectionRoutes are the GET routes that answer a list. Each answers an
// object with the list under "items", never a bare array, and an empty list
// is [] rather than null.
var collectionRoutes = []string{
	"/api/v1/scan-jobs",
	"/api/v1/findings",
	"/api/v1/findings/enriched",
	"/api/v1/history",
	"/api/v1/stats/trend",
	"/api/v1/stats/timeline",
	"/api/v1/blocked-ips",
	"/api/v1/components",
	"/api/v1/quarantine",
	"/api/v1/modsec/blocks",
	"/api/v1/modsec/events",
	"/api/v1/modsec/rules",
	"/api/v1/modsec/rules/escalation",
	"/api/v1/verified-bots",
	"/api/v1/accounts",
	"/api/v1/incident?ip=203.0.113.5",
	"/api/v1/incidents",
	"/api/v1/incidents?limit=10",
	"/api/v1/incidents/groups",
	"/api/v1/email/quarantine",
	"/api/v1/email/groups",
	"/api/v1/email/relay-abuse",
	"/api/v1/email/forwarders",
	"/api/v1/email/held",
	"/api/v1/threat/top-attackers",
	"/api/v1/threat/events?ip=203.0.113.5",
	"/api/v1/threat/whitelist",
	"/api/v1/audit",
	"/api/v1/rules/list",
	"/api/v1/suppressions",
	"/api/v1/firewall/audit",
	"/api/v1/firewall/subnets",
	"/api/v1/db-object-backups",
	"/api/v1/prefs/views",
	"/api/v1/sessions",
}

func TestCollectionsAnswerItems(t *testing.T) {
	s := newUIServer(t)
	db, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	previous := store.Global()
	store.SetGlobal(db)
	t.Cleanup(func() { store.SetGlobal(previous); _ = db.Close() })
	s.cfg.ConfigFile = filepath.Join(t.TempDir(), "csm.yaml")
	if err := os.WriteFile(s.cfg.ConfigFile, []byte("hostname: host.example.test\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cookie := loginBrowser(t, s, "admin-secret", nil)
	for _, path := range collectionRoutes {
		req := httptest.NewRequest("GET", path, nil)
		req.AddCookie(cookie)
		w := httptest.NewRecorder()
		s.httpSrv.Handler.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("%s: status = %d, body %s", path, w.Code, w.Body.String())
			continue
		}
		var body map[string]json.RawMessage
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Errorf("%s: body is not an object: %s", path, w.Body.String())
			continue
		}
		var items []json.RawMessage
		raw, ok := body["items"]
		if !ok || json.Unmarshal(raw, &items) != nil || items == nil {
			t.Errorf("%s: items = %s, want a list; body %s", path, raw, w.Body.String())
			continue
		}
		if raw, ok := body["total"]; ok {
			var total int
			if err := json.Unmarshal(raw, &total); err != nil || total < len(items) {
				t.Errorf("%s: total = %s with %d items", path, raw, len(items))
			}
		}
	}
}

// A collection that holds every item says how many there are.
func TestWriteAllCountsTheItems(t *testing.T) {
	w := httptest.NewRecorder()
	writeAll(w, []string{"a", "b"})
	if strings.TrimSpace(w.Body.String()) != `{"items":["a","b"],"total":2}` {
		t.Errorf("body = %s", w.Body.String())
	}
	w = httptest.NewRecorder()
	var none []int
	writeAll(w, none)
	if strings.TrimSpace(w.Body.String()) != `{"items":[],"total":0}` {
		t.Errorf("empty body = %s", w.Body.String())
	}
}
