package webui

import (
	"bufio"
	"bytes"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/session"
)

func auditActorServer(t *testing.T) *Server {
	t.Helper()
	s := newTestServer(t, "")
	s.cfg.WebUI.Tokens = []config.WebUIToken{
		{Name: "alice", Token: "alice-admin-token-0123456789abcdef", Scope: "admin"},
		{Name: "phpanel", Token: "phpanel-admin-token-0123456789abc", Scope: "admin"},
	}
	return s
}

// The Audit page shows who acted and exports it with the row.
func TestAuditPageShowsAndExportsTheActor(t *testing.T) {
	src, err := os.ReadFile("../../ui/static/js/audit.js")
	if err != nil {
		t.Fatal(err)
	}
	text := string(src)
	for _, fragment := range []string{
		`<th>Details</th><th>By</th><th>Admin IP</th>`,
		`CSM.esc(auditActorLabel(e))`,
		`{key: 'actor',    label: 'By'},`,
		`actor:    cells[4].textContent.trim(),`,
		`admin_ip: cells[5].textContent.trim()`,
		`if (cells.length < 6) return;`,
	} {
		if !strings.Contains(text, fragment) {
			t.Errorf("audit.js missing actor fragment %q", fragment)
		}
	}
}

func TestAuditLogNamesTheAPICredential(t *testing.T) {
	s := auditActorServer(t)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/block-ip", nil)
	r.Header.Set("Authorization", "Bearer phpanel-admin-token-0123456789abc")
	s.auditLog(r, "block", "203.0.113.9", "")

	entries := readUIAuditLog(s.cfg.StatePath, 1)
	if len(entries) != 1 {
		t.Fatalf("entries = %d", len(entries))
	}
	if entries[0].Actor != "phpanel" || entries[0].Via != "api" {
		t.Fatalf("actor=%q via=%q, want phpanel over api", entries[0].Actor, entries[0].Via)
	}
}

func TestAuditLogNamesTheBrowserLogin(t *testing.T) {
	s := auditActorServer(t)
	secret, _, err := s.sessions.Create("alice", session.Hash("alice-admin-token-0123456789abcdef"), "", "192.0.2.10", "test", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "/api/v1/block-ip", nil)
	r.AddCookie(&http.Cookie{Name: "csm_auth", Value: secret})
	s.auditLog(r, "block", "203.0.113.9", "")

	entries := readUIAuditLog(s.cfg.StatePath, 1)
	if len(entries) != 1 || entries[0].Actor != "alice" || entries[0].Via != "browser" {
		t.Fatalf("entries = %+v, want alice over browser", entries)
	}
}

// A dropped audit entry must leave an operator-visible trace, as the
// firewall audit writer already does.
func TestAuditLogReportsAnEntryItCannotWrite(t *testing.T) {
	s := auditActorServer(t)
	blocked := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(blocked, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	s.cfg.StatePath = blocked

	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	s.auditLog(httptest.NewRequest(http.MethodPost, "/", nil), "block", "203.0.113.9", "")
	if !strings.Contains(buf.String(), "audit") {
		t.Fatalf("dropped audit entry left no log line: %q", buf.String())
	}
}

// Two writers that both see an oversized log must rotate it once. Rotating
// twice renames the fresh file over the archived one and loses the history.
func TestAuditLogRotationKeepsHistoryUnderConcurrentWriters(t *testing.T) {
	s := auditActorServer(t)
	path := filepath.Join(s.cfg.StatePath, uiAuditFile)
	history := bytes.Repeat([]byte(`{"action":"old"}`+"\n"), maxUIAuditSize/16+1)
	if err := os.WriteFile(path, history, 0600); err != nil {
		t.Fatal(err)
	}

	const writers = 32
	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.auditLog(httptest.NewRequest(http.MethodPost, "/", nil), "block", "203.0.113.9", "")
		}()
	}
	wg.Wait()

	archived, err := os.ReadFile(path + ".1")
	if err != nil || !bytes.Equal(archived, history) {
		t.Fatalf("rotated history lost: %d bytes, err=%v", len(archived), err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	lines := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		lines++
	}
	if lines != writers {
		t.Fatalf("current log has %d entries, want %d", lines, writers)
	}
}

func TestAuditActorMatchesAuthorizationAndSurvivesRevocation(t *testing.T) {
	for _, revoke := range []bool{false, true} {
		t.Run(fmt.Sprint(revoke), func(t *testing.T) {
			s := auditActorServer(t)
			readToken := newSuppressionID()
			s.cfg.WebUI.Tokens = append(s.cfg.WebUI.Tokens, config.WebUIToken{Name: "reader", Token: readToken, Scope: "read"})
			secret, rec, err := s.sessions.Create("alice", session.Hash(s.cfg.WebUI.Tokens[0].Token), "", "192.0.2.10", "test", time.Now())
			if err != nil {
				t.Fatal(err)
			}
			r := httptest.NewRequest(http.MethodPost, "/api/v1/dismiss", nil)
			r.AddCookie(&http.Cookie{Name: "csm_auth", Value: secret})
			if !revoke {
				r.Header.Set("Authorization", "Bearer "+readToken)
			}
			w := httptest.NewRecorder()
			s.requireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if revoke {
					if err := s.sessions.Revoke(rec.ID); err != nil {
						t.Fatal(err)
					}
				}
				s.auditLog(r, "dismiss", "webshell:test", "")
			})).ServeHTTP(w, r)
			entries := readUIAuditLog(s.cfg.StatePath, 1)
			if len(entries) != 1 || entries[0].Actor != "alice" || entries[0].Via != "browser" {
				t.Fatalf("audit must retain the authorizing browser actor: %+v", entries)
			}
		})
	}
}

func TestAuditLargeDismissDoesNotHideSubsequentActions(t *testing.T) {
	s := auditActorServer(t)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/dismiss", nil)
	s.auditLog(r, "dismiss", "webshell:"+strings.Repeat("x", 300*1024), "")
	s.auditLog(r, "block", "192.0.2.1", "")
	entries := readUIAuditLog(s.cfg.StatePath, 2)
	if len(entries) != 2 || entries[0].Action != "block" || entries[1].Action != "dismiss" {
		t.Fatal("a large dismissal hid audit entries")
	}
}
