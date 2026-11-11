package webui

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/store"
)

type fakeSuspensions struct {
	rows       []MailboxSuspensionRow
	releaseErr error
	released   []string
	actors     []string
}

func (f *fakeSuspensions) ListSuspensions() ([]MailboxSuspensionRow, error) { return f.rows, nil }
func (f *fakeSuspensions) ReleaseSuspension(id, actor string) error {
	if f.releaseErr != nil {
		return f.releaseErr
	}
	f.released = append(f.released, id)
	f.actors = append(f.actors, actor)
	return nil
}

const testSuspensionID = "0123456789abcdef"

func releaseRequest(id string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/api/v1/email/suspensions/"+id+"/release", nil)
	return withAuditActor(r, "alice", "browser", "admin")
}

func TestEmailSuspensionsList_NoServiceReturnsEmpty(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	s.apiEmailSuspensionsList(w, httptest.NewRequest(http.MethodGet, "/api/v1/email/suspensions", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	assertEmptyItems(t, w.Body.Bytes())
}

func TestEmailSuspensionsList_ReturnsRows(t *testing.T) {
	s := newTestServer(t, "tok")
	s.SetMailboxSuspensions(&fakeSuspensions{rows: []MailboxSuspensionRow{{
		MailboxSuspension: store.MailboxSuspension{
			ID: testSuspensionID, Backend: "cpanel", Subject: "real@victim.example", Kind: store.SuspensionKindMailbox,
			Account: "cpuser", Applied: []string{store.AppliedSuspendLogin}, Check: "mail_account_compromised",
			SuspendedAt: time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC),
		},
		Active: true,
	}}})
	w := httptest.NewRecorder()
	s.apiEmailSuspensionsList(w, httptest.NewRequest(http.MethodGet, "/api/v1/email/suspensions", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var got []MailboxSuspensionRow
	decodeItems(t, w.Body.Bytes(), &got)
	if len(got) != 1 || got[0].Subject != "real@victim.example" || !got[0].Active || got[0].ID != testSuspensionID {
		t.Fatalf("rows = %+v", got)
	}
	if body := w.Body.String(); !strings.Contains(body, `"active":true`) || !strings.Contains(body, `"subject":"real@victim.example"`) {
		t.Fatalf("body = %s", body)
	}
}

func TestEmailSuspensionsList_MethodNotAllowed(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	s.apiEmailSuspensionsList(w, httptest.NewRequest(http.MethodPost, "/api/v1/email/suspensions", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", w.Code)
	}
}

func TestEmailSuspensionRelease_RejectsBadID(t *testing.T) {
	s := newTestServer(t, "tok")
	fake := &fakeSuspensions{}
	s.SetMailboxSuspensions(fake)
	for _, id := range []string{"..%2f..%2fetc", "ZZZZZZZZZZZZZZZZ", "0123456789abcde", "0123456789abcdef0"} {
		w := httptest.NewRecorder()
		s.apiEmailSuspensionAction(w, releaseRequest(id))
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400", id, w.Code)
		}
	}
	if len(fake.released) != 0 {
		t.Fatalf("a bad ID reached the service: %v", fake.released)
	}
}

func TestEmailSuspensionRelease_StatusCodes(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want int
	}{
		{fmt.Errorf("%w: %s", store.ErrMailboxSuspensionNotFound, testSuspensionID), http.StatusNotFound},
		{ErrSuspensionReleased, http.StatusConflict},
		{errors.New("uapi Email unsuspend_login: busy"), http.StatusInternalServerError},
	} {
		s := newTestServer(t, "tok")
		s.SetMailboxSuspensions(&fakeSuspensions{releaseErr: tc.err})
		w := httptest.NewRecorder()
		s.apiEmailSuspensionAction(w, releaseRequest(testSuspensionID))
		if w.Code != tc.want {
			t.Errorf("%v: status = %d, want %d", tc.err, w.Code, tc.want)
		}
	}
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	s.apiEmailSuspensionAction(w, releaseRequest(testSuspensionID))
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("no service: status = %d, want 503", w.Code)
	}
}

func TestEmailSuspensionRelease_PassesActorAndAudits(t *testing.T) {
	s := newTestServer(t, "tok")
	fake := &fakeSuspensions{}
	s.SetMailboxSuspensions(fake)
	w := httptest.NewRecorder()
	s.apiEmailSuspensionAction(w, releaseRequest(testSuspensionID))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), testSuspensionID) {
		t.Fatalf("status = %d, body %s", w.Code, w.Body.String())
	}
	if len(fake.released) != 1 || fake.released[0] != testSuspensionID || fake.actors[0] != "alice" {
		t.Fatalf("released %v by %v, want the ID by alice", fake.released, fake.actors)
	}
	data, _ := os.ReadFile(filepath.Join(s.cfg.StatePath, uiAuditFile))
	if !strings.Contains(string(data), "email_mailbox_release") || !strings.Contains(string(data), testSuspensionID) {
		t.Fatalf("audit log = %s", data)
	}
}

func TestEmailSuspensionRelease_MethodAndAction(t *testing.T) {
	s := newTestServer(t, "tok")
	fake := &fakeSuspensions{}
	s.SetMailboxSuspensions(fake)
	w := httptest.NewRecorder()
	s.apiEmailSuspensionAction(w, httptest.NewRequest(http.MethodGet, "/api/v1/email/suspensions/"+testSuspensionID+"/release", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET: status = %d, want 405", w.Code)
	}
	w = httptest.NewRecorder()
	s.apiEmailSuspensionAction(w, httptest.NewRequest(http.MethodPost, "/api/v1/email/suspensions/"+testSuspensionID+"/delete", nil))
	if w.Code != http.StatusBadRequest {
		t.Errorf("unknown action: status = %d, want 400", w.Code)
	}
	if len(fake.released) != 0 {
		t.Fatalf("a refused request released %v", fake.released)
	}
}
