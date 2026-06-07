package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/mailfwd/quarantine"
)

type fakeHeldStore struct {
	msgs       []quarantine.HeldMessage
	listErr    error
	released   []string
	deleted    []string
	releaseErr error
	deleteErr  error
}

func (f *fakeHeldStore) List() ([]quarantine.HeldMessage, error) { return f.msgs, f.listErr }
func (f *fakeHeldStore) Release(id string) error {
	if f.releaseErr != nil {
		return f.releaseErr
	}
	f.released = append(f.released, id)
	return nil
}
func (f *fakeHeldStore) Delete(id string) error {
	if f.deleteErr != nil {
		return f.deleteErr
	}
	f.deleted = append(f.deleted, id)
	return nil
}

func TestApiEmailHeldListSerialization(t *testing.T) {
	s := newTestServer(t, "tok")
	s.forwardHeld = &fakeHeldStore{msgs: []quarantine.HeldMessage{
		{ID: "1.1.csm", Forwarder: "sales@shop.example", Recipient: "owner@yahoo.com", Reasons: []string{"bounce_backscatter"}},
	}}
	w := httptest.NewRecorder()
	s.apiEmailHeldList(w, httptest.NewRequest(http.MethodGet, "/api/v1/email/held", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var got []quarantine.HeldMessage
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Forwarder != "sales@shop.example" || got[0].Recipient != "owner@yahoo.com" {
		t.Errorf("held list = %+v", got)
	}
}

func TestApiEmailHeldListEmptyWhenNoStore(t *testing.T) {
	s := newTestServer(t, "tok")
	s.forwardHeld = nil
	w := httptest.NewRecorder()
	s.apiEmailHeldList(w, httptest.NewRequest(http.MethodGet, "/api/v1/email/held", nil))
	if w.Code != http.StatusOK || strings.TrimSpace(w.Body.String()) != "[]" {
		t.Errorf("want empty array, got %d %q", w.Code, w.Body.String())
	}
}

func TestApiEmailHeldRelease(t *testing.T) {
	s := newTestServer(t, "tok")
	fake := &fakeHeldStore{}
	s.forwardHeld = fake
	w := httptest.NewRecorder()
	s.apiEmailHeldAction(w, httptest.NewRequest(http.MethodPost, "/api/v1/email/held/1.1.csm/release", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if len(fake.released) != 1 || fake.released[0] != "1.1.csm" {
		t.Errorf("released = %v", fake.released)
	}
	// audit-logged
	data, _ := os.ReadFile(filepath.Join(s.cfg.StatePath, uiAuditFile))
	if !strings.Contains(string(data), "email_held_release") {
		t.Errorf("release not audit-logged: %s", data)
	}
}

func TestApiEmailHeldDelete(t *testing.T) {
	s := newTestServer(t, "tok")
	fake := &fakeHeldStore{}
	s.forwardHeld = fake
	w := httptest.NewRecorder()
	s.apiEmailHeldAction(w, httptest.NewRequest(http.MethodDelete, "/api/v1/email/held/1.1.csm", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if len(fake.deleted) != 1 || fake.deleted[0] != "1.1.csm" {
		t.Errorf("deleted = %v", fake.deleted)
	}
}

func TestApiEmailHeldReleaseErrorSurfaces(t *testing.T) {
	s := newTestServer(t, "tok")
	s.forwardHeld = &fakeHeldStore{releaseErr: errForwarderTest}
	w := httptest.NewRecorder()
	s.apiEmailHeldAction(w, httptest.NewRequest(http.MethodPost, "/api/v1/email/held/1.1.csm/release", nil))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", w.Code)
	}
}

func TestApiEmailHeldActionUnavailableWhenNoStore(t *testing.T) {
	s := newTestServer(t, "tok")
	s.forwardHeld = nil
	w := httptest.NewRecorder()
	s.apiEmailHeldAction(w, httptest.NewRequest(http.MethodPost, "/api/v1/email/held/1.1.csm/release", nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", w.Code)
	}
}

func TestApiEmailHeldListMethodNotAllowed(t *testing.T) {
	s := newTestServer(t, "tok")
	s.forwardHeld = &fakeHeldStore{}
	w := httptest.NewRecorder()
	s.apiEmailHeldList(w, httptest.NewRequest(http.MethodPost, "/api/v1/email/held", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", w.Code)
	}
}
