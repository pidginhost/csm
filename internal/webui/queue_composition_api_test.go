package webui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/mailfwd/intel"
)

type fakeQueueReporter struct {
	comp intel.QueueComposition
	err  error
}

func (f fakeQueueReporter) Composition() (intel.QueueComposition, error) { return f.comp, f.err }

func TestApiEmailQueueCompositionSerialization(t *testing.T) {
	s := newTestServer(t, "tok")
	s.queueReporter = fakeQueueReporter{comp: intel.QueueComposition{
		Total: 4, Bounce: 3, Real: 1, Frozen: 1, OldestAge: "4d",
		TopRecipients: []intel.RecipientCount{{Address: "victim@yahoo.com", Count: 2}},
	}}

	w := httptest.NewRecorder()
	s.apiEmailQueueComposition(w, httptest.NewRequest(http.MethodGet, "/api/v1/email/queue-composition", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{`"total": 4`, `"bounce": 3`, `"frozen": 1`, `"oldest_age": "4d"`, `victim@yahoo.com`} {
		if !strings.Contains(body, want) {
			t.Errorf("response missing %q\nbody: %s", want, body)
		}
	}
}

func TestApiEmailQueueCompositionEmptyArraysWhenNoReporter(t *testing.T) {
	s := newTestServer(t, "tok")
	s.queueReporter = nil

	w := httptest.NewRecorder()
	s.apiEmailQueueComposition(w, httptest.NewRequest(http.MethodGet, "/api/v1/email/queue-composition", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if !jsonHasEmptyArray(t, w.Body.String(), "top_recipients") {
		t.Errorf("top_recipients not an empty array: %s", w.Body.String())
	}
}

func TestApiEmailQueueCompositionReporterError(t *testing.T) {
	s := newTestServer(t, "tok")
	s.queueReporter = fakeQueueReporter{err: errForwarderTest}

	w := httptest.NewRecorder()
	s.apiEmailQueueComposition(w, httptest.NewRequest(http.MethodGet, "/api/v1/email/queue-composition", nil))

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", w.Code)
	}
}

func TestApiEmailQueueCompositionMethodNotAllowed(t *testing.T) {
	s := newTestServer(t, "tok")
	s.queueReporter = intel.EmptyQueueReporter{}

	w := httptest.NewRecorder()
	s.apiEmailQueueComposition(w, httptest.NewRequest(http.MethodPost, "/api/v1/email/queue-composition", nil))

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", w.Code)
	}
}
