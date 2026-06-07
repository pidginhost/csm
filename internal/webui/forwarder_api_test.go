package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pidginhost/csm/internal/mailfwd/inventory"
)

// fakeForwarderSource is an inventory.Source whose result is fixed by the test.
type fakeForwarderSource struct {
	fwds []inventory.Forwarder
	err  error
}

func (f fakeForwarderSource) Forwarders() ([]inventory.Forwarder, error) {
	return f.fwds, f.err
}

func decodeForwarders(t *testing.T, body []byte) forwardersResponse {
	t.Helper()
	var resp forwardersResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("unmarshal response: %v\nbody: %s", err, body)
	}
	return resp
}

func TestApiEmailForwardersSerialization(t *testing.T) {
	s := newTestServer(t, "tok")
	s.forwarderSource = fakeForwarderSource{fwds: []inventory.Forwarder{
		{
			Source: "sales@shop.example",
			Domain: "shop.example",
			Owner:  "shopuser",
			Destinations: []inventory.Destination{
				{Address: "owner@yahoo.com", Domain: "yahoo.com", Provider: inventory.ProviderYahoo},
			},
			ForwardOnly: true,
		},
		{
			Source: "team@corp.example",
			Domain: "corp.example",
			Owner:  "corpuser",
			Destinations: []inventory.Destination{
				{Address: "team@corp.example", Domain: "corp.example", Provider: inventory.ProviderLocal},
				{Address: "ext@partner.example", Domain: "partner.example", Provider: inventory.ProviderExternal},
				{Address: "boss@gmail.com", Domain: "gmail.com", Provider: inventory.ProviderGmail},
			},
			KeepLocal: true,
		},
	}}

	w := httptest.NewRecorder()
	s.apiEmailForwarders(w, httptest.NewRequest(http.MethodGet, "/api/v1/email/forwarders", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	resp := decodeForwarders(t, w.Body.Bytes())

	if len(resp.Forwarders) != 2 {
		t.Fatalf("forwarders len = %d, want 2", len(resp.Forwarders))
	}

	// First: forward-only free-provider relay (the reputation-risk case).
	a := resp.Forwarders[0]
	if a.Source != "sales@shop.example" || a.Domain != "shop.example" || a.Owner != "shopuser" {
		t.Errorf("forwarder[0] identity = %+v", a)
	}
	if !a.ForwardOnly || a.KeepLocal {
		t.Errorf("forwarder[0] keep/forward flags = keep=%v forward=%v, want forward-only", a.KeepLocal, a.ForwardOnly)
	}
	if !a.HasExternal || !a.HasFreeProvider {
		t.Errorf("forwarder[0] has_external=%v has_free_provider=%v, want both true", a.HasExternal, a.HasFreeProvider)
	}
	if len(a.Destinations) != 1 || a.Destinations[0].Provider != "yahoo" || a.Destinations[0].Address != "owner@yahoo.com" {
		t.Errorf("forwarder[0] destinations = %+v", a.Destinations)
	}
	if len(a.Providers) != 1 || a.Providers[0] != "yahoo" {
		t.Errorf("forwarder[0] providers = %v, want [yahoo]", a.Providers)
	}

	// Second: keep-local with distinct providers; Providers must be deduped+sorted.
	b := resp.Forwarders[1]
	if !b.KeepLocal || b.ForwardOnly {
		t.Errorf("forwarder[1] keep/forward flags = keep=%v forward=%v, want keep-local", b.KeepLocal, b.ForwardOnly)
	}
	if !b.HasExternal || !b.HasFreeProvider {
		t.Errorf("forwarder[1] has_external=%v has_free_provider=%v, want both true", b.HasExternal, b.HasFreeProvider)
	}
	wantProviders := []string{"external", "gmail", "local"}
	if len(b.Providers) != len(wantProviders) {
		t.Fatalf("forwarder[1] providers = %v, want %v", b.Providers, wantProviders)
	}
	for i, p := range wantProviders {
		if b.Providers[i] != p {
			t.Fatalf("forwarder[1] providers = %v, want sorted %v", b.Providers, wantProviders)
		}
	}

	if resp.Summary.Total != 2 || resp.Summary.External != 2 || resp.Summary.FreeProvider != 2 {
		t.Errorf("summary = %+v, want total=2 external=2 free_provider=2", resp.Summary)
	}
}

func TestApiEmailForwardersLocalOnlyNotCountedExternal(t *testing.T) {
	s := newTestServer(t, "tok")
	s.forwarderSource = fakeForwarderSource{fwds: []inventory.Forwarder{
		{
			Source: "info@corp.example",
			Domain: "corp.example",
			Destinations: []inventory.Destination{
				{Address: "staff@corp.example", Domain: "corp.example", Provider: inventory.ProviderLocal},
			},
			KeepLocal: true,
		},
	}}

	w := httptest.NewRecorder()
	s.apiEmailForwarders(w, httptest.NewRequest(http.MethodGet, "/api/v1/email/forwarders", nil))
	resp := decodeForwarders(t, w.Body.Bytes())

	if resp.Summary.Total != 1 || resp.Summary.External != 0 || resp.Summary.FreeProvider != 0 {
		t.Errorf("summary = %+v, want total=1 external=0 free_provider=0", resp.Summary)
	}
	if resp.Forwarders[0].HasExternal || resp.Forwarders[0].HasFreeProvider {
		t.Errorf("local-only forwarder flagged external/free: %+v", resp.Forwarders[0])
	}
}

func TestApiEmailForwardersEmptyWhenNoSource(t *testing.T) {
	s := newTestServer(t, "tok")
	s.forwarderSource = nil

	w := httptest.NewRecorder()
	s.apiEmailForwarders(w, httptest.NewRequest(http.MethodGet, "/api/v1/email/forwarders", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	// forwarders must serialize as [] not null so the UI can iterate.
	if got := w.Body.String(); !jsonHasEmptyArray(t, got, "forwarders") {
		t.Errorf("forwarders not an empty array: %s", got)
	}
	resp := decodeForwarders(t, w.Body.Bytes())
	if resp.Summary.Total != 0 {
		t.Errorf("summary total = %d, want 0", resp.Summary.Total)
	}
}

func TestApiEmailForwardersEmptySource(t *testing.T) {
	s := newTestServer(t, "tok")
	s.forwarderSource = inventory.EmptySource{}

	w := httptest.NewRecorder()
	s.apiEmailForwarders(w, httptest.NewRequest(http.MethodGet, "/api/v1/email/forwarders", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	resp := decodeForwarders(t, w.Body.Bytes())
	if len(resp.Forwarders) != 0 || resp.Summary.Total != 0 {
		t.Errorf("EmptySource produced data: %+v", resp)
	}
}

func TestApiEmailForwardersSourceError(t *testing.T) {
	s := newTestServer(t, "tok")
	s.forwarderSource = fakeForwarderSource{err: errForwarderTest}

	w := httptest.NewRecorder()
	s.apiEmailForwarders(w, httptest.NewRequest(http.MethodGet, "/api/v1/email/forwarders", nil))

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", w.Code)
	}
}

func TestApiEmailForwardersMethodNotAllowed(t *testing.T) {
	s := newTestServer(t, "tok")
	s.forwarderSource = inventory.EmptySource{}

	w := httptest.NewRecorder()
	s.apiEmailForwarders(w, httptest.NewRequest(http.MethodPost, "/api/v1/email/forwarders", nil))

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", w.Code)
	}
}

var errForwarderTest = &forwarderTestError{}

type forwarderTestError struct{}

func (*forwarderTestError) Error() string { return "boom" }

// jsonHasEmptyArray reports whether key maps to an empty JSON array (not null).
func jsonHasEmptyArray(t *testing.T, body, key string) bool {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	raw, ok := m[key]
	if !ok {
		return false
	}
	var arr []json.RawMessage
	if err := json.Unmarshal(raw, &arr); err != nil {
		return false
	}
	return len(arr) == 0
}
