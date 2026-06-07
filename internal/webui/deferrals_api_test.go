package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/mailfwd/intel"
	"github.com/pidginhost/csm/internal/platform"
)

type fakeReporter struct {
	rep intel.Report
	err error
}

func (f fakeReporter) Report() (intel.Report, error) { return f.rep, f.err }

func decodeReport(t *testing.T, body []byte) intel.Report {
	t.Helper()
	var rep intel.Report
	if err := json.Unmarshal(body, &rep); err != nil {
		t.Fatalf("unmarshal report: %v\nbody: %s", err, body)
	}
	return rep
}

func TestSelectDeferralReporterUsesEmptyReporterOffCPanel(t *testing.T) {
	platform.ResetForTest()
	t.Cleanup(platform.ResetForTest)
	panel := platform.PanelNone
	if !platform.SetOverrides(platform.Overrides{Panel: &panel}) {
		t.Fatal("platform override rejected before Detect")
	}

	if _, ok := selectDeferralReporter().(intel.EmptyReporter); !ok {
		t.Fatalf("selectDeferralReporter returned %T, want EmptyReporter", selectDeferralReporter())
	}
}

func TestSelectDeferralReporterUsesEximSourceOnCPanel(t *testing.T) {
	platform.ResetForTest()
	t.Cleanup(platform.ResetForTest)
	panel := platform.PanelCPanel
	if !platform.SetOverrides(platform.Overrides{Panel: &panel}) {
		t.Fatal("platform override rejected before Detect")
	}

	if _, ok := selectDeferralReporter().(*intel.EximSource); !ok {
		t.Fatalf("selectDeferralReporter returned %T, want *EximSource", selectDeferralReporter())
	}
}

func TestApiEmailDeferralsSerialization(t *testing.T) {
	s := newTestServer(t, "tok")
	now := time.Now()
	s.deferralReporter = fakeReporter{rep: intel.Report{
		Deferrals: 3,
		Providers: []intel.ProviderRollup{
			{Provider: "yahoo", Deferrals: 2, Reasons: []intel.ReasonCount{{Code: "TSS04", Count: 2}}, LastSeen: now, Sample: "421 4.7.0 [TSS04] ..."},
			{Provider: "gmail", Deferrals: 1, Reasons: []intel.ReasonCount{{Code: "rate_limit", Count: 1}}, LastSeen: now},
		},
		OutboundIPs: []intel.OutboundIPRollup{
			{IP: "198.51.100.7", Deferrals: 3, Providers: []intel.ProviderCount{{Provider: "yahoo", Count: 2}, {Provider: "gmail", Count: 1}}},
		},
	}}

	w := httptest.NewRecorder()
	s.apiEmailDeferrals(w, httptest.NewRequest(http.MethodGet, "/api/v1/email/deferrals", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	rep := decodeReport(t, w.Body.Bytes())
	if rep.Deferrals != 3 {
		t.Errorf("deferrals = %d, want 3", rep.Deferrals)
	}
	if len(rep.Providers) != 2 || rep.Providers[0].Provider != "yahoo" || rep.Providers[0].Deferrals != 2 {
		t.Errorf("providers = %+v", rep.Providers)
	}
	if rep.Providers[0].Reasons[0].Code != "TSS04" {
		t.Errorf("yahoo reason = %+v", rep.Providers[0].Reasons)
	}
	if len(rep.OutboundIPs) != 1 || rep.OutboundIPs[0].IP != "198.51.100.7" || len(rep.OutboundIPs[0].Providers) != 2 {
		t.Errorf("outbound ips = %+v", rep.OutboundIPs)
	}
}

func TestApiEmailDeferralsEmptyArraysWhenNoReporter(t *testing.T) {
	s := newTestServer(t, "tok")
	s.deferralReporter = nil

	w := httptest.NewRecorder()
	s.apiEmailDeferrals(w, httptest.NewRequest(http.MethodGet, "/api/v1/email/deferrals", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	body := w.Body.String()
	if !jsonHasEmptyArray(t, body, "providers") || !jsonHasEmptyArray(t, body, "outbound_ips") {
		t.Errorf("rollups not empty arrays: %s", body)
	}
}

func TestApiEmailDeferralsEmptyReporter(t *testing.T) {
	s := newTestServer(t, "tok")
	s.deferralReporter = intel.EmptyReporter{}

	w := httptest.NewRecorder()
	s.apiEmailDeferrals(w, httptest.NewRequest(http.MethodGet, "/api/v1/email/deferrals", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	rep := decodeReport(t, w.Body.Bytes())
	if rep.Deferrals != 0 || len(rep.Providers) != 0 || len(rep.OutboundIPs) != 0 {
		t.Errorf("EmptyReporter produced data: %+v", rep)
	}
}

func TestApiEmailDeferralsReporterError(t *testing.T) {
	s := newTestServer(t, "tok")
	s.deferralReporter = fakeReporter{err: errForwarderTest}

	w := httptest.NewRecorder()
	s.apiEmailDeferrals(w, httptest.NewRequest(http.MethodGet, "/api/v1/email/deferrals", nil))

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", w.Code)
	}
}

func TestApiEmailDeferralsMethodNotAllowed(t *testing.T) {
	s := newTestServer(t, "tok")
	s.deferralReporter = intel.EmptyReporter{}

	w := httptest.NewRecorder()
	s.apiEmailDeferrals(w, httptest.NewRequest(http.MethodPost, "/api/v1/email/deferrals", nil))

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", w.Code)
	}
}
