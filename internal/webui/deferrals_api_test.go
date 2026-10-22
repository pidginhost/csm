package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
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
		Lines:     20000,
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
	if rep.Lines != 20000 {
		t.Errorf("lines = %d, want 20000", rep.Lines)
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

type countingReporter struct {
	reads int
	rep   intel.Report
}

func (c *countingReporter) Report() (intel.Report, error) {
	c.reads++
	return c.rep, nil
}

// The report reads up to 8 MiB of exim_mainlog. The page asks for it on
// every load and every minute while its tab is open, so one read serves a
// minute of requests.
func TestApiEmailDeferralsReadsTheLogOncePerMinute(t *testing.T) {
	s := newTestServer(t, "tok")
	src := &countingReporter{rep: intel.Report{Deferrals: 2, Lines: 900, Providers: []intel.ProviderRollup{}, OutboundIPs: []intel.OutboundIPRollup{}}}
	s.deferralReporter = src
	get := func() intel.Report {
		t.Helper()
		w := httptest.NewRecorder()
		s.apiEmailDeferrals(w, httptest.NewRequest(http.MethodGet, "/api/v1/email/deferrals", nil))
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", w.Code)
		}
		return decodeReport(t, w.Body.Bytes())
	}
	if rep := get(); rep.Deferrals != 2 || rep.Lines != 900 {
		t.Fatalf("first answer = %+v", rep)
	}
	if rep := get(); rep.Deferrals != 2 || rep.Lines != 900 {
		t.Fatalf("second answer = %+v", rep)
	}
	if src.reads != 1 {
		t.Errorf("two requests within a minute read the log %d times, want 1", src.reads)
	}
	// Past the minute the log is read again.
	withMemoAges(t, 0, 0)
	get()
	if src.reads != 2 {
		t.Errorf("an expired answer was reused: %d reads, want 2", src.reads)
	}
}

// Any read token can send groups queries that each take a memo; they must
// not push the deferrals answer out and force a fresh log read.
func TestApiEmailDeferralsMemoSurvivesGroupsTraffic(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	src := &countingReporter{rep: intel.Report{Providers: []intel.ProviderRollup{}, OutboundIPs: []intel.OutboundIPRollup{}}}
	s.deferralReporter = src
	deferrals := func() {
		t.Helper()
		w := httptest.NewRecorder()
		s.apiEmailDeferrals(w, httptest.NewRequest(http.MethodGet, "/api/v1/email/deferrals", nil))
		if w.Code != http.StatusOK {
			t.Fatalf("deferrals status = %d, want 200", w.Code)
		}
	}
	deferrals()
	for i := 1; i <= historyMemosMax+8; i++ {
		w := httptest.NewRecorder()
		s.apiEmailGroups(w, httptest.NewRequest(http.MethodGet, "/api/v1/email/groups?limit="+strconv.Itoa(i), nil))
		if w.Code != http.StatusOK {
			t.Fatalf("groups status = %d, want 200", w.Code)
		}
	}
	deferrals()
	if src.reads != 1 {
		t.Errorf("groups traffic evicted the deferrals answer: %d log reads, want 1", src.reads)
	}
}
