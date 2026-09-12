package webui

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/pidginhost/csm/internal/health"
)

type wpCoverageProvider struct{ statusFakeProvider }

func (wpCoverageProvider) WordPressVerification() map[string]health.WPVerificationCounts {
	return map[string]health.WPVerificationCounts{"core": {Verified: 3, Unverified: 2}}
}

func TestAPIStatusIncludesWordPressVerification(t *testing.T) {
	s := &Server{cfg: capsTestCfg(), provider: wpCoverageProvider{}}
	rr := httptest.NewRecorder()
	s.apiStatus(rr, httptest.NewRequest("GET", "/api/v1/status", nil))
	var body struct {
		WordPress map[string]health.WPVerificationCounts `json:"wordpress_verification"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.WordPress["core"].Verified != 3 || body.WordPress["core"].Unverified != 2 {
		t.Fatalf("API omitted coverage: %s", rr.Body.String())
	}
}
