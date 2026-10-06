package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pidginhost/csm/internal/health"
)

// Clients can distinguish no recorded damage from a latched damage cause
// without interpreting the owner's running state.
func TestAPIStatusAdmissionDamageContract(t *testing.T) {
	for _, damage := range []string{"", "admission record is corrupt"} {
		t.Run(map[bool]string{true: "healthy", false: "damage"}[damage == ""], func(t *testing.T) {
			s := &Server{cfg: capsTestCfg()}
			s.SetHealthProvider(admissionStatusProvider{
				statusFakeProvider: statusFakeProvider{},
				status: &health.AdmissionStatus{
					Owner: &health.AdmissionOwner{DamageError: damage},
				},
			})
			rec := httptest.NewRecorder()
			s.apiStatus(rec, httptest.NewRequest(http.MethodGet, "/api/v1/status", nil))
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d", rec.Code)
			}
			var body struct {
				Admission struct {
					Owner map[string]json.RawMessage `json:"owner"`
				} `json:"admission"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if body.Admission.Owner == nil {
				t.Fatal("status omitted the admission owner")
			}
			value, present := body.Admission.Owner["damage_error"]
			if present != (damage != "") {
				t.Fatalf("damage_error presence = %v for %q", present, damage)
			}
			if present && string(value) != `"admission record is corrupt"` {
				t.Fatalf("damage_error = %s", value)
			}
			if _, present := body.Admission.Owner["error"]; present {
				t.Fatal("damage alone marked the owner as not running")
			}
		})
	}
}
