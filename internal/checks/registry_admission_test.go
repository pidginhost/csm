package checks

import (
	"testing"

	"github.com/pidginhost/csm/internal/admission"
)

// Every check an admission notice is delivered as is registered, and the
// two response notices are self-health: correlation ignores them.
func TestAdmissionNoticeChecksAreRegistered(t *testing.T) {
	for k := admission.NoticeWithheld; k.Valid(); k++ {
		if _, ok := LookupCheck(k.Check()); !ok {
			t.Errorf("%v is delivered as unregistered check %s", k, k.Check())
		}
	}
	for _, name := range []string{"auto_response_withheld", "response_capacity_exhausted"} {
		info, ok := LookupCheck(name)
		if !ok || info.Correlation != CorrelationIgnored || info.CorrelationReason != reasonSelfHealth {
			t.Errorf("%s = %+v, %v", name, info, ok)
		}
	}
}
