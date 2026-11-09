package checks

import (
	"testing"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/alert"
)

// On Postfix hosts the SMTP spray tracker reads the mail log, so each
// counted address is a mail_log record. The mail_log producer publishes the
// SMTP spray check, so each root mints.
func TestPostfixSMTPSprayRootsMint(t *testing.T) {
	a := withAdmission(t)
	withBlocker(t)
	withChallengeList(t, nil)
	var minted []error
	a.mint = func(f alert.Finding) admission.Evidence {
		_, _, err := mintScanFinding(t, f)
		minted = append(minted, err)
		return admission.Evidence{}
	}
	spray := sprayFinding(2)
	spray.Check = "smtp_subnet_spray"
	AutoBlockIPs(liveAutoBlockConfig(t), []alert.Finding{spray})
	if len(minted) != 2 {
		t.Fatalf("%d roots minted, want 2", len(minted))
	}
	for i, err := range minted {
		if err != nil {
			t.Fatalf("root %d: %v", i, err)
		}
	}
}
