package checks

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/alert"
)

func attributionRefusal(c admission.Cause) error {
	return &admission.Error{Reason: admission.ReasonAttribution, Cause: c}
}

// A funnel leaves an automatic block to admission only while admission
// applies block picks and took this one. A refusal legacy does not share
// keeps the legacy block, so no detection stops blocking; a client behind
// a trusted proxy or a CDN edge gets a block from neither.
func TestRespondLeavesBlocksAdmissionTakes(t *testing.T) {
	f := alert.Finding{Check: "wp_login_bruteforce", SourceIP: "203.0.113.90"}
	overflow := &admission.Error{Reason: admission.ReasonQueueOverflow}
	for _, tc := range []struct {
		name                string
		executes            bool
		kind                admission.Kind
		mintErr, respondErr error
		want                bool
	}{
		{"not executing", false, admission.KindBlockIP, nil, nil, false},
		{"taken", true, admission.KindBlockIP, nil, nil, true},
		{"ingress refused", true, admission.KindBlockIP, nil, overflow, false},
		{"closed ingress", true, admission.KindBlockIP, nil, &admission.Error{Reason: admission.ReasonEngineUnavailable}, false},
		{"unsupported containment", true, admission.KindBlockIP, nil, &admission.Error{Reason: admission.ReasonUnsupportedContainment}, false},
		{"rootless policy", true, admission.KindBlockIP, nil, &admission.Error{Reason: admission.ReasonPolicy}, false},
		{"target mismatch", true, admission.KindBlockIP, nil, attributionRefusal(admission.CauseTargetMismatch), false},
		{"unknown mint refusal", true, admission.KindBlockIP, attributionRefusal(admission.Cause(255)), nil, false},
		{"no observation", true, admission.KindBlockIP, attributionRefusal(admission.CauseNoObservation), nil, false},
		{"kind not allowed", true, admission.KindBlockIP, attributionRefusal(admission.CauseKindNotAllowed), nil, false},
		{"rewritten log", true, admission.KindBlockIP, attributionRefusal(admission.CauseRewrittenLog), nil, false},
		{"proxied client", true, admission.KindBlockIP, attributionRefusal(admission.CauseUnreachable), nil, true},
		{"proxy edge", true, admission.KindBlockIP, attributionRefusal(admission.CauseProxyPeer), nil, true},
		{"proxied client while previewing", false, admission.KindBlockIP, attributionRefusal(admission.CauseUnreachable), nil, false},
		{"challenge", true, admission.KindChallenge, nil, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := withAdmission(t)
			a.executes, a.mintErr, a.respondErr = tc.executes, tc.mintErr, tc.respondErr
			if _, taken := respond(tc.kind, f, f.SourceIP, 0); taken != tc.want {
				t.Fatalf("respond taken = %v, want %v", taken, tc.want)
			}
		})
	}
}

// A derived path answers the same rule: its kept root is accepted, or its
// preserved mint refusal is one legacy does not share.
func TestDerivedAnswersLeaveBlocksAdmissionTakes(t *testing.T) {
	a := withAdmission(t)
	a.executes = true
	if !AnswerRoot(admission.KindBlockIP, "203.0.113.91", admission.Evidence{}, admission.EntryCentral, time.Hour) {
		t.Fatal("an accepted derived block was left to legacy")
	}
	if AnswerPreparedRoot(admission.KindBlockIP, "203.0.113.91", admission.Evidence{}, admission.EntryCentral, alert.Finding{Check: "ftp_bruteforce"}, attributionRefusal(admission.CauseNoObservation), time.Hour) {
		t.Fatal("an unobserved root was taken from legacy")
	}
	if !AnswerPreparedRoot(admission.KindBlockIP, "203.0.113.91", admission.Evidence{}, admission.EntryCentral, alert.Finding{Check: "wp_login_bruteforce"}, attributionRefusal(admission.CauseUnreachable), time.Hour) {
		t.Fatal("a proxied client's derived block was left to legacy")
	}
	a.respondErr = &admission.Error{Reason: admission.ReasonQueueOverflow}
	if AnswerRoot(admission.KindBlockIP, "203.0.113.91", admission.Evidence{}, admission.EntryCentral, time.Hour) {
		t.Fatal("a derived block ingress refused was taken from legacy")
	}
	a.respondErr, a.executes = nil, false
	if AnswerRoot(admission.KindBlockIP, "203.0.113.91", admission.Evidence{}, admission.EntryCentral, time.Hour) {
		t.Fatal("a derived block was taken while admission previews")
	}
}

type refusalSwitchAdmission struct{ *fakeAdmission }

func (a refusalSwitchAdmission) Refuse(kind admission.Kind, f alert.Finding, via admission.Entry, err error) {
	a.fakeAdmission.Refuse(kind, f, via, err)
	a.mu.Lock()
	a.executes = !a.executes
	a.mu.Unlock()
}

// A refusal can race a policy publication, but this hand-off uses the
// execution state read before answering it.
func TestPreparedRootUsesExecutionSnapshotBeforeRefusal(t *testing.T) {
	for _, executing := range []bool{true, false} {
		a := withAdmission(t)
		a.executes = executing
		SetResponseAdmission(refusalSwitchAdmission{a})
		got := AnswerPreparedRoot(admission.KindBlockIP, "203.0.113.91", admission.Evidence{}, admission.EntryCentral, alert.Finding{}, attributionRefusal(admission.CauseUnreachable), time.Hour)
		if got != executing {
			t.Fatalf("prepared root taken = %v, want pre-refusal execution %v", got, executing)
		}
	}
}
