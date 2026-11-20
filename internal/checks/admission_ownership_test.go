package checks

import (
	"errors"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/platform"
)

func attributionRefusal(c admission.Cause) error {
	return &admission.Error{Reason: admission.ReasonAttribution, Cause: c}
}

// A funnel leaves an automatic block to admission only while admission
// applies block picks. Then every answer is final: an accepted block is
// admission's to apply, and a refused one is applied by neither path. Two
// answers keep the legacy block: an address the web server may have
// rewritten from a proxy header, which this build cannot verify yet, and an
// admission that could not answer at all.
func TestRespondLeavesBlocksAdmissionTakes(t *testing.T) {
	f := alert.Finding{Check: "wp_login_bruteforce", SourceIP: "203.0.113.90"}
	for _, tc := range []struct {
		name                string
		executes            bool
		kind                admission.Kind
		mintErr, respondErr error
		want                bool
	}{
		{"not executing", false, admission.KindBlockIP, nil, nil, false},
		{"taken", true, admission.KindBlockIP, nil, nil, true},
		{"queue overflow", true, admission.KindBlockIP, nil, &admission.Error{Reason: admission.ReasonQueueOverflow}, true},
		{"closed ingress", true, admission.KindBlockIP, nil, &admission.Error{Reason: admission.ReasonEngineUnavailable}, false},
		{"unsupported containment", true, admission.KindBlockIP, nil, &admission.Error{Reason: admission.ReasonUnsupportedContainment}, true},
		{"stale evidence", true, admission.KindBlockIP, nil, &admission.Error{Reason: admission.ReasonStale}, true},
		{"invalid response", true, admission.KindBlockIP, nil, &admission.Error{Reason: admission.ReasonInvalid}, true},
		{"rootless policy", true, admission.KindBlockIP, nil, &admission.Error{Reason: admission.ReasonPolicy}, true},
		{"unregistered producer", true, admission.KindBlockIP, &admission.Error{Reason: admission.ReasonPolicy}, nil, true},
		{"target mismatch", true, admission.KindBlockIP, nil, attributionRefusal(admission.CauseTargetMismatch), true},
		{"unknown mint refusal", true, admission.KindBlockIP, attributionRefusal(admission.Cause(255)), nil, true},
		{"no observation", true, admission.KindBlockIP, attributionRefusal(admission.CauseNoObservation), nil, true},
		{"kind not allowed", true, admission.KindBlockIP, attributionRefusal(admission.CauseKindNotAllowed), nil, true},
		{"forged client", true, admission.KindBlockIP, attributionRefusal(admission.CauseForgedClient), nil, true},
		{"rewritten log", true, admission.KindBlockIP, attributionRefusal(admission.CauseRewrittenLog), nil, false},
		{"rewritten log at the ingress", true, admission.KindBlockIP, nil, attributionRefusal(admission.CauseRewrittenLog), false},
		{"error admission does not name", true, admission.KindBlockIP, errors.New("admission is not running"), nil, false},
		{"proxied client", true, admission.KindBlockIP, attributionRefusal(admission.CauseUnreachable), nil, true},
		{"proxy edge", true, admission.KindBlockIP, attributionRefusal(admission.CauseProxyPeer), nil, true},
		{"proxied client while previewing", false, admission.KindBlockIP, attributionRefusal(admission.CauseUnreachable), nil, false},
		{"challenge", true, admission.KindChallenge, nil, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := withAdmission(t)
			a.executes, a.mintErr, a.respondErr = tc.executes, tc.mintErr, tc.respondErr
			taken, accepted := respond(tc.kind, f, f.SourceIP, 0)
			if taken != tc.want {
				t.Fatalf("respond taken = %v, want %v", taken, tc.want)
			}
			wantAccepted := tc.executes && tc.kind == admission.KindBlockIP && tc.mintErr == nil && tc.respondErr == nil
			if accepted != wantAccepted {
				t.Fatalf("respond accepted = %v, want %v", accepted, wantAccepted)
			}
		})
	}
}

// LiteSpeed applies forwarding headers from the host itself, so any local
// user chooses the address it logs, and a log format that writes request
// data where CSM reads the client lets any client choose it: there a
// rewritten-address refusal is final like any other. Apache and nginx
// header handling keeps the legacy block until the address can be verified.
func TestRewrittenRefusalIsFinalOnLiteSpeed(t *testing.T) {
	f := alert.Finding{Check: "wp_login_bruteforce", SourceIP: "203.0.113.90"}
	for _, tc := range []struct {
		name  string
		rw    HTTPRewrite
		taken bool
	}{
		{"litespeed", HTTPRewrite{State: RewriteActive, Server: platform.WSLiteSpeed}, true},
		{"apache client format", HTTPRewrite{State: RewriteActive, Server: platform.WSApache, Format: true}, true},
		{"nginx client format", HTTPRewrite{State: RewriteActive, Server: platform.WSNginx, Format: true}, true},
		{"litespeed unknown", HTTPRewrite{State: RewriteUnknown, Server: platform.WSLiteSpeed}, true},
		{"apache", HTTPRewrite{State: RewriteActive, Server: platform.WSApache}, false},
		{"nginx", HTTPRewrite{State: RewriteActive, Server: platform.WSNginx}, false},
		{"unknown server", HTTPRewrite{State: RewriteUnknown}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withHTTPRewrite(t, tc.rw)
			a := withAdmission(t)
			a.executes, a.mintErr = true, attributionRefusal(admission.CauseRewrittenLog)
			if taken, _ := respond(admission.KindBlockIP, f, f.SourceIP, 0); taken != tc.taken {
				t.Fatalf("taken = %v, want %v", taken, tc.taken)
			}
			a.mintErr = nil
			if got := AnswerPreparedRoot(admission.KindBlockIP, f.SourceIP, admission.Evidence{}, admission.EntryChallengeTimeout, f, attributionRefusal(admission.CauseRewrittenLog), time.Hour); got != tc.taken {
				t.Fatalf("derived taken = %v, want %v", got, tc.taken)
			}
		})
	}
}

// A derived path answers the same rule: its kept root is accepted, its
// preserved mint refusal is final unless the web server may have rewritten
// the address, and an ingress refusal is final too.
func TestDerivedAnswersLeaveBlocksAdmissionTakes(t *testing.T) {
	a := withAdmission(t)
	a.executes = true
	if !AnswerRoot(admission.KindBlockIP, "203.0.113.91", admission.Evidence{}, admission.EntryCentral, time.Hour) {
		t.Fatal("an accepted derived block was left to legacy")
	}
	if !AnswerPreparedRoot(admission.KindBlockIP, "203.0.113.91", admission.Evidence{}, admission.EntryCentral, alert.Finding{Check: "ftp_bruteforce"}, attributionRefusal(admission.CauseNoObservation), time.Hour) {
		t.Fatal("an unobserved root was left to legacy")
	}
	if AnswerPreparedRoot(admission.KindBlockIP, "203.0.113.91", admission.Evidence{}, admission.EntryCentral, alert.Finding{Check: "wp_login_bruteforce"}, attributionRefusal(admission.CauseRewrittenLog), time.Hour) {
		t.Fatal("a rewritten address was taken from legacy")
	}
	if !AnswerPreparedRoot(admission.KindBlockIP, "203.0.113.91", admission.Evidence{}, admission.EntryCentral, alert.Finding{Check: "wp_login_bruteforce"}, attributionRefusal(admission.CauseUnreachable), time.Hour) {
		t.Fatal("a proxied client's derived block was left to legacy")
	}
	a.respondErr = &admission.Error{Reason: admission.ReasonQueueOverflow}
	if !AnswerRoot(admission.KindBlockIP, "203.0.113.91", admission.Evidence{}, admission.EntryCentral, time.Hour) {
		t.Fatal("a derived block the ingress refused was left to legacy")
	}
	a.respondErr = &admission.Error{Reason: admission.ReasonEngineUnavailable}
	if AnswerRoot(admission.KindBlockIP, "203.0.113.91", admission.Evidence{}, admission.EntryCentral, time.Hour) {
		t.Fatal("a derived block a closed ingress could not answer was taken from legacy")
	}
	a.respondErr, a.executes = nil, false
	if AnswerRoot(admission.KindBlockIP, "203.0.113.91", admission.Evidence{}, admission.EntryCentral, time.Hour) {
		t.Fatal("a derived block was taken while admission previews")
	}
}

// A permanent block stays with legacy until admission can apply one: it is
// still handed over, so admission counts it, but no answer takes it.
func TestPermanentDerivedBlockStaysLegacy(t *testing.T) {
	for _, executes := range []bool{true, false} {
		a := withAdmission(t)
		a.executes = executes
		if respondDerived(ApplyBlockRequest{IP: "203.0.113.92", Entry: admission.EntryPermblock}, time.Hour) {
			t.Fatalf("executes %v: a permanent block was taken from legacy", executes)
		}
		if calls := a.responses(); len(calls) != 1 || calls[0].via != admission.EntryPermblock {
			t.Fatalf("executes %v: permanent block hand-offs = %+v, want one through the permblock entry", executes, calls)
		}
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
