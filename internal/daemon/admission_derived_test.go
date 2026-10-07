package daemon

import (
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/challenge"
	"github.com/pidginhost/csm/internal/checks"
)

type derivedResponse struct {
	kind admission.Kind
	root admission.Evidence
	via  admission.Entry
	ttl  time.Duration
}

// recordingAdmission stands for the admission owner: it mints with the
// production registry and records each response.
type recordingAdmission struct {
	t         *testing.T
	mu        sync.Mutex
	responses []derivedResponse
	refusals  []derivedRefusal
}

type derivedRefusal struct {
	kind   admission.Kind
	check  string
	via    admission.Entry
	reason admission.Reason
}

func (a *recordingAdmission) Mint(f alert.Finding, target string) (admission.Evidence, error) {
	if f.Observation.Producer == "" {
		return admission.Evidence{}, &admission.Error{Reason: admission.ReasonAttribution, Detail: "finding has no observation"}
	}
	return mintedRoot(a.t, f, target), nil
}

func (a *recordingAdmission) Refuse(kind admission.Kind, f alert.Finding, via admission.Entry, err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	reason, _ := admission.ReasonOf(err)
	a.refusals = append(a.refusals, derivedRefusal{kind, f.Check, via, reason})
}

func (a *recordingAdmission) Respond(kind admission.Kind, e admission.Evidence, via admission.Entry, ttl ...time.Duration) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	var selected time.Duration
	if len(ttl) != 0 {
		selected = ttl[0]
	}
	a.responses = append(a.responses, derivedResponse{kind: kind, root: e, via: via, ttl: selected})
	return nil
}

func (a *recordingAdmission) got() []derivedResponse {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]derivedResponse(nil), a.responses...)
}

func withRecordingAdmission(t *testing.T) *recordingAdmission {
	t.Helper()
	a := &recordingAdmission{t: t}
	checks.SetResponseAdmission(a)
	t.Cleanup(func() { checks.SetResponseAdmission(nil) })
	return a
}

func mintedRoot(t *testing.T, f alert.Finding, target string) admission.Evidence {
	t.Helper()
	reg, err := admission.NewRegistry(checks.AdmissionPolicy)
	if err != nil {
		t.Fatal(err)
	}
	var producer *admission.Producer
	for _, p := range checks.ProducerTable() {
		h, regErr := reg.Register(p.Spec)
		if regErr != nil {
			t.Fatal(regErr)
		}
		if string(h.ID()) == f.Observation.Producer {
			producer = h
		}
	}
	tg, err := checks.AdmissionTarget(target, admission.Caps{})
	if err != nil {
		t.Fatal(err)
	}
	_, in, err := checks.AdmissionEvidence(f, tg)
	if err != nil {
		t.Fatal(err)
	}
	e, err := producer.Mint(in)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func observedBruteForce(ip string) alert.Finding {
	at := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	return alert.Finding{
		Check: "wp_login_bruteforce", Severity: alert.Critical, SourceIP: ip, Message: "brute force", Timestamp: at,
		Observation: alert.Observation{Producer: string(checks.ProducerAccessLog), Stream: "access", Cursor: "offset=9", ObservedAt: at},
	}
}

// A challenge's timeout answers the root it was routed with through the
// challenge timeout entry (spec 5.12: a timeout is a linked child of the
// original candidate); one routed without a root is handed over without one.
func TestChallengeEscalationAnswersItsRoot(t *testing.T) {
	cfg, _ := applyWiringSetup(t)
	a := withRecordingAdmission(t)
	d := New(cfg, nil, nil, "")
	d.ipList = challenge.NewIPList(filepath.Join(t.TempDir(), "challenge_ips.txt"))
	root := mintedRoot(t, observedBruteForce("203.0.113.70"), "203.0.113.70")
	d.ipList.AddWithRoot("203.0.113.70", "wp brute", -time.Minute, root.FindingID(), root)
	d.escalateExpiredChallenges(parseBlockExpiry(cfg.AutoResponse.BlockExpiry))
	got := a.got()
	if len(got) != 1 || got[0].kind != admission.KindBlockIP || got[0].via != admission.EntryChallengeTimeout || !got[0].root.Equal(root) || got[0].ttl != parseBlockExpiry(cfg.AutoResponse.BlockExpiry) {
		t.Fatalf("responses = %+v", got)
	}
}
