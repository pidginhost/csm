package daemon

import (
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/challenge"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/incident"
	"github.com/pidginhost/csm/internal/reporting"
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

// Central intel answers the local finding's root through the central
// entry: a block when it blocks and a challenge when it challenges; central
// data never mints a root of its own (spec 5.3).
func TestCentralActionAnswersTheLocalRoot(t *testing.T) {
	cfg, _ := applyWiringSetup(t)
	a := withRecordingAdmission(t)
	d := New(cfg, nil, nil, "")
	d.ipList = challenge.NewIPList(filepath.Join(t.TempDir(), "challenge_ips.txt"))
	store := centralStoreWith(t, []reporting.ScoredEntry{
		{IP: "198.51.100.20", Score: 95, Classes: []reporting.Class{reporting.ClassBruteforce}, LastSeen: time.Unix(1_700_000_000, 0).UTC()},
	})
	notProtected := func(string) bool { return false }
	f := observedBruteForce("198.51.100.20")
	root := mintedRoot(t, f, f.SourceIP)
	block, ok := d.planCentralAction(store, reporting.ActionBlockIfLocalCorroborated, 80, notProtected, f)
	if !ok || !block.root.Equal(root) {
		t.Fatalf("planned %+v (%v), want the local root", block, ok)
	}
	if err := d.performCentralAction(block); err != nil {
		t.Fatal(err)
	}
	challenged := block
	challenged.decision = reporting.DecisionChallenge
	if err := d.performCentralAction(challenged); err != nil {
		t.Fatal(err)
	}
	got := a.got()
	if len(got) != 2 || got[0].kind != admission.KindBlockIP || got[1].kind != admission.KindChallenge || got[0].ttl != centralBlockTTL || got[1].ttl != centralChallengeTTL {
		t.Fatalf("responses = %+v", got)
	}
	for _, r := range got {
		if r.via != admission.EntryCentral || !r.root.Equal(root) {
			t.Fatalf("response %+v, want the root through the central entry", r)
		}
	}
}

// An incident block answers the root the correlator kept, through the
// entry of the path that decided it.
func TestIncidentBlockAnswersItsRoot(t *testing.T) {
	cfg, _ := applyWiringSetup(t)
	a := withRecordingAdmission(t)
	d := New(cfg, nil, nil, "")
	root := incident.PreparedRoot{Evidence: mintedRoot(t, observedBruteForce("203.0.113.90"), "203.0.113.90")}
	for _, entry := range []admission.Entry{admission.EntryIncident, admission.EntryIncidentSpray} {
		if _, err := d.applyIncidentBlock("203.0.113.90", "incident", 7*24*time.Hour, root.FindingID(), root, entry); err != nil {
			t.Fatal(err)
		}
	}
	got := a.got()
	if len(got) != 2 || got[0].via != admission.EntryIncident || got[1].via != admission.EntryIncidentSpray || !got[0].root.Equal(root.Evidence) || !got[1].root.Equal(root.Evidence) || got[0].ttl != 7*24*time.Hour || got[1].ttl != 7*24*time.Hour {
		t.Fatalf("responses = %+v", got)
	}
}

// The correlator hands each block the root it kept for the attesting
// finding, and the daemon's hand-off names the entry of the path that
// decided it: credential spray or a generic incident.
func TestIncidentCorrelatorHandsItsBlocksTheirRootsAndEntries(t *testing.T) {
	for _, spray := range []bool{true, false} {
		t.Run(map[bool]string{true: "spray", false: "generic"}[spray], func(t *testing.T) {
			resetIncidentForTest()
			t.Cleanup(resetIncidentForTest)
			withRecordingAdmission(t)
			cfg := &config.Config{}
			cfg.AutoResponse.Enabled, cfg.AutoResponse.BlockIPs = true, true
			if spray {
				cfg.Incidents.SpraySuppression.Enabled = true
				cfg.Incidents.SpraySuppression.DistinctMailboxes = 3
				cfg.Incidents.SpraySuppression.SeverityEscalateAt = 6
				cfg.Incidents.SpraySuppression.PerCheck = []string{"pam_bruteforce"}
				cfg.Incidents.SpraySuppression.BlockAtSeverity = "high"
			} else {
				cfg.Incidents.AutoBlock.Enabled = true
				cfg.Incidents.AutoBlock.BlockAtSeverity = "critical"
			}
			SetIncidentConfigSource(func() *config.Config { return cfg })
			type handed struct {
				root  incident.PreparedRoot
				entry admission.Entry
			}
			var mu sync.Mutex
			var got []handed
			SetIncidentSprayBlocker(func(_, _ string, _ time.Duration, _ string, root incident.PreparedRoot, entry admission.Entry) (bool, error) {
				mu.Lock()
				defer mu.Unlock()
				got = append(got, handed{root, entry})
				return true, nil
			})
			c := IncidentCorrelator()
			at := time.Unix(1_700_000_000, 0).UTC()
			findings := []alert.Finding{{
				Check: "modsec_csm_block_escalation", Severity: alert.Critical, SourceIP: "192.0.2.81", Timestamp: at,
				Observation: alert.Observation{Producer: string(checks.ProducerModSecLog), Stream: "modsec", Cursor: "offset=1", ObservedAt: at},
			}}
			if spray {
				findings = nil
				for i := 0; i < 3; i++ {
					findings = append(findings, alert.Finding{
						Check: "pam_bruteforce", Severity: alert.Critical, SourceIP: "192.0.2.81", Mailbox: fmt.Sprintf("user%d@example.com", i),
						Timestamp:   at.Add(time.Duration(i) * time.Minute),
						Observation: alert.Observation{Producer: string(checks.ProducerPAMSocket), Stream: "pam:boot", Cursor: fmt.Sprintf("1:%d", i), ObservedAt: at.Add(time.Duration(i) * time.Minute)},
					})
				}
			}
			for _, f := range findings {
				if _, _, err := c.OnFinding(f); err != nil {
					t.Fatal(err)
				}
			}
			want := admission.EntryIncident
			if spray {
				want = admission.EntryIncidentSpray
			}
			mu.Lock()
			defer mu.Unlock()
			if len(got) == 0 || got[0].entry != want || got[0].root.Equal(admission.Evidence{}) || got[0].root.Check() != findings[0].Check {
				t.Fatalf("handed %+v, want a root through %s", got, want)
			}
		})
	}
}

// A failed mint is kept until a response is selected. It becomes one
// Attribution refusal without changing the legacy block; mere event
// collection counts nothing.
func TestIncidentCorrelatorCountsItsSelectedMintRefusal(t *testing.T) {
	for _, spray := range []bool{false, true} {
		for _, selected := range []bool{false, true} {
			t.Run(fmt.Sprintf("spray=%t/selected=%t", spray, selected), func(t *testing.T) {
				resetIncidentForTest()
				t.Cleanup(resetIncidentForTest)
				cfg, blocker := applyWiringSetup(t)
				a := withRecordingAdmission(t)
				cfg.Incidents.AutoBlock.Enabled = selected && !spray
				cfg.Incidents.AutoBlock.BlockAtSeverity = "critical"
				if spray {
					cfg.Incidents.SpraySuppression.Enabled = true
					cfg.Incidents.SpraySuppression.DistinctMailboxes = 3
					cfg.Incidents.SpraySuppression.SeverityEscalateAt = 6
					cfg.Incidents.SpraySuppression.PerCheck = []string{"pam_bruteforce"}
					if selected {
						cfg.Incidents.SpraySuppression.BlockAtSeverity = "high"
					}
				}
				SetIncidentConfigSource(func() *config.Config { return cfg })
				d := New(cfg, nil, nil, "")
				SetIncidentSprayBlocker(d.applyIncidentBlock)
				c := IncidentCorrelator()
				at := time.Now().UTC()
				findings := []alert.Finding{{Check: "modsec_csm_block_escalation", Severity: alert.Critical, SourceIP: "192.0.2.83", Timestamp: at}}
				entry, check := admission.EntryIncident, "modsec_csm_block_escalation"
				if spray {
					entry, check = admission.EntryIncidentSpray, "pam_bruteforce"
					findings = nil
					for i := range 3 {
						findings = append(findings, alert.Finding{Check: check, Severity: alert.Critical, SourceIP: "192.0.2.83", Mailbox: fmt.Sprintf("user%d@example.com", i), Timestamp: at.Add(time.Duration(i) * time.Second)})
					}
				}
				for _, finding := range findings {
					if _, _, err := c.OnFinding(finding); err != nil {
						t.Fatal(err)
					}
				}
				a.mu.Lock()
				defer a.mu.Unlock()
				if !selected {
					if len(a.refusals) != 0 || len(a.responses) != 0 || len(blocker.calls) != 0 {
						t.Fatalf("unselected events counted: refusals=%+v responses=%+v legacy=%+v", a.refusals, a.responses, blocker.calls)
					}
					return
				}
				want := derivedRefusal{admission.KindBlockIP, check, entry, admission.ReasonAttribution}
				if len(a.refusals) != 1 || a.refusals[0] != want || len(a.responses) != 0 || len(blocker.calls) != 1 || blocker.calls[0].ip != "192.0.2.83" {
					t.Fatalf("selected response lost attribution or changed legacy: refusals=%+v responses=%+v legacy=%+v", a.refusals, a.responses, blocker.calls)
				}
			})
		}
	}
}

// An unobserved local finding keeps its attribution refusal and check.
// Legacy still blocks; no second empty-root refusal replaces that refusal.
func TestCentralUnobservedRootIsRefusedOnce(t *testing.T) {
	cfg, b := applyWiringSetup(t)
	a := withRecordingAdmission(t)
	d := New(cfg, nil, nil, "")
	store := centralStoreWith(t, []reporting.ScoredEntry{{IP: "198.51.100.21", Score: 95, Classes: []reporting.Class{reporting.ClassBruteforce}, LastSeen: time.Unix(1_700_000_000, 0).UTC()}})
	f := alert.Finding{Check: "ip_reputation", Severity: alert.Critical, SourceIP: "198.51.100.21"}
	planned, ok := d.planCentralAction(store, reporting.ActionBlockIfLocalCorroborated, 80, func(string) bool { return false }, f)
	if !ok {
		t.Fatal("legacy central policy did not select its block")
	}
	if err := d.performCentralAction(planned); err != nil {
		t.Fatal(err)
	}
	if len(b.calls) != 1 || b.calls[0].ip != f.SourceIP || len(a.got()) != 0 {
		t.Fatalf("legacy calls=%+v admission responses=%+v", b.calls, a.got())
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	want := derivedRefusal{admission.KindBlockIP, "ip_reputation", admission.EntryCentral, admission.ReasonAttribution}
	if len(a.refusals) != 1 || a.refusals[0] != want {
		t.Fatalf("refusals=%+v, want %+v", a.refusals, want)
	}
}

// An incident keeps a prepared root for each attesting event until a block
// is selected. Only what a refusal counts survives with it, the check and
// severity, never the finding's message or details.
func TestIncidentRootsKeepOnlyWhatARefusalCounts(t *testing.T) {
	withRecordingAdmission(t)
	observed := observedBruteForce("203.0.113.91")
	observed.Details = strings.Repeat("x", 4096)
	unobserved := observed
	unobserved.Observation = alert.Observation{}
	for name, f := range map[string]alert.Finding{"minted": observed, "refused": unobserved} {
		root := prepareIncidentRoot(f, f.SourceIP)
		if (name == "minted") != (root.Err == nil) {
			t.Fatalf("%s: mint error = %v", name, root.Err)
		}
		if want := (alert.Finding{Check: f.Check, Severity: f.Severity}); !reflect.DeepEqual(root.Finding, want) {
			t.Fatalf("%s: retained finding = %+v, want %+v", name, root.Finding, want)
		}
	}
}
