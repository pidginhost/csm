package checks

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/alert"
)

func observedSSHLogin() alert.Finding {
	return alert.Finding{
		Check: "ssh_login_unknown_ip", Severity: alert.Critical, SourceIP: "192.0.2.7",
		Message: "SSH login from an unknown address", Timestamp: time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC),
		Observation: alert.Observation{Producer: string(ProducerSSHLog), Stream: "secure:dev=2049,ino=77", Cursor: "offset=4096",
			ObservedAt: time.Date(2026, 10, 6, 11, 59, 59, 0, time.UTC)},
		Claims:      []admission.Claim{{Kind: admission.ClaimAccount, Value: "alice"}},
		Attribution: admission.AttributionPeer,
	}
}

// A finding asks admission for the evidence its own observation supports:
// the producer that stamped it, the check, severity and finding identity,
// the observation's stream, cursor and time, the producer's parser and the
// finding's claims and intel (spec 5.1).
func TestAdmissionEvidenceFromAFinding(t *testing.T) {
	f := observedSSHLogin()
	f.Intel = &admission.IntelRef{Source: "feed", Expires: f.Observation.ObservedAt.Add(time.Hour)}
	target, err := AdmissionTarget(f.SourceIP, admission.Caps{})
	if err != nil {
		t.Fatal(err)
	}
	producer, in, err := AdmissionEvidence(f, target)
	if err != nil {
		t.Fatal(err)
	}
	parser, _ := ProducerParser(ProducerSSHLog)
	if producer != ProducerSSHLog || in.Check != f.Check || in.Severity != admission.SeverityCritical || in.FindingID != alert.FindingID(f) ||
		in.Observation != (admission.ObservationRef{Stream: f.Observation.Stream, Cursor: f.Observation.Cursor, Version: 1}) ||
		!in.ObservedAt.Equal(f.Observation.ObservedAt) || in.Parser != parser || in.Target != target || in.Attribution != admission.AttributionPeer ||
		len(in.Claims) != 1 || in.Claims[0] != f.Claims[0] || in.Intel != f.Intel || in.Inventory != nil {
		t.Fatalf("producer %s, input %+v", producer, in)
	}
}

// Provenance is never reconstructed (spec 5.1): a finding without an
// observation, or one naming a producer the table does not list, asks for
// nothing.
func TestAdmissionEvidenceRefusesAFindingWithoutProvenance(t *testing.T) {
	target, err := AdmissionTarget("192.0.2.7", admission.Caps{})
	if err != nil {
		t.Fatal(err)
	}
	unobserved := observedSSHLogin()
	unobserved.Observation = alert.Observation{}
	_, _, err = AdmissionEvidence(unobserved, target)
	wantAdmissionReason(t, "no observation", err, admission.ReasonAttribution)
	if admission.CauseOf(err) != admission.CauseNoObservation {
		t.Errorf("no observation: cause %s", admission.CauseOf(err))
	}
	unknown := observedSSHLogin()
	unknown.Observation.Producer = "tail_scan"
	_, _, err = AdmissionEvidence(unknown, target)
	wantAdmissionReason(t, "unregistered producer", err, admission.ReasonPolicy)
}

// A response target is canonical: an address, or a prefix when the funnel
// acts on a subnet; an IPv6 target needs the firewall's IPv6 capability.
func TestAdmissionTarget(t *testing.T) {
	for raw, want := range map[string]string{
		"192.0.2.7":        "ip:192.0.2.7",
		"::ffff:192.0.2.7": "ip:192.0.2.7",
		"198.51.100.7/24":  "net:198.51.100.0/24",
		"2001:db8::7":      "ip:2001:db8::7",
	} {
		target, err := AdmissionTarget(raw, admission.Caps{IPv6: true})
		if err != nil || target.Key() != want {
			t.Errorf("%s: %s, %v; want %s", raw, target.Key(), err, want)
		}
	}
	_, err := AdmissionTarget("2001:db8::7", admission.Caps{})
	wantAdmissionReason(t, "IPv6 without the capability", err, admission.ReasonUnsupportedContainment)
	_, err = AdmissionTarget("127.0.0.1", admission.Caps{})
	wantAdmissionReason(t, "loopback", err, admission.ReasonProtected)
}

func wantAdmissionReason(t *testing.T, what string, err error, want admission.Reason) {
	t.Helper()
	if got, ok := admission.ReasonOf(err); !ok || got != want {
		t.Errorf("%s: err = %v, want reason %s", what, err, want)
	}
}

// A finding whose parser vouched for no kind mints nothing, whatever its
// observation; the production registry refuses it with the cause.
func TestAdmissionRefusesAFindingWithoutAttribution(t *testing.T) {
	reg, err := admission.NewRegistry(AdmissionPolicy)
	if err != nil {
		t.Fatal(err)
	}
	var sshd *admission.Producer
	for _, p := range ProducerTable() {
		registered, regErr := reg.Register(p.Spec)
		if regErr != nil {
			t.Fatal(regErr)
		}
		if p.Spec.ID == ProducerSSHLog {
			sshd = registered
		}
	}
	target, err := AdmissionTarget("192.0.2.7", admission.Caps{})
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []admission.Attribution{admission.AttributionUnknown, admission.AttributionHTTPPeer} {
		f := observedSSHLogin()
		f.Attribution = kind
		_, in, inErr := AdmissionEvidence(f, target)
		if inErr != nil {
			t.Fatal(inErr)
		}
		if _, err = sshd.Mint(in); admission.CauseOf(err) != admission.CauseKindNotAllowed {
			t.Errorf("%s: minted or refused without the cause: %v", kind, err)
		}
	}
	_, in, err := AdmissionEvidence(observedSSHLogin(), target)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = sshd.Mint(in); err != nil {
		t.Fatalf("an sshd peer: %v", err)
	}
}

// The relay's client address is a mail header: it mints nothing, and
// evidence a build that once trusted it retained is refused on use.
func TestPHPRelayCannotMintOrReuseEvidence(t *testing.T) {
	reg, err := admission.NewRegistry(AdmissionPolicy)
	if err != nil {
		t.Fatal(err)
	}
	var relay *admission.Producer
	for _, row := range ProducerTable() {
		p, registerErr := reg.Register(row.Spec)
		if registerErr != nil {
			t.Fatal(registerErr)
		}
		if row.Spec.ID == ProducerPHPRelaySpool {
			relay = p
		}
	}
	if relay == nil {
		t.Fatal("PHP relay producer is missing")
	}
	reg.Seal()
	f := observedSSHLogin()
	f.Check = "email_php_form_relay"
	f.Observation.Producer = string(ProducerPHPRelaySpool)
	f.Claims = nil
	f.Attribution = admission.AttributionHTTPPeer
	target, err := AdmissionTarget(f.SourceIP, admission.Caps{})
	if err != nil {
		t.Fatal(err)
	}
	_, in, err := AdmissionEvidence(f, target)
	if err != nil {
		t.Fatal(err)
	}
	e, err := relay.Mint(in)
	wantAdmissionReason(t, "PHP relay mint", err, admission.ReasonAttribution)
	if !e.Equal(admission.Evidence{}) {
		t.Error("PHP relay minted evidence from a mail header")
	}

	// Model evidence from a registry that used to trust the relay address.
	old, err := admission.NewRegistry(AdmissionPolicy)
	if err != nil {
		t.Fatal(err)
	}
	spec, _ := reg.Spec(ProducerPHPRelaySpool)
	spec.Attribution = admission.Attributions(admission.AttributionHTTPPeer)
	p, err := old.Register(spec)
	if err != nil {
		t.Fatal(err)
	}
	e, err = p.Mint(in)
	if err != nil {
		t.Fatal(err)
	}
	body, err := e.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	e, err = admission.UnmarshalEvidence(body)
	if err != nil {
		t.Fatal(err)
	}
	wantAdmissionReason(t, "retained PHP relay evidence", reg.Validate(e), admission.ReasonAttribution)
}
