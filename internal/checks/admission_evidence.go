package checks

import (
	"strings"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/alert"
)

// AdmissionEvidence is what a finding asks admission to mint: the producer
// that stamped its observation and the evidence input that producer attests,
// aimed at the address the finding's parser read (spec 5.8). A finding
// without an observation, naming a producer the table does not list, or
// whose parser vouched for no address asks for nothing: provenance is never
// reconstructed from the finding's other fields, and message text never
// becomes a target. The caller supplies the inventory the owner resolves
// claims against.
func AdmissionEvidence(f alert.Finding) (admission.ProducerID, admission.EvidenceInput, error) {
	if f.Observation.Producer == "" {
		return "", admission.EvidenceInput{}, &admission.Error{Reason: admission.ReasonAttribution, Cause: admission.CauseNoObservation, Detail: "finding has no observation"}
	}
	producer := admission.ProducerID(f.Observation.Producer)
	parser, ok := ProducerParser(producer)
	if !ok {
		return "", admission.EvidenceInput{}, &admission.Error{Reason: admission.ReasonPolicy, Detail: "finding names no registered producer"}
	}
	if !f.Attribution.Valid() {
		return "", admission.EvidenceInput{}, &admission.Error{Reason: admission.ReasonAttribution, Cause: admission.CauseKindNotAllowed, Detail: "no parser vouched for the finding's address"}
	}
	// A client behind a trusted proxy sends no packets to this host, so no
	// response this build applies can contain it (spec 5.8).
	if f.Attribution == admission.AttributionTrustedHTTPChain {
		return "", admission.EvidenceInput{}, &admission.Error{Reason: admission.ReasonAttribution, Cause: admission.CauseUnreachable, Detail: "the address is a client behind a trusted proxy"}
	}
	target, err := admission.CanonicalAddress(f.SourceIP, admission.Caps{IPv6: true})
	if err != nil {
		return "", admission.EvidenceInput{}, err
	}
	return producer, admission.EvidenceInput{
		Check: f.Check, FindingID: alert.FindingID(f), Severity: admissionSeverity(f.Severity),
		Observation: admission.ObservationRef{Stream: f.Observation.Stream, Cursor: f.Observation.Cursor, Version: 1},
		ObservedAt:  f.Observation.ObservedAt, Parser: parser, Target: target, Attribution: f.Attribution, Claims: f.Claims, Intel: f.Intel,
	}, nil
}

// AdmissionTarget is the canonical target of a response: an address, or a
// prefix when the funnel acts on a subnet.
func AdmissionTarget(raw string, caps admission.Caps) (admission.Target, error) {
	if strings.Contains(raw, "/") {
		return admission.CanonicalPrefix(raw, caps)
	}
	return admission.CanonicalAddress(raw, caps)
}

// AdmissionSeverity is the admission severity of an alert severity.
func AdmissionSeverity(s alert.Severity) admission.Severity { return admissionSeverity(s) }
