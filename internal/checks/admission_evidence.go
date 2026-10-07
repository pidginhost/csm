package checks

import (
	"strings"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/alert"
)

// AdmissionEvidence is what a finding asks admission to mint for target:
// the producer that stamped its observation and the evidence input that
// producer attests. A finding without an observation, or naming a producer
// the table does not list, asks for nothing: provenance is never
// reconstructed from the finding's other fields (spec 5.1). Missing
// provenance is an attribution refusal, not malformed input. The caller
// supplies the inventory the owner resolves claims against.
func AdmissionEvidence(f alert.Finding, target admission.Target) (admission.ProducerID, admission.EvidenceInput, error) {
	if f.Observation.Producer == "" {
		return "", admission.EvidenceInput{}, &admission.Error{Reason: admission.ReasonAttribution, Detail: "finding has no observation"}
	}
	producer := admission.ProducerID(f.Observation.Producer)
	parser, ok := ProducerParser(producer)
	if !ok {
		return "", admission.EvidenceInput{}, &admission.Error{Reason: admission.ReasonPolicy, Detail: "finding names no registered producer"}
	}
	return producer, admission.EvidenceInput{
		Check: f.Check, FindingID: alert.FindingID(f), Severity: admissionSeverity(f.Severity),
		Observation: admission.ObservationRef{Stream: f.Observation.Stream, Cursor: f.Observation.Cursor, Version: 1},
		ObservedAt:  f.Observation.ObservedAt, Parser: parser, Target: target, Claims: f.Claims, Intel: f.Intel,
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
