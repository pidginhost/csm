package main

import (
	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/health"
)

// admissionDoctorChecks renders the admission rules for a snapshot whose
// daemon owns a ledger, judged at the time the daemon read it.
func admissionDoctorChecks(a *health.AdmissionStatus) []DoctorCheck {
	if a == nil {
		return nil
	}
	rows := admission.DoctorChecks(a.Ledger, a.Ingress, a.CheckedAt)
	checks := make([]DoctorCheck, 0, len(rows))
	for _, r := range rows {
		checks = append(checks, DoctorCheck{Name: r.Name, Status: r.Status, Message: r.Message, Fix: r.Fix})
	}
	return checks
}
