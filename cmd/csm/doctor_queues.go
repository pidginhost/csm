package main

import (
	"sort"

	"github.com/pidginhost/csm/internal/queuehealth"
)

func queueDoctorChecks(queues map[string]queuehealth.Status) []DoctorCheck {
	names := make([]string, 0, len(queues))
	for name := range queues {
		names = append(names, name)
	}
	sort.Strings(names)
	checks := make([]DoctorCheck, 0, len(names))
	for _, name := range names {
		q := queues[name]
		check := DoctorCheck{
			Name:    "queue: " + name,
			Status:  "ok",
			Message: q.Evidence(),
		}
		if q.Status == "degraded" {
			check.Status = "fail"
			check.Message += "; " + q.Reason
			check.Fix = "inspect worker errors and host CPU, memory and I/O pressure; reduce competing bulk work, then verify the backlog drains and recent drops stop"
		}
		checks = append(checks, check)
	}
	return checks
}
