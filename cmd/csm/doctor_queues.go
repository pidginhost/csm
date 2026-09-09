package main

import (
	"fmt"
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
			Name:   "queue: " + name,
			Status: "ok",
			Message: fmt.Sprintf("depth=%d/%d running=%d dropped=%d lag=%.0fs processing=%.0fs",
				q.Depth, q.Capacity, q.InFlight, q.DroppedTotal, q.LagSeconds, q.ProcessingSeconds),
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
