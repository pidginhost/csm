package main

import (
	"sort"

	"github.com/pidginhost/csm/internal/health"
	"github.com/pidginhost/csm/internal/queuehealth"
)

func queueDoctorChecks(queues map[string]queuehealth.Status, automation health.AutomationStatus) []DoctorCheck {
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
			check.Message += "; " + q.Reason
			if why := autoBlocksNotApplied(name, q.Reason, automation); why != "" {
				check.Message += "; " + why
				checks = append(checks, check)
				continue
			}
			check.Status = "fail"
			if q.Advisory {
				check.Status = "warn"
			}
			check.Fix = "inspect worker errors and host CPU, memory and I/O pressure; reduce competing bulk work, then verify the backlog drains and recent drops stop"
		}
		checks = append(checks, check)
	}
	return checks
}

// autoBlocksNotApplied explains a degraded auto-block retry queue on a host
// whose firewall is disabled. No engine exists to apply a block, so every
// queued block fails until it ages out: the configured state, not a stuck
// queue. State file errors stay failures either way.
func autoBlocksNotApplied(name, reason string, automation health.AutomationStatus) string {
	if name != "auto_block.pending" || automation.FirewallEnabled || (reason != "retry_failed" && reason != "backlog_lag") {
		return ""
	}
	why := "blocks are not applied: firewall disabled"
	if automation.AutoResponseDryRun {
		why += " and auto_response.dry_run on"
	}
	return why
}
