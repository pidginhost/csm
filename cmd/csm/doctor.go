package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/control"
	"github.com/pidginhost/csm/internal/health"
)

// DoctorCheck is one line item in a DoctorReport. Status is one of
// "ok", "warn", or "fail".
type DoctorCheck struct {
	Name    string `json:"name"`
	Status  string `json:"status"` // ok | warn | fail
	Message string `json:"message,omitempty"`
	Fix     string `json:"fix,omitempty"`
}

// DoctorReport is the top-level result of `csm doctor`.
type DoctorReport struct {
	OverallStatus string           `json:"overall_status"`
	Checks        []DoctorCheck    `json:"checks"`
	Snapshot      *health.Snapshot `json:"snapshot,omitempty"`
}

func runDoctor() {
	jsonOut := false
	for _, arg := range os.Args[2:] {
		if arg == "--json" {
			jsonOut = true
		}
	}

	report := buildDoctorReport(tryLoadConfigLite, func() ([]byte, error) {
		return sendControl(control.CmdStatus, nil)
	})
	emitDoctor(report, jsonOut)
}

func buildDoctorReport(loadConfig func() (*config.Config, error), readStatus func() ([]byte, error)) DoctorReport {
	report := DoctorReport{}

	// 1. Config validation (offline). Keep this path JSON-friendly: runDoctor
	// must not call loadConfigLite directly because that helper exits on error.
	cfg, err := loadConfig()
	if err != nil {
		report.Checks = append(report.Checks, DoctorCheck{
			Name:    "config valid",
			Status:  "fail",
			Message: err.Error(),
			Fix:     "edit csm.yaml or the failing conf.d fragment, then run `csm validate`",
		})
		report.OverallStatus = collapseDoctor(report.Checks)
		return report
	}
	report.Checks = append(report.Checks, DoctorCheck{Name: "config valid", Status: "ok"})
	_ = cfg

	// 2. Daemon reachable
	resp, err := readStatus()
	if err != nil {
		report.Checks = append(report.Checks, DoctorCheck{
			Name:    "daemon reachable",
			Status:  "fail",
			Message: err.Error(),
			Fix:     "systemctl start csm.service",
		})
		report.OverallStatus = collapseDoctor(report.Checks)
		return report
	}
	report.Checks = append(report.Checks, DoctorCheck{Name: "daemon reachable", Status: "ok"})

	// 3. Snapshot-derived checks
	var sr control.StatusResult
	if err := json.Unmarshal(resp, &sr); err != nil {
		report.Checks = append(report.Checks, DoctorCheck{
			Name:    "health snapshot available",
			Status:  "fail",
			Message: fmt.Sprintf("daemon status response is not valid JSON: %v", err),
			Fix:     "restart csm.service and inspect daemon logs",
		})
		report.OverallStatus = collapseDoctor(report.Checks)
		return report
	}
	if sr.Snapshot == nil {
		report.Checks = append(report.Checks, DoctorCheck{
			Name:    "health snapshot available",
			Status:  "fail",
			Message: "daemon status response did not include a health snapshot",
			Fix:     "upgrade or restart csm.service",
		})
		report.OverallStatus = collapseDoctor(report.Checks)
		return report
	}

	report.Snapshot = sr.Snapshot
	report.Checks = append(report.Checks, DoctorCheck{Name: "health snapshot available", Status: "ok"})
	if len(sr.Snapshot.Watchers) == 0 {
		report.Checks = append(report.Checks, DoctorCheck{
			Name:    "watchers registered",
			Status:  "fail",
			Message: "daemon reported no watcher attachment state",
			Fix:     "restart csm.service and inspect startup logs",
		})
	}
	for name, attached := range sr.Snapshot.Watchers {
		st := DoctorCheck{Name: "watcher: " + name}
		if attached {
			st.Status = "ok"
		} else {
			st.Status = "fail"
			st.Message = "watcher failed to attach"
			st.Fix = fmt.Sprintf("check daemon logs: journalctl -u csm.service -g %q", name)
		}
		report.Checks = append(report.Checks, st)
	}
	if !sr.Snapshot.StoreHealthy {
		report.Checks = append(report.Checks, DoctorCheck{
			Name:    "bbolt store healthy",
			Status:  "fail",
			Message: "store missing required buckets",
			Fix:     "stop daemon, run `csm store import <last-good>` or `csm baseline --confirm`",
		})
	} else {
		report.Checks = append(report.Checks, DoctorCheck{Name: "bbolt store healthy", Status: "ok"})
	}

	report.OverallStatus = collapseDoctor(report.Checks)
	return report
}

// collapseDoctor reduces a slice of checks to the worst status seen:
// "fail" > "warn" > "ok".
func collapseDoctor(checks []DoctorCheck) string {
	worst := "ok"
	for _, c := range checks {
		switch c.Status {
		case "fail":
			return "fail"
		case "warn":
			worst = "warn"
		}
	}
	return worst
}

func emitDoctor(r DoctorReport, jsonOut bool) {
	if jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(r)
		if r.OverallStatus == "fail" {
			os.Exit(1)
		}
		return
	}
	fmt.Print(r.Human())
	if r.OverallStatus == "fail" {
		os.Exit(1)
	}
}

// Human renders the report as plain text.
func (r DoctorReport) Human() string {
	var b strings.Builder
	b.WriteString("=== csm doctor ===\n")
	for _, c := range r.Checks {
		var tag string
		switch c.Status {
		case "ok":
			tag = "[OK]   "
		case "warn":
			tag = "[WARN] "
		case "fail":
			tag = "[FAIL] "
		}
		fmt.Fprintf(&b, "%s%s\n", tag, c.Name)
		if c.Message != "" {
			fmt.Fprintf(&b, "       %s\n", c.Message)
		}
		if c.Fix != "" {
			fmt.Fprintf(&b, "       Fix: %s\n", c.Fix)
		}
	}
	fmt.Fprintf(&b, "\nOverall: %s\n", strings.ToUpper(r.OverallStatus))
	return b.String()
}
