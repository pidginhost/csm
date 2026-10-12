package antispam

import (
	"fmt"
	"strings"
)

// The systemd units CSM reloads. It never restarts either (spec section 6.3).
const (
	RspamdUnit = "rspamd.service"
	EximUnit   = "exim.service"
)

// UnitShowArgs are the `systemctl` arguments the collector runs per unit.
func UnitShowArgs(unit string) []string {
	return []string{"show", "-p", "LoadState", "-p", "User", "-p", "CanReload", unit}
}

// ParseUnitShow reads `systemctl show -p ...` output: one Key=Value per line.
func ParseUnitShow(out string) map[string]string {
	props := make(map[string]string)
	for _, line := range strings.Split(out, "\n") {
		if key, value, ok := strings.Cut(strings.TrimSpace(line), "="); ok {
			props[key] = value
		}
	}
	return props
}

// checkServices applies spec section 6.2 item 1: CSM mutates only through
// systemd-run, and both services must reload in place.
func checkServices(f HostFacts) []Problem {
	var out []Problem
	add := func(sev Severity, format string, args ...any) {
		out = append(out, Problem{Code: CodeSystemd, Severity: sev, Detail: fmt.Sprintf(format, args...)})
	}
	if f.SystemdRunErr != nil {
		add(Temporary, "systemd-run is not available; CSM changes mail configuration only through it")
	}
	for _, s := range []struct {
		unit string
		show CommandResult
	}{{RspamdUnit, f.RspamdService}, {EximUnit, f.EximService}} {
		props := ParseUnitShow(s.show.Stdout)
		switch {
		case s.show.Err != nil:
			add(Temporary, "systemctl show %s failed; check systemd", s.unit)
		case props["LoadState"] != "loaded":
			add(Temporary, "%s is not loaded; check that it is installed", s.unit)
		case props["CanReload"] != "yes":
			add(Definite, "%s cannot reload; CSM applies changes only by reload, never by restart", s.unit)
		}
	}
	return out
}

// checkEximLog applies the log half of spec section 6.2 item 5: CSM reads
// scan markers only from the Exim main log it already monitors.
func checkEximLog(settings map[string]string, monitored string) []Problem {
	var out []Problem
	add := func(sev Severity, format string, args ...any) {
		out = append(out, Problem{Code: CodeEximLog, Severity: sev, Detail: fmt.Sprintf(format, args...)})
	}
	raw, ok := settings["log_file_path"]
	switch {
	case !ok:
		add(Temporary, "exim -bP did not report log_file_path")
		return out
	case monitored == "":
		add(Temporary, "the Exim log CSM monitors is unknown")
		return out
	case strings.ContainsAny(raw, "$<"):
		add(Temporary, "Exim's log_file_path uses an expansion or list separator CSM does not evaluate")
		return out
	}
	for _, entry := range strings.Split(raw, ":") {
		if strings.ReplaceAll(strings.TrimSpace(entry), "%s", "main") == monitored {
			return out
		}
	}
	add(Definite, "Exim does not write its main log to %s, where CSM reads antispam markers; restore log_file_path", monitored)
	return out
}
