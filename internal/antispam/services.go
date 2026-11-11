package antispam

import (
	"fmt"
	"strings"
)

// The systemd units CSM reloads. It never restarts either.
const (
	RspamdUnit = "rspamd.service"
	EximUnit   = "exim.service"
)

// The units postfix runs in; CSM only reads them and never changes postfix.
// Debian and Ubuntu run the master in PostfixInstanceUnit and make
// PostfixUnit a oneshot wrapper that stays active while postfix is down.
const (
	PostfixUnit         = "postfix.service"
	PostfixInstanceUnit = "postfix@-.service"
)

// UnitShowArgs are the `systemctl` arguments the collector runs per unit.
func UnitShowArgs(unit string) []string {
	return []string{"show", "-p", "LoadState", "-p", "User", "-p", "Group", "-p", "CanReload", unit}
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

// checkServices checks that CSM mutates only through systemd-run and that
// the services it reloads reload in place. Postfix, which CSM only reads,
// must be running.
func checkServices(f HostFacts) []Problem {
	var out []Problem
	add := func(sev Severity, format string, args ...any) {
		out = append(out, Problem{Code: CodeSystemd, Severity: sev, Detail: fmt.Sprintf(format, args...)})
	}
	if f.SystemdRunErr != nil {
		add(Temporary, "systemd-run is not available; CSM changes mail configuration only through it")
	}
	reloaded := []struct {
		unit string
		show CommandResult
	}{{RspamdUnit, f.RspamdService}, {EximUnit, f.EximService}}
	if f.Stack == StackPostfix {
		reloaded = reloaded[:1]
	}
	for _, s := range reloaded {
		props := ParseUnitShow(s.show.Stdout)
		switch {
		case s.show.Err != nil:
			add(Temporary, "systemctl show %s failed; check systemd", s.unit)
		case props["LoadState"] != "loaded":
			add(Temporary, "%s is not loaded; check that it is installed", s.unit)
		case props["CanReload"] == "no":
			add(Definite, "%s cannot reload; CSM applies changes only by reload, never by restart", s.unit)
		case props["CanReload"] != "yes":
			add(Temporary, "systemctl show %s did not report a readable CanReload property", s.unit)
		}
	}
	if f.Stack == StackPostfix {
		props := ParseUnitShow(f.PostfixService.Stdout)
		switch {
		case f.PostfixService.Err != nil:
			add(Temporary, "systemctl show for postfix failed; check systemd")
		case props["LoadState"] != "loaded":
			add(Temporary, "the postfix service is not loaded; check that postfix is installed")
		case props["ActiveState"] != "active":
			add(Temporary, "the postfix service is not active; check postfix")
		}
	}
	return out
}

// checkEximLog checks that CSM reads scan markers only from the Exim main
// log it already monitors.
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
	path, found := firstEximLogPath(raw)
	if found && path == "" {
		add(Temporary, "Exim uses its default log destination; set an explicit log_file_path so CSM can verify where antispam markers are written")
		return out
	}
	if found && strings.ReplaceAll(path, "%s", "main") == monitored {
		return out
	}
	add(Definite, "Exim does not write its main log to %s, where CSM reads antispam markers; restore log_file_path", monitored)
	return out
}

// Exim uses only the first non-syslog item, with doubled colons denoting a
// literal colon. An empty path selects a build-time default we cannot verify.
func firstEximLogPath(raw string) (string, bool) {
	const space = " \t\r\n\v\f"
	if raw == "" {
		return "", true
	}
	for raw != "" {
		raw = strings.TrimLeft(raw, space)
		if raw == "" {
			break
		}
		var entry strings.Builder
		for raw != "" {
			c := raw[0]
			raw = raw[1:]
			if c == ':' {
				if !strings.HasPrefix(raw, ":") {
					break
				}
				raw = raw[1:]
			}
			entry.WriteByte(c)
		}
		path := strings.TrimRight(entry.String(), space)
		if path != "syslog" {
			return path, true
		}
	}
	return "", false
}
