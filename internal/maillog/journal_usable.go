package maillog

import (
	"bufio"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
)

// Paths the journal probe reads; variables so tests can redirect them.
var (
	devLogPath       = "/dev/log"
	journaldSocket   = "/run/systemd/journal/dev-log"
	journalDirs      = []string{"/run/log/journal", "/var/log/journal"}
	postfixMainCF    = "/etc/postfix/main.cf"
	journalSupported = JournalSupported
	journalProcPath  = "/proc"
)

// JournalUsable reports whether the journal holds every syslog line with
// the credentials journald recorded for its sender: the build reads the
// journal, syslog goes through journald, and journald stores entries.
func JournalUsable() bool {
	if !journalSupported() {
		return false
	}
	target, err := filepath.EvalSymlinks(devLogPath)
	if err != nil || target != journaldSocket {
		return false
	}
	// Storage=none and previous boots can leave journal files behind. Only
	// an open journal in the default journald service proves live storage.
	processes, _ := filepath.Glob(filepath.Join(journalProcPath, "[0-9]*", "exe"))
	for _, exe := range processes {
		target, err := os.Readlink(exe)
		proc := filepath.Dir(exe)
		if err != nil || filepath.Base(strings.TrimSuffix(target, " (deleted)")) != "systemd-journald" {
			continue
		}
		root, err := rootProcess(proc)
		if unit, uerr := processUnit(proc); err != nil || !root || uerr != nil || unit != "systemd-journald.service" {
			continue
		}
		fds, _ := filepath.Glob(filepath.Join(proc, "fd", "*"))
		for _, fd := range fds {
			target, err := os.Readlink(fd)
			if err != nil {
				continue
			}
			for _, dir := range journalDirs {
				if match, _ := filepath.Match(filepath.Join(dir, "*", "*.journal"), target); match {
					return true
				}
			}
		}
	}
	return false
}

// postfixLogsToFile reports whether Postfix writes its own log file through
// postlogd, which leaves no Postfix entries in the journal.
func postfixLogsToFile() bool {
	if _, err := os.Stat(postfixMainCF); os.IsNotExist(err) {
		return false
	}
	return postfixConfigLogsToFile(postfixMainCF, make(map[string]bool))
}

func postfixConfigLogsToFile(path string, seen map[string]bool) bool {
	if seen[path] {
		return false
	}
	seen[path] = true
	// #nosec G304 -- Postfix's main.cf, or the main.cf of an instance its root-owned configuration lists.
	f, err := os.Open(path)
	if err != nil {
		return true
	}
	defer f.Close()
	values := make(map[string]string)
	key := ""
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			if key == "maillog_file" || key == "multi_instance_directories" {
				values[key] += " " + trimmed
			}
			continue
		}
		k, v, _ := strings.Cut(line, "=")
		key = strings.TrimSpace(k)
		if key == "maillog_file" || key == "multi_instance_directories" {
			values[key] = strings.TrimSpace(v)
		}
	}
	if sc.Err() != nil || strings.TrimSpace(values["maillog_file"]) != "" {
		return true
	}
	for _, dir := range strings.FieldsFunc(values["multi_instance_directories"], func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t'
	}) {
		// A macro needs Postfix's expansion context; do not guess coverage.
		if !filepath.IsAbs(dir) || strings.Contains(dir, "$") || postfixConfigLogsToFile(filepath.Join(dir, "main.cf"), seen) {
			return true
		}
	}
	return false
}

// mailUnitsCovered keeps auto on the file when a running mail master would
// fall outside the journal filter. Read kernel process metadata, not syslog
// tags that an unprivileged process could forge to force a source change.
func mailUnitsCovered(units []string) bool {
	selected := make([]string, 0, len(units))
	for _, u := range units {
		selected = append(selected, journalUnitName(u))
	}
	processes, _ := filepath.Glob(filepath.Join(journalProcPath, "[0-9]*"))
	for _, proc := range processes {
		// Only root runs a mail master. Read the uid first: any user controls
		// their own executable's path and can make it unreadable. A process
		// that exits mid-read decides nothing; a read that fails otherwise
		// keeps auto on the file.
		root, err := rootProcess(proc)
		if err != nil {
			if processGone(err) {
				continue
			}
			return false
		}
		if !root {
			continue
		}
		target, err := os.Readlink(filepath.Join(proc, "exe"))
		if err != nil {
			if processGone(err) {
				continue
			}
			return false
		}
		name := filepath.Base(strings.TrimSuffix(target, " (deleted)"))
		if name != "master" && name != "dovecot" {
			continue
		}
		unit, err := processUnit(proc)
		if err != nil {
			if processGone(err) {
				continue
			}
			return false
		}
		if !slices.Contains(selected, unit) {
			return false
		}
		// Custom units accept root senders only. Postfix's unprivileged
		// workers would be discarded even though their master is covered.
		if name == "master" && !postfixJournalUnit(unit) {
			return false
		}
	}
	// No master running yet is nothing the journal would miss: one that
	// starts in a configured unit is read from its first entry.
	return true
}

func rootProcess(proc string) (bool, error) {
	// #nosec G304 -- procfs status of a numeric process directory under the probe root.
	status, err := os.ReadFile(filepath.Join(proc, "status"))
	if err != nil {
		return false, err
	}
	for line := range strings.SplitSeq(string(status), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 5 && fields[0] == "Uid:" {
			return fields[1] == "0" && fields[2] == "0", nil
		}
	}
	return false, errors.New("process status has no Uid")
}

func processUnit(proc string) (string, error) {
	// #nosec G304 -- procfs cgroup of a numeric process directory under the probe root.
	data, err := os.ReadFile(filepath.Join(proc, "cgroup"))
	if err != nil {
		return "", err
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		fields := strings.SplitN(line, ":", 3)
		if len(fields) != 3 || (fields[1] != "" && fields[1] != "name=systemd") {
			continue
		}
		for _, part := range strings.Split(fields[2], "/") {
			if strings.HasSuffix(part, ".service") {
				return part, nil
			}
		}
	}
	return "", nil
}

// processGone reports whether err says the process exited while it was
// read.
func processGone(err error) bool {
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ESRCH)
}
