package maillog

import (
	"bufio"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
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
		if err != nil || !root || processUnit(proc) != "systemd-journald.service" {
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
	f, err := os.Open(postfixMainCF)
	if err != nil {
		return !os.IsNotExist(err)
	}
	defer f.Close()
	value := ""
	key := ""
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			if key == "maillog_file" {
				value += trimmed
			}
			continue
		}
		k, v, _ := strings.Cut(line, "=")
		key = strings.TrimSpace(k)
		if key == "maillog_file" {
			value = strings.TrimSpace(v)
		}
	}
	return sc.Err() != nil || value != ""
}

// mailUnitsCovered keeps auto on the file when a running mail master would
// fall outside the journal filter. Read kernel process metadata, not syslog
// tags that an unprivileged process could forge to force a source change.
func mailUnitsCovered(units []string) bool {
	selected := make([]string, 0, len(units))
	for _, u := range units {
		selected = append(selected, journalUnitName(u))
	}
	processes, _ := filepath.Glob(filepath.Join(journalProcPath, "[0-9]*", "exe"))
	found := false
	for _, exe := range processes {
		target, err := os.Readlink(exe)
		if err != nil {
			if !os.IsNotExist(err) {
				return false
			}
			continue
		}
		name := filepath.Base(strings.TrimSuffix(target, " (deleted)"))
		if name != "master" && name != "dovecot" {
			continue
		}
		proc := filepath.Dir(exe)
		root, err := rootProcess(proc)
		if err != nil {
			return false
		}
		if !root {
			continue
		}
		found = true
		if !slices.Contains(selected, processUnit(proc)) {
			return false
		}
	}
	return found
}

func rootProcess(proc string) (bool, error) {
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

func processUnit(proc string) string {
	data, err := os.ReadFile(filepath.Join(proc, "cgroup"))
	if err != nil {
		return ""
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		fields := strings.SplitN(line, ":", 3)
		if len(fields) != 3 || (fields[1] != "" && fields[1] != "name=systemd") {
			continue
		}
		for _, part := range strings.Split(fields[2], "/") {
			if strings.HasSuffix(part, ".service") {
				return part
			}
		}
	}
	return ""
}
