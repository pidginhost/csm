package maillog

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// Paths the journal probe reads; variables so tests can redirect them.
var (
	devLogPath       = "/dev/log"
	journaldSocket   = "/run/systemd/journal/dev-log"
	journalDirs      = []string{"/run/log/journal", "/var/log/journal"}
	postfixMainCF    = "/etc/postfix/main.cf"
	journalSupported = JournalSupported
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
	for _, dir := range journalDirs {
		if files, _ := filepath.Glob(filepath.Join(dir, "*", "*.journal")); len(files) > 0 {
			return true
		}
	}
	return false
}

// postfixLogsToFile reports whether Postfix writes its own log file through
// postlogd, which leaves no Postfix entries in the journal.
func postfixLogsToFile() bool {
	f, err := os.Open(postfixMainCF)
	if err != nil {
		return false
	}
	defer f.Close()
	value := ""
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		key, v, ok := strings.Cut(sc.Text(), "=")
		if ok && strings.TrimSpace(key) == "maillog_file" {
			value = strings.TrimSpace(v)
		}
	}
	return value != ""
}
