package platform

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// pure-ftpd reads cPanel's or the packaged configuration file; Debian's
// wrapper reads one file per option from pureFTPDOptionDir instead.
// Variables for tests.
var (
	pureFTPDConfigFiles = []string{"/etc/pure-ftpd.conf", "/etc/pure-ftpd/pure-ftpd.conf"}
	pureFTPDOptionDir   = "/etc/pure-ftpd/conf"
)

// PureFTPDDontResolve returns the pure-ftpd configuration sources present on
// the host and those that do not turn DontResolve on. Without it pure-ftpd
// logs a client's reverse DNS name, which the client's owner controls and
// can make read as another address. A source that cannot be read counts as
// missing the setting, and an installed server with no source CSM knows
// reports its configuration as a whole.
func PureFTPDDontResolve() (configs, missing []string) {
	for _, path := range pureFTPDConfigFiles {
		if _, err := os.Lstat(path); errors.Is(err, fs.ErrNotExist) {
			continue
		}
		configs = append(configs, path)
		data, err := os.ReadFile(path) // #nosec G304 -- fixed pure-ftpd configuration paths
		if err != nil || !pureFTPDConfEnables(string(data), "DontResolve") {
			missing = append(missing, path)
		}
	}
	if _, err := os.Lstat(pureFTPDOptionDir); !errors.Is(err, fs.ErrNotExist) {
		path := filepath.Join(pureFTPDOptionDir, "DontResolve")
		configs = append(configs, path)
		data, err := os.ReadFile(path) // #nosec G304 -- fixed pure-ftpd configuration path
		if err != nil || !pureFTPDOptionEnabled(string(data)) {
			missing = append(missing, path)
		}
	}
	if len(configs) == 0 && PureFTPDInstalled() {
		missing = []string{"pure-ftpd's configuration"}
	}
	return configs, missing
}

// PureFTPDConfigChanged returns when the newest configuration source last
// changed: the latest status change of each path and, for a link, of its
// target. pure-ftpd reads its configuration only when it starts, and a file
// copied or moved into place keeps an older modification time but not an
// older status change. ok is false with no source or one that cannot be read.
func PureFTPDConfigChanged(configs []string) (changed time.Time, ok bool) {
	if len(configs) == 0 {
		return time.Time{}, false
	}
	for _, path := range configs {
		for _, stat := range []func(string) (fs.FileInfo, error){os.Lstat, os.Stat} {
			fi, err := stat(path)
			if err != nil {
				return time.Time{}, false
			}
			if at := fileChanged(fi); at.After(changed) {
				changed = at
			}
		}
	}
	return changed, true
}

// pureFTPDConfEnables reports whether a pure-ftpd.conf line turns key on.
// Like pure-ftpd, it matches the key without case, takes '=', ':' or
// whitespace after it, and counts any enabled line: no later line undoes it.
func pureFTPDConfEnables(conf, key string) bool {
	for _, line := range strings.Split(conf, "\n") {
		line = strings.Trim(line, " \t\r\v\f")
		if len(line) <= len(key) || !strings.EqualFold(line[:len(key)], key) {
			continue
		}
		rest := line[len(key):]
		if rest[0] != '=' && rest[0] != ':' && !strings.ContainsAny(rest[:1], " \t\r\v\f") {
			continue
		}
		rest = strings.TrimLeft(rest, " \t\r\v\f")
		if len(rest) > 0 && (rest[0] == '=' || rest[0] == ':') {
			rest = rest[1:]
		}
		switch strings.ToLower(strings.Trim(rest, " \t\r\v\f")) {
		case "yes", "on", "true", "1":
			return true
		}
	}
	return false
}

// pureFTPDOptionEnabled reads a Debian option file the way pure-ftpd-wrapper
// does: trimmed lines, '#' comments skipped, yes, 1 or on without case.
func pureFTPDOptionEnabled(body string) bool {
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		switch strings.ToLower(line) {
		case "yes", "1", "on":
			return true
		}
	}
	return false
}
