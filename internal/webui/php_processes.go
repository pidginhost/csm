package webui

import (
	"os"
	"path/filepath"
	"strings"
)

// scanPHPProcesses reports whether a PHP-FPM or lsphp process runs on this
// host, including inside containers, and whether one of them can see the
// PHP Shield script in its own root filesystem.
//
// shortcut: Apache mod_php containers (php:apache images) have no PHP process
// of their own and are not found; match the httpd cmdline if one shows up.
func scanPHPProcesses(procRoot, shieldPath string) (running, shielded bool) {
	cmdlinePaths, _ := filepath.Glob(filepath.Join(procRoot, "[0-9]*", "cmdline"))
	for _, cmdPath := range cmdlinePaths {
		// #nosec G304 -- cmdPath from /proc/*/cmdline glob; kernel pseudo-FS.
		data, err := os.ReadFile(cmdPath)
		if err != nil {
			continue
		}
		cmd := strings.ReplaceAll(string(data), "\x00", " ")
		// An idle ondemand pool runs only its master.
		if !isPHPWorkerCmdline(cmd) && !strings.HasPrefix(cmd, "php-fpm: master") {
			continue
		}
		running = true
		// Lstat: a container must not claim the shield by linking to the host's copy.
		fi, err := os.Lstat(filepath.Join(filepath.Dir(cmdPath), "root", shieldPath))
		if err == nil && fi.Mode().IsRegular() {
			return true, true
		}
	}
	return running, false
}
