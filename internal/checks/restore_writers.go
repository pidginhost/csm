package checks

import (
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// maxRestoreChainDepth bounds the walk up from a writer. A deeper chain of
// one account's processes is not the shape this response is for, so nothing
// is stopped.
const maxRestoreChainDepth = 16

// RestoreWriterChain names the processes to stop after pid wrote back a file
// CSM had removed: the writer and its parents of the same account that keep it
// running, writer first. It returns nil unless the chain was started by the
// web server or runs detached under init. A process with a terminal, or one an
// SSH, cPanel or cron session started, belongs to a person or a scheduled job:
// CSM still removes the file but leaves the process to the operator.
func RestoreWriterChain(pid int, writtenAt time.Time) []int {
	uid := getProcessUID(strconv.Itoa(pid))
	if uid == "" || uid == "0" {
		return nil
	}
	var chain []int
	for p := pid; len(chain) < maxRestoreChainDepth; {
		id := strconv.Itoa(p)
		parent, tty, ok := procParentAndTTY(id)
		exe := getProcessExe(id)
		if !ok || tty != 0 || exe == "" || getProcessUID(id) != uid || !processStartedBefore(id, writtenAt) {
			return nil
		}
		if isServerPHPExe(exe) {
			// PHP code looping inside a request writes from the worker
			// itself. A worker above a writer serves the site and stays.
			if len(chain) == 0 {
				chain = append(chain, p)
			}
			return chain
		}
		if isControlPlaneExe(exe) {
			return nil
		}
		chain = append(chain, p)
		if parent <= 1 {
			return chain
		}
		parentID := strconv.Itoa(parent)
		if getProcessUID(parentID) != uid {
			if isWebServerExe(getProcessExe(parentID)) {
				return chain
			}
			return nil
		}
		p = parent
	}
	return nil
}

// isServerPHPExe matches the PHP binaries a web server runs requests in.
// The PHP command-line binary is not one: a script it runs is stoppable.
func isServerPHPExe(exe string) bool {
	base := filepath.Base(exe)
	return strings.HasPrefix(base, "lsphp") || strings.HasPrefix(base, "php-fpm") || strings.HasPrefix(base, "php-cgi")
}

func isWebServerExe(exe string) bool {
	if isServerPHPExe(exe) {
		return true
	}
	switch filepath.Base(exe) {
	case "httpd", "apache2", "lshttpd", "litespeed", "openlitespeed", "lscgid", "nginx":
		return true
	}
	return false
}

// isControlPlaneExe matches panel, web server and system service binaries,
// including the per-user processes cPanel and SSH run as the account.
func isControlPlaneExe(exe string) bool {
	for _, prefix := range []string{
		"/usr/local/cpanel/", "/usr/local/lsws/", "/usr/sbin/", "/usr/libexec/",
		"/usr/lib/systemd/", "/lib/systemd/", "/opt/cloudlinux/", "/opt/imunify360/",
	} {
		if strings.HasPrefix(exe, prefix) {
			return true
		}
	}
	return false
}

// procParentAndTTY reads the parent PID and controlling terminal of pid.
func procParentAndTTY(pid string) (parent, tty int, ok bool) {
	fields, ok := procStatFields(pid)
	// After the command name: state, ppid, pgrp, session, tty_nr.
	if !ok || len(fields) < 5 {
		return 0, 0, false
	}
	parent, err := strconv.Atoi(fields[1])
	if err != nil {
		return 0, 0, false
	}
	tty, err = strconv.Atoi(fields[4])
	if err != nil {
		return 0, 0, false
	}
	return parent, tty, true
}
