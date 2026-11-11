package checks

import (
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// maxRestoreChainDepth bounds the full ancestry walk, including parents
// that are not termination targets. Incomplete ancestry refuses the response.
const maxRestoreChainDepth = 16

// RestoreWriterChain names the processes to stop after pid wrote back a file
// CSM had removed: the writer and its parents of the same account that keep it
// running, writer first. It returns nil unless the chain was started by the
// web server or runs detached under init. A process with a terminal, or one an
// SSH, cPanel or cron session started, belongs to a person or a scheduled job:
// CSM still removes the file but leaves the process to the operator.
func RestoreWriterChain(pid int, writtenAt time.Time) []int {
	return restoreWriterChain(pid, writtenAt, true)
}

func restoreWriterChain(pid int, writtenAt time.Time, directWriter bool) []int {
	uid := getProcessUID(strconv.Itoa(pid))
	if uid == "" || uid == "0" {
		return nil
	}
	var chain []int
	collecting := true
	for p, depth := pid, 0; depth < maxRestoreChainDepth; depth++ {
		id := strconv.Itoa(p)
		parent, tty, ok := procParentAndTTY(id)
		exe := getProcessExe(id)
		owner := getProcessUID(id)
		if !ok || parent < 1 || tty != 0 || exe == "" || owner == "" || !processStartedBefore(id, writtenAt) {
			return nil
		}
		if p == pid && owner != uid {
			return nil
		}
		if isSessionExe(exe) {
			return nil
		}
		if isWebServerExe(exe) {
			// A web worker ends the set of targets, not the safety walk:
			// PHP can itself have been launched from SSH or cron.
			if p == pid && directWriter && isServerPHPExe(exe) {
				chain = append(chain, p)
			}
			collecting = false
		} else {
			if isControlPlaneExe(exe) || collecting && owner != uid {
				return nil
			}
			if collecting {
				chain = append(chain, p)
			}
		}
		if parent == 1 {
			return chain
		}
		p = parent
	}
	return nil
}

// isSessionExe identifies administrative origins even when they run as the
// account or PHP appears between the session and the writer.
func isSessionExe(exe string) bool {
	exe = strings.TrimSuffix(exe, " (deleted)")
	if strings.HasPrefix(exe, "/usr/local/cpanel/") {
		return true
	}
	switch filepath.Base(exe) {
	case "sshd", "sshd-session", "sshd-auth", "cron", "crond", "anacron", "cpsrvd", "cpsrvd-dormant":
		return true
	}
	return false
}

// isServerPHPExe matches the PHP binaries a web server runs requests in.
// The PHP command-line binary is not one: a script it runs is stoppable.
func isServerPHPExe(exe string) bool {
	base := filepath.Base(strings.TrimSuffix(exe, " (deleted)"))
	return strings.HasPrefix(base, "lsphp") || strings.HasPrefix(base, "php-fpm") || strings.HasPrefix(base, "php-cgi")
}

func isWebServerExe(exe string) bool {
	if isServerPHPExe(exe) {
		return true
	}
	switch filepath.Base(strings.TrimSuffix(exe, " (deleted)")) {
	case "httpd", "apache2", "lshttpd", "litespeed", "openlitespeed", "lscgid", "nginx":
		return true
	}
	return false
}

// isControlPlaneExe matches panel, web server and system service binaries,
// including the per-user processes cPanel and SSH run as the account.
func isControlPlaneExe(exe string) bool {
	exe = strings.TrimSuffix(exe, " (deleted)")
	if isSessionExe(exe) || isWebServerExe(exe) {
		return true
	}
	switch filepath.Base(exe) {
	case "systemd", "init", "dbus-daemon", "dbus-broker", "dbus-broker-launch",
		"mysqld", "mariadbd", "postgres", "redis-server", "valkey-server", "memcached":
		return true
	}
	for _, prefix := range []string{
		"/usr/local/cpanel/", "/opt/cpanel/", "/usr/local/lsws/",
		"/sbin/", "/usr/sbin/", "/usr/local/sbin/", "/usr/libexec/", "/usr/lib/", "/lib/",
		"/opt/cloudlinux/", "/opt/imunify360/",
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
