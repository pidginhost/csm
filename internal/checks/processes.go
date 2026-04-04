package checks

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

func CheckFakeKernelThreads(_ *config.Config, _ *state.Store) []alert.Finding {
	var findings []alert.Finding

	procs, _ := filepath.Glob("/proc/[0-9]*/status")
	for _, statusPath := range procs {
		pid := filepath.Base(filepath.Dir(statusPath))

		data, err := os.ReadFile(statusPath)
		if err != nil {
			continue
		}

		var name, uid string
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "Name:\t") {
				name = strings.TrimPrefix(line, "Name:\t")
			}
			if strings.HasPrefix(line, "Uid:\t") {
				fields := strings.Fields(strings.TrimPrefix(line, "Uid:\t"))
				if len(fields) > 0 {
					uid = fields[0]
				}
			}
		}

		// Kernel threads run as root (uid 0). Non-root process with
		// a name that looks like a kernel thread is suspicious.
		if uid == "0" || uid == "" {
			continue
		}

		// Read cmdline — real kernel threads have empty cmdline
		cmdline, _ := os.ReadFile(filepath.Join("/proc", pid, "cmdline"))
		cmdStr := strings.TrimRight(strings.ReplaceAll(string(cmdline), "\x00", " "), " ")

		// Check if the process name contains brackets (faking kernel thread)
		// or if cmdline starts with [
		if strings.HasPrefix(cmdStr, "[") || strings.HasPrefix(name, "[") {
			// This is a non-root process masquerading as a kernel thread
			exe, _ := os.Readlink(filepath.Join("/proc", pid, "exe"))
			uidInt, _ := strconv.Atoi(uid)

			pidInt, _ := strconv.Atoi(pid)
			findings = append(findings, alert.Finding{
				Severity: alert.Critical,
				Check:    "fake_kernel_thread",
				Message:  fmt.Sprintf("Non-root process masquerading as kernel thread: [%s]", name),
				Details:  fmt.Sprintf("PID: %s, UID: %d, exe: %s, cmdline: %s", pid, uidInt, exe, cmdStr),
				PID:      pidInt,
			})
		}
	}

	return findings
}

func CheckSuspiciousProcesses(_ *config.Config, _ *state.Store) []alert.Finding {
	var findings []alert.Finding

	suspiciousNames := []string{"defunct", "gsocket", "gs-netcat", "gs-sftp"}
	suspiciousCmdline := []string{
		"/bin/sh -i", "/bin/bash -i", "bash -i",
		"/dev/tcp/", "semutmerah", "gsocket",
		"reverse", "nc -e", "ncat -e",
	}
	suspiciousPaths := []string{"/tmp/", "/dev/shm/", "/.config/"}

	procs, _ := filepath.Glob("/proc/[0-9]*/exe")
	for _, exePath := range procs {
		pid := filepath.Base(filepath.Dir(exePath))
		pidInt, _ := strconv.Atoi(pid)

		statusData, _ := os.ReadFile(filepath.Join("/proc", pid, "status"))
		var uid string
		for _, line := range strings.Split(string(statusData), "\n") {
			if strings.HasPrefix(line, "Uid:\t") {
				fields := strings.Fields(strings.TrimPrefix(line, "Uid:\t"))
				if len(fields) > 0 {
					uid = fields[0]
				}
			}
		}
		if uid == "0" {
			continue // Skip root processes for this check
		}

		exe, _ := os.Readlink(exePath)
		cmdline, _ := os.ReadFile(filepath.Join("/proc", pid, "cmdline"))
		cmdStr := strings.TrimRight(strings.ReplaceAll(string(cmdline), "\x00", " "), " ")

		// Check executable name
		exeName := filepath.Base(exe)
		for _, s := range suspiciousNames {
			if strings.Contains(strings.ToLower(exeName), s) {
				findings = append(findings, alert.Finding{
					Severity: alert.Critical,
					Check:    "suspicious_process",
					Message:  fmt.Sprintf("Suspicious process name: %s", exeName),
					Details:  fmt.Sprintf("PID: %s, UID: %s, exe: %s, cmdline: %s", pid, uid, exe, cmdStr),
					PID:      pidInt,
				})
			}
		}

		// Check cmdline for suspicious patterns
		cmdLower := strings.ToLower(cmdStr)
		for _, s := range suspiciousCmdline {
			if strings.Contains(cmdLower, strings.ToLower(s)) {
				findings = append(findings, alert.Finding{
					Severity: alert.Critical,
					Check:    "suspicious_process",
					Message:  fmt.Sprintf("Suspicious cmdline pattern: %s", s),
					Details:  fmt.Sprintf("PID: %s, UID: %s, exe: %s, cmdline: %s", pid, uid, exe, cmdStr),
					PID:      pidInt,
				})
				break
			}
		}

		// Check executable path
		for _, s := range suspiciousPaths {
			if strings.Contains(exe, s) {
				findings = append(findings, alert.Finding{
					Severity: alert.High,
					Check:    "suspicious_process",
					Message:  fmt.Sprintf("Process running from suspicious path: %s", exe),
					Details:  fmt.Sprintf("PID: %s, UID: %s, cmdline: %s", pid, uid, cmdStr),
					PID:      pidInt,
				})
				break
			}
		}
	}

	return findings
}

// CheckPHPProcesses inspects running lsphp processes to detect active
// webshell execution. Only reads /proc cmdline — zero disk I/O.
func CheckPHPProcesses(_ *config.Config, _ *state.Store) []alert.Finding {
	var findings []alert.Finding

	suspiciousPHPPaths := []string{
		"/tmp/",
		"/dev/shm/",
		"/wp-content/uploads/",
		"/.config/",
	}

	procs, _ := filepath.Glob("/proc/[0-9]*/cmdline")
	for _, cmdPath := range procs {
		pid := filepath.Base(filepath.Dir(cmdPath))
		pidInt, _ := strconv.Atoi(pid)

		cmdline, err := os.ReadFile(cmdPath)
		if err != nil {
			continue
		}
		cmdStr := strings.ReplaceAll(string(cmdline), "\x00", " ")

		// Only check lsphp processes
		if !strings.Contains(cmdStr, "lsphp") {
			continue
		}

		for _, sus := range suspiciousPHPPaths {
			if strings.Contains(cmdStr, sus) {
				statusData, _ := os.ReadFile(filepath.Join("/proc", pid, "status"))
				var uid string
				for _, line := range strings.Split(string(statusData), "\n") {
					if strings.HasPrefix(line, "Uid:\t") {
						fields := strings.Fields(strings.TrimPrefix(line, "Uid:\t"))
						if len(fields) > 0 {
							uid = fields[0]
						}
					}
				}

				findings = append(findings, alert.Finding{
					Severity: alert.Critical,
					Check:    "php_suspicious_execution",
					Message:  fmt.Sprintf("PHP executing from suspicious path: %s", sus),
					Details:  fmt.Sprintf("PID: %s, UID: %s, cmdline: %s", pid, uid, strings.TrimSpace(cmdStr)),
					PID:      pidInt,
				})
				break
			}
		}
	}

	return findings
}
