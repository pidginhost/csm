package checks

import (
	"context"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

// suspiciousExeNames flags processes whose exe basename contains any of
// these substrings. Shared between the periodic CheckSuspiciousProcesses
// and the live BPF exec backend (which cannot see cmdline patterns and
// relies on exe-name + exe-path matching).
var suspiciousExeNames = []string{"defunct", "gsocket", "gs-netcat", "gs-sftp"}

// suspiciousExePaths flags processes whose exe path contains any of these
// directory prefixes. Shared with the live BPF exec backend.
var suspiciousExePaths = []string{"/tmp/", "/dev/shm/", "/.config/"}

// suspiciousCmdlinePatterns is checked only by the periodic
// CheckSuspiciousProcesses; the BPF exec backend cannot read cmdline at
// the moment of exec.
var suspiciousCmdlinePatterns = []string{
	"/bin/sh -i", "/bin/bash -i", "bash -i",
	"/dev/tcp/", "semutmerah", "gsocket",
	"reverse", "nc -e", "ncat -e",
}

// EvaluateExec returns findings for a single execve event observed by the
// BPF live backend. Inputs are the (UID, PID, comm, exe, parentComm)
// tuple the kernel hook collects. Pure function: no IO. The legacy
// periodic checks (CheckSuspiciousProcesses, CheckFakeKernelThreads) keep
// using cmdline-aware detection that this function cannot replicate.
func EvaluateExec(uid uint32, pid uint32, comm, exe, parentComm string) []alert.Finding {
	var out []alert.Finding
	pidInt := int(pid)

	if uid != 0 && len(comm) >= 2 && comm[0] == '[' && comm[len(comm)-1] == ']' {
		out = append(out, alert.Finding{
			Severity: alert.Critical,
			Check:    "fake_kernel_thread",
			Message:  fmt.Sprintf("Non-root process masquerading as kernel thread: %s", comm),
			Details:  fmt.Sprintf("PID: %d, UID: %d, exe: %s, parent: %s", pid, uid, exe, parentComm),
			PID:      pidInt,
		})
	}

	if uid == 0 {
		return out
	}

	exeName := filepath.Base(exe)
	exeNameLower := strings.ToLower(exeName)
	for _, s := range suspiciousExeNames {
		if strings.Contains(exeNameLower, s) {
			out = append(out, alert.Finding{
				Severity: alert.Critical,
				Check:    "suspicious_process",
				Message:  fmt.Sprintf("Suspicious process name: %s", exeName),
				Details:  fmt.Sprintf("PID: %d, UID: %d, exe: %s, comm: %s, parent: %s", pid, uid, exe, comm, parentComm),
				PID:      pidInt,
			})
			break
		}
	}

	for _, p := range suspiciousExePaths {
		if strings.Contains(exe, p) {
			out = append(out, alert.Finding{
				Severity: alert.High,
				Check:    "suspicious_process",
				Message:  fmt.Sprintf("Process running from suspicious path: %s", exe),
				Details:  fmt.Sprintf("PID: %d, UID: %d, comm: %s, parent: %s", pid, uid, comm, parentComm),
				PID:      pidInt,
			})
			break
		}
	}

	return out
}

func CheckFakeKernelThreads(ctx context.Context, _ *config.Config, _ *state.Store) []alert.Finding {
	var findings []alert.Finding

	procs, _ := osFS.Glob("/proc/[0-9]*/status")
	for _, statusPath := range procs {
		pid := filepath.Base(filepath.Dir(statusPath))

		data, err := osFS.ReadFile(statusPath)
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

		// Read cmdline - real kernel threads have empty cmdline
		cmdline, _ := osFS.ReadFile(filepath.Join("/proc", pid, "cmdline"))
		cmdStr := strings.TrimRight(strings.ReplaceAll(string(cmdline), "\x00", " "), " ")

		// Check if the process name contains brackets (faking kernel thread)
		// or if cmdline starts with [
		if strings.HasPrefix(cmdStr, "[") || strings.HasPrefix(name, "[") {
			// This is a non-root process masquerading as a kernel thread
			exe, _ := osFS.Readlink(filepath.Join("/proc", pid, "exe"))
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

func CheckSuspiciousProcesses(ctx context.Context, _ *config.Config, _ *state.Store) []alert.Finding {
	var findings []alert.Finding

	suspiciousNames := suspiciousExeNames
	suspiciousCmdline := suspiciousCmdlinePatterns
	suspiciousPaths := suspiciousExePaths

	procs, _ := osFS.Glob("/proc/[0-9]*/exe")
	for _, exePath := range procs {
		pid := filepath.Base(filepath.Dir(exePath))
		pidInt, _ := strconv.Atoi(pid)

		statusData, _ := osFS.ReadFile(filepath.Join("/proc", pid, "status"))
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

		exe, _ := osFS.Readlink(exePath)
		cmdline, _ := osFS.ReadFile(filepath.Join("/proc", pid, "cmdline"))
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
// webshell execution. Only reads /proc cmdline - zero disk I/O.
func CheckPHPProcesses(ctx context.Context, _ *config.Config, _ *state.Store) []alert.Finding {
	var findings []alert.Finding

	suspiciousPHPPaths := []string{
		"/tmp/",
		"/dev/shm/",
		"/wp-content/uploads/",
		"/.config/",
	}

	procs, _ := osFS.Glob("/proc/[0-9]*/cmdline")
	for _, cmdPath := range procs {
		pid := filepath.Base(filepath.Dir(cmdPath))
		pidInt, _ := strconv.Atoi(pid)

		cmdline, err := osFS.ReadFile(cmdPath)
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
				statusData, _ := osFS.ReadFile(filepath.Join("/proc", pid, "status"))
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
