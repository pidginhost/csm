//go:build linux

package ci

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestAutoUpgradeCronReportsFailures(t *testing.T) {
	body := autoUpgradeCron(t)
	if !strings.Contains(body, "SHELL=/bin/bash\n") {
		t.Fatal("randomized delay requires bash in cron")
	}
	if !strings.Contains(body, "MAILTO=root\n") {
		t.Error("nightly failures must reach root's cron mail")
	}
	var schedule string
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, "30 3 ") {
			if schedule != "" {
				t.Fatal("multiple upgrade schedules")
			}
			schedule = line
		}
	}
	fields := strings.Fields(schedule)
	if len(fields) < 7 || strings.Join(fields[:6], " ") != "30 3 * * * root" {
		t.Fatalf("invalid system crontab schedule: %q", schedule)
	}
	command := strings.TrimPrefix(schedule, strings.Join(fields[:6], " ")+" ")
	// Cron removes the escape before passing a literal percent to the shell.
	command = strings.ReplaceAll(command, `\%`, "%")
	for _, tc := range []struct {
		name       string
		exit       string
		busy       bool
		logFailure bool
	}{
		{name: "success", exit: "0"},
		{name: "upgrade failure", exit: "23"},
		{name: "log failure", exit: "0", logFailure: true},
		{name: "lock held", exit: "0", busy: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			deploy := filepath.Join(dir, "deploy.sh")
			logPath := filepath.Join(dir, "auto-upgrade.log")
			if tc.logFailure {
				logPath = filepath.Join(dir, "missing", "auto-upgrade.log")
			}
			if err := os.WriteFile(deploy, []byte("#!/bin/bash\n[ \"$1\" = upgrade ] || exit 99\necho ran >> \"$TEST_RAN\"\necho upgrade-output\nexit "+tc.exit+"\n"), 0o700); err != nil {
				t.Fatal(err)
			}
			lockPath := filepath.Join(dir, "lock")
			run := strings.NewReplacer("/opt/csm/deploy.sh", deploy, "/var/log/csm/auto-upgrade.log", logPath,
				"/var/lock/csm-auto-upgrade.lock", lockPath).Replace(command)
			prefix := "sleep() { [ \"$#\" = 1 ] && [ \"$1\" -ge 0 ] && [ \"$1\" -lt 3600 ]; }\n"
			if tc.busy {
				prefix += "exec 8>" + lockPath + "\nflock -n 8 || exit 99\n"
			}
			cmd := exec.Command("/bin/bash", "-c", prefix+run)
			ranPath := filepath.Join(dir, "ran")
			cmd.Env = append(os.Environ(), "TEST_RAN="+ranPath)
			out, err := cmd.CombinedOutput()
			failed := tc.exit != "0" || tc.logFailure
			if failed {
				if err == nil || !strings.Contains(string(out), "CSM automatic upgrade failed") {
					t.Fatalf("failure must exit nonzero and produce cron mail: %v\n%s", err, out)
				}
			} else if err != nil || len(out) != 0 {
				t.Fatalf("successful or locked run should be quiet: %v\n%s", err, out)
			}
			ran, readErr := os.ReadFile(ranPath)
			if tc.busy || tc.logFailure {
				if !os.IsNotExist(readErr) {
					t.Fatalf("upgrade ran without lock or log: %q (%v)", ran, readErr)
				}
			} else {
				if readErr != nil || string(ran) != "ran\n" {
					t.Fatalf("upgrade did not run exactly once: %q (%v)", ran, readErr)
				}
				log, readErr := os.ReadFile(logPath)
				if readErr != nil || !strings.Contains(string(log), "upgrade-output") {
					t.Fatalf("upgrade output missing from log: %q (%v)", log, readErr)
				}
			}
		})
	}
}
