package ci

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

const autoUpgradeCronPath = "../../build/packaging/cron/csm-auto-upgrade"

func autoUpgradeCron(t *testing.T) string {
	t.Helper()
	body, err := os.ReadFile(autoUpgradeCronPath)
	if err != nil {
		t.Fatalf("read %s: %v", autoUpgradeCronPath, err)
	}
	return string(body)
}

// The schedule line has to survive review as a whole: an unattended upgrade
// of the daemon that protects the host is only safe with the pieces below,
// and each one is easy to drop in an edit.
func TestAutoUpgradeCronScheduleIsSafe(t *testing.T) {
	var schedule string
	for _, line := range strings.Split(autoUpgradeCron(t), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || !strings.Contains(line, "deploy.sh") {
			continue
		}
		schedule = line
	}
	if schedule == "" {
		t.Fatal("no schedule line invoking deploy.sh")
	}

	// A fixed minute means one bad release reaches an entire fleet at once.
	if !strings.Contains(schedule, "RANDOM") {
		t.Error("schedule has no randomized delay; every host would upgrade in the same minute")
	}
	// cron treats an unescaped % as end-of-command and turns the rest into
	// stdin, so the delay would silently become no delay.
	if idx := strings.Index(schedule, "%"); idx > 0 && schedule[idx-1] != '\\' {
		t.Error("unescaped % in a crontab line: cron truncates the command there")
	}
	// A slow upgrade must not overlap the next night's run.
	if !strings.Contains(schedule, "flock") {
		t.Error("schedule takes no lock; two upgrades could run at once")
	}
	// Silent automation is unreviewable after the fact.
	if !strings.Contains(schedule, "auto-upgrade.log") {
		t.Error("schedule does not record its output")
	}
	// It must go through the script that verifies signatures, gates on
	// health, and rolls back -- not dnf, which does none of that for CSM.
	if !strings.Contains(schedule, "deploy.sh upgrade") {
		t.Errorf("schedule does not call `deploy.sh upgrade`: %q", schedule)
	}
}

// Shipping this enabled would start unattended upgrades on every host that
// installs the package, which is a decision for the operator and not for a
// package default.
func TestAutoUpgradeCronShipsDisabled(t *testing.T) {
	body := autoUpgradeCron(t)
	if !regexp.MustCompile(`(?i)disabled`).MatchString(body) {
		t.Error("file does not state that it ships disabled")
	}
	// The packaged path must not be a live cron.d entry.
	for _, live := range []string{"/etc/cron.d/csm-auto-upgrade\n", "etc/cron.d/csm-auto-upgrade:"} {
		if strings.Contains(nfpmConfig(t), live) {
			t.Errorf("package installs the cron into cron.d, enabling it by default: %q", live)
		}
	}
}

// The version-comparison hazard is not obvious and costs a silent downgrade
// if missed, so the file has to warn about it where the operator will look.
func TestAutoUpgradeCronWarnsAboutDevelopmentBuilds(t *testing.T) {
	body := strings.ToLower(autoUpgradeCron(t))
	if !strings.Contains(body, "deploy.sh check") {
		t.Error("file does not tell the operator how to check the installed version first")
	}
	if !strings.Contains(body, "backwards") && !strings.Contains(body, "downgrade") {
		t.Error("file does not warn that a development build would be moved back onto a release")
	}
}

func nfpmConfig(t *testing.T) string {
	t.Helper()
	body, err := os.ReadFile("../../build/nfpm.yaml")
	if err != nil {
		t.Fatalf("read nfpm.yaml: %v", err)
	}
	return string(body)
}
