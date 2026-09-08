package daemon

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// fakeCSMBinary writes a stand-in for the installed binary whose `doctor`
// exits with the given code.
func fakeCSMBinary(t *testing.T, exitCode int) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "csm")
	body := "#!/bin/bash\nexit " + strconv.Itoa(exitCode) + "\n"
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

// runUpgradeHealthGate executes deploy.sh's post-start health gate against a
// stubbed systemctl and a stand-in binary, the same way the signature tests
// in this package drive verify_signature.
//
// systemctlExit selects what `systemctl is-active` reports: 0 active,
// anything else not active.
func runUpgradeHealthGate(t *testing.T, binaryPath string, systemctlExit int) (string, int) {
	t.Helper()
	tmp := t.TempDir()
	scriptPath := filepath.Join(repoRootFromDaemonTest(), "scripts", "deploy.sh")
	wrapper := filepath.Join(tmp, "run.sh")
	body := strings.Join([]string{
		"#!/bin/bash",
		"set -uo pipefail",
		"SERVICE_NAME=csm",
		"BINARY_PATH=" + binaryPath,
		// Keep the gate quick under test; production waits longer.
		"CSM_UPGRADE_HEALTH_SETTLE=2",
		"systemctl() { return " + strconv.Itoa(systemctlExit) + "; }",
		"sleep() { return 0; }",
		extractShellFunction(t, scriptPath, "verify_upgrade_health"),
		"verify_upgrade_health",
		"",
	}, "\n")
	if err := os.WriteFile(wrapper, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	// The wrapper is generated into a temp dir by this test; no external input
	// reaches it. This mirrors the existing shell-function harness here.
	out, err := exec.Command("/bin/bash", wrapper).CombinedOutput() // #nosec G204
	if err == nil {
		return string(out), 0
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		return string(out), exitErr.ExitCode()
	}
	t.Fatalf("running bash wrapper failed: %v\n%s", err, out)
	return "", 0
}

// The upgrade's only health check was `systemctl is-active` two seconds after
// start. A daemon that starts and then dies, or one that comes up with a
// broken firewall or an unloadable ruleset, passes that check -- so no
// rollback fires and the host keeps running a build that does not protect it.
// For an unattended nightly upgrade of a security daemon, that is the
// difference between a failed upgrade and a silently unprotected server.
//
// `csm doctor` already reports watcher, bbolt store and firewall state, which
// is exactly the started-but-broken case.
func TestUpgradeHealthGateFailsWhenDoctorFails(t *testing.T) {
	out, code := runUpgradeHealthGate(t, fakeCSMBinary(t, 1), 0)
	if code == 0 {
		t.Fatalf("health gate passed although doctor failed:\n%s", out)
	}
	if !strings.Contains(strings.ToLower(out), "doctor") {
		t.Errorf("failure does not name the failing check: %q", out)
	}
}

// The gate must not invent failures: a healthy daemon has to pass, or every
// upgrade rolls back and the automation is worse than none.
func TestUpgradeHealthGatePassesWhenHealthy(t *testing.T) {
	out, code := runUpgradeHealthGate(t, fakeCSMBinary(t, 0), 0)
	if code != 0 {
		t.Fatalf("healthy daemon failed the gate (exit %d):\n%s", code, out)
	}
}

// A daemon that exits during the settle window must be caught there. doctor
// would pass in this case, so only the liveness check can catch it.
func TestUpgradeHealthGateCatchesDaemonExitDuringSettle(t *testing.T) {
	out, code := runUpgradeHealthGate(t, fakeCSMBinary(t, 0), 3)
	if code == 0 {
		t.Fatalf("gate passed although the service was not active:\n%s", out)
	}
	if !strings.Contains(strings.ToLower(out), "not running") {
		t.Errorf("failure does not say the service stopped running: %q", out)
	}
}
