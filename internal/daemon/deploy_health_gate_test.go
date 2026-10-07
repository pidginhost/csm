package daemon

import (
	"fmt"
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
		"BINARY_PATH=\"$TEST_BINARY\"",
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
	cmd := exec.Command("/bin/bash", wrapper) // #nosec G204 -- test-generated wrapper
	cmd.Env = withEnv(os.Environ(), "TEST_BINARY="+binaryPath)
	out, err := cmd.CombinedOutput()
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

// Run under the caller's `if !` context: errexit is disabled inside the
// function there, so every failed shell command needs an explicit return.
func TestUpgradeHealthGateShellBoundaries(t *testing.T) {
	for _, rel := range deployScriptPaths {
		for _, tc := range []struct {
			name, settle                 string
			failSleep, stopAfterDoctor   bool
			wantCode, wantSleeps, stopAt int
		}{
			{name: "default", wantSleeps: 20},
			{name: "override", settle: "2", wantSleeps: 2},
			{name: "maximum", settle: "3600", wantSleeps: 3600},
			{name: "too long", settle: "3601", wantCode: 1},
			{name: "exit on second poll", settle: "3", stopAt: 2, wantCode: 1, wantSleeps: 2},
			{name: "text", settle: "oops", wantCode: 1},
			{name: "negative", settle: "-1", wantCode: 1},
			{name: "zero", settle: "0", wantCode: 1},
			{name: "fraction", settle: "1.5", wantCode: 1},
			{name: "overflow", settle: "999999999999999999999", wantCode: 1},
			{name: "sleep failure", settle: "2", failSleep: true, wantCode: 1, wantSleeps: 1},
			{name: "exit during doctor", settle: "2", stopAfterDoctor: true, wantCode: 1, wantSleeps: 2},
		} {
			t.Run(rel+"/"+tc.name, func(t *testing.T) {
				dir := t.TempDir()
				binary := filepath.Join(dir, "csm with spaces")
				writeDeployTestFile(t, binary, "#!/bin/bash\n[ \"$#\" = 1 ] && [ \"$1\" = doctor ] || exit 9\ntouch \"$TEST_DOCTOR\"\n")
				if err := os.Chmod(binary, 0o700); err != nil {
					t.Fatal(err)
				}
				wrapper := filepath.Join(dir, "gate.sh")
				body := strings.Join([]string{
					"set -euo pipefail",
					"SERVICE_NAME='csm service'",
					"calls=0; active_calls=0",
					"sleep() { calls=$((calls + 1)); [ \"$FAIL_SLEEP\" = false ]; }",
					"systemctl() { [ \"$#\" = 3 ] && [ \"$1\" = is-active ] && [ \"$2\" = --quiet ] && [ \"$3\" = \"$SERVICE_NAME\" ] || return 9; active_calls=$((active_calls + 1)); [ \"$active_calls\" != \"$STOP_AT\" ] || return 1; [ \"$STOP_AFTER_DOCTOR\" = false ] || [ ! -f \"$TEST_DOCTOR\" ]; }",
					extractShellFunction(t, filepath.Join(repoRootFromDaemonTest(), rel), "verify_upgrade_health"),
					"status=0; if ! verify_upgrade_health; then status=1; fi",
					"echo sleeps=$calls; exit \"$status\"",
				}, "\n")
				writeDeployTestFile(t, wrapper, body)
				cmd := exec.Command("/bin/bash", wrapper)
				cmd.Env = withEnv(os.Environ(), "BINARY_PATH="+binary, "CSM_UPGRADE_HEALTH_SETTLE="+tc.settle,
					"TEST_DOCTOR="+filepath.Join(dir, "doctor"), "FAIL_SLEEP="+strconv.FormatBool(tc.failSleep),
					"STOP_AFTER_DOCTOR="+strconv.FormatBool(tc.stopAfterDoctor), "STOP_AT="+strconv.Itoa(tc.stopAt))
				out, err := cmd.CombinedOutput()
				code := 0
				if err != nil {
					if exitErr, ok := err.(*exec.ExitError); ok {
						code = exitErr.ExitCode()
					} else {
						t.Fatal(err)
					}
				}
				if code != tc.wantCode || !strings.Contains(string(out), fmt.Sprintf("sleeps=%d\n", tc.wantSleeps)) {
					t.Fatalf("exit=%d, want %d; want %d sleeps:\n%s", code, tc.wantCode, tc.wantSleeps, out)
				}
			})
		}
	}
}
