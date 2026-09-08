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
	for _, rel := range []string{"scripts/deploy.sh", "scripts/deploy-gitlab.sh"} {
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

func TestUpgradeHealthGateRollsBackRunningDaemon(t *testing.T) {
	for _, rel := range []string{"scripts/deploy.sh", "scripts/deploy-gitlab.sh"} {
		for _, failure := range []string{"doctor", "settle", "none"} {
			t.Run(rel+"/"+failure, func(t *testing.T) {
				dir := t.TempDir()
				installDir := filepath.Join(dir, "install")
				binary := filepath.Join(installDir, "csm")
				packageBinary := filepath.Join(dir, "new")
				for path, version := range map[string]string{binary: "1.0.0", packageBinary: "2.0.0"} {
					writeDeployTestFile(t, path, "#!/bin/bash\ncase \"$1\" in\nversion) echo 'csm "+version+"';;\nrehash) echo 'rehash "+version+"' >> \"$TEST_EVENTS\";;\ndoctor) [ \"$TEST_FAILURE\" != doctor ];;\nesac\n")
					if err := os.Chmod(path, 0o700); err != nil {
						t.Fatal(err)
					}
				}
				for _, entry := range []string{"ui", "configs", "pam"} {
					writeDeployTestFile(t, filepath.Join(installDir, entry, "release"), "old")
				}
				writeDeployTestFile(t, filepath.Join(installDir, "deploy.sh"), "old")
				for _, rule := range []string{"malware.yml", "malware.yar"} {
					writeDeployTestFile(t, filepath.Join(installDir, "rules", rule), "old")
				}
				script := filepath.Join(repoRootFromDaemonTest(), rel)
				body := []string{
					"set -euo pipefail", "SERVICE_NAME=csm", "ARTIFACT_NAME=csm-linux-amd64", "CSM_UPGRADE_HEALTH_SETTLE=2",
					"die() { echo \"$1\" >&2; exit 1; }", "id() { echo 0; }",
					"detect_auth_header() { :; }", "save_token() { :; }", githubReleaseTagResolverStub(rel),
					"download_package() { command cp \"$TEST_PACKAGE_BINARY\" \"$2/$ARTIFACT_NAME\"; }",
					"download_and_stage_assets() { local stage=\"$2/assets-stage\"; mkdir -p \"$stage\"/{ui,configs,pam}; for entry in ui configs pam; do echo new > \"$stage/$entry/release\"; done; echo new > \"$stage/deploy.sh\"; for rule in malware.yml malware.yar; do echo new > \"$stage/configs/$rule\"; done; echo \"$stage\"; }",
					"stop_services() { echo stop >> \"$TEST_EVENTS\"; rm -f \"$TEST_RUNNING\"; }",
					"start_services() { if [ ! -f \"$TEST_RUNNING\" ]; then \"$BINARY_PATH\" version > \"$TEST_RUNNING\"; echo \"start $(cat \"$TEST_RUNNING\")\" >> \"$TEST_EVENTS\"; fi; }",
					// Linux refuses to overwrite an executing binary (ETXTBSY).
					"cp() { if [ \"${!#}\" = \"$BINARY_PATH\" ] && [ -f \"$TEST_RUNNING\" ]; then echo 'Text file busy' >&2; return 1; fi; command cp \"$@\"; }",
					"systemctl() { [ \"$TEST_FAILURE\" != settle ]; }",
					"sleep() { :; }", "lsattr() { :; }", "chattr() { :; }",
				}
				for _, fn := range []string{"activate_assets", "rollback_assets", "rollback_upgrade", "cleanup_upgrade_backup", "version_key", "refuse_downgrade", "verify_upgrade_health", "do_upgrade"} {
					body = append(body, extractShellFunction(t, script, fn))
				}
				body = append(body, "do_upgrade")
				wrapper := filepath.Join(dir, "upgrade.sh")
				writeDeployTestFile(t, wrapper, strings.Join(body, "\n"))
				events := filepath.Join(dir, "events")
				cmd := exec.Command("/bin/bash", wrapper)
				cmd.Env = withEnv(os.Environ(), "INSTALL_DIR="+installDir, "BINARY_PATH="+binary, "TEST_PACKAGE_BINARY="+packageBinary,
					"TEST_EVENTS="+events, "TEST_RUNNING="+filepath.Join(dir, "running"), "TEST_FAILURE="+failure)
				out, err := cmd.CombinedOutput()
				wantVersion, wantAssets := "1.0.0", "old"
				wantEvents := "stop\nrehash 2.0.0\nstart csm 2.0.0\nstop\nrehash 1.0.0\nstart csm 1.0.0\n"
				if failure == "none" {
					wantVersion, wantAssets = "2.0.0", "new"
					wantEvents = "stop\nrehash 2.0.0\nstart csm 2.0.0\n"
					if err != nil {
						t.Fatalf("healthy upgrade failed: %v\n%s", err, out)
					}
				} else if err == nil || !strings.Contains(string(out), "rolled back to previous version") {
					t.Errorf("unhealthy upgrade did not complete rollback: %v\n%s", err, out)
				}
				gotEvents, readErr := os.ReadFile(events)
				if readErr != nil || string(gotEvents) != wantEvents {
					t.Errorf("recovery order: %v\n%s\nwant:\n%s", readErr, gotEvents, wantEvents)
				}
				version, versionErr := exec.Command(binary, "version").CombinedOutput()
				if versionErr != nil || strings.TrimSpace(string(version)) != "csm "+wantVersion {
					t.Errorf("installed version: %v %s", versionErr, version)
				}
				for _, entry := range []string{"ui/release", "configs/release", "pam/release", "deploy.sh", "rules/malware.yml", "rules/malware.yar"} {
					data, readErr := os.ReadFile(filepath.Join(installDir, entry))
					if readErr != nil || strings.TrimSpace(string(data)) != wantAssets {
						t.Errorf("%s not restored: %q (%v)", entry, data, readErr)
					}
				}
			})
		}
	}
}

func TestDeployHealthGateImplementationsMatch(t *testing.T) {
	root := repoRootFromDaemonTest()
	for _, fn := range []string{"verify_upgrade_health", "rollback_upgrade"} {
		github := extractShellFunction(t, filepath.Join(root, "scripts/deploy.sh"), fn)
		gitlab := extractShellFunction(t, filepath.Join(root, "scripts/deploy-gitlab.sh"), fn)
		if github != gitlab {
			t.Errorf("%s differs between deploy scripts", fn)
		}
	}
}
