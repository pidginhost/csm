package scripts

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func systemdHarnessSection(t *testing.T, start, end string) string {
	t.Helper()
	data, err := os.ReadFile("systemd-account-roots-test.sh")
	if err != nil {
		t.Fatal(err)
	}
	_, rest, found := strings.Cut(string(data), start+"\n")
	if !found {
		t.Fatalf("missing harness section %q", start)
	}
	body, _, found := strings.Cut(rest, "\n"+end+"\n")
	if !found {
		t.Fatalf("missing harness section end %q", end)
	}
	return body
}

func TestKernelServiceGoEnvironmentWithoutHome(t *testing.T) {
	unit := systemdHarnessSection(t, "  cat > /etc/systemd/system/csm-production-kernel.service <<UNIT", "UNIT")
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(goBinary, "env", "-json", "GOPATH", "GOCACHE", "GOMODCACHE")
	// EL8 system services do not inherit the launcher's HOME. Keep the
	// generated service environment as the only source of Go cache paths.
	cmd.Env = []string{"GOTOOLCHAIN=local"}
	for line := range strings.SplitSeq(unit, "\n") {
		if value, ok := strings.CutPrefix(line, "Environment="); ok {
			cmd.Env = append(cmd.Env, value)
		}
	}
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Go environment: %v\n%s", err, output)
	}
	var got struct{ GOPATH, GOCACHE, GOMODCACHE string }
	if err := json.Unmarshal(output, &got); err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(got.GOPATH) || got.GOCACHE != "/gocache" || got.GOMODCACHE != "/gomodcache" {
		t.Fatalf("service cannot resolve its workspace and shared caches without HOME: %+v", got)
	}
}

func TestSystemdHarnessCollectsResultsBeforeImmediateExit(t *testing.T) {
	body := systemdHarnessSection(t, "cat > \"$artifacts/finish.sh\" <<'FINISH'", "FINISH")
	body = strings.ReplaceAll(body, "artifacts=/src/.cache/systemd-account-roots", `artifacts="$CSM_TEST_ARTIFACTS"`)
	body = strings.ReplaceAll(body, "/etc/systemd/system/csm-production-kernel.service", `"$CSM_TEST_KERNEL_UNIT"`)
	for _, tc := range []struct {
		name, serviceResult, serviceStatus, kernelResult, kernelStatus, want string
		kernel, passLog                                                      bool
	}{
		{"service pass", "success", "0", "success", "0", "0", false, true},
		{"both pass", "success", "0", "success", "0", "0", true, true},
		{"service failed", "exit-code", "1", "success", "0", "1", true, true},
		{"service status failed", "success", "1", "success", "0", "1", true, true},
		{"missing pass record", "success", "0", "success", "0", "1", true, false},
		{"kernel failed", "success", "0", "exit-code", "1", "1", true, true},
		{"kernel status failed", "success", "0", "success", "1", "1", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			write := func(name, contents string, mode os.FileMode) string {
				t.Helper()
				path := filepath.Join(dir, name)
				if err := os.WriteFile(path, []byte(contents), mode); err != nil {
					t.Fatal(err)
				}
				return path
			}
			write("systemctl", `#!/bin/bash
set -eu
if [[ "$1" == show ]]; then
  result=$CSM_TEST_SERVICE_RESULT
  status=$CSM_TEST_SERVICE_STATUS
  if [[ "$2" == csm-production-kernel.service ]]; then
    result=$CSM_TEST_KERNEL_RESULT
    status=$CSM_TEST_KERNEL_STATUS
  fi
  case "$*" in
    *--property=Result\ --value) printf '%s\n' "$result" ;;
    *--property=ExecMainStatus\ --value) printf '%s\n' "$status" ;;
    *) printf 'Result=%s\nExecMainStatus=%s\n' "$result" "$status" ;;
  esac
else
  test -s "$CSM_TEST_ARTIFACTS/result"
  test -s "$CSM_TEST_ARTIFACTS/properties"
  test -s "$CSM_TEST_ARTIFACTS/journal.log"
  if test -f "$CSM_TEST_KERNEL_UNIT"; then
    test -s "$CSM_TEST_ARTIFACTS/kernel-properties"
    test -s "$CSM_TEST_ARTIFACTS/kernel-journal.log"
  fi
  printf '%s\n' "$@" > "$CSM_TEST_ARTIFACTS/exit-args"
fi
`, 0o700)
			write("journalctl", "#!/bin/sh\nprintf 'test journal\\n'\n", 0o700)
			if tc.kernel {
				write("kernel.service", "present", 0o600)
			}
			passLog := ""
			if tc.passLog {
				passLog = "--- PASS: TestCustomAccountRootsInSystemdService (1.00s)\n"
			}
			write("service.log", passLog, 0o600)
			cmd := exec.Command("bash", write("finish.sh", body, 0o700))
			cmd.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"), "CSM_TEST_ARTIFACTS="+dir,
				"CSM_TEST_KERNEL_UNIT="+filepath.Join(dir, "kernel.service"),
				"CSM_TEST_SERVICE_RESULT="+tc.serviceResult, "CSM_TEST_SERVICE_STATUS="+tc.serviceStatus,
				"CSM_TEST_KERNEL_RESULT="+tc.kernelResult, "CSM_TEST_KERNEL_STATUS="+tc.kernelStatus)
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("finish harness: %v\n%s", err, output)
			}
			args, err := os.ReadFile(filepath.Join(dir, "exit-args"))
			if err != nil {
				t.Fatal(err)
			}
			if want := "--force\nexit\n" + tc.want + "\n"; string(args) != want {
				t.Errorf("exit arguments = %q, want %q; EL8 orderly exit can loop in exit.target", args, want)
			}
			result, err := os.ReadFile(filepath.Join(dir, "result"))
			if err != nil {
				t.Fatal(err)
			}
			wantResult := "PASS\n"
			if tc.want != "0" {
				wantResult = "FAIL\n"
			}
			if string(result) != wantResult {
				t.Errorf("result = %q, want %q", result, wantResult)
			}
		})
	}
}
