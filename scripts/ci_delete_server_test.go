package scripts

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// fakePhctl installs a stub phctl on PATH. The stub reports one server present
// until it has been asked to delete it deletesNeeded times, which reproduces a
// delete that is accepted while the server is still provisioning and therefore
// leaves the server running.
func fakePhctl(t *testing.T, deletesNeeded int, listBroken bool) string {
	t.Helper()

	dir := t.TempDir()
	state := filepath.Join(dir, "state")
	if err := os.MkdirAll(state, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(state, "present"), []byte("1"), 0o644); err != nil {
		t.Fatal(err)
	}

	listBody := `echo "ID    HOSTNAME   IMAGE  PACKAGE   STATUS"
    if [ -f "$STATE/present" ]; then echo "4461  csm-a1331  alma9  cloudv-1  active"; fi`
	if listBroken {
		listBody = `echo "list unavailable" >&2; exit 1`
	}

	stub := "#!/usr/bin/env bash\n" +
		"STATE=" + state + "\n" +
		"NEEDED=" + strconv.Itoa(deletesNeeded) + "\n" +
		"case \"$3\" in\n" +
		"  list)\n    " + listBody + "\n    ;;\n" +
		"  delete)\n" +
		"    n=$(cat \"$STATE/deletes\" 2>/dev/null || echo 0); n=$((n+1)); echo \"$n\" > \"$STATE/deletes\"\n" +
		"    if [ \"$n\" -ge \"$NEEDED\" ]; then rm -f \"$STATE/present\"; fi\n" +
		"    echo \"Server $4 deleted.\"\n" +
		"    ;;\n" +
		"esac\n"

	path := filepath.Join(dir, "phctl")
	if err := os.WriteFile(path, []byte(stub), 0o755); err != nil {
		t.Fatal(err)
	}
	return dir
}

func runCleanup(t *testing.T, binDir string, args ...string) (string, int) {
	t.Helper()

	cmd := exec.Command("./ci-delete-server.sh", args...)
	cmd.Env = append(os.Environ(),
		"PATH="+binDir+string(os.PathListSeparator)+os.Getenv("PATH"),
		"CSM_DELETE_INTERVAL=0",
		"CSM_DELETE_ATTEMPTS=4",
	)
	out, err := cmd.CombinedOutput()
	code := 0
	if err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("running cleanup script: %v (output %s)", err, out)
		}
		code = exitErr.ExitCode()
	}
	return string(out), code
}

// A delete that lands while the server is still provisioning is acknowledged by
// the API but leaves the server running. The cleanup must retry until the
// server is actually gone rather than trusting the first success.
func TestDeleteRetriesUntilServerIsGone(t *testing.T) {
	bin := fakePhctl(t, 2, false)

	out, code := runCleanup(t, bin, "4461")

	if code != 0 {
		t.Fatalf("cleanup should succeed once the server disappears, exit %d:\n%s", code, out)
	}
	if !strings.Contains(out, "attempt 2") {
		t.Fatalf("expected a second delete attempt after the first left the server running, got:\n%s", out)
	}
}

// Never reporting success for a server that is still there is the whole point:
// a leaked server consumes the account's capacity and wedges the next run.
func TestDeleteFailsLoudlyWhenServerSurvives(t *testing.T) {
	bin := fakePhctl(t, 99, false)

	out, code := runCleanup(t, bin, "4461")

	if code == 0 {
		t.Fatalf("cleanup must fail when the server is still present:\n%s", out)
	}
	if !strings.Contains(out, "4461") || !strings.Contains(out, "manually") {
		t.Fatalf("failure must name the surviving server and ask for manual deletion, got:\n%s", out)
	}
}

// An unreadable server list means "unknown", not "deleted". Treating a failed
// lookup as success is how a leak gets reported as a clean run.
func TestUnreadableListIsNotTreatedAsDeleted(t *testing.T) {
	bin := fakePhctl(t, 1, true)

	out, code := runCleanup(t, bin, "4461")

	if code == 0 {
		t.Fatalf("cleanup must not claim success when deletion cannot be verified:\n%s", out)
	}
	if !strings.Contains(out, "verify") {
		t.Fatalf("failure should say verification was impossible, got:\n%s", out)
	}
}

// Empty ids come from a create that never returned one; they are not failures.
func TestEmptyIDsAreIgnored(t *testing.T) {
	bin := fakePhctl(t, 1, false)

	out, code := runCleanup(t, bin, "", "")

	if code != 0 {
		t.Fatalf("empty ids must be skipped, exit %d:\n%s", code, out)
	}
}
