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

type fakePhctlConfig struct {
	serverIDs         []string
	deletesNeeded     int
	listBroken        bool
	listFailsAfter    int
	resurrectServerID string
	resurrectAfter    int
	deleteBarrier     int
}

type fakePhctl struct {
	path     string
	stateDir string
}

// newFakePhctl installs a strict phctl stub. Each server stays present until it
// has received deletesNeeded deletes, reproducing an accepted delete that loses
// a race with provisioning.
func newFakePhctl(t *testing.T, cfg fakePhctlConfig) fakePhctl {
	t.Helper()

	dir := t.TempDir()
	state := filepath.Join(dir, "state")
	if err := os.MkdirAll(state, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, id := range cfg.serverIDs {
		if err := os.WriteFile(filepath.Join(state, "present-"+id), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	stub := `#!/usr/bin/env bash
set -u
STATE=` + strconv.Quote(state) + `
NEEDED=` + strconv.Itoa(cfg.deletesNeeded) + `
LIST_BROKEN=` + strconv.FormatBool(cfg.listBroken) + `
LIST_FAILS_AFTER=` + strconv.Itoa(cfg.listFailsAfter) + `
RESURRECT_ID=` + strconv.Quote(cfg.resurrectServerID) + `
RESURRECT_AFTER=` + strconv.Itoa(cfg.resurrectAfter) + `
DELETE_BARRIER=` + strconv.Itoa(cfg.deleteBarrier) + `

printf '%s\n' "$*" >> "$STATE/calls"
if [ "$1" != compute ] || [ "$2" != server ]; then
    echo "unexpected phctl invocation: $*" >&2
    exit 64
fi

case "$3" in
  list)
    if $LIST_BROKEN; then
        echo "list unavailable" >&2
        exit 1
    fi
    if [ "$LIST_FAILS_AFTER" -gt 0 ]; then
        n=$(cat "$STATE/lists" 2>/dev/null || echo 0)
        n=$((n + 1))
        echo "$n" > "$STATE/lists"
        if [ "$n" -gt "$LIST_FAILS_AFTER" ]; then
            echo "list unavailable" >&2
            exit 1
        fi
    fi
    echo "ID HOSTNAME IMAGE PACKAGE STATUS"
    found=false
    for file in "$STATE"/present-*; do
        [ -e "$file" ] || continue
        found=true
        id="${file##*/present-}"
        echo "$id csm-$id alma9 cloudv-1 active"
    done
    if [ -n "$RESURRECT_ID" ] && ! $found && [ ! -e "$STATE/resurrected" ]; then
        n=$(cat "$STATE/absent-lists" 2>/dev/null || echo 0)
        n=$((n + 1))
        echo "$n" > "$STATE/absent-lists"
        if [ "$n" -ge "$RESURRECT_AFTER" ]; then
            : > "$STATE/present-$RESURRECT_ID"
            : > "$STATE/resurrected"
        fi
    fi
    ;;
  delete)
    id="$4"
    count_file="$STATE/deletes-$id"
    n=$(cat "$count_file" 2>/dev/null || echo 0)
    n=$((n + 1))
    echo "$n" > "$count_file"
    if [ "$DELETE_BARRIER" -gt 0 ]; then
        : > "$STATE/started-$id"
        for ((waits = 0; waits < 200; waits++)); do
            started=0
            for marker in "$STATE"/started-*; do
                [ -e "$marker" ] || continue
                started=$((started + 1))
            done
            [ "$started" -lt "$DELETE_BARRIER" ] || break
            sleep 0.01
        done
        if [ "$started" -lt "$DELETE_BARRIER" ]; then
            : > "$STATE/barrier-timeout-$id"
            exit 1
        fi
    fi
    if [ "$n" -ge "$NEEDED" ]; then
        rm -f "$STATE/present-$id"
    fi
    echo "Server $id deleted."
    ;;
  *)
    echo "unexpected phctl invocation: $*" >&2
    exit 64
    ;;
esac
`

	path := filepath.Join(dir, "phctl")
	if err := os.WriteFile(path, []byte(stub), 0o755); err != nil {
		t.Fatal(err)
	}
	return fakePhctl{path: path, stateDir: state}
}

func runCleanup(t *testing.T, fake fakePhctl, args ...string) (string, int) {
	t.Helper()
	return runCleanupWithSettings(t, fake, "5", "0", args...)
}

func runCleanupWithSettings(t *testing.T, fake fakePhctl, attempts, interval string, args ...string) (string, int) {
	t.Helper()

	cmd := exec.Command("./ci-delete-server.sh", args...)
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"PHCTL=" + fake.path,
		"CSM_DELETE_INTERVAL=" + interval,
		"CSM_DELETE_ATTEMPTS=" + attempts,
	}
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

func deleteCount(t *testing.T, fake fakePhctl, id string) int {
	t.Helper()

	data, err := os.ReadFile(filepath.Join(fake.stateDir, "deletes-"+id))
	if err != nil {
		t.Fatal(err)
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func assertNoPhctlCalls(t *testing.T, fake fakePhctl) {
	t.Helper()

	if _, err := os.Stat(filepath.Join(fake.stateDir, "calls")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unexpected phctl calls were made: %v", err)
	}
}

// A delete that lands while the server is still provisioning is acknowledged by
// the API but leaves the server running. The cleanup must retry until the
// server is actually gone rather than trusting the first success.
func TestDeleteRetriesUntilServerIsGone(t *testing.T) {
	fake := newFakePhctl(t, fakePhctlConfig{serverIDs: []string{"4461"}, deletesNeeded: 2})

	out, code := runCleanup(t, fake, "4461")

	if code != 0 {
		t.Fatalf("cleanup should succeed once the server disappears, exit %d:\n%s", code, out)
	}
	if deleteCount(t, fake, "4461") != 2 {
		t.Fatalf("cleanup did not retry the accepted delete:\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(fake.stateDir, "present-4461")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("server remains after successful cleanup: %v", err)
	}
}

// A server can stay absent for multiple polls and then be recreated by the
// in-flight provisioner. Cleanup must monitor the full retry window.
func TestDeleteCatchesDelayedProvisioningRace(t *testing.T) {
	fake := newFakePhctl(t, fakePhctlConfig{
		serverIDs:         []string{"4461"},
		deletesNeeded:     1,
		resurrectServerID: "4461",
		resurrectAfter:    2,
	})

	out, code := runCleanup(t, fake, "4461")

	if code != 0 {
		t.Fatalf("cleanup should delete a server recreated by provisioning, exit %d:\n%s", code, out)
	}
	if deleteCount(t, fake, "4461") != 2 {
		t.Fatalf("cleanup stopped polling before the server reappeared:\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(fake.stateDir, "present-4461")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("recreated server remains after successful cleanup: %v", err)
	}
}

// Never reporting success for a server that is still there is the whole point:
// a leaked server consumes the account's capacity and wedges the next run.
func TestDeleteFailsLoudlyWhenServerSurvives(t *testing.T) {
	fake := newFakePhctl(t, fakePhctlConfig{serverIDs: []string{"4461"}, deletesNeeded: 99})

	out, code := runCleanup(t, fake, "4461")

	if code == 0 {
		t.Fatalf("cleanup must fail when the server is still present:\n%s", out)
	}
	if deleteCount(t, fake, "4461") != 5 {
		t.Fatalf("cleanup did not exhaust every delete attempt:\n%s", out)
	}
	if !strings.Contains(out, "4461") || !strings.Contains(out, "manually") {
		t.Fatalf("failure must name the surviving server and ask for manual deletion, got:\n%s", out)
	}
}

// An unreadable server list means "unknown", not "deleted". Treating a failed
// lookup as success is how a leak gets reported as a clean run.
func TestUnreadableListIsNotTreatedAsDeleted(t *testing.T) {
	fake := newFakePhctl(t, fakePhctlConfig{
		serverIDs:     []string{"4461"},
		deletesNeeded: 1,
		listBroken:    true,
	})

	out, code := runCleanup(t, fake, "4461")

	if code == 0 {
		t.Fatalf("cleanup must not claim success when deletion cannot be verified:\n%s", out)
	}
	if !strings.Contains(out, "cannot verify") {
		t.Fatalf("failure should say verification was impossible, got:\n%s", out)
	}
}

// The final list result controls the diagnostic. A previous successful read
// must not turn a later API outage into a false "still present" claim.
func TestFinalListFailureIsReportedAsUnverifiable(t *testing.T) {
	fake := newFakePhctl(t, fakePhctlConfig{
		serverIDs:      []string{"4461"},
		deletesNeeded:  99,
		listFailsAfter: 1,
	})

	out, code := runCleanup(t, fake, "4461")

	if code == 0 {
		t.Fatalf("cleanup must fail when the final server state is unknown:\n%s", out)
	}
	if !strings.Contains(out, "cannot verify") || strings.Contains(out, "still present") {
		t.Fatalf("failure used stale state from an earlier list:\n%s", out)
	}
}

// IDs are matched as complete first-column values. A listed server whose ID
// merely starts with the requested ID must not keep cleanup retrying.
func TestServerIDMatchIsExact(t *testing.T) {
	fake := newFakePhctl(t, fakePhctlConfig{serverIDs: []string{"4461"}, deletesNeeded: 99})

	out, code := runCleanup(t, fake, "446")

	if code != 0 {
		t.Fatalf("server 446 should be absent when only 4461 is listed, exit %d:\n%s", code, out)
	}
	if deleteCount(t, fake, "446") != 1 {
		t.Fatalf("partial ID match caused an unnecessary retry:\n%s", out)
	}
}

// Server IDs are numeric. Rejecting other tokens prevents the table header from
// ever being interpreted as a server and keeps malformed values away from phctl.
func TestHeaderAndInvalidIDsAreRejected(t *testing.T) {
	fake := newFakePhctl(t, fakePhctlConfig{serverIDs: []string{"4461"}, deletesNeeded: 1})

	out, code := runCleanup(t, fake, "ID")

	if code == 0 || !strings.Contains(out, "invalid server id") {
		t.Fatalf("non-numeric server ID should fail before phctl is called, exit %d:\n%s", code, out)
	}
	assertNoPhctlCalls(t, fake)
}

func TestInvalidRetrySettingsAreRejected(t *testing.T) {
	tests := []struct {
		name     string
		attempts string
		interval string
	}{
		{name: "zero attempts", attempts: "0", interval: "0"},
		{name: "one attempt", attempts: "1", interval: "0"},
		{name: "negative interval", attempts: "2", interval: "-1"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fake := newFakePhctl(t, fakePhctlConfig{serverIDs: []string{"4461"}, deletesNeeded: 1})

			out, code := runCleanupWithSettings(t, fake, tc.attempts, tc.interval, "4461")

			if code == 0 || !strings.Contains(out, "must be") {
				t.Fatalf("invalid retry settings should fail clearly, exit %d:\n%s", code, out)
			}
			assertNoPhctlCalls(t, fake)
		})
	}
}

// Servers are cleaned concurrently so three full retry windows fit inside
// GitLab's five-minute after_script timeout. The fake deletes wait for all
// three calls to start, making this fail deterministically if they are serial.
func TestMultipleServersAreDeletedConcurrently(t *testing.T) {
	fake := newFakePhctl(t, fakePhctlConfig{
		serverIDs:     []string{"4461", "4462", "4463"},
		deletesNeeded: 99,
		deleteBarrier: 3,
	})

	out, code := runCleanupWithSettings(t, fake, "2", "0", "4461", "4462", "4463")

	if code == 0 {
		t.Fatalf("cleanup must fail while all three servers remain:\n%s", out)
	}
	for _, id := range []string{"4461", "4462", "4463"} {
		if deleteCount(t, fake, id) != 2 {
			t.Fatalf("server %s did not exhaust both delete attempts:\n%s", id, out)
		}
		if _, err := os.Stat(filepath.Join(fake.stateDir, "barrier-timeout-"+id)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("server %s cleanup started serially: %v\n%s", id, err, out)
		}
	}
}

// Empty IDs come from a create that never returned one; no API request should
// be made for them.
func TestEmptyIDsAreIgnored(t *testing.T) {
	fake := newFakePhctl(t, fakePhctlConfig{serverIDs: []string{"4461"}, deletesNeeded: 1})

	out, code := runCleanup(t, fake, "", "")

	if code != 0 {
		t.Fatalf("empty ids must be skipped, exit %d:\n%s", code, out)
	}
	assertNoPhctlCalls(t, fake)
}
