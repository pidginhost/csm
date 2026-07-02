package daemon

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/control"
)

func TestWriteFirewallRollbackFileCapturesEmptyRuleset(t *testing.T) {
	installFakeNft(t)

	rollbackFile := filepath.Join(t.TempDir(), "rollback.nft")
	if err := writeFirewallRollbackFile(rollbackFile); err != nil {
		t.Fatalf("writeFirewallRollbackFile: %v", err)
	}

	got, err := os.ReadFile(rollbackFile)
	if err != nil {
		t.Fatalf("read rollback file: %v", err)
	}
	if string(got) != "flush ruleset\n" {
		t.Fatalf("rollback file = %q, want empty-ruleset flush", got)
	}
	info, err := os.Stat(rollbackFile)
	if err != nil {
		t.Fatalf("stat rollback file: %v", err)
	}
	if gotMode := info.Mode().Perm(); gotMode != 0600 {
		t.Fatalf("rollback mode = %o, want 0600", gotMode)
	}
}

func TestWriteFirewallRollbackFileStoresNftDumpWithoutShellWrapper(t *testing.T) {
	installFakeNft(t)
	dump := "table inet csm { # NFTEOF; $(touch /tmp/pwn)\n}\n"
	t.Setenv("NFT_LIST_TEXT", dump)

	rollbackFile := filepath.Join(t.TempDir(), "rollback.nft")
	if err := writeFirewallRollbackFile(rollbackFile); err != nil {
		t.Fatalf("writeFirewallRollbackFile: %v", err)
	}

	got, err := os.ReadFile(rollbackFile)
	if err != nil {
		t.Fatalf("read rollback file: %v", err)
	}
	text := string(got)
	if !strings.HasPrefix(text, "flush ruleset\n") {
		t.Fatalf("rollback file missing flush prefix: %q", text)
	}
	if !strings.Contains(text, dump) {
		t.Fatalf("rollback file missing nft dump: %q", text)
	}
	if strings.Contains(text, "#!/bin/bash") || strings.Contains(text, "nft -f - <<") {
		t.Fatalf("rollback file contains shell wrapper material: %q", text)
	}
}

func TestRestoreFirewallRollbackKeepsMarkersWhenNftFails(t *testing.T) {
	installFakeNft(t)
	t.Setenv("NFT_RESTORE_FAIL", "1")

	dir := t.TempDir()
	confirmFile := filepath.Join(dir, "confirm_pending")
	rollbackFile := filepath.Join(dir, "rollback.nft")
	writeTestFile(t, confirmFile, "pending")
	writeTestFile(t, rollbackFile, "flush ruleset\n")

	err := restoreFirewallRollback(confirmFile, rollbackFile, []byte("pending"))
	if err == nil {
		t.Fatal("restoreFirewallRollback succeeded, want nft failure")
	}
	if !strings.Contains(err.Error(), "restore failed") {
		t.Fatalf("restore error = %q, want nft output", err.Error())
	}
	requirePathExists(t, confirmFile)
	requirePathExists(t, rollbackFile)
}

func TestRestoreFirewallRollbackRemovesMarkersAfterNftSuccess(t *testing.T) {
	installFakeNft(t)

	dir := t.TempDir()
	confirmFile := filepath.Join(dir, "confirm_pending")
	rollbackFile := filepath.Join(dir, "rollback.nft")
	legacyRollbackFile := filepath.Join(dir, "rollback.sh")
	seenFile := filepath.Join(dir, "seen")
	t.Setenv("NFT_RESTORE_SEEN", seenFile)
	writeTestFile(t, confirmFile, "pending")
	writeTestFile(t, rollbackFile, "flush ruleset\n")
	writeTestFile(t, legacyRollbackFile, "#!/bin/sh\n")

	if err := restoreFirewallRollback(confirmFile, rollbackFile, []byte("pending")); err != nil {
		t.Fatalf("restoreFirewallRollback: %v", err)
	}
	requirePathMissing(t, confirmFile)
	requirePathMissing(t, rollbackFile)
	requirePathMissing(t, legacyRollbackFile)
	got, err := os.ReadFile(seenFile)
	if err != nil {
		t.Fatalf("read seen file: %v", err)
	}
	if strings.TrimSpace(string(got)) != rollbackFile {
		t.Fatalf("nft restored %q, want %q", strings.TrimSpace(string(got)), rollbackFile)
	}
}

func TestHandleFirewallConfirmRemovesLegacyRollbackScript(t *testing.T) {
	statePath := t.TempDir()
	confirmFile, rollbackFile, legacyRollbackFile := firewallRollbackFiles(statePath)
	if err := os.MkdirAll(filepath.Dir(confirmFile), 0700); err != nil {
		t.Fatalf("mkdir firewall dir: %v", err)
	}
	writeTestFile(t, confirmFile, "pending")
	writeTestFile(t, rollbackFile, "flush ruleset\n")
	writeTestFile(t, legacyRollbackFile, "#!/bin/sh\n")

	cfg := &config.Config{StatePath: statePath}
	config.SetActive(cfg)
	t.Cleanup(func() { config.SetActive(nil) })
	c := &ControlListener{d: &Daemon{cfg: cfg}}

	result, err := c.handleFirewallConfirm(nil)
	if err != nil {
		t.Fatalf("handleFirewallConfirm: %v", err)
	}
	ack, ok := result.(control.FirewallAckResult)
	if !ok {
		t.Fatalf("result type = %T, want FirewallAckResult", result)
	}
	if !strings.Contains(ack.Message, "Rollback timer cancelled") {
		t.Fatalf("message = %q", ack.Message)
	}
	requirePathMissing(t, confirmFile)
	requirePathMissing(t, rollbackFile)
	requirePathMissing(t, legacyRollbackFile)
}

func TestFirewallConfirmMarkerKeepsSameDeadlineWindowsDistinct(t *testing.T) {
	deadline := time.Date(2026, 7, 3, 10, 11, 12, 123456789, time.UTC)

	first := newFirewallConfirmMarker(deadline)
	second := newFirewallConfirmMarker(deadline)
	if bytes.Equal(first, second) {
		t.Fatalf("markers for separate windows are identical: %q", first)
	}

	got, err := parseFirewallConfirmDeadline(first)
	if err != nil {
		t.Fatalf("parse marker deadline: %v", err)
	}
	if !got.Equal(deadline) {
		t.Fatalf("parsed deadline = %v, want %v", got, deadline)
	}
}

// setupFirewallDeadmanState creates the firewall state dir and returns the
// marker paths plus a Daemon wired to it and the fake-nft "seen" path.
func setupFirewallDeadmanState(t *testing.T) (d *Daemon, confirmFile, rollbackFile, legacyRollbackFile, seenFile string) {
	t.Helper()
	installFakeNft(t)
	statePath := t.TempDir()
	confirmFile, rollbackFile, legacyRollbackFile = firewallRollbackFiles(statePath)
	if err := os.MkdirAll(filepath.Dir(confirmFile), 0700); err != nil {
		t.Fatalf("mkdir firewall dir: %v", err)
	}
	seenFile = filepath.Join(t.TempDir(), "seen")
	t.Setenv("NFT_RESTORE_SEEN", seenFile)
	return &Daemon{cfg: &config.Config{StatePath: statePath}}, confirmFile, rollbackFile, legacyRollbackFile, seenFile
}

func TestRecoverFirewallApplyConfirmedExpiredRestoresPreviousRuleset(t *testing.T) {
	d, confirmFile, rollbackFile, legacyRollbackFile, seenFile := setupFirewallDeadmanState(t)
	writeTestFile(t, confirmFile, time.Now().Add(-time.Minute).UTC().Format(time.RFC3339))
	writeTestFile(t, rollbackFile, "flush ruleset\n")
	writeTestFile(t, legacyRollbackFile, "#!/bin/sh\n")

	d.recoverFirewallApplyConfirmed()

	got, err := os.ReadFile(seenFile)
	if err != nil {
		t.Fatalf("expired window was not rolled back: %v", err)
	}
	if strings.TrimSpace(string(got)) != rollbackFile {
		t.Fatalf("nft restored %q, want %q", strings.TrimSpace(string(got)), rollbackFile)
	}
	requirePathMissing(t, confirmFile)
	requirePathMissing(t, rollbackFile)
	requirePathMissing(t, legacyRollbackFile)
}

func TestRecoverFirewallApplyConfirmedFutureKeepsWindowFiles(t *testing.T) {
	d, confirmFile, rollbackFile, _, seenFile := setupFirewallDeadmanState(t)
	writeTestFile(t, confirmFile, time.Now().Add(time.Hour).UTC().Format(time.RFC3339))
	writeTestFile(t, rollbackFile, "flush ruleset\n")

	d.recoverFirewallApplyConfirmed()

	requirePathMissing(t, seenFile)
	requirePathExists(t, confirmFile)
	requirePathExists(t, rollbackFile)
}

func TestRecoverFirewallApplyConfirmedFutureRestoresAtDeadline(t *testing.T) {
	d, confirmFile, rollbackFile, _, _ := setupFirewallDeadmanState(t)
	// Sub-second deadline so the re-armed timer fires inside the test.
	writeTestFile(t, confirmFile, time.Now().Add(300*time.Millisecond).UTC().Format(time.RFC3339Nano))
	writeTestFile(t, rollbackFile, "flush ruleset\n")

	d.recoverFirewallApplyConfirmed()

	waitUntil := time.Now().Add(5 * time.Second)
	for {
		_, confirmErr := os.Stat(confirmFile)
		_, rollbackErr := os.Stat(rollbackFile)
		if os.IsNotExist(confirmErr) && os.IsNotExist(rollbackErr) {
			return
		}
		if time.Now().After(waitUntil) {
			t.Fatal("re-armed deadman did not restore by the persisted deadline")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestRecoverFirewallApplyConfirmedCorruptMarkerFailsSafe(t *testing.T) {
	d, confirmFile, rollbackFile, _, seenFile := setupFirewallDeadmanState(t)
	writeTestFile(t, confirmFile, "not-a-deadline")
	writeTestFile(t, rollbackFile, "flush ruleset\n")

	d.recoverFirewallApplyConfirmed()

	requirePathExists(t, seenFile)
	requirePathMissing(t, confirmFile)
	requirePathMissing(t, rollbackFile)
}

func TestRecoverFirewallApplyConfirmedRemovesOrphanSnapshot(t *testing.T) {
	d, confirmFile, rollbackFile, legacyRollbackFile, seenFile := setupFirewallDeadmanState(t)
	writeTestFile(t, rollbackFile, "flush ruleset\n")
	writeTestFile(t, legacyRollbackFile, "#!/bin/sh\n")

	d.recoverFirewallApplyConfirmed()

	requirePathMissing(t, seenFile)
	requirePathMissing(t, confirmFile)
	requirePathMissing(t, rollbackFile)
	requirePathMissing(t, legacyRollbackFile)
}

func TestApplyFirewallDeadmanWritesMarkerBeforeApply(t *testing.T) {
	_, confirmFile, rollbackFile, legacyRollbackFile, _ := setupFirewallDeadmanState(t)

	var markerAtApply string
	apply := func() error {
		raw, err := os.ReadFile(confirmFile)
		if err != nil {
			t.Errorf("confirm marker missing at apply time: %v", err)
			return nil
		}
		markerAtApply = string(raw)
		return nil
	}
	if err := applyFirewallDeadman(confirmFile, rollbackFile, legacyRollbackFile, 3*time.Minute, apply); err != nil {
		t.Fatalf("applyFirewallDeadman: %v", err)
	}

	deadline, err := parseFirewallConfirmDeadline([]byte(markerAtApply))
	if err != nil {
		t.Fatalf("marker at apply time = %q, want RFC3339 deadline: %v", markerAtApply, err)
	}
	if !deadline.After(time.Now()) {
		t.Fatalf("marker deadline %v is not in the future", deadline)
	}
	requirePathExists(t, confirmFile)
	requirePathExists(t, rollbackFile)
}

func TestApplyFirewallDeadmanRejectsPendingWindowWithoutRemovingFiles(t *testing.T) {
	_, confirmFile, rollbackFile, legacyRollbackFile, _ := setupFirewallDeadmanState(t)
	writeTestFile(t, confirmFile, "existing-window")
	writeTestFile(t, rollbackFile, "old snapshot")
	writeTestFile(t, legacyRollbackFile, "old legacy")
	applyCalled := false

	err := applyFirewallDeadman(confirmFile, rollbackFile, legacyRollbackFile, time.Minute, func() error {
		applyCalled = true
		return nil
	})
	if err == nil {
		t.Fatal("applyFirewallDeadman succeeded with a pending window")
	}
	if !strings.Contains(err.Error(), "confirmation already pending") {
		t.Fatalf("error = %q, want pending-window error", err.Error())
	}
	if applyCalled {
		t.Fatal("apply callback ran despite a pending window")
	}
	requireFileContent(t, confirmFile, "existing-window")
	requireFileContent(t, rollbackFile, "old snapshot")
	requireFileContent(t, legacyRollbackFile, "old legacy")
}

func TestApplyFirewallDeadmanHonorsPersistedDeadlineAfterSlowApply(t *testing.T) {
	_, confirmFile, rollbackFile, legacyRollbackFile, _ := setupFirewallDeadmanState(t)

	if err := applyFirewallDeadman(confirmFile, rollbackFile, legacyRollbackFile, time.Millisecond, func() error {
		time.Sleep(50 * time.Millisecond)
		return nil
	}); err != nil {
		t.Fatalf("applyFirewallDeadman: %v", err)
	}

	waitUntil := time.Now().Add(5 * time.Second)
	for {
		_, confirmErr := os.Stat(confirmFile)
		_, rollbackErr := os.Stat(rollbackFile)
		if os.IsNotExist(confirmErr) && os.IsNotExist(rollbackErr) {
			return
		}
		if time.Now().After(waitUntil) {
			t.Fatal("deadman did not restore after the persisted deadline passed during apply")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestHandleFirewallConfirmWaitsForApplyConfirmedProtocol(t *testing.T) {
	d, confirmFile, rollbackFile, legacyRollbackFile, _ := setupFirewallDeadmanState(t)
	c := &ControlListener{d: d}
	markerWritten := make(chan struct{})
	releaseApply := make(chan struct{})
	applyDone := make(chan error, 1)

	go func() {
		applyDone <- applyFirewallDeadman(confirmFile, rollbackFile, legacyRollbackFile, time.Minute, func() error {
			close(markerWritten)
			<-releaseApply
			return nil
		})
	}()

	select {
	case <-markerWritten:
	case <-time.After(5 * time.Second):
		t.Fatal("apply-confirmed did not reach apply phase")
	}

	confirmDone := make(chan error, 1)
	go func() {
		_, err := c.handleFirewallConfirm(nil)
		confirmDone <- err
	}()

	select {
	case err := <-confirmDone:
		t.Fatalf("confirm returned while apply-confirmed protocol was in progress: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	close(releaseApply)
	if err := <-applyDone; err != nil {
		t.Fatalf("applyFirewallDeadman: %v", err)
	}
	select {
	case err := <-confirmDone:
		if err != nil {
			t.Fatalf("handleFirewallConfirm: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("confirm did not finish after apply-confirmed completed")
	}
	requirePathMissing(t, confirmFile)
	requirePathMissing(t, rollbackFile)
}

func TestApplyFirewallDeadmanApplyFailureRestoresPreviousRuleset(t *testing.T) {
	_, confirmFile, rollbackFile, legacyRollbackFile, seenFile := setupFirewallDeadmanState(t)

	apply := func() error { return errors.New("nft transaction rejected") }
	err := applyFirewallDeadman(confirmFile, rollbackFile, legacyRollbackFile, 3*time.Minute, apply)
	if err == nil {
		t.Fatal("applyFirewallDeadman succeeded, want apply failure")
	}
	if !strings.Contains(err.Error(), "previous ruleset restored") {
		t.Fatalf("error = %q, want restore notice", err.Error())
	}
	got, readErr := os.ReadFile(seenFile)
	if readErr != nil {
		t.Fatalf("failed apply was not rolled back: %v", readErr)
	}
	if strings.TrimSpace(string(got)) != rollbackFile {
		t.Fatalf("nft restored %q, want %q", strings.TrimSpace(string(got)), rollbackFile)
	}
	requirePathMissing(t, confirmFile)
	requirePathMissing(t, rollbackFile)
}

func TestApplyFirewallDeadmanApplyAndRestoreFailureKeepsWindowFiles(t *testing.T) {
	_, confirmFile, rollbackFile, legacyRollbackFile, _ := setupFirewallDeadmanState(t)
	t.Setenv("NFT_RESTORE_FAIL", "1")

	apply := func() error { return errors.New("nft transaction rejected") }
	err := applyFirewallDeadman(confirmFile, rollbackFile, legacyRollbackFile, time.Minute, apply)
	if err == nil {
		t.Fatal("applyFirewallDeadman succeeded, want apply+restore failure")
	}
	if !strings.Contains(err.Error(), "rollback restore failed") {
		t.Fatalf("error = %q, want restore-failure notice", err.Error())
	}
	// Window files must survive so the still-armed deadman (and startup
	// recovery after a crash) can retry the restore at the deadline.
	requirePathExists(t, confirmFile)
	requirePathExists(t, rollbackFile)
}

func TestRestoreFirewallRollbackSkipsSupersededMarker(t *testing.T) {
	installFakeNft(t)
	dir := t.TempDir()
	confirmFile := filepath.Join(dir, "confirm_pending")
	rollbackFile := filepath.Join(dir, "rollback.nft")
	seenFile := filepath.Join(dir, "seen")
	t.Setenv("NFT_RESTORE_SEEN", seenFile)
	writeTestFile(t, confirmFile, "newer-window-deadline")
	writeTestFile(t, rollbackFile, "flush ruleset\n")

	if err := restoreFirewallRollback(confirmFile, rollbackFile, []byte("older-window-deadline")); err != nil {
		t.Fatalf("restoreFirewallRollback: %v", err)
	}
	requirePathMissing(t, seenFile)
	requirePathExists(t, confirmFile)
	requirePathExists(t, rollbackFile)
}

func installFakeNft(t *testing.T) {
	t.Helper()
	binDir := t.TempDir()
	nftPath := filepath.Join(binDir, "nft")
	script := `#!/bin/sh
if [ "$1" = "list" ] && [ "$2" = "ruleset" ]; then
	if [ -n "$NFT_LIST_TEXT" ]; then
		printf '%s' "$NFT_LIST_TEXT"
	fi
	exit 0
fi
if [ "$1" = "-f" ]; then
	if [ -n "$NFT_RESTORE_SEEN" ]; then
		printf '%s\n' "$2" > "$NFT_RESTORE_SEEN"
	fi
	if [ "$NFT_RESTORE_FAIL" = "1" ]; then
		echo "restore failed" >&2
		exit 7
	fi
	exit 0
fi
echo "unexpected nft args: $*" >&2
exit 64
`
	if err := os.WriteFile(nftPath, []byte(script), 0700); err != nil {
		t.Fatalf("write fake nft: %v", err)
	}
	t.Setenv("PATH", binDir)
}

func writeTestFile(t *testing.T, path, data string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatalf("write %s: %v", filepath.Base(path), err)
	}
}

func requirePathExists(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("%s should exist: %v", filepath.Base(path), err)
	}
}

func requireFileContent(t *testing.T, path, want string) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", filepath.Base(path), err)
	}
	if string(got) != want {
		t.Fatalf("%s = %q, want %q", filepath.Base(path), got, want)
	}
}

func requirePathMissing(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("%s should be missing, stat err=%v", filepath.Base(path), err)
	}
}
