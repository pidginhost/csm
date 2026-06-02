package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

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

	err := restoreFirewallRollback(confirmFile, rollbackFile)
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

	if err := restoreFirewallRollback(confirmFile, rollbackFile); err != nil {
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

func requirePathMissing(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("%s should be missing, stat err=%v", filepath.Base(path), err)
	}
}
