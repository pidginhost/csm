//go:build linux

package firewall

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/nftables"
)

var stateAsideAt = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

const stateAsideSuffix = ".unreadable-20260301T120000Z"

func stateAsideEngine(t *testing.T, dir string) (*Engine, *bool) {
	t.Helper()
	listed := false
	return &Engine{
		statePath:   dir,
		cfg:         &FirewallConfig{},
		expiryClock: func() time.Time { return stateAsideAt },
		listTables: func() ([]*nftables.Table, error) {
			listed = true
			return nil, errors.New("listing stops the test before the kernel")
		},
	}, &listed
}

// A fresh engine read an unreadable state file as empty, and its next
// write replaced the file: every block and allow it held was lost. The
// file is now kept aside before anything writes, and the engine says where.
func TestUnreadableStateIsKeptAsideBeforeAnyWrite(t *testing.T) {
	dir := t.TempDir()
	e, _ := stateAsideEngine(t, dir)
	path := filepath.Join(dir, "state.json")
	bad := []byte(`{"blocked": [{"ip": "203.0.113.9"`)
	if err := os.WriteFile(path, bad, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := e.loadStateFile(); len(got.Blocked) != 0 || len(got.Allowed) != 0 {
		t.Fatalf("unreadable state loaded as %+v", got)
	}
	aside := path + stateAsideSuffix
	if got := e.StateSetAside(); got != aside {
		t.Fatalf("StateSetAside = %q, want %q", got, aside)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("unreadable state left in place: %v", err)
	}
	if err := e.saveBlockedEntry(BlockedEntry{IP: "198.51.100.4", Reason: "operator"}); err != nil {
		t.Fatal(err)
	}
	if kept, err := os.ReadFile(aside); err != nil || string(kept) != string(bad) {
		t.Fatalf("kept file = %q, %v; want the unreadable bytes", kept, err)
	}
	if !e.IsBlocked("198.51.100.4") {
		t.Fatal("the engine did not keep operating after setting the file aside")
	}
}

// An engine that already holds its state keeps it across an unreadable
// rewrite and writes it back later; nothing is moved aside.
func TestUnreadableRewriteKeepsHeldState(t *testing.T) {
	dir := t.TempDir()
	e, _ := stateAsideEngine(t, dir)
	if err := e.saveBlockedEntry(BlockedEntry{IP: "198.51.100.5", Reason: "operator"}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "state.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !e.IsBlocked("198.51.100.5") {
		t.Fatal("held state dropped on an unreadable rewrite")
	}
	if got := e.StateSetAside(); got != "" {
		t.Fatalf("StateSetAside = %q for an engine holding its state", got)
	}
	if _, err := os.Stat(path + stateAsideSuffix); !os.IsNotExist(err) {
		t.Fatalf("file moved aside while the engine held its state: %v", err)
	}
}

// A state file that cannot be moved aside would be replaced by the next
// write. Apply refuses before the kernel, which keeps running the ruleset
// it has, with its blocks.
func TestApplyRefusesStateItCannotKeepAside(t *testing.T) {
	dir := t.TempDir()
	e, listed := stateAsideEngine(t, dir)
	path := filepath.Join(dir, "state.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	e.renameStateAside = func(string, string) error { return os.ErrPermission }
	err := e.Apply()
	if !errors.Is(err, ErrStateNotKeptAside) || *listed {
		t.Fatalf("Apply = %v (kernel reached: %v), want a refusal before the kernel", err, *listed)
	}
	if data, readErr := os.ReadFile(path); readErr != nil || string(data) != "{not json" {
		t.Fatalf("state file = %q, %v; want it untouched", data, readErr)
	}
	if got := e.StateSetAside(); got != "" {
		t.Fatalf("StateSetAside = %q after a failed rename", got)
	}
}

// A state path the engine cannot even stat is refused the same way: the
// empty state it used to install let Apply clear the kernel's blocks.
func TestApplyRefusesStateItCannotStat(t *testing.T) {
	file := filepath.Join(t.TempDir(), "firewall")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	e, listed := stateAsideEngine(t, file)
	if err := e.Apply(); !errors.Is(err, ErrStateNotKeptAside) || *listed {
		t.Fatalf("Apply = %v (kernel reached: %v), want a refusal before the kernel", err, *listed)
	}
}

func TestUnreadableStateAsideNamesDoNotReplaceEarlierFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	prior := path + stateAsideSuffix
	if err := os.WriteFile(prior, []byte("earlier bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 2; i++ {
		e, _ := stateAsideEngine(t, dir)
		bad := []byte(fmt.Sprintf("{broken %d", i))
		if err := os.WriteFile(path, bad, 0o600); err != nil {
			t.Fatal(err)
		}
		_ = e.loadStateFile()
		want := fmt.Sprintf("%s-%d", prior, i)
		if e.StateSetAside() != want {
			t.Fatalf("kept at %q, want %q", e.StateSetAside(), want)
		}
		if got, err := os.ReadFile(want); err != nil || string(got) != string(bad) {
			t.Fatalf("kept bytes %q, %v; want %q", got, err, bad)
		}
	}
	if got, err := os.ReadFile(prior); err != nil || string(got) != "earlier bytes" {
		t.Fatalf("earlier file replaced: %q, %v", got, err)
	}
}

func TestFirstStateWriteKeepsUnreadableBytes(t *testing.T) {
	dir := t.TempDir()
	e, _ := stateAsideEngine(t, dir)
	path := filepath.Join(dir, "state.json")
	if err := os.WriteFile(path, []byte("{broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := e.saveState(&FirewallState{}); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(e.StateSetAside()); err != nil || string(got) != "{broken" {
		t.Fatalf("first write lost unreadable bytes: %q, %v", got, err)
	}
}

func TestStateWriteRefusesBytesItCannotKeepAside(t *testing.T) {
	dir := t.TempDir()
	e, _ := stateAsideEngine(t, dir)
	e.renameStateAside = func(string, string) error { return os.ErrPermission }
	path := filepath.Join(dir, "state.json")
	if err := os.WriteFile(path, []byte("{broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := e.saveState(&FirewallState{}); !errors.Is(err, ErrStateNotKeptAside) {
		t.Fatalf("save = %v, want refusal", err)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != "{broken" {
		t.Fatalf("refused write replaced bytes: %q, %v", got, err)
	}
}

func TestApplyRefusesStatFailureEvenWhenRenameCouldSucceed(t *testing.T) {
	dir := t.TempDir()
	e, listed := stateAsideEngine(t, dir)
	path := filepath.Join(dir, "state.json")
	if err := os.Symlink("state.json", path); err != nil {
		t.Fatal(err)
	}
	err := e.Apply()
	if !errors.Is(err, ErrStateNotKeptAside) || *listed || e.StateSetAside() != "" {
		t.Fatalf("Apply = %v, kernel=%v aside=%q; want refusal without a rename", err, *listed, e.StateSetAside())
	}
	if target, err := os.Readlink(path); err != nil || target != "state.json" {
		t.Fatalf("state link changed: %q, %v", target, err)
	}
}

func TestApplyReportsButRefusesUnsyncedKeptState(t *testing.T) {
	dir := t.TempDir()
	e, listed := stateAsideEngine(t, dir)
	e.syncStateAside = func(string) error { return errors.New("fixture sync failure") }
	path := filepath.Join(dir, "state.json")
	if err := os.WriteFile(path, []byte("{broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := e.Apply(); !errors.Is(err, ErrStateNotKeptAside) || *listed {
		t.Fatalf("Apply = %v, kernel=%v; want refusal", err, *listed)
	}
	if got, err := os.ReadFile(e.StateSetAside()); err != nil || string(got) != "{broken" {
		t.Fatalf("unsynced kept bytes or report lost: %q, %v", got, err)
	}
	if err := e.saveState(&FirewallState{}); !errors.Is(err, ErrStateNotKeptAside) {
		t.Fatalf("save = %v; want refusal until a fresh startup", err)
	}
}

func TestFailedStateWriteRetainsHeldStateAcrossUnreadableRewrite(t *testing.T) {
	dir := t.TempDir()
	e, _ := stateAsideEngine(t, dir)
	if err := e.saveBlockedEntry(BlockedEntry{IP: "198.51.100.5", Reason: "operator"}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "state.json")
	broken := []byte("{broken")
	if err := os.WriteFile(path, broken, 0o600); err != nil {
		t.Fatal(err)
	}
	write := writeFirewallStateJSON
	t.Cleanup(func() { writeFirewallStateJSON = write })
	writeFirewallStateJSON = func(string, os.FileMode, interface{}) error { return os.ErrPermission }
	if err := e.saveBlockedEntry(BlockedEntry{IP: "198.51.100.6", Reason: "operator"}); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("save = %v, want the write failure", err)
	}
	if !e.IsBlocked("198.51.100.5") || e.IsBlocked("198.51.100.6") {
		t.Error("failed write lost the held block or published the failed block")
	}
	if aside := e.StateSetAside(); aside != "" {
		t.Fatalf("held state was renamed after a write failure: %q", aside)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != string(broken) {
		t.Fatalf("failed write changed unreadable bytes: %q, %v", got, err)
	}
	writeFirewallStateJSON = write
	if err := e.saveBlockedEntry(BlockedEntry{IP: "198.51.100.6", Reason: "operator"}); err != nil {
		t.Fatal(err)
	}
	state, ok := e.loadStateFileRawLocked()
	if !ok || len(state.Blocked) != 2 || !e.IsBlocked("198.51.100.5") || !e.IsBlocked("198.51.100.6") {
		t.Fatalf("retry did not restore both blocks: %+v, readable=%v", state, ok)
	}
}

func TestRawStateReadRefusesUnsyncedKeptStateOnRetry(t *testing.T) {
	dir := t.TempDir()
	e, _ := stateAsideEngine(t, dir)
	e.syncStateAside = func(string) error { return os.ErrPermission }
	path := filepath.Join(dir, "state.json")
	if err := os.WriteFile(path, []byte("{broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok := e.loadStateFileRawLocked(); ok {
		t.Fatal("first raw read accepted unreadable state")
	}
	if _, ok := e.loadStateFileRawLocked(); ok {
		t.Fatal("raw retry accepted missing state after the rename failed to sync")
	}
}
