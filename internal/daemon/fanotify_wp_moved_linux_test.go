//go:build linux

package daemon

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/wpcheck"
)

// Use the real path detection and descriptor hashing with an in-memory
// manifest, so no network timing can decide whether a moved event is queued.
type movedPluginVerifier struct {
	*wpcheck.Cache
	ready    bool
	manifest map[string]string
}

func newMovedPluginVerifier(t *testing.T) *movedPluginVerifier {
	t.Helper()
	c := wpcheck.NewCache(t.TempDir())
	stop := make(chan struct{})
	close(stop)
	c.SetStopCh(stop)
	return &movedPluginVerifier{Cache: c, manifest: make(map[string]string)}
}

func (v *movedPluginVerifier) stock(rel, body string) {
	sum := sha256.Sum256([]byte(body))
	v.manifest[rel] = hex.EncodeToString(sum[:])
}

func (v *movedPluginVerifier) Verify(file wpcheck.Verification) wpcheck.Verdict {
	if !v.ready {
		return wpcheck.VerdictPending
	}
	if file.Kind == wpcheck.KindPlugin && file.Slug == "gtm-kit" && file.Version == "2.18.1" &&
		file.Digest != "" && file.Digest == v.manifest[file.Rel] {
		return wpcheck.VerdictVerified
	}
	return wpcheck.VerdictMismatch
}

func (v *movedPluginVerifier) VerifyFile(fd int, path string) wpcheck.Verification {
	file := v.Cache.VerifyFile(fd, path)
	if file.Verdict == wpcheck.VerdictPending {
		file.Verdict = v.Verify(file)
	}
	return file
}

const movedPluginHeader = "<?php\n/*\nPlugin Name: GTM Kit\nVersion: 2.18.1\n*/\n"

func installStagedPlugin(t *testing.T, wpRoot, root string) string {
	t.Helper()
	installed := filepath.Join(wpRoot, "wp-content/plugins/gtm-kit")
	if err := os.Rename(installed, installed+".old"); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(root, installed); err != nil {
		t.Fatal(err)
	}
	return installed
}

func TestMovedPluginEventIdentifiesEarlierQueuedFiles(t *testing.T) {
	for _, ready := range []bool{false, true} {
		name := "pending"
		if ready {
			name = "verified"
		}
		t.Run(name, func(t *testing.T) {
			wpRoot, staging := stagedPluginFixture(t)
			root := filepath.Join(staging, "gtm-kit")
			verifier := newMovedPluginVerifier(t)
			verifier.stock("first.php", cleanStagedPHP)
			verifier.stock("gtm-kit.php", movedPluginHeader)
			verifier.ready = ready
			fm, ch := newStagedPackageMonitor(t, verifier)
			first := filepath.Join(root, "first.php")
			fm.analyzeFile(fileEvent{path: first, fd: writeStagedFile(t, first, cleanStagedPHP)})
			if fm.stagedPackages().pendingCount() != 1 {
				t.Fatal("file without a header was not queued")
			}
			header := filepath.Join(root, "gtm-kit.php")
			fd := writeStagedFile(t, header, movedPluginHeader)
			installed := installStagedPlugin(t, wpRoot, root)
			fm.analyzeFile(fileEvent{path: header, fd: fd})
			// A rollback removes the only readable header before the
			// next drain. The moved event must have retained its identity.
			if err := os.RemoveAll(installed); err != nil {
				t.Fatal(err)
			}
			verifier.ready = true
			fm.drainStagedPackages(time.Now())
			if got := drainFindings(ch); len(got) != 0 || fm.stagedPackages().pendingCount() != 0 {
				t.Fatalf("moved event did not resolve its earlier file: pending=%d findings=%+v", fm.stagedPackages().pendingCount(), got)
			}
		})
	}
}

func TestMovedPluginMismatchUsesInstalledPathWhenStagingReused(t *testing.T) {
	for _, ready := range []bool{false, true} {
		wpRoot, staging := stagedPluginFixture(t)
		root := filepath.Join(staging, "gtm-kit")
		verifier := newMovedPluginVerifier(t)
		verifier.ready = ready
		verifier.stock("file.php", cleanStagedPHP)
		fm, ch := newStagedPackageMonitor(t, verifier)
		path := filepath.Join(root, "file.php")
		fd := writeStagedFile(t, path, cleanStagedPHP+"// modified\n")
		writeStagedFile(t, filepath.Join(root, "gtm-kit.php"), movedPluginHeader)
		installed := installStagedPlugin(t, wpRoot, root)
		// This path now names a different event, without its header yet.
		writeStagedFile(t, path, cleanStagedPHP)
		fm.analyzeFile(fileEvent{path: path, fd: fd})
		// A later repair must not erase the retained event's mismatch.
		writeStagedFile(t, filepath.Join(installed, "file.php"), cleanStagedPHP)
		verifier.ready = true
		fm.drainStagedPackages(time.Now())
		got := drainFindings(ch)
		want := filepath.Join(installed, "file.php")
		if len(got) != 1 || got[0].FilePath != want || !strings.Contains(got[0].Details, path) || fm.stagedPackages().pendingCount() != 0 {
			t.Fatalf("ready=%v: findings=%+v, want the original event at %s", ready, got, want)
		}
	}
}

func TestMovedPluginStockContentSkipsContentRules(t *testing.T) {
	wpRoot, staging := stagedPluginFixture(t)
	root := filepath.Join(staging, "gtm-kit")
	verifier := newMovedPluginVerifier(t)
	verifier.ready = true
	const body = "<?php eval(base64_decode($body));\n"
	verifier.stock("file.php", body)
	fm, ch := newStagedPackageMonitor(t, verifier)
	path := filepath.Join(root, "file.php")
	fd := writeStagedFile(t, path, body)
	writeStagedFile(t, filepath.Join(root, "gtm-kit.php"), movedPluginHeader)
	installStagedPlugin(t, wpRoot, root)
	fm.analyzeFile(fileEvent{path: path, fd: fd})
	if got := drainFindings(ch); len(got) != 0 || fm.stagedPackages().pendingCount() != 0 {
		t.Fatalf("official bytes triggered content scanning: %+v", got)
	}
}

func TestMovedPluginIdentityDoesNotIdentifyRecreatedStagingTree(t *testing.T) {
	wpRoot, staging := stagedPluginFixture(t)
	root := filepath.Join(staging, "gtm-kit")
	verifier := newMovedPluginVerifier(t)
	verifier.ready = true
	verifier.stock("gtm-kit.php", movedPluginHeader)
	fm, ch := newStagedPackageMonitor(t, verifier)
	header := filepath.Join(root, "gtm-kit.php")
	fd := writeStagedFile(t, header, movedPluginHeader)
	installStagedPlugin(t, wpRoot, root)
	fresh := filepath.Join(root, "new.php")
	fm.analyzeFile(fileEvent{path: fresh, fd: writeStagedFile(t, fresh, cleanStagedPHP)})
	fm.analyzeFile(fileEvent{path: header, fd: fd})
	fm.drainStagedPackages(time.Now())
	if got := drainFindings(ch); len(got) != 0 || fm.stagedPackages().pendingCount() != 1 {
		t.Fatalf("replacement borrowed the moved tree's release: pending=%d findings=%+v", fm.stagedPackages().pendingCount(), got)
	}
}
