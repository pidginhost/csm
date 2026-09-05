//go:build linux

package daemon

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/wpcheck"
	"golang.org/x/sys/unix"
)

func queuedAtomicWriteEvent(t *testing.T, fm *FileMonitor, path string, mask uint64) fileEvent {
	t.Helper()
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	fm.handleEvent(fd, 0, mask)
	select {
	case event := <-fm.analyzerCh:
		t.Cleanup(func() { _ = unix.Close(event.fd) })
		if event.dropperOnly {
			t.Fatal("staging file admitted only to dropper tracking")
		}
		return event
	default:
		t.Fatal("staging file was excluded from content analysis")
		return fileEvent{}
	}
}

func assertAtomicWriteFinding(t *testing.T, alerts <-chan alert.Finding, path string, want bool) {
	t.Helper()
	if !want {
		select {
		case f := <-alerts:
			t.Fatalf("unexpected finding: %+v", f)
		default:
		}
		return
	}
	select {
	case f := <-alerts:
		if f.Check != "signature_match_realtime" || f.Severity != alert.High || f.FilePath != path {
			t.Fatalf("finding = %+v, want High signature at %s", f, path)
		}
	default:
		t.Fatal("event content did not reach the signature engine")
	}
	if len(alerts) != 0 {
		t.Fatalf("duplicate findings: %d", len(alerts))
	}
}

// The marker is harmless PHP, but matches the test signature. A pathname
// change must not replace its event bytes with the current path's contents.
func TestAtomicWriteScansEventObject(t *testing.T) {
	useRealtimeRules(t, realtimeHighRule)
	for _, transition := range []string{"keep", "rename", "replace-final", "replace-stage", "delete", "delete-before-admission"} {
		for _, detected := range []bool{false, true} {
			label := "clean"
			if detected {
				label = "signature"
			}
			t.Run(transition+"/"+label, func(t *testing.T) {
				dir := t.TempDir()
				path := filepath.Join(dir, ".temp.123.example.php")
				body := []byte("<?php echo 'fixture'; ?>")
				if detected {
					body = []byte("<?php echo 'EVIL_MARKER_A'; ?>")
				}
				if err := os.WriteFile(path, body, 0o644); err != nil {
					t.Fatal(err)
				}
				alerts := make(chan alert.Finding, 8)
				fm := &FileMonitor{cfg: &config.Config{}, alertCh: alerts, analyzerCh: make(chan fileEvent, 1)}
				var event fileEvent
				if transition == "delete-before-admission" {
					fd := openRawFd(t, path)
					dup, err := unix.Dup(fd)
					if err != nil {
						t.Fatal(err)
					}
					if err := os.Remove(path); err != nil {
						_ = unix.Close(dup)
						t.Fatal(err)
					}
					fm.handleEvent(dup, 0, FAN_CLOSE_WRITE)
					select {
					case event = <-fm.analyzerCh:
						t.Cleanup(func() { _ = unix.Close(event.fd) })
					default:
						t.Fatal("deleted staging file excluded")
					}
				} else {
					event = queuedAtomicWriteEvent(t, fm, path, FAN_CLOSE_WRITE)
				}
				switch transition {
				case "rename", "replace-final":
					final := filepath.Join(dir, "example.php")
					if transition == "replace-final" {
						if err := os.WriteFile(final, []byte("<?php echo 'old'; ?>"), 0o644); err != nil {
							t.Fatal(err)
						}
					}
					if err := os.Rename(path, final); err != nil {
						t.Fatal(err)
					}
				case "replace-stage", "delete":
					if err := os.Remove(path); err != nil {
						t.Fatal(err)
					}
					if transition == "replace-stage" {
						if err := os.WriteFile(path, []byte("<?php echo 'replacement'; ?>"), 0o644); err != nil {
							t.Fatal(err)
						}
					}
				}
				fm.analyzeFile(event)
				assertAtomicWriteFinding(t, alerts, path, detected)
			})
		}
	}
}

func TestAtomicWriteCloseScansCompletedContent(t *testing.T) {
	useRealtimeRules(t, realtimeHighRule)
	path := filepath.Join(t.TempDir(), ".temp.42.example.php")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	if _, err := f.WriteString("<?php echo '"); err != nil {
		t.Fatal(err)
	}
	alerts := make(chan alert.Finding, 8)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: alerts, analyzerCh: make(chan fileEvent, 1)}
	fm.analyzeFile(queuedAtomicWriteEvent(t, fm, path, FAN_CREATE))
	assertAtomicWriteFinding(t, alerts, path, false)
	if _, err := f.WriteString("EVIL_MARKER_A'; ?>"); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	fm.analyzeFile(queuedAtomicWriteEvent(t, fm, path, FAN_CLOSE_WRITE))
	assertAtomicWriteFinding(t, alerts, path, true)
}

func TestAtomicWriteScansConfigurationContent(t *testing.T) {
	for _, tc := range []struct{ name, content, check string }{
		{".temp.1..htaccess", "php_value auto_prepend_file /tmp/fixture.php\n", "htaccess_injection_realtime"},
		{".temp.1..user.ini", "disable_functions = \n", "php_config_realtime"},
		{".temp.1.php.ini", "disable_functions = \n", "php_config_realtime"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, tc.name)
			if err := os.WriteFile(path, []byte(tc.content), 0o644); err != nil {
				t.Fatal(err)
			}
			alerts := make(chan alert.Finding, 8)
			fm := &FileMonitor{cfg: &config.Config{}, alertCh: alerts, analyzerCh: make(chan fileEvent, 1), webRootPatterns: []string{dir}}
			fm.analyzeFile(queuedAtomicWriteEvent(t, fm, path, FAN_CLOSE_WRITE))
			select {
			case finding := <-alerts:
				if finding.Check != tc.check || finding.FilePath != path {
					t.Fatalf("finding = %+v, want %s at %s", finding, tc.check, path)
				}
			default:
				t.Fatal("staged configuration did not reach its content scanner")
			}
		})
	}
}

func TestAtomicWriteVerificationUsesWholeEventContent(t *testing.T) {
	useRealtimeRules(t, realtimeHighRule)
	trusted := []byte("<?php echo 'EVIL_MARKER_A'; ?>")
	for _, kind := range []string{"verified", "changed", "partial", "replaced"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			includes := filepath.Join(root, "wp-includes")
			if err := os.Mkdir(includes, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(includes, "version.php"), []byte("<?php $wp_version = '6.9.4';"), 0o644); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(includes, ".temp.123.example.php")
			body := append([]byte(nil), trusted...)
			switch kind {
			case "changed", "replaced":
				body = append(body, []byte("<?php echo 'changed'; ?>")...)
			case "partial":
				body = body[:len(body)-2]
			}
			if err := os.WriteFile(path, body, 0o644); err != nil {
				t.Fatal(err)
			}
			// A clean final pathname must never vouch for different event bytes.
			if err := os.WriteFile(filepath.Join(includes, "example.php"), trusted, 0o644); err != nil {
				t.Fatal(err)
			}
			sum := md5.Sum(trusted)
			checksums := map[string]string{"wp-includes/example.php": hex.EncodeToString(sum[:])}
			raw, err := json.Marshal(map[string]any{"checksums": checksums})
			if err != nil {
				t.Fatal(err)
			}
			cache := wpcheck.NewCache(t.TempDir())
			if err := cache.PersistChecksums("6.9.4", "en_US", raw, checksums); err != nil {
				t.Fatal(err)
			}
			alerts := make(chan alert.Finding, 8)
			fm := &FileMonitor{cfg: &config.Config{}, wpCache: cache, alertCh: alerts, analyzerCh: make(chan fileEvent, 1)}
			event := queuedAtomicWriteEvent(t, fm, path, FAN_CLOSE_WRITE)
			if kind == "replaced" {
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, trusted, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			fm.analyzeFile(event)
			assertAtomicWriteFinding(t, alerts, path, kind != "verified")
		})
	}
}

func TestAtomicWriteBurstUsesBoundedQueueAndReconciliation(t *testing.T) {
	useRealtimeRules(t, realtimeHighRule)
	path := filepath.Join(t.TempDir(), ".temp.123.example.php")
	if err := os.WriteFile(path, []byte("<?php echo 'EVIL_MARKER_A'; ?>"), 0o644); err != nil {
		t.Fatal(err)
	}
	alerts := make(chan alert.Finding, 8)
	fm := &FileMonitor{cfg: &config.Config{}, alertCh: alerts, analyzerCh: make(chan fileEvent, 4)}
	for range 20 {
		fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		fm.handleEvent(fd, 0, FAN_CLOSE_WRITE)
	}
	if len(fm.analyzerCh) != 4 || fm.droppedEvents != 16 || len(fm.reconcileDirs) != 1 {
		t.Fatalf("queue=%d drops=%d reconcile dirs=%d, want 4/16/1", len(fm.analyzerCh), fm.droppedEvents, len(fm.reconcileDirs))
	}
	for len(fm.analyzerCh) > 0 {
		event := <-fm.analyzerCh
		fm.analyzeFile(event)
		_ = unix.Close(event.fd)
	}
	assertAtomicWriteFinding(t, alerts, path, true)
	fm.reconcileDrops()
	assertAtomicWriteFinding(t, alerts, path, false)
	if len(fm.reconcileDirs) != 0 || len(fm.analyzerCh) != 0 {
		t.Fatal("completed burst left queued work")
	}
	// A monitor that lost every event must recover detection from this file.
	fm = &FileMonitor{cfg: &config.Config{}, alertCh: alerts}
	fm.recordDroppedDir(path)
	fm.reconcileDrops()
	assertAtomicWriteFinding(t, alerts, path, true)
}
