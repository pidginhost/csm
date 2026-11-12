//go:build linux

package maillog

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

// newestDated stands in for the Stalwart resolver: the greatest
// stalwart.log.* name in dir.
func newestDated(dir string) func() (string, error) {
	return func() (string, error) {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return "", err
		}
		newest := ""
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), "stalwart.log.") && e.Name() > newest {
				newest = e.Name()
			}
		}
		if newest == "" {
			return "", fmt.Errorf("no dated file: %w", fs.ErrNotExist)
		}
		return filepath.Join(dir, newest), nil
	}
}

func writeLog(t *testing.T, path, content string) *os.File {
	t.Helper()
	w, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.WriteString(content); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Close() })
	return w
}

func TestResolvedFileReaderStartsAtEndOfNewest(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		dir := t.TempDir()
		writeLog(t, filepath.Join(dir, "stalwart.log.2026-11-10"), "older\n")
		w := writeLog(t, filepath.Join(dir, "stalwart.log.2026-11-11"), "historical\n")
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		r, err := NewResolvedFileReader(newestDated(dir), NewQueue())
		if err != nil {
			t.Fatal(err)
		}
		out, err := r.Run(ctx)
		if err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		appendMailAndPoll(t, w, "fresh\n")
		expectMailLine(t, out, "fresh\n")
		expectNoMailLine(t, out)
	})
}

func TestResolvedFileReaderFinishesOldFileBeforeNewest(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		dir := t.TempDir()
		old := writeLog(t, filepath.Join(dir, "stalwart.log.2026-11-10"), "")
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		r, err := NewResolvedFileReader(newestDated(dir), NewQueue())
		if err != nil {
			t.Fatal(err)
		}
		out, err := r.Run(ctx)
		if err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		if _, err := old.WriteString("a\n"); err != nil {
			t.Fatal(err)
		}
		writeLog(t, filepath.Join(dir, "stalwart.log.2026-11-11"), "b\n")
		time.Sleep(2 * time.Second)
		synctest.Wait()
		expectMailLine(t, out, "a\n")
		time.Sleep(2 * time.Second)
		synctest.Wait()
		expectMailLine(t, out, "b\n")
		expectNoMailLine(t, out)
	})
}

func TestResolvedFileReaderSwitchesOnlyAtEOF(t *testing.T) {
	dir := t.TempDir()
	writeLog(t, filepath.Join(dir, "stalwart.log.2026-11-10"), "")
	r, err := NewResolvedFileReader(newestDated(dir), NewQueue())
	if err != nil {
		t.Fatal(err)
	}
	if path, err := r.switchTarget(true); path != "" || err != nil {
		t.Fatalf("switch with no newer file = %q, %v", path, err)
	}
	newer := filepath.Join(dir, "stalwart.log.2026-11-11")
	writeLog(t, newer, "")
	if path, err := r.switchTarget(false); path != "" || err != nil {
		t.Fatal("the minute ticker must not switch: the old file may hold unread lines")
	}
	if got, err := r.switchTarget(true); err != nil || got != newer {
		t.Fatalf("switchTarget(atEOF) = %q, %v; want %q", got, err, newer)
	}
}

func TestNewResolvedFileReaderPropagatesResolveError(t *testing.T) {
	_, err := NewResolvedFileReader(newestDated(t.TempDir()), NewQueue())
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("err = %v, want fs.ErrNotExist", err)
	}
}

func TestResolvedFileReaderReportsRuntimeFailures(t *testing.T) {
	for _, failure := range []string{"resolve", "open"} {
		t.Run(failure, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				dir := t.TempDir()
				oldPath := filepath.Join(dir, "stalwart.log.2026-11-10")
				writeLog(t, oldPath, "")
				nextPath := filepath.Join(dir, "stalwart.log.2026-11-11")
				target, resolveErr := oldPath, error(nil)
				var resolveMu sync.Mutex
				r, err := NewResolvedFileReader(func() (string, error) {
					resolveMu.Lock()
					defer resolveMu.Unlock()
					return target, resolveErr
				}, NewQueue())
				if err != nil {
					t.Fatal(err)
				}
				gone := make(chan error, 4)
				restored := make(chan struct{}, 4)
				r.SetOnGone(func(err error) { gone <- err })
				r.SetOnRestored(func() { restored <- struct{}{} })
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				out, err := r.Run(ctx)
				if err != nil {
					t.Fatal(err)
				}
				synctest.Wait()
				wantErr := fs.ErrNotExist
				resolveMu.Lock()
				if failure == "resolve" {
					resolveErr, wantErr = fs.ErrPermission, fs.ErrPermission
				} else {
					target = nextPath
				}
				resolveMu.Unlock()
				time.Sleep(2 * time.Second)
				synctest.Wait()
				if len(gone) != 0 {
					t.Fatal("a transient failure reported unavailable before the grace period")
				}
				time.Sleep(defaultGoneGrace + 2*time.Second)
				synctest.Wait()
				if len(gone) != 1 {
					t.Fatalf("unavailable callbacks = %d, want one", len(gone))
				}
				if err := <-gone; !errors.Is(err, wantErr) {
					t.Fatalf("unavailable = %v, want %v", err, wantErr)
				}
				writeLog(t, nextPath, "recovered\n")
				resolveMu.Lock()
				target, resolveErr = nextPath, nil
				resolveMu.Unlock()
				time.Sleep(4 * time.Second)
				synctest.Wait()
				expectMailLine(t, out, "recovered\n")
				if len(restored) != 1 || len(gone) != 0 {
					t.Fatalf("restored=%d unavailable=%d, want one recovery and no repeated failure", len(restored), len(gone))
				}
			})
		})
	}
}

func TestPlainFileReaderNeverSwitches(t *testing.T) {
	r := NewFileReader(filepath.Join(t.TempDir(), "maillog"), NewQueue())
	if path, err := r.switchTarget(true); path != "" || err != nil {
		t.Fatal("a fixed-path reader has no resolver")
	}
}

// Removing the current file must not send the reader back to an older day,
// which it would read from its start and replay.
func TestResolvedFileReaderNeverMovesBackward(t *testing.T) {
	dir := t.TempDir()
	writeLog(t, filepath.Join(dir, "stalwart.log.2026-11-10"), "")
	current := filepath.Join(dir, "stalwart.log.2026-11-11")
	writeLog(t, current, "")
	r, err := NewResolvedFileReader(newestDated(dir), NewQueue())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(current); err != nil {
		t.Fatal(err)
	}
	if path, err := r.switchTarget(true); path != "" || err != nil {
		t.Fatalf("switchTarget after removing the current file = %q, %v; want no move", path, err)
	}
}
