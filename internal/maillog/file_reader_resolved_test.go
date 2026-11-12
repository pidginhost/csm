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
	if _, ok := r.switchTarget(true); ok {
		t.Fatal("switched with no newer file")
	}
	newer := filepath.Join(dir, "stalwart.log.2026-11-11")
	writeLog(t, newer, "")
	if _, ok := r.switchTarget(false); ok {
		t.Fatal("the minute ticker must not switch: the old file may hold unread lines")
	}
	if got, ok := r.switchTarget(true); !ok || got != newer {
		t.Fatalf("switchTarget(atEOF) = %q, %v; want %q", got, ok, newer)
	}
}

func TestNewResolvedFileReaderPropagatesResolveError(t *testing.T) {
	_, err := NewResolvedFileReader(newestDated(t.TempDir()), NewQueue())
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("err = %v, want fs.ErrNotExist", err)
	}
}

func TestPlainFileReaderNeverSwitches(t *testing.T) {
	r := NewFileReader(filepath.Join(t.TempDir(), "maillog"), NewQueue())
	if _, ok := r.switchTarget(true); ok {
		t.Fatal("a fixed-path reader has no resolver")
	}
}
