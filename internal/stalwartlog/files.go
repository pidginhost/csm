package stalwartlog

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// NewestFile returns the newest "<prefix>.YYYY-MM-DD" regular file in dir.
// Stalwart starts one such file per UTC day, so the newest by name is the
// one being written. Files dated after tomorrow (UTC, relative to now) are
// skipped: Stalwart cannot be writing them, and a reader that only moves
// forward would stay on one. The error wraps fs.ErrNotExist when there is none.
func NewestFile(dir, prefix string, now time.Time) (string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}
	y, m, d := now.UTC().Date()
	latest := time.Date(y, m, d+1, 0, 0, 0, 0, time.UTC)
	newest := ""
	for _, e := range entries {
		if !e.Type().IsRegular() {
			continue
		}
		date, ok := strings.CutPrefix(e.Name(), prefix+".")
		if !ok {
			continue
		}
		day, err := time.Parse("2006-01-02", date)
		if err != nil || len(date) != len("2006-01-02") || day.After(latest) {
			continue
		}
		if e.Name() > newest {
			newest = e.Name()
		}
	}
	if newest == "" {
		return "", fmt.Errorf("no %s.YYYY-MM-DD file in %s: %w", prefix, dir, fs.ErrNotExist)
	}
	return filepath.Join(dir, newest), nil
}
