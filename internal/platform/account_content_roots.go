package platform

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/pidginhost/csm/internal/safepath"
)

// ValidateAccountRootPattern rejects paths that cannot define a confined
// content tree. Missing directories are allowed for later provisioning.
func ValidateAccountRootPattern(pattern string) error {
	if !filepath.IsAbs(pattern) || filepath.Clean(pattern) != pattern {
		return fmt.Errorf("account root must be an absolute, clean path: %q", pattern)
	}
	for _, char := range pattern {
		if char < 0x20 || char == 0x7f || char == '\\' {
			return fmt.Errorf("account root contains an unsupported character: %q", pattern)
		}
	}
	parts := strings.Split(strings.TrimPrefix(pattern, "/"), "/")
	if len(parts) < 2 || strings.IndexAny(pattern, "*?[") == 1 {
		return fmt.Errorf("account root must select a content directory below a fixed top-level directory: %q", pattern)
	}
	if _, err := filepath.Match(pattern, ""); err != nil {
		return fmt.Errorf("invalid account root pattern %q: %w", pattern, err)
	}
	return nil
}

// ResolveAccountRoots expands configured content directories without following
// symlinks. Unsafe directories are excluded and reported alongside valid roots,
// so a broken tenant tree does not block remediation of other accounts.
func ResolveAccountRoots(patterns []string) ([]string, error) {
	var roots []string
	var problems []error
	for _, pattern := range patterns {
		if err := ValidateAccountRootPattern(pattern); err != nil {
			return nil, err
		}
		matches, err := filepath.Glob(pattern)
		if err != nil {
			return nil, err
		}
		for _, path := range matches {
			info, err := os.Lstat(path)
			if os.IsNotExist(err) {
				continue
			}
			if err != nil {
				problems = append(problems, err)
				continue
			}
			if !info.IsDir() && info.Mode()&os.ModeSymlink == 0 {
				continue
			}
			if err := validateAccountRootDirectory(path); err != nil {
				problems = append(problems, err)
				continue
			}
			roots = append(roots, path)
		}
	}
	slices.Sort(roots)
	return slices.Compact(roots), errors.Join(problems...)
}

func validateAccountRootDirectory(path string) error {
	dir, err := safepath.OpenDirNoFollow(path)
	if err != nil {
		return fmt.Errorf("open account root %s without symlinks: %w", path, err)
	}
	return dir.Close()
}
