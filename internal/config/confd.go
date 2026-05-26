package config

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"gopkg.in/yaml.v3"
)

// ValidateConfDir vets an operator-selected conf.d directory before any YAML
// fragments are loaded from it. The returned path is symlink-resolved so later
// reads do not depend on a mutable link name.
func ValidateConfDir(dir string) (string, error) {
	if dir == "" {
		return "", nil
	}
	if !filepath.IsAbs(dir) {
		return "", fmt.Errorf("conf.d directory must be an absolute path, got %q", dir)
	}
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("conf.d directory does not exist: %s", dir)
		}
		return "", fmt.Errorf("conf.d directory symlink resolution: %w", err)
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return "", fmt.Errorf("conf.d directory stat: %w", err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("conf.d directory is not a directory: %s", resolved)
	}
	if trustErr := validateConfPathTrust("conf.d directory", resolved, info); trustErr != nil {
		return "", trustErr
	}
	return resolved, nil
}

// LoadConfDir reads every *.yaml file in dir in lexicographic order and
// returns each as a parsed yaml.DocumentNode. A missing directory is not
// an error and returns an empty slice; an unreadable file or invalid YAML
// is fatal so operators see misconfigurations at startup.
func LoadConfDir(dir string) ([]*yaml.Node, error) {
	if dir == "" {
		return nil, nil
	}
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("conf.d directory symlink resolution: %w", err)
	}
	info, err := os.Stat(resolved)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("conf.d directory stat: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("conf.d directory is not a directory: %s", resolved)
	}
	if trustErr := validateConfPathTrust("conf.d directory", resolved, info); trustErr != nil {
		return nil, trustErr
	}
	dir = resolved
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading %s: %w", dir, err)
	}

	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if !strings.HasSuffix(e.Name(), ".yaml") && !strings.HasSuffix(e.Name(), ".yml") {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)

	out := make([]*yaml.Node, 0, len(names))
	for _, name := range names {
		path := filepath.Join(dir, name)
		data, err := readTrustedConfFragment(path)
		if err != nil {
			return nil, err
		}
		var node yaml.Node
		if err := yaml.Unmarshal(data, &node); err != nil {
			return nil, fmt.Errorf("parsing %s: %w", path, err)
		}
		// Skip empty files (Unmarshal yields a zero-Content document).
		if len(node.Content) == 0 {
			continue
		}
		out = append(out, &node)
	}
	return out, nil
}

func readTrustedConfFragment(path string) ([]byte, error) {
	// #nosec G304 -- path is built from an operator-selected conf.d and a directory entry.
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("conf.d fragment is not a regular file: %s", path)
	}
	if trustErr := validateConfPathTrust("conf.d fragment", path, info); trustErr != nil {
		return nil, trustErr
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	return data, nil
}

func validateConfPathTrust(kind, path string, info os.FileInfo) error {
	if mode := info.Mode().Perm(); mode&0022 != 0 {
		return fmt.Errorf("%s %s has unsafe mode %04o (group or world writable); set 0750/0640 or stricter", kind, path, mode)
	}
	sys, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	selfUID := uint32(os.Geteuid())
	if sys.Uid != 0 && sys.Uid != selfUID {
		return fmt.Errorf("%s %s owner uid=%d is neither root (0) nor process uid=%d; refusing to load untrusted YAML", kind, path, sys.Uid, selfUID)
	}
	return nil
}
