package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// validateConfDir vets a conf.d directory before CSM loads YAML
// fragments from it. The conf.d path is operator-controlled via the
// CSM_CONFIG_DIR env var or the --config-dir CLI flag; CSM loads every
// matching YAML and merges it into the live config, which means an
// attacker who can write a single fragment can disable detectors,
// whitelist their IP, or downgrade auto-response. The defensive
// posture, even if env/flag attack vectors are uncommon, is to refuse
// any path whose ownership or permissions do not match a directory the
// operator (or root) deliberately set up.
//
// Rules:
//   - Empty path is a no-op: callers fall back to the packaged default.
//   - The path must be absolute. Relative paths could be reinterpreted
//     by callers running with different working directories.
//   - The path must exist after symlink resolution and be a directory.
//   - The resolved directory must not be group- or world-writable
//     (mode bits 0022 forbidden). YAML loaders trust file content; an
//     attacker who can write to the dir bypasses every detector.
//   - The resolved directory must be owned either by root (uid 0) or
//     by the running process (Geteuid). Anything else means a third
//     user could drop a fragment there.
//
// Errors carry the path so operators can diagnose without re-reading
// strace.
func validateConfDir(path string) error {
	if path == "" {
		return nil
	}
	if !filepath.IsAbs(path) {
		return fmt.Errorf("conf.d directory must be an absolute path, got %q", path)
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("conf.d directory does not exist: %s", path)
		}
		return fmt.Errorf("conf.d directory symlink resolution: %w", err)
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return fmt.Errorf("conf.d directory stat: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("conf.d directory is not a directory: %s", resolved)
	}
	if mode := info.Mode().Perm(); mode&0022 != 0 {
		return fmt.Errorf("conf.d directory %s has unsafe mode %04o (group or world writable); set 0750 or stricter", resolved, mode)
	}
	sys, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		// Platform without uid surface (none of CSM's targets land
		// here, but stay forward-compatible).
		return nil
	}
	selfUID := uint32(os.Geteuid())
	if sys.Uid != 0 && sys.Uid != selfUID {
		return fmt.Errorf("conf.d directory %s owner uid=%d is neither root (0) nor process uid=%d; refusing to load untrusted YAML", resolved, sys.Uid, selfUID)
	}
	return nil
}
