package yara

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// validateRulesDir refuses to compile YARA rules from a directory or
// file whose ownership or permissions would let a non-root non-self
// account drop a rule that disables detection. Mirrors the same trust
// rules CSM applies to /etc/csm/conf.d: only root or the running
// process may own the dir or any rule file, and group/world write bits
// are refused. A missing directory is a no-op so an operator who has
// not installed YARA rules yet does not see startup failures.
func validateRulesDir(dir string) error {
	if dir == "" {
		return nil
	}
	info, err := os.Stat(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("rules dir stat: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("rules dir is not a directory: %s", dir)
	}
	if trustErr := checkYaraEntryTrust(dir, info); trustErr != nil {
		return trustErr
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("rules dir read: %w", err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		ext := filepath.Ext(entry.Name())
		if ext != ".yar" && ext != ".yara" {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		fileInfo, err := os.Lstat(path)
		if err != nil {
			return fmt.Errorf("rule file stat %s: %w", path, err)
		}
		if fileInfo.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("rule file is a symlink: %s", path)
		}
		if !fileInfo.Mode().IsRegular() {
			return fmt.Errorf("rule file is not a regular file: %s", path)
		}
		if trustErr := checkYaraEntryTrust(path, fileInfo); trustErr != nil {
			return trustErr
		}
	}
	return nil
}

// checkYaraEntryTrust enforces the perm + ownership trust rules on a
// single path. Used for both the rules dir itself and each rule file.
func checkYaraEntryTrust(path string, info os.FileInfo) error {
	if mode := info.Mode().Perm(); mode&0022 != 0 {
		return fmt.Errorf("rules path %s has unsafe mode %04o (group or world writable); set 0750 or stricter", path, mode)
	}
	sys, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	selfUID := uint32(os.Geteuid()) // #nosec G115 -- Linux uid_t is uint32; os.Geteuid returns a non-negative process uid.
	if sys.Uid != 0 && sys.Uid != selfUID {
		return fmt.Errorf("rules path %s owner uid=%d is neither root nor process uid=%d; refusing to load untrusted rules", path, sys.Uid, selfUID)
	}
	return nil
}
