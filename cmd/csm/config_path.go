package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

func configPathFromArgs(args []string) (string, bool) {
	for i, arg := range args {
		if arg == "--config" && i+1 < len(args) {
			return args[i+1], true
		}
	}
	return "", false
}

func resolveConfigPathFromArgs(args []string) (string, bool, error) {
	if path, explicit := configPathFromArgs(args); explicit {
		return path, true, nil
	}
	path, err := resolveDefaultConfigPath(preferredConfigPath, legacyConfigPath)
	return path, false, err
}

func resolveDefaultConfigPath(preferred, legacy string) (string, error) {
	preferredInfo, preferredErr := os.Stat(preferred)
	legacyInfo, legacyErr := os.Stat(legacy)

	switch {
	case preferredErr == nil:
		if legacyErr == nil && !os.SameFile(preferredInfo, legacyInfo) {
			same, err := filesEqual(preferred, legacy)
			if err != nil {
				return "", err
			}
			if !same {
				hashOnly, hashErr := divergesOnlyByIntegrityHashes(preferred, legacy)
				if hashErr != nil {
					return "", hashErr
				}
				if !hashOnly {
					return "", fmt.Errorf("both %s and %s exist with different content; move one aside or pass --config <path>", preferred, legacy)
				}
				fmt.Fprintf(os.Stderr, "warning: %s and %s differ only by CSM-written integrity hashes; using %s. Run `csm rehash` to converge the copies.\n",
					preferred, legacy, preferred)
			}
		} else if legacyErr != nil && !os.IsNotExist(legacyErr) {
			return "", fmt.Errorf("checking config %s: %w", legacy, legacyErr)
		}
		return preferred, nil
	case os.IsNotExist(preferredErr):
		if legacyErr == nil {
			return legacy, nil
		}
		if !os.IsNotExist(legacyErr) {
			return "", fmt.Errorf("checking config %s: %w", legacy, legacyErr)
		}
		return preferred, nil
	default:
		return "", fmt.Errorf("checking config %s: %w", preferred, preferredErr)
	}
}

func migrateDefaultConfigPaths(preferred, legacy string) error {
	if err := copyLegacyConfigIfNeeded(preferred, legacy); err != nil {
		return err
	}
	return ensureLegacyConfigSymlink(preferred, legacy)
}

// convergeDefaultConfigCopies runs the default-path migration after a
// rehash. Rehash re-signs one copy only, so two real copies drift apart in
// CSM-written hashes with every upgrade or drop-in edit; folding the legacy
// path into the compatibility link here keeps them from ever diverging
// further. An explicit --config or a non-default path is left alone.
func convergeDefaultConfigCopies(cfgPath string, explicit bool, preferred, legacy string) error {
	if explicit || cfgPath != preferred {
		return nil
	}
	return migrateDefaultConfigPaths(preferred, legacy)
}

// sameOperatorConfig reports whether two config copies carry the same
// operator configuration: byte-identical, or differing only in the
// integrity hashes CSM rewrites itself.
func sameOperatorConfig(preferred, legacy string) (bool, error) {
	same, err := filesEqual(preferred, legacy)
	if err != nil || same {
		return same, err
	}
	return divergesOnlyByIntegrityHashes(preferred, legacy)
}

func copyLegacyConfigIfNeeded(preferred, legacy string) error {
	legacyInfo, legacyErr := os.Lstat(legacy)
	if legacyErr != nil {
		if os.IsNotExist(legacyErr) {
			return nil
		}
		return fmt.Errorf("checking legacy config %s: %w", legacy, legacyErr)
	}
	if legacyInfo.Mode()&os.ModeSymlink != 0 {
		return nil
	}

	preferredInfo, preferredErr := os.Lstat(preferred)
	if preferredErr != nil {
		if os.IsNotExist(preferredErr) {
			return copyFilePreserveMeta(legacy, preferred)
		}
		return fmt.Errorf("checking preferred config %s: %w", preferred, preferredErr)
	}
	if preferredInfo.Mode()&os.ModeSymlink != 0 {
		preferredStat, statErr := os.Stat(preferred)
		legacyStat, legacyStatErr := os.Stat(legacy)
		if statErr != nil {
			return fmt.Errorf("checking preferred config target %s: %w", preferred, statErr)
		}
		if legacyStatErr != nil {
			return fmt.Errorf("checking legacy config %s: %w", legacy, legacyStatErr)
		}
		if os.SameFile(preferredStat, legacyStat) {
			// Some transitional installs linked the new path back to the old
			// file. Replacing the old file with the normal compatibility link
			// without first materialising the new path would create a symlink
			// cycle and make both config paths unreadable.
			target, err := os.Readlink(preferred)
			if err != nil {
				return err
			}
			if err := os.Remove(preferred); err != nil {
				return fmt.Errorf("removing reverse config symlink %s: %w", preferred, err)
			}
			if err := copyFilePreserveMeta(legacy, preferred); err != nil {
				if restoreErr := os.Symlink(target, preferred); restoreErr != nil {
					return fmt.Errorf("materialising preferred config: %w (restoring reverse symlink failed: %v)", err, restoreErr)
				}
				return fmt.Errorf("materialising preferred config: %w", err)
			}
		}
		return nil
	}

	preferredStat, statErr := os.Stat(preferred)
	legacyStat, legacyStatErr := os.Stat(legacy)
	if statErr == nil && legacyStatErr == nil && os.SameFile(preferredStat, legacyStat) {
		return nil
	}

	same, err := sameOperatorConfig(preferred, legacy)
	if err != nil {
		return err
	}
	if same {
		return nil
	}

	preferredPlaceholder, err := isPlaceholderConfig(preferred)
	if err != nil {
		return err
	}
	if preferredPlaceholder {
		return copyFilePreserveMeta(legacy, preferred)
	}
	return fmt.Errorf("both %s and %s exist with different content; refusing automatic config migration", preferred, legacy)
}

func ensureLegacyConfigSymlink(preferred, legacy string) error {
	if _, err := os.Stat(preferred); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("checking preferred config %s: %w", preferred, err)
	}
	if err := os.MkdirAll(filepath.Dir(legacy), 0o700); err != nil {
		return err
	}

	legacyInfo, legacyErr := os.Lstat(legacy)
	if legacyErr != nil {
		if os.IsNotExist(legacyErr) {
			return os.Symlink(preferred, legacy)
		}
		return fmt.Errorf("checking legacy config %s: %w", legacy, legacyErr)
	}
	if legacyInfo.Mode()&os.ModeSymlink != 0 {
		target, err := os.Readlink(legacy)
		if err != nil {
			return err
		}
		if sameLinkTarget(target, preferred, filepath.Dir(legacy)) {
			return nil
		}
		if err := os.Remove(legacy); err != nil {
			return err
		}
		return os.Symlink(preferred, legacy)
	}

	same, err := sameOperatorConfig(preferred, legacy)
	if err != nil {
		return err
	}
	if !same {
		return fmt.Errorf("legacy config %s differs from %s; refusing to replace it with a symlink", legacy, preferred)
	}
	if err := os.Remove(legacy); err != nil {
		return err
	}
	return os.Symlink(preferred, legacy)
}

func sameLinkTarget(target, preferred, linkDir string) bool {
	if target == preferred {
		return true
	}
	if filepath.IsAbs(target) {
		return filepath.Clean(target) == filepath.Clean(preferred)
	}
	return filepath.Clean(filepath.Join(linkDir, target)) == filepath.Clean(preferred)
}

func filesEqual(a, b string) (bool, error) {
	// #nosec G304 -- a and b are package-constant config paths or test-injected temp paths.
	aData, err := os.ReadFile(a)
	if err != nil {
		return false, fmt.Errorf("reading %s: %w", a, err)
	}
	// #nosec G304 -- a and b are package-constant config paths or test-injected temp paths.
	bData, err := os.ReadFile(b)
	if err != nil {
		return false, fmt.Errorf("reading %s: %w", b, err)
	}
	return bytes.Equal(aData, bData), nil
}

func isPlaceholderConfig(path string) (bool, error) {
	// #nosec G304 -- path is a package-constant config path or test-injected temp path.
	data, err := os.ReadFile(path)
	if err != nil {
		return false, fmt.Errorf("reading %s: %w", path, err)
	}
	// Only the SET_*_HERE markers are reliable placeholders. The shipped
	// default has both. `auth_token: ""` is a legitimate operator value
	// in v2.11.0+ when the new webui.tokens block replaces the legacy
	// single-token field, so it must not count as a placeholder.
	return bytes.Contains(data, []byte("SET_HOSTNAME_HERE")) ||
		bytes.Contains(data, []byte("SET_EMAIL_HERE")), nil
}

func copyFilePreserveMeta(src, dst string) error {
	// #nosec G304 -- src is a package-constant config path or test-injected temp path.
	data, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("reading %s: %w", src, err)
	}
	info, err := os.Stat(src)
	if err != nil {
		return fmt.Errorf("stat %s: %w", src, err)
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	mode := info.Mode().Perm()
	if err := writeFileAtomic(dst, data, mode); err != nil {
		return fmt.Errorf("writing %s: %w", dst, err)
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		_ = os.Chown(dst, int(stat.Uid), int(stat.Gid))
	}
	return os.Chmod(dst, mode)
}

// divergesOnlyByIntegrityHashes reports whether two config copies differ
// solely in the integrity binary_hash, config_hash and confd_hash values.
//
// `csm rehash` rewrites those fields in one copy only, so after every
// upgrade or drop-in edit the two default paths disagree by exactly these
// lines. Refusing to start on that difference takes the daemon down for
// values CSM itself rewrote, while any real setting divergence must still
// be surfaced.
func divergesOnlyByIntegrityHashes(preferred, legacy string) (bool, error) {
	preferredData, err := os.ReadFile(preferred) // #nosec G304 -- operator-owned config paths
	if err != nil {
		return false, err
	}
	legacyData, err := os.ReadFile(legacy) // #nosec G304 -- operator-owned config paths
	if err != nil {
		return false, err
	}

	preferredLines := strings.Split(string(preferredData), "\n")
	legacyLines := strings.Split(string(legacyData), "\n")
	// Differing line counts mean the structure changed, not just a value.
	if len(preferredLines) != len(legacyLines) {
		return false, nil
	}

	sawHashDifference := false
	for i := range preferredLines {
		if preferredLines[i] == legacyLines[i] {
			continue
		}
		preferredKey, preferredHash := integrityHashLineKey(preferredLines[i])
		legacyKey, legacyHash := integrityHashLineKey(legacyLines[i])
		if !preferredHash || !legacyHash || preferredKey != legacyKey {
			return false, nil
		}
		sawHashDifference = true
	}
	return sawHashDifference, nil
}

func isIntegrityHashLine(line string) bool {
	_, ok := integrityHashLineKey(line)
	return ok
}

func integrityHashLineKey(line string) (string, bool) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "-") {
		return "", false
	}
	key, _, found := strings.Cut(trimmed, ":")
	if !found {
		return "", false
	}
	key = strings.TrimSpace(key)
	switch key {
	case "binary_hash", "config_hash", "confd_hash":
		return key, true
	}
	return "", false
}
