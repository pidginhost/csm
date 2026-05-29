package integrity

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/pidginhost/csm/internal/config"
)

// HashFile returns the SHA256 hash of a file.
func HashFile(path string) (string, error) {
	// #nosec G304 -- integrity hashing of operator-configured binary/config paths.
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}

	return fmt.Sprintf("sha256:%x", h.Sum(nil)), nil
}

// HashConfigStable hashes the config file excluding the integrity section,
// so that writing hashes back to the config doesn't change the hash.
//
// Line length is capped at 1 MiB; anything longer is treated as a
// corrupted config and the digest reflects whatever was scanned up to
// the truncation point. A corruption-driven hash will trip
// integrity.Verify on the next start, which is the intended response.
func HashConfigStable(path string) (string, error) {
	// #nosec G304 -- operator-supplied config file path.
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("reading config: %w", err)
	}
	return HashConfigStableBytes(data), nil
}

// HashConfigStableBytes is the in-memory counterpart to
// HashConfigStable: compute the stable hash from an already-serialised
// config body without touching disk. Used by the SIGHUP reload path
// and `csm rehash` so both can hash a prospective file content before
// committing it, avoiding the two-pass-write dance that could leave
// integrity.config_hash blank on disk if the second save failed.
//
// Returns the same "sha256:..." string shape as HashConfigStable.
// The scanner is sized to cover config lines well beyond any
// realistic CSM yaml; a line longer than 1 MiB is treated as
// corruption and the final digest reflects whatever was scanned
// before the truncation (the resulting mismatch against any stored
// hash will trip integrity.Verify, which is the correct response).
func HashConfigStableBytes(data []byte) string {
	h := sha256.New()
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)
	inIntegrity := false
	for scanner.Scan() {
		line := scanner.Text()

		// Skip the integrity section
		if strings.HasPrefix(line, "integrity:") {
			inIntegrity = true
			continue
		}
		if inIntegrity {
			// Still inside integrity block (indented lines)
			if strings.HasPrefix(line, "  ") || strings.HasPrefix(line, "\t") || line == "" {
				continue
			}
			inIntegrity = false
		}

		_, _ = h.Write([]byte(line + "\n"))
	}

	return fmt.Sprintf("sha256:%x", h.Sum(nil))
}

// SignAndSaveAtomic re-computes integrity.config_hash for cfg and
// writes the result to cfg.ConfigFile atomically. Atomicity means:
// the on-disk file either carries the prior content (operation
// failed) or the fully-signed new content (operation succeeded).
// There is no window where the file exists on disk with an empty or
// stale config_hash, so a crash between the two passes of the
// previous two-save dance can no longer put the daemon into a
// crash-loop on next startup.
//
// The integrity.binary_hash is set to the supplied binaryHash. The
// CALLER is responsible for picking the right value: `csm rehash`
// hashes /opt/csm/csm afresh; SIGHUP reload preserves the prior
// daemon's binary hash because a reload cannot upgrade the binary.
//
// Implementation: marshal the config with a blank ConfigHash, hash
// the stable form of those bytes, store the hash, marshal again,
// write to a sibling temp file, rename into place. The YAML hashing
// strips the integrity block so both marshals round-trip to the
// same stable hash.
func SignAndSaveAtomic(cfg *config.Config, binaryHash string) error {
	cfg.Integrity.BinaryHash = binaryHash
	cfg.Integrity.ConfigHash = ""
	confdHash, err := HashConfDir(cfg.ConfigDir)
	if err != nil {
		return fmt.Errorf("hashing conf.d: %w", err)
	}
	cfg.Integrity.ConfdHash = confdHash
	preHash, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal (pre-hash): %w", err)
	}
	cfg.Integrity.ConfigHash = HashConfigStableBytes(preHash)
	final, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal (post-hash): %w", err)
	}
	return atomicWriteFile(cfg.ConfigFile, final, 0o600)
}

// atomicWriteFile writes data to a temp file in the same directory
// as path, fsyncs and closes the temp, then renames it onto path.
// Rename is atomic on POSIX when source and destination are on the
// same filesystem (which is why the temp is created in the target's
// dir, not /tmp). Permission is applied before the rename.
func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".csm-cfg-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpName := tmp.Name()
	// Best-effort cleanup: if any error below leaves the temp
	// behind, unlink it so we do not fill the dir with orphans.
	cleanup := func() { _ = os.Remove(tmpName) }

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("write temp: %w", err)
	}
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("chmod temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("fsync temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("close temp: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		cleanup()
		return fmt.Errorf("rename: %w", err)
	}
	return nil
}

// HashConfDir returns a stable digest over every conf.d drop-in fragment that
// would be merged on top of the main config, in merge order. It returns the
// empty string when there are no fragments, so a config without conf.d keeps
// the empty digest and its pre-existing baseline still verifies after upgrade.
//
// Each fragment is domain-separated by name and length so two fragments cannot
// collide by shuffling bytes across the filename boundary.
func HashConfDir(confDir string) (string, error) {
	frags, err := config.ConfDirFragmentDigestInput(confDir)
	if err != nil {
		return "", err
	}
	if len(frags) == 0 {
		return "", nil
	}
	h := sha256.New()
	for _, f := range frags {
		fmt.Fprintf(h, "confd-fragment:%s:%d\n", f.Name, len(f.Data))
		_, _ = h.Write(f.Data)
	}
	return fmt.Sprintf("sha256:%x", h.Sum(nil)), nil
}

// Verify checks the binary and config file integrity.
func Verify(binaryPath string, cfg *config.Config) error {
	if cfg.Integrity.BinaryHash == "" {
		return nil // Not yet baselined
	}

	currentHash, err := HashFile(binaryPath)
	if err != nil {
		return fmt.Errorf("hashing binary: %w", err)
	}
	if currentHash != cfg.Integrity.BinaryHash {
		return fmt.Errorf("binary hash mismatch: expected %s, got %s", cfg.Integrity.BinaryHash, currentHash)
	}

	if cfg.Integrity.ConfigHash != "" {
		configHash, err := HashConfigStable(cfg.ConfigFile)
		if err != nil {
			return fmt.Errorf("hashing config: %w", err)
		}
		if configHash != cfg.Integrity.ConfigHash {
			return fmt.Errorf("config hash mismatch: expected %s, got %s", cfg.Integrity.ConfigHash, configHash)
		}

		// conf.d fragments are merged on top of the main config at load time,
		// so they must be covered too. A symmetric comparison closes the gap
		// both ways: a tampered or added fragment makes the computed digest
		// diverge from the stored one, and a baseline taken without conf.d
		// stays empty == empty. Operators who already use conf.d must re-run
		// `csm rehash` once after upgrade to populate confd_hash.
		confdHash, err := HashConfDir(cfg.ConfigDir)
		if err != nil {
			return fmt.Errorf("hashing conf.d: %w", err)
		}
		if confdHash != cfg.Integrity.ConfdHash {
			return fmt.Errorf("conf.d hash mismatch: expected %s, got %s", cfg.Integrity.ConfdHash, confdHash)
		}
	}

	return nil
}
