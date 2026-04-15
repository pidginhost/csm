package integrity

import (
	"bufio"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"strings"

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
func HashConfigStable(path string) (string, error) {
	// #nosec G304 -- operator-supplied config file path.
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()

	h := sha256.New()
	scanner := bufio.NewScanner(f)
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
	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("scanning config: %w", err)
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
	}

	return nil
}
