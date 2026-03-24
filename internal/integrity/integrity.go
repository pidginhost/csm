package integrity

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"

	"github.com/pidginhost/cpanel-security-monitor/internal/config"
)

func HashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}

	return fmt.Sprintf("sha256:%x", h.Sum(nil)), nil
}

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
		configHash, err := HashFile(cfg.ConfigFile)
		if err != nil {
			return fmt.Errorf("hashing config: %w", err)
		}
		if configHash != cfg.Integrity.ConfigHash {
			return fmt.Errorf("config hash mismatch: expected %s, got %s", cfg.Integrity.ConfigHash, configHash)
		}
	}

	return nil
}
