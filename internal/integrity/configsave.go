package integrity

import (
	"fmt"
	"os"
	"reflect"
	"strings"

	"github.com/pidginhost/csm/internal/config"
)

// WriteConfigBytesAtomic writes data to path with the same atomic-rename
// semantics SignAndSaveAtomic uses. Intended for paths that ship pre-signed
// bytes (e.g. restoring a snapshot whose hash already matches its content)
// where re-signing would mutate the integrity block we want to preserve.
func WriteConfigBytesAtomic(path string, data []byte) error {
	return atomicWriteFile(path, data, 0o600)
}

// SignAndSavePreserving writes editedBytes to path after patching
// integrity.binary_hash and integrity.config_hash inside the byte
// stream itself, not by re-marshaling the cfg. Operator comments and
// untouched formatting outside the integrity block survive
// byte-for-byte.
//
// Verifies the final bytes decode via config.LoadBytes and match
// intendedClone under reflect.DeepEqual (with integrity fields
// normalised). Mismatch aborts the write.
//
// Atomic write semantics match SignAndSaveAtomic: same-directory
// tempfile, fsync, rename. On success, intendedClone.Integrity.BinaryHash
// and .ConfigHash are updated in place to reflect the hashes written to
// disk. intendedClone.ConfigFile must equal path and intendedClone.ConfigDir
// must equal confDir.
func SignAndSavePreserving(path, confDir string, editedBytes []byte, intendedClone *config.Config, binaryHash string) error {
	if intendedClone == nil {
		return fmt.Errorf("intendedClone is nil")
	}
	if intendedClone.ConfigFile != path {
		return fmt.Errorf("intendedClone.ConfigFile=%q does not match path=%q", intendedClone.ConfigFile, path)
	}
	if intendedClone.ConfigDir != confDir {
		return fmt.Errorf("intendedClone.ConfigDir=%q does not match confDir=%q", intendedClone.ConfigDir, confDir)
	}

	// Hash the operator-edited bytes before the integrity scalars are
	// rewritten. HashConfigStableBytes ignores the integrity block, so
	// the stored hash still matches the final file after the integrity
	// patch.
	newConfigHash := HashConfigStableBytes(editedBytes)

	// Cover the conf.d fragments merged on top of this main config. Empty
	// when there are none, leaving conf.d-free configs byte-identical to
	// their prior baseline.
	newConfdHash, err := HashConfDir(confDir)
	if err != nil {
		return fmt.Errorf("hashing conf.d: %w", err)
	}

	patched, err := config.YAMLEdit(editedBytes, []config.YAMLChange{
		{Path: []string{"integrity", "binary_hash"}, Value: binaryHash},
		{Path: []string{"integrity", "config_hash"}, Value: newConfigHash},
		{Path: []string{"integrity", "confd_hash"}, Value: newConfdHash},
	})
	if err != nil {
		return fmt.Errorf("patch integrity scalars: %w", err)
	}
	if stripIntegrityBlock(string(patched)) != stripIntegrityBlock(string(editedBytes)) {
		return fmt.Errorf("integrity patch drift: bytes outside integrity block changed")
	}

	decoded, err := config.LoadBytes(patched)
	if err != nil {
		return fmt.Errorf("verify decode: %w", err)
	}
	decoded.ConfigFile = path
	decoded.ConfigDir = confDir

	expected := *intendedClone
	expected.Integrity.BinaryHash = binaryHash
	expected.Integrity.ConfigHash = newConfigHash
	expected.Integrity.ConfdHash = newConfdHash

	if !reflect.DeepEqual(decoded, &expected) {
		return fmt.Errorf("yaml rewrite drift: decoded config does not match intended clone")
	}

	intendedClone.Integrity.BinaryHash = binaryHash
	intendedClone.Integrity.ConfigHash = newConfigHash
	intendedClone.Integrity.ConfdHash = newConfdHash

	return atomicWriteFile(path, patched, 0o600)
}

// SignConfigFilePreserving signs path in place without re-marshaling the
// config. It updates only the operator-owned main config file, but folds the
// conf.d fragments under confDir into integrity.confd_hash so a later edit to
// any fragment is detected by Verify.
func SignConfigFilePreserving(path, confDir, binaryHash string) (configHash, confdHash string, err error) {
	// #nosec G304 -- operator-configured config path.
	data, err := os.ReadFile(path)
	if err != nil {
		return "", "", fmt.Errorf("read config: %w", err)
	}
	cfg, err := config.LoadBytes(data)
	if err != nil {
		return "", "", err
	}
	cfg.ConfigFile = path
	cfg.ConfigDir = confDir
	if err := SignAndSavePreserving(path, confDir, data, cfg, binaryHash); err != nil {
		return "", "", err
	}
	return cfg.Integrity.ConfigHash, cfg.Integrity.ConfdHash, nil
}

// stripIntegrityBlock removes the top-level `integrity:` mapping and
// its indented children from s, then returns the remaining text.
// Used both by SignAndSavePreserving's drift guard and by tests, so
// both compare using the same definition of "outside the integrity
// block".
func stripIntegrityBlock(s string) string {
	lines := strings.Split(s, "\n")
	var out []string
	inIntegrity := false
	for _, line := range lines {
		if strings.HasPrefix(line, "integrity:") {
			inIntegrity = true
			continue
		}
		if inIntegrity {
			if strings.HasPrefix(line, "  ") || strings.HasPrefix(line, "\t") || line == "" {
				continue
			}
			inIntegrity = false
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}
