package integrity

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/pidginhost/csm/internal/config"
)

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
// disk. intendedClone.ConfigFile must equal path.
func SignAndSavePreserving(path string, editedBytes []byte, intendedClone *config.Config, binaryHash string) error {
	if intendedClone == nil {
		return fmt.Errorf("intendedClone is nil")
	}
	if intendedClone.ConfigFile != path {
		return fmt.Errorf("intendedClone.ConfigFile=%q does not match path=%q", intendedClone.ConfigFile, path)
	}

	// Hash the operator-edited bytes before the integrity scalars are
	// rewritten. HashConfigStableBytes ignores the integrity block, so
	// the stored hash still matches the final file after the integrity
	// patch.
	newConfigHash := HashConfigStableBytes(editedBytes)

	patched, err := config.YAMLEdit(editedBytes, []config.YAMLChange{
		{Path: []string{"integrity", "binary_hash"}, Value: binaryHash},
		{Path: []string{"integrity", "config_hash"}, Value: newConfigHash},
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

	expected := *intendedClone
	expected.Integrity.BinaryHash = binaryHash
	expected.Integrity.ConfigHash = newConfigHash

	if !reflect.DeepEqual(decoded, &expected) {
		return fmt.Errorf("yaml rewrite drift: decoded config does not match intended clone")
	}

	intendedClone.Integrity.BinaryHash = binaryHash
	intendedClone.Integrity.ConfigHash = newConfigHash

	return atomicWriteFile(path, patched, 0o600)
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
