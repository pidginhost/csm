package yara

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ErrNoEngine is returned by the compile and load entry points of a build
// without YARA-X.
var ErrNoEngine = errors.New("yara: YARA-X is not compiled into this build")

// Source is the text of one rule file, ready to compile. Name is the file's
// base name, so compile errors say which file is broken.
type Source struct {
	Name string
	Text []byte
}

// ReadSources reads the .yar and .yara files in rulesDir in name order, with
// the built-in suppressions and the operator's disabled rules stripped, and
// counts the rules stripped. A missing or unset directory is an empty rule
// set, not an error. Reading needs no engine, so the daemon can prepare rule
// text that a separate process compiles.
func ReadSources(rulesDir string, disabled []string) ([]Source, int, error) {
	if rulesDir == "" {
		return nil, 0, nil
	}
	// Refuse to read rules from a directory or file that a third party could
	// overwrite. An attacker who can drop a blank rule silently disables
	// every detection downstream of YARA.
	if err := validateRulesDir(rulesDir); err != nil {
		return nil, 0, err
	}
	entries, err := os.ReadDir(rulesDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, 0, nil
		}
		return nil, 0, fmt.Errorf("reading YARA rules dir: %w", err)
	}

	names := strippedRuleNames(disabled)
	var sources []Source
	disabledCount := 0
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(name))
		if ext != ".yar" && ext != ".yara" {
			continue
		}
		path := filepath.Join(rulesDir, name)
		data, err := os.ReadFile(path) // #nosec G304 -- ReadDir supplies a basename in the operator-selected directory; rule files are trust-checked above.
		if err != nil {
			return nil, 0, fmt.Errorf("reading %s: %w", path, err)
		}
		// Strip at compile time, not only at download time: a tier already on
		// disk would otherwise keep firing until the next weekly update. The
		// operator's own list rides along, so switching off a shipped rule
		// does not mean editing rule files on a production host.
		filtered, removed := stripRules(data, names)
		disabledCount += removed
		sources = append(sources, Source{Name: name, Text: filtered})
	}
	return sources, disabledCount, nil
}

// strippedRuleNames merges the built-in suppressions with the operator's
// disabled list, dropping blanks and duplicates.
func strippedRuleNames(disabled []string) []string {
	builtin := SuppressedRuleNames()
	seen := make(map[string]struct{}, len(builtin)+len(disabled))
	out := make([]string, 0, len(builtin)+len(disabled))
	for _, name := range append(builtin, disabled...) {
		trimmed := strings.TrimSpace(name)
		if trimmed == "" {
			continue
		}
		if _, dup := seen[trimmed]; dup {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	return out
}
