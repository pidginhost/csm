package checks

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

func TestCheckRegistryHasNoDuplicates(t *testing.T) {
	seen := map[string]struct{}{}
	for _, c := range checkRegistry {
		if _, dup := seen[c.Name]; dup {
			t.Errorf("duplicate check name in registry: %q", c.Name)
		}
		seen[c.Name] = struct{}{}
	}
}

func TestCheckRegistryEveryEntryHasCategory(t *testing.T) {
	validCategories := map[string]struct{}{}
	for _, c := range checkCategoryOrder {
		validCategories[c] = struct{}{}
	}
	for _, c := range checkRegistry {
		if c.Category == "" {
			t.Errorf("check %q has empty category", c.Name)
			continue
		}
		if _, ok := validCategories[c.Category]; !ok {
			t.Errorf("check %q uses unknown category %q", c.Name, c.Category)
		}
	}
}

func TestPublicCheckInfosExcludesInternal(t *testing.T) {
	for _, c := range PublicCheckInfos() {
		if c.Internal {
			t.Errorf("PublicCheckInfos should not include internal check %q", c.Name)
		}
	}
}

// TestCheckRegistryCoversProductionCode scans the repository for every
// pattern that emits an alert.Finding.Check name and fails if any name is
// not present in checkRegistry. This prevents drift when a new check is
// added via any of the supported emission patterns.
//
// Scan scope: internal/checks, internal/daemon, internal/webui. Excludes
// *_test.go files.
//
// Patterns matched (after stripping // comments):
//   - Struct literal:       `Check: "name"` (exported field)
//   - namedCheck literal:   `check: "name"` (lowercase unexported field)
//   - Local assignment:     `check = "name"` or `check := "name"`
//   - Helper calls that take the check name as a bare string argument:
//       sendAlert(sev, "name", ...)
//       sendAlertWithPath(sev, "name", ...)
//       emitFinding("name", ...)            // first arg
//       emitReloadFinding(sev, "name", ...)
//
// Add a new pattern here if a new emission helper is introduced — the
// test failure message points at the callsite so it is obvious what to
// do.
func TestCheckRegistryCoversProductionCode(t *testing.T) {
	repoRoot := findRepoRoot(t)
	scanDirs := []string{
		filepath.Join(repoRoot, "internal", "checks"),
		filepath.Join(repoRoot, "internal", "daemon"),
		filepath.Join(repoRoot, "internal", "webui"),
	}

	// Names captured by the patterns below. Each regex has exactly one
	// capture group: the check name.
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`Check:\s*"([A-Za-z_][A-Za-z0-9_]*)"`),
		regexp.MustCompile(`\bcheck:\s*"([A-Za-z_][A-Za-z0-9_]*)"`),
		regexp.MustCompile(`\bcheck\s*:?=\s*"([A-Za-z_][A-Za-z0-9_]*)"`),
		regexp.MustCompile(`\bsendAlert(?:WithPath)?\(\s*[^,]+?,\s*"([A-Za-z_][A-Za-z0-9_]*)"`),
		regexp.MustCompile(`\bemitFinding\(\s*"([A-Za-z_][A-Za-z0-9_]*)"`),
		regexp.MustCompile(`\bemitReloadFinding\(\s*[^,]+?,\s*"([A-Za-z_][A-Za-z0-9_]*)"`),
	}

	registered := map[string]struct{}{}
	for _, c := range checkRegistry {
		registered[c.Name] = struct{}{}
	}

	type hit struct{ name, where string }
	var missing []hit
	seen := map[string]struct{}{}

	for _, dir := range scanDirs {
		err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() {
				return nil
			}
			if !strings.HasSuffix(path, ".go") {
				return nil
			}
			if strings.HasSuffix(path, "_test.go") {
				return nil
			}
			data, rerr := os.ReadFile(path) // #nosec G304 -- test-only scanner with fixed dir roots
			if rerr != nil {
				return rerr
			}
			for lineNo, line := range strings.Split(string(data), "\n") {
				code := stripLineComment(line)
				for _, re := range patterns {
					for _, m := range re.FindAllStringSubmatch(code, -1) {
						name := m[1]
						if _, ok := seen[name]; ok {
							continue
						}
						seen[name] = struct{}{}
						if _, ok := registered[name]; !ok {
							missing = append(missing, hit{name: name, where: fmt.Sprintf("%s:%d", path, lineNo+1)})
						}
					}
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", dir, err)
		}
	}

	if len(missing) > 0 {
		sort.Slice(missing, func(i, j int) bool { return missing[i].name < missing[j].name })
		var lines []string
		for _, m := range missing {
			lines = append(lines, m.name+" (at "+m.where+")")
		}
		t.Fatalf("%d check name(s) missing from checkRegistry — add them to internal/checks/registry.go:\n  %s",
			len(missing), strings.Join(lines, "\n  "))
	}
}

// stripLineComment removes a trailing `//` comment from a Go source line.
// It walks byte-by-byte tracking whether we are inside a string or rune
// literal so a // occurring inside a "..." string is preserved. Escaped
// quotes inside strings are handled. Does not handle /* */ block comments;
// those are rare for inline Check: literals and a false-positive inside one
// would be caught with a clear error message.
func stripLineComment(line string) string {
	inString := false
	inRune := false
	escape := false
	for i := 0; i < len(line); i++ {
		c := line[i]
		if escape {
			escape = false
			continue
		}
		if c == '\\' && (inString || inRune) {
			escape = true
			continue
		}
		if c == '"' && !inRune {
			inString = !inString
			continue
		}
		if c == '\'' && !inString {
			inRune = !inRune
			continue
		}
		if !inString && !inRune && c == '/' && i+1 < len(line) && line[i+1] == '/' {
			return line[:i]
		}
	}
	return line
}

// findRepoRoot walks upward from the current test file's directory until it
// finds a go.mod. Used so the drift scanner works regardless of where the
// test is invoked from (root, package dir, `go test ./...`, IDE, etc.).
func findRepoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for dir := wd; ; {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("go.mod not found walking up from %s", wd)
		}
		dir = parent
	}
}
