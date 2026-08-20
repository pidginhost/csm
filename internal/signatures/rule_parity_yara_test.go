//go:build yara

package signatures

import (
	"os"
	"path/filepath"
	"slices"
	"sort"
	"testing"

	yara_x "github.com/VirusTotal/yara-x/go"
)

// Keep the lightweight parser honest against the grammar implementation used
// in production. This runs in CI's YARA-X builder image.
func TestYARARuleNameExtractionMatchesYARAX(t *testing.T) {
	source, err := os.ReadFile(filepath.Join("..", "..", "configs", "malware.yar"))
	if err != nil {
		t.Fatal(err)
	}

	compiler, err := yara_x.NewCompiler()
	if err != nil {
		t.Fatal(err)
	}
	defer compiler.Destroy()
	if err := compiler.AddSource(string(source)); err != nil {
		t.Fatalf("compiling malware.yar: %v", err)
	}
	rules := compiler.Build()
	defer rules.Destroy()

	compiledNames := make([]string, 0, rules.Count())
	for _, rule := range rules.Slice() {
		compiledNames = append(compiledNames, rule.Identifier())
	}
	extractedNames := extractYARARuleNames(source)
	sort.Strings(compiledNames)
	sort.Strings(extractedNames)
	if !slices.Equal(extractedNames, compiledNames) {
		t.Fatalf("parsed rule names differ from YARA-X: parsed=%v compiled=%v", extractedNames, compiledNames)
	}
}
