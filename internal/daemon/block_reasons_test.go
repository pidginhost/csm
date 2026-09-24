package daemon

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/responsereplay"
)

// The replay tool recognises blocks from outside the scan budget by the
// reason these paths record. Each produced reason must match exactly one of
// the replay's prefixes, and every prefix must have a producer.
func TestNonScanBlockReasonsMatchReplayPrefixes(t *testing.T) {
	produced := []string{
		challengeTimeoutReasonPrefix + "wp brute",
		centralIntelBlockReason,
		sprayBlockReasonPrefix + "9 distinct mailboxes",
		incidentReasonPrefix + "brute_force HIGH",
	}
	used := map[string]bool{}
	for _, reason := range produced {
		matches := 0
		for _, prefix := range responsereplay.NonScanReasonPrefixes {
			if strings.HasPrefix(reason, prefix) {
				matches++
				used[prefix] = true
			}
		}
		if matches != 1 {
			t.Errorf("reason %q matches %d replay prefixes", reason, matches)
		}
	}
	for _, prefix := range responsereplay.NonScanReasonPrefixes {
		if !used[prefix] {
			t.Errorf("replay prefix %q has no producer here", prefix)
		}
	}
}

// A reason typed out again at a call site would drift from the constants
// above without failing anything. Only block_reasons.go may spell them.
func TestNonScanBlockReasonsAreOnlySpelledOnce(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") || name == "block_reasons.go" {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), name, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		checked++
		ast.Inspect(file, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			value, err := strconv.Unquote(lit.Value)
			if err != nil {
				return true
			}
			for _, prefix := range responsereplay.NonScanReasonPrefixes {
				if strings.HasPrefix(value, prefix) {
					t.Errorf("%s spells the block reason %q; use the constant in block_reasons.go", name, prefix)
				}
			}
			return true
		})
	}
	if checked == 0 {
		t.Fatal("no daemon files checked")
	}
}
