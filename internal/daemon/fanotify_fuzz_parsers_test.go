//go:build linux

package daemon

import (
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/checks"
)

func FuzzPHPNamespaceScopes(f *testing.F) {
	for _, source := range []string{
		"<?php system($_POST['x']);",
		"<?php namespace App; system($_POST['x']);",
		"<?php namespace Decoy {} namespace { system($_POST['x']); }",
		"<?php namespace App { use function Vendor\\run as system; system($_POST['x']); }",
	} {
		f.Add(source)
	}
	f.Fuzz(func(t *testing.T, source string) {
		if len(source) > 1<<16 {
			return
		}
		structure := strings.ToLower(checks.PHPExecutableStructure(source))
		masked := maskUserDispatchedPHPCalls(structure)
		if len(masked) != len(structure) {
			t.Fatalf("masked length=%d, want %d", len(masked), len(structure))
		}
		for _, scope := range phpNamespaceScopes(structure) {
			if scope.id < 1 || scope.start < 0 || scope.start > scope.end || scope.end > len(structure) {
				t.Fatalf("invalid namespace scope: %+v for length %d", scope, len(structure))
			}
		}
	})
}
