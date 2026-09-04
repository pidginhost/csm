package checks

import (
	"fmt"
	"strings"
	"testing"
)

// The startup sweep runs only when its token changed since the last start. A
// change to the sweep's own semantics -- which findings it may demote, which
// paths its verifiers can reach -- otherwise waits for the next deep-scan cycle
// on every host that already recorded one, which is where the token needs a
// component the sweep's own changes can move.

func TestFindingReverifyVersionIncludesSweepLogicVersion(t *testing.T) {
	v := FindingReverifyVersion()
	want := fmt.Sprintf("reverify=%d", reverifySweepLogicVersion)
	if !strings.Contains(v, want) {
		t.Fatalf("reverify token %q missing %q", v, want)
	}
}

func TestReverifySweepLogicVersionCoversRemediationRootFix(t *testing.T) {
	// Bumped when content, permission and htaccess re-checks stopped reading
	// the raw allow-list var (nil in production) and started resolving the
	// platform's account roots. Without this bump a host that already stored a
	// token keeps skipping the sweep and the fix reaches nothing.
	const remediationRootFixVersion = 1
	if reverifySweepLogicVersion < remediationRootFixVersion {
		t.Fatalf("reverifySweepLogicVersion = %d, want at least %d so existing findings are re-checked",
			reverifySweepLogicVersion, remediationRootFixVersion)
	}
}
