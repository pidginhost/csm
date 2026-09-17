package platform

import (
	"path/filepath"
	"testing"
)

func FuzzAccountRootPattern(f *testing.F) {
	for _, seed := range []string{"/srv/accounts/*/public", "/srv/[", "/srv/../etc", "/*/public", "/home[2-9]/*/public_html"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, pattern string) {
		if ValidateAccountRootPattern(pattern) == nil && (!filepath.IsAbs(pattern) || filepath.Clean(pattern) != pattern) {
			t.Fatalf("accepted unconfined root %q", pattern)
		}
	})
}
