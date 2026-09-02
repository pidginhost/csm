package platform

import (
	"slices"
	"testing"
)

// Account-scoped checks assumed every account lives under /home. Plesk
// keeps vhosts under /var/www/vhosts, so on that panel every per-account
// scan, remediation and re-check was looking at an empty directory.
func TestAccountHomeRoots(t *testing.T) {
	cases := []struct {
		name string
		info Info
		want []string
	}{
		{"cpanel", Info{Panel: PanelCPanel, OS: OSAlma}, []string{"/home"}},
		{"directadmin", Info{Panel: PanelDA, OS: OSAlma}, []string{"/home"}},
		{"plesk", Info{Panel: PanelPlesk, OS: OSUbuntu}, []string{"/var/www/vhosts"}},
		{"none", Info{Panel: PanelNone, OS: OSDebian}, []string{"/home"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.info.AccountHomeRoots(); !slices.Equal(got, tc.want) {
				t.Fatalf("AccountHomeRoots() = %v, want %v", got, tc.want)
			}
		})
	}
}
