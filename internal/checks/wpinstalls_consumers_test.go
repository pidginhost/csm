package checks

import (
	"context"
	"testing"
)

// These three checks globbed public_html only, so an addon-domain or nested
// install was never scanned for injected database objects, shared admin email
// or reused administrator password hashes.
func TestReadOnlyDetectors_SeeNestedAndAddonInstalls(t *testing.T) {
	for _, tc := range []struct {
		name    string
		configs func(ctx context.Context) []string
	}{
		{"db_objects", dbObjectWPConfigs},
		{"admin_overlap", adminOverlapWPConfigs},
		{"credential_reuse", credentialReuseWPConfigs},
	} {
		t.Run(tc.name, func(t *testing.T) {
			old := osFS
			osFS = &mockOSGlobRoots{files: []string{
				"/home/alice/public_html/wp-config.php",
				"/home/alice/public_html/blog/wp-config.php",
				"/home/alice/shop.example.com/wp-config.php",
			}}
			t.Cleanup(func() { osFS = old })

			if got := tc.configs(context.Background()); len(got) != 3 {
				t.Errorf("configs = %v, want all three installs", got)
			}
		})
	}
}
