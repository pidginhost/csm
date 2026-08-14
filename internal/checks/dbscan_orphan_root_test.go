package checks

import (
	"context"
	"os"
	"testing"
)

// mockOSCPanelMap serves a cPanel /etc/userdatadomains map plus an on-disk
// layout, so discovery can be exercised on the cPanel code path.
type mockOSCPanelMap struct {
	mockOS
	mapBody string
	files   []string
}

func (m *mockOSCPanelMap) ReadFile(name string) ([]byte, error) {
	if name == userdataDomainsPath {
		return []byte(m.mapBody), nil
	}
	return nil, os.ErrNotExist
}

func (m *mockOSCPanelMap) Lstat(name string) (os.FileInfo, error) {
	for _, f := range m.files {
		if f == name {
			return fakeFileInfo{name: "wp-config.php"}, nil
		}
	}
	return nil, os.ErrNotExist
}

func (m *mockOSCPanelMap) Glob(pattern string) ([]string, error) {
	var out []string
	for _, f := range m.files {
		if globMatchesTest(pattern, f) {
			out = append(out, f)
		}
	}
	return out, nil
}

// The production compromise that motivated addon-root scanning sat in a
// document root that cPanel no longer serves: karmaboutique.ro was absent from
// /etc/userdatadomains, /etc/userdomains and vhost userdata entirely. Trusting
// the served-domain map alone puts that install back out of reach, which is
// exactly how it stayed unreported for months. An unserved WordPress install
// still holds a live database, and re-pointing the domain publishes it again.
func TestWPConfigPaths_CPanelMapDoesNotHideOrphanedDocRoots(t *testing.T) {
	old := osFS
	osFS = &mockOSCPanelMap{
		mapBody: "served.example.com: alice==root==addon==served.example.com.alice.example==" +
			"/home/alice/served.example.com==192.0.2.1:80==192.0.2.1:443====0==ea-php82\n",
		files: []string{
			"/home/alice/served.example.com/wp-config.php",
			"/home/alice/orphan.example.com/wp-config.php",
		},
	}
	t.Cleanup(func() { osFS = old })

	got := wpConfigPaths(context.Background())
	found := map[string]bool{}
	for _, p := range got {
		found[p] = true
	}
	if !found["/home/alice/served.example.com/wp-config.php"] {
		t.Errorf("served document root missing from discovery: %v", got)
	}
	if !found["/home/alice/orphan.example.com/wp-config.php"] {
		t.Errorf("orphaned document root not discovered on a cPanel host: %v", got)
	}
}
