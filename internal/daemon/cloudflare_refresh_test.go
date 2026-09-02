package daemon

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

// The refresh replaces the kernel sets, the saved list and the checks
// package's Cloudflare ranges with whatever the fetch returned. An empty
// family must never reach that step: it would flush every Cloudflare guard
// and the next brute-force finding carrying an edge address would block that
// edge for every visitor behind it. The previous list stays in force.
func TestRefreshCloudflareIPsKeepsPreviousListOnEmptyFetch(t *testing.T) {
	orig := fetchCloudflareIPs
	t.Cleanup(func() { fetchCloudflareIPs = orig })

	state := t.TempDir()
	saved := filepath.Join(state, "cf_whitelist.txt")
	const previous = "173.245.48.0/20\n2400:cb00::/32\n"
	if err := os.WriteFile(saved, []byte(previous), 0o644); err != nil {
		t.Fatal(err)
	}
	d := &Daemon{cfg: &config.Config{StatePath: state}}

	for name, fetch := range map[string]func() ([]string, []string, error){
		"both empty":  func() ([]string, []string, error) { return nil, nil, nil },
		"ipv6 empty":  func() ([]string, []string, error) { return []string{"173.245.48.0/20"}, nil, nil },
		"fetch error": func() ([]string, []string, error) { return nil, nil, os.ErrDeadlineExceeded },
	} {
		t.Run(name, func(t *testing.T) {
			fetchCloudflareIPs = fetch
			d.refreshCloudflareIPs()
			got, err := os.ReadFile(saved)
			if err != nil || string(got) != previous {
				t.Fatalf("saved Cloudflare list changed after an unusable fetch: %q (%v)", got, err)
			}
		})
	}
}
