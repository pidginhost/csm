package checks

import (
	"os"
	"testing"
)

func TestDomainAccountOwnerParsesUserdomains(t *testing.T) {
	oldOS := osFS
	osFS = &mockOS{readFile: func(name string) ([]byte, error) {
		if name == "/etc/userdomains" {
			return []byte("radius.ro: radiusro\nthermaroll.ro: radiusro\n*: nobody\n"), nil
		}
		return nil, os.ErrNotExist
	}}
	t.Cleanup(func() { osFS = oldOS })
	resetDomainOwnerCache()
	t.Cleanup(resetDomainOwnerCache)

	if got := domainAccountOwner("radius.ro"); got != "radiusro" {
		t.Fatalf("radius.ro owner = %q want radiusro", got)
	}
	if got := domainAccountOwner("THERMAROLL.RO"); got != "radiusro" {
		t.Fatalf("case-insensitive lookup failed, got %q", got)
	}
	if got := domainAccountOwner("unknown.example"); got != "" {
		t.Fatalf("unknown domain owner = %q want empty", got)
	}
	if got := domainAccountOwner(""); got != "" {
		t.Fatalf("empty domain owner = %q want empty", got)
	}
}
