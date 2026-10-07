package checks

import (
	"os"
	"testing"
)

func TestDomainAccountOwnerParsesUserdomains(t *testing.T) {
	oldOS := osFS
	osFS = &mockOS{readFile: func(name string) ([]byte, error) {
		if name == "/etc/userdomains" {
			return []byte("acmeradio.example: acmeradio\nacmeheating.example: acmeradio\n*: nobody\n"), nil
		}
		return nil, os.ErrNotExist
	}}
	t.Cleanup(func() { osFS = oldOS })
	resetDomainOwnerCache()
	t.Cleanup(resetDomainOwnerCache)

	if got := domainAccountOwner("acmeradio.example"); got != "acmeradio" {
		t.Fatalf("acmeradio.example owner = %q want acmeradio", got)
	}
	if got := domainAccountOwner("ACMEHEATING.EXAMPLE"); got != "acmeradio" {
		t.Fatalf("case-insensitive lookup failed, got %q", got)
	}
	if got := domainAccountOwner("unknown.example"); got != "" {
		t.Fatalf("unknown domain owner = %q want empty", got)
	}
	if got := domainAccountOwner(""); got != "" {
		t.Fatalf("empty domain owner = %q want empty", got)
	}
}
