package checks

import (
	"os"
	"testing"
)

// cPanel marks a suspended account with a file under /var/cpanel/suspended.
// The account's database users are locked at the same time, so every query
// against its installs fails with an access error. Counting that as missing
// coverage produced a permanent warning on every scan that no operator action
// could clear.
func TestAccountSuspendedReadsCpanelMarker(t *testing.T) {
	withMockOS(t, &mockOS{
		stat: func(name string) (os.FileInfo, error) {
			if name == "/var/cpanel/suspended/parked" {
				return fakeFileInfo{name: "parked"}, nil
			}
			return nil, os.ErrNotExist
		},
	})
	if !accountSuspended("parked") {
		t.Fatal("an account with a cPanel suspension marker was not reported suspended")
	}
	if accountSuspended("live") {
		t.Fatal("an account with no suspension marker was reported suspended")
	}
}

// A path separator or traversal in the account name must not let the lookup
// escape the suspension directory.
func TestAccountSuspendedRejectsUnsafeNames(t *testing.T) {
	withMockOS(t, &mockOS{
		stat: func(string) (os.FileInfo, error) { return fakeFileInfo{name: "x"}, nil },
	})
	for _, name := range []string{"", ".", "..", "a/b", "../root"} {
		if accountSuspended(name) {
			t.Errorf("unsafe account name %q was resolved against the suspension directory", name)
		}
	}
}
