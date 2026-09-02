//go:build linux

package firewall

import (
	"errors"
	"testing"

	"github.com/google/nftables"
)

// Apply discarded the error from listing tables. With a create-only
// AddTable, a failed listing (ENOBUFS under a large ruleset, a transient
// netlink error) left the old csm table in place and every rule was
// appended a second time to the live chains: doubled meters, halved rate
// limits. A failed listing now aborts the apply.
func TestApplyAbortsWhenTableListingFails(t *testing.T) {
	e := &Engine{
		cfg:       &FirewallConfig{},
		statePath: t.TempDir(),
		listTables: func() ([]*nftables.Table, error) {
			return nil, errors.New("netlink: ENOBUFS")
		},
	}
	err := e.Apply()
	if err == nil || !errors.Is(err, errTableListing) {
		t.Fatalf("Apply with a failed table listing returned %v, want a table-listing error", err)
	}
}
