//go:build linux

package firewall

import (
	"errors"
	"io"
	"testing"

	"github.com/google/nftables"
	"github.com/mdlayher/netlink"
)

func TestCheckBlockBatchUsesFreshSnapshotSockets(t *testing.T) {
	f := newBatchFixture(t, FirewallState{})
	sharedReads := 0
	conn, err := nftables.New(nftables.AsLasting(), nftables.WithTestDial(func([]netlink.Message) ([]netlink.Message, error) {
		sharedReads++
		return nil, errors.New("shared socket must not read a batch snapshot")
	}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.CloseLasting() })
	freshReads := 0
	conn.TestDial = func([]netlink.Message) ([]netlink.Message, error) {
		freshReads++
		return nil, io.EOF
	}
	f.e.conn = conn
	f.e.liveBlockedDump = nil
	got, err := f.e.CheckBlockBatch([]BlockMember{f.member("act_v4", "203.0.113.20")})
	if err != nil || len(got) != 1 || got[0] != "" || sharedReads != 0 || freshReads != 2 {
		t.Fatalf("answers %q, error %v, shared reads %d, fresh reads %d; want two fresh family dumps", got, err, sharedReads, freshReads)
	}
}
