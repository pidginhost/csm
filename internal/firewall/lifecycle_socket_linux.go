//go:build linux

package firewall

import (
	"errors"
	"fmt"
	"time"

	"github.com/google/nftables"
	"github.com/mdlayher/netlink"
)

// Bound the actual socket exchange, including both request writes and replies.
// This option runs on every transient dial, so a reused nftables connection
// receives a fresh deadline for each operation.
func applyLifecycleSocketDeadline(connection *netlink.Conn) error {
	if err := connection.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		// nftables does not close a socket when one of its socket options fails.
		_ = connection.Close()
		return fmt.Errorf("setting firewall lifecycle socket deadline: %w", err)
	}
	return nil
}

func newLifecycleConn(engine *Engine) (*nftables.Conn, error) {
	if engine == nil || engine.conn == nil {
		return nil, errors.New("firewall lifecycle transport unavailable")
	}
	options := []nftables.ConnOption{
		nftables.WithNetNSFd(engine.conn.NetNS),
		nftables.WithTestDial(engine.conn.TestDial),
		nftables.WithSockOptions(applyNFTSocketBuffer),
	}
	// The explicitly injected nltest transport has no OS socket or deadline
	// support. Never suppress deadline errors on a live transport.
	if engine.conn.TestDial == nil {
		options = append(options, nftables.WithSockOptions(applyLifecycleSocketDeadline))
	}
	return nftables.New(options...)
}
