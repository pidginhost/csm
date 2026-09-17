//go:build linux

package firewall

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"

	"github.com/google/nftables"
	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nltest"
	"golang.org/x/sys/unix"
)

// The namespace generation advances on a committed nftables transaction.
// Together with a unique inert chain in our atomic Apply batch it proves both
// that the intended batch committed and that no later ruleset edit intervened.
// Unrelated namespace edits conservatively require recovery review too.
func (e *Engine) actionGeneration() (uint32, error) {
	var socket *netlink.Conn
	if e.conn.TestDial != nil {
		socket = nltest.Dial(e.conn.TestDial)
	} else {
		var err error
		socket, err = netlink.Dial(unix.NETLINK_NETFILTER, &netlink.Config{NetNS: e.conn.NetNS})
		if err != nil {
			return 0, err
		}
		if err = applyLifecycleSocketDeadline(socket); err != nil {
			return 0, err
		}
	}
	defer func() { _ = socket.Close() }()
	messages, err := socket.Execute(netlink.Message{Header: netlink.Header{Type: netlink.HeaderType(unix.NFNL_SUBSYS_NFTABLES<<8 | unix.NFT_MSG_GETGEN), Flags: netlink.Request}, Data: []byte{unix.AF_UNSPEC, 0, 0, 0}})
	if err != nil {
		return 0, err
	}
	for _, message := range messages {
		if len(message.Data) < 4 {
			continue
		}
		attrs, decodeErr := netlink.UnmarshalAttributes(message.Data[4:])
		if decodeErr != nil {
			return 0, decodeErr
		}
		for _, attr := range attrs {
			if attr.Type&0x3fff == unix.NFTA_GEN_ID && len(attr.Data) == 4 {
				return binary.BigEndian.Uint32(attr.Data), nil
			}
		}
	}
	return 0, errors.New("missing nftables generation evidence")
}
func (e *Engine) prepareRulesetEvidence(a *FirewallAction) error {
	generation, err := e.actionGeneration()
	if err != nil {
		return err
	}
	if generation == math.MaxUint32 {
		return errors.New("nftables generation rollover requires a new recovery baseline")
	}
	a.Ruleset = &ActionRuleset{Generation: generation, Marker: "csm_action_" + stateFingerprint(a.Request)[4:]}
	return nil
}
func (e *Engine) rulesetEvidenceMatches(a FirewallAction, generation uint32) (ActionObservation, error) {
	if a.Ruleset == nil || a.Ruleset.Marker != "csm_action_"+stateFingerprint(a.Request)[4:] || a.Ruleset.Generation == math.MaxUint32 {
		return ActionObservation{}, errors.New("invalid ruleset recovery evidence")
	}
	conn, err := newLifecycleConn(e)
	if err != nil {
		return ActionObservation{}, err
	}
	chains, err := conn.ListChainsOfTableFamily(nftables.TableFamilyINet)
	if err != nil {
		return ActionObservation{}, err
	}
	marker := false
	for _, chain := range chains {
		if chain.Table.Name == "csm" && chain.Name == a.Ruleset.Marker {
			marker = true
		}
	}
	after, err := e.actionGeneration()
	if err != nil {
		return ActionObservation{}, err
	}
	if after != generation {
		return ActionObservation{}, fmt.Errorf("%w: ruleset changed during verification", ErrActionUnknown)
	}
	return ActionObservation{Before: generation == a.Ruleset.Generation && !marker, After: generation == a.Ruleset.Generation+1 && marker}, nil
}
