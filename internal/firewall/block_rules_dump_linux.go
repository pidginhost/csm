//go:build linux

package firewall

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nltest"
	"golang.org/x/sys/unix"
)

func (e *Engine) blockRulesLocked() ([]*nftables.Rule, error) {
	if e.blockRuleDump != nil {
		return e.blockRuleDump()
	}
	if e.conn == nil {
		return nil, errors.New("firewall lifecycle transport unavailable")
	}
	var socket *netlink.Conn
	if e.conn.TestDial != nil {
		socket = nltest.Dial(e.conn.TestDial)
	} else {
		var err error
		socket, err = netlink.Dial(unix.NETLINK_NETFILTER, &netlink.Config{NetNS: e.conn.NetNS})
		if err != nil {
			return nil, err
		}
		if err = applyLifecycleSocketDeadline(socket); err != nil {
			return nil, err
		}
		_ = applyNFTSocketBuffer(socket)
	}
	defer func() { _ = socket.Close() }()
	table := e.setBlocked.Table
	attrs, err := netlink.MarshalAttributes([]netlink.Attribute{
		{Type: unix.NFTA_RULE_TABLE, Data: []byte(table.Name + "\x00")},
		{Type: unix.NFTA_RULE_CHAIN, Data: []byte("input\x00")},
	})
	if err != nil {
		return nil, err
	}
	messages, err := socket.Execute(netlink.Message{
		Header: netlink.Header{Type: unix.NFNL_SUBSYS_NFTABLES<<8 | unix.NFT_MSG_GETRULE, Flags: netlink.Request | netlink.Dump},
		Data:   append([]byte{byte(table.Family), 0, 0, 0}, attrs...),
	})
	if err != nil {
		return nil, err
	}
	rules := make([]*nftables.Rule, 0, len(messages))
	for _, message := range messages {
		rule, err := decodeBlockRule(message)
		if err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

// GetRules silently discards unknown expression types. Enforcement proof
// must count the raw expressions, including any predicates or register
// writes its decoder cannot represent. Other rules still supply handles.
func decodeBlockRule(message netlink.Message) (*nftables.Rule, error) {
	if message.Header.Type != unix.NFNL_SUBSYS_NFTABLES<<8|unix.NFT_MSG_NEWRULE || len(message.Data) < 4 {
		return nil, errors.New("invalid input rule message")
	}
	ad, err := netlink.NewAttributeDecoder(message.Data[4:])
	if err != nil {
		return nil, err
	}
	ad.ByteOrder = binary.BigEndian
	rule := new(nftables.Rule)
	for ad.Next() {
		switch ad.Type() {
		case unix.NFTA_RULE_HANDLE:
			rule.Handle = ad.Uint64()
		case unix.NFTA_RULE_EXPRESSIONS:
			rule.Exprs, err = decodeBlockExpressions(message.Data[0], ad.Bytes())
			if err != nil {
				return nil, err
			}
		}
	}
	if err := ad.Err(); err != nil {
		return nil, err
	}
	if rule.Handle == 0 {
		return nil, errors.New("input rule has no handle")
	}
	return rule, nil
}

func decodeBlockExpressions(family byte, data []byte) ([]expr.Any, error) {
	attrs, err := netlink.UnmarshalAttributes(data)
	if err != nil {
		return nil, err
	}
	names := []string{"meta", "cmp", "payload", "lookup", "immediate"}
	if len(attrs) != len(names) {
		return nil, nil
	}
	expressions := []expr.Any{&expr.Meta{}, &expr.Cmp{}, &expr.Payload{}, &expr.Lookup{}, &expr.Immediate{}}
	for i, attr := range attrs {
		ad, err := netlink.NewAttributeDecoder(attr.Data)
		if err != nil {
			return nil, err
		}
		var name string
		var body []byte
		for ad.Next() {
			switch ad.Type() {
			case unix.NFTA_EXPR_NAME:
				name = ad.String()
			case unix.NFTA_EXPR_DATA:
				body = ad.Bytes()
			}
		}
		if err := ad.Err(); err != nil {
			return nil, err
		}
		if name != names[i] || len(body) == 0 {
			return nil, nil
		}
		if err := expr.Unmarshal(family, body, expressions[i]); err != nil {
			return nil, fmt.Errorf("decoding block %s: %w", name, err)
		}
		if immediate, ok := expressions[i].(*expr.Immediate); ok && immediate.Register == unix.NFT_REG_VERDICT && len(immediate.Data) == 0 {
			verdict := new(expr.Verdict)
			if err := expr.Unmarshal(family, body, verdict); err != nil {
				return nil, err
			}
			expressions[i] = verdict
		}
	}
	return expressions, nil
}
