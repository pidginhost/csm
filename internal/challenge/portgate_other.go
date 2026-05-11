//go:build !linux

package challenge

// newPortGate is the non-Linux stub. CSM only supports the port-gate on
// Linux because the implementation drives nftables via netlink; on
// other platforms the gate is silently absent (returning nil + nil so
// IPList add/remove no-ops via the nil PortGate path).
func newPortGate(_ PortGateConfig) (PortGate, error) {
	return nil, nil
}
