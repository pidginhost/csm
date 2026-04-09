//go:build !linux

package firewall

import (
	"fmt"
	"time"
)

// Engine stub for non-Linux platforms.
type Engine struct{}

type BlockedEntry struct {
	IP        string    `json:"ip"`
	Reason    string    `json:"reason"`
	Source    string    `json:"source,omitempty"`
	BlockedAt time.Time `json:"blocked_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

type AllowedEntry struct {
	IP        string    `json:"ip"`
	Reason    string    `json:"reason"`
	Source    string    `json:"source,omitempty"`
	Port      int       `json:"port,omitempty"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
}

type SubnetEntry struct {
	CIDR      string    `json:"cidr"`
	Reason    string    `json:"reason"`
	Source    string    `json:"source,omitempty"`
	BlockedAt time.Time `json:"blocked_at"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
}

type PortAllowEntry struct {
	IP     string `json:"ip"`
	Port   int    `json:"port"`
	Proto  string `json:"proto"`
	Reason string `json:"reason"`
	Source string `json:"source,omitempty"`
}

type FirewallState struct {
	Blocked     []BlockedEntry   `json:"blocked"`
	BlockedNet  []SubnetEntry    `json:"blocked_nets"`
	Allowed     []AllowedEntry   `json:"allowed"`
	PortAllowed []PortAllowEntry `json:"port_allowed"`
}

func NewEngine(_ *FirewallConfig, _ string) (*Engine, error) {
	return nil, fmt.Errorf("nftables firewall not available on this platform")
}

func ConnectExisting(_ *FirewallConfig, _ string) (*Engine, error) {
	return nil, fmt.Errorf("nftables firewall not available on this platform")
}

func (e *Engine) Apply() error                                          { return nil }
func (e *Engine) BlockIP(_ string, _ string, _ time.Duration) error     { return nil }
func (e *Engine) UnblockIP(_ string) error                              { return nil }
func (e *Engine) IsBlocked(_ string) bool                               { return false }
func (e *Engine) AllowIP(_ string, _ string) error                      { return nil }
func (e *Engine) RemoveAllowIP(_ string) error                          { return nil }
func (e *Engine) BlockSubnet(_ string, _ string, _ time.Duration) error { return nil }
func (e *Engine) UnblockSubnet(_ string) error                          { return nil }
func (e *Engine) TempAllowIP(_ string, _ string, _ time.Duration) error { return nil }
func (e *Engine) AllowIPPort(_ string, _ int, _ string, _ string) error { return nil }
func (e *Engine) RemoveAllowIPPort(_ string, _ int, _ string) error     { return nil }
func (e *Engine) CleanExpiredAllows() int                               { return 0 }
func (e *Engine) CleanExpiredSubnets() int                              { return 0 }
func (e *Engine) FlushBlocked() error                                   { return nil }
func (e *Engine) Status() map[string]interface{}                        { return nil }

func (e *Engine) UpdateCloudflareSet(_, _ []string) error { return nil }
func (e *Engine) CloudflareIPs() ([]string, []string)     { return nil, nil }
