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
	BlockedAt time.Time `json:"blocked_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

type AllowedEntry struct {
	IP     string `json:"ip"`
	Reason string `json:"reason"`
	Port   int    `json:"port,omitempty"`
}

type FirewallState struct {
	Blocked []BlockedEntry `json:"blocked"`
	Allowed []AllowedEntry `json:"allowed"`
}

func NewEngine(_ *FirewallConfig, _ string) (*Engine, error) {
	return nil, fmt.Errorf("nftables firewall not available on this platform")
}

func (e *Engine) Apply() error                                       { return nil }
func (e *Engine) BlockIP(_ string, _ string, _ time.Duration) error  { return nil }
func (e *Engine) UnblockIP(_ string) error                           { return nil }
func (e *Engine) AllowIP(_ string, _ string) error                   { return nil }
func (e *Engine) Status() map[string]interface{}                     { return nil }
