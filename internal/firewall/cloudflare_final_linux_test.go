//go:build linux

package firewall

import (
	"testing"
	"time"
)

// cloudflare.go is 0% covered. It requires real nftables, so we only
// test the paths that do NOT need a live conn.

// CloudflareIPs just delegates to LoadCFState(statePath) - we can exercise
// that without nftables.
func TestEngineCloudflareIPsEmptyStatePath(t *testing.T) {
	e := &Engine{statePath: t.TempDir()}
	v4, v6 := e.CloudflareIPs()
	if v4 != nil || v6 != nil {
		t.Errorf("fresh statePath should return nil, got v4=%v v6=%v", v4, v6)
	}
}

func TestEngineCloudflareIPsReadsSaved(t *testing.T) {
	dir := t.TempDir()
	ipv4 := []string{"173.245.48.0/20"}
	ipv6 := []string{"2400:cb00::/32"}
	SaveCFState(dir, ipv4, ipv6, time.Now())

	e := &Engine{statePath: dir}
	gv4, gv6 := e.CloudflareIPs()
	if len(gv4) != 1 || gv4[0] != ipv4[0] {
		t.Errorf("v4 = %v, want %v", gv4, ipv4)
	}
	if len(gv6) != 1 || gv6[0] != ipv6[0] {
		t.Errorf("v6 = %v, want %v", gv6, ipv6)
	}
}

// UpdateCloudflareSet requires a real nftables.Conn. With setCFWhitelist
// nil, the error branch fires immediately and returns cleanly.
func TestEngineUpdateCloudflareSetNilSetReturnsError(t *testing.T) {
	e := &Engine{statePath: t.TempDir()}
	// setCFWhitelist is nil
	err := e.UpdateCloudflareSet([]string{"1.2.3.0/24"}, nil)
	if err == nil {
		t.Error("expected error when setCFWhitelist is nil")
	}
}
