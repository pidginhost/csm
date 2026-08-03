//go:build linux

package firewall

import (
	"testing"
	"time"

	"github.com/google/nftables"
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
	if err := SaveCFState(dir, ipv4, ipv6, time.Now()); err != nil {
		t.Fatalf("SaveCFState: %v", err)
	}

	e := &Engine{statePath: dir}
	gv4, gv6 := e.CloudflareIPs()
	if len(gv4) != 1 || gv4[0] != ipv4[0] {
		t.Errorf("v4 = %v, want %v", gv4, ipv4)
	}
	if len(gv6) != 1 || gv6[0] != ipv6[0] {
		t.Errorf("v6 = %v, want %v", gv6, ipv6)
	}
}

func TestEngineCloudflareCoversReadsSavedRanges(t *testing.T) {
	dir := t.TempDir()
	if err := SaveCFState(dir, []string{"198.51.100.0/24"}, []string{"2001:db8:100::/48"}, time.Now()); err != nil {
		t.Fatalf("SaveCFState: %v", err)
	}
	e := &Engine{statePath: dir}
	if !e.CloudflareCovers("198.51.100.7") {
		t.Error("CloudflareCovers returned false for saved IPv4 range")
	}
	if !e.CloudflareCovers("2001:db8:100::7") {
		t.Error("CloudflareCovers returned false for saved IPv6 range")
	}
	if e.CloudflareCovers("203.0.113.7") {
		t.Error("CloudflareCovers returned true outside saved ranges")
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

// Regression: ConnectExisting loads each CF set independently, so the v4 set
// can be present while the v6 set is nil. The old code only nil-checked v4
// and then called FlushSet(setCFWhitelist6)/SetAddElements on the nil v6 set,
// which panics. The guard must require both sets and return an error.
func TestEngineUpdateCloudflareSetNilV6SetReturnsError(t *testing.T) {
	e := &Engine{statePath: t.TempDir(), setCFWhitelist: &nftables.Set{}}
	// setCFWhitelist6 is nil
	err := e.UpdateCloudflareSet([]string{"1.2.3.0/24"}, []string{"2400:cb00::/32"})
	if err == nil {
		t.Error("expected error when setCFWhitelist6 is nil (would otherwise panic)")
	}
}
