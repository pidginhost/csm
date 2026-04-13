package checks

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// =========================================================================
// Helper — build /proc/net/tcp lines
// =========================================================================

// procTCPHeader is the header line from /proc/net/tcp.
const procTCPHeader = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"

// tcpLine builds a /proc/net/tcp entry.  localHex and remoteHex are
// "IIIIIIII:PPPP" hex strings, state is the 2-digit hex state.
func tcpLine(sl, localHex, remoteHex, state string) string {
	return "   " + sl + ": " + localHex + " " + remoteHex + " " + state + " 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0\n"
}

// ipToHex converts a dotted-decimal IP to /proc/net/tcp little-endian hex.
func ipToHex(a, b, c, d byte) string {
	// /proc/net/tcp stores IP as a single 32-bit LE hex value
	return strings.ToUpper(
		hexByte(d) + hexByte(c) + hexByte(b) + hexByte(a),
	)
}

func hexByte(v byte) string {
	const digits = "0123456789ABCDEF"
	return string([]byte{digits[v>>4], digits[v&0x0f]})
}

func portToHex(p int) string {
	const digits = "0123456789ABCDEF"
	return string([]byte{
		digits[(p>>12)&0xf],
		digits[(p>>8)&0xf],
		digits[(p>>4)&0xf],
		digits[p&0xf],
	})
}

func hexAddr(a, b, c, d byte, port int) string {
	return ipToHex(a, b, c, d) + ":" + portToHex(port)
}

// =========================================================================
// Tests
// =========================================================================

func TestCheckOutboundConnectionsNoProcNet(t *testing.T) {
	withMockOS(t, &mockOS{})
	findings := CheckOutboundConnections(context.Background(), &config.Config{}, nil)
	if len(findings) != 0 {
		t.Errorf("no /proc/net/tcp should produce 0 findings, got %d", len(findings))
	}
}

func TestCheckOutboundConnectionsReadError(t *testing.T) {
	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			return nil, os.ErrPermission
		},
	})
	findings := CheckOutboundConnections(context.Background(), &config.Config{}, nil)
	if len(findings) != 0 {
		t.Errorf("read error should produce 0 findings, got %d", len(findings))
	}
}

func TestCheckOutboundConnectionsEmptyFile(t *testing.T) {
	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			return []byte(procTCPHeader), nil
		},
	})
	findings := CheckOutboundConnections(context.Background(), &config.Config{}, nil)
	if len(findings) != 0 {
		t.Errorf("header-only should produce 0 findings, got %d", len(findings))
	}
}

func TestCheckOutboundConnectionsNoEstablished(t *testing.T) {
	// State 0A = LISTEN, not ESTABLISHED
	data := procTCPHeader +
		tcpLine("0", hexAddr(0, 0, 0, 0, 80), hexAddr(10, 20, 30, 40, 54321), "0A")
	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			return []byte(data), nil
		},
	})
	findings := CheckOutboundConnections(context.Background(), &config.Config{}, nil)
	if len(findings) != 0 {
		t.Errorf("LISTEN state should produce 0 findings, got %d", len(findings))
	}
}

func TestCheckOutboundConnectionsLocalhostSkipped(t *testing.T) {
	// ESTABLISHED connection to 127.0.0.1 -- should be skipped
	data := procTCPHeader +
		tcpLine("0", hexAddr(127, 0, 0, 1, 3306), hexAddr(127, 0, 0, 1, 54321), "01")
	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			return []byte(data), nil
		},
	})
	cfg := &config.Config{
		C2Blocklist:   []string{"127.0.0.1"},
		BackdoorPorts: []int{3306},
	}
	findings := CheckOutboundConnections(context.Background(), cfg, nil)
	if len(findings) != 0 {
		t.Errorf("localhost should be skipped, got %d findings", len(findings))
	}
}

func TestCheckOutboundConnectionsC2Detection(t *testing.T) {
	// ESTABLISHED connection to C2 IP 10.20.30.40 on port 443
	c2IP := "10.20.30.40"
	data := procTCPHeader +
		tcpLine("0",
			hexAddr(192, 168, 1, 100, 54321), // local: ephemeral port
			hexAddr(10, 20, 30, 40, 443),     // remote: C2 IP on 443
			"01")

	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			return []byte(data), nil
		},
	})
	cfg := &config.Config{
		C2Blocklist:   []string{c2IP},
		BackdoorPorts: []int{},
	}
	findings := CheckOutboundConnections(context.Background(), cfg, nil)

	found := false
	for _, f := range findings {
		if f.Check == "c2_connection" {
			found = true
			if f.Severity != alert.Critical {
				t.Errorf("C2 severity = %v, want Critical", f.Severity)
			}
			if !strings.Contains(f.Message, c2IP) {
				t.Errorf("C2 message should contain IP, got %q", f.Message)
			}
		}
	}
	if !found {
		t.Errorf("expected c2_connection finding, got %v", findings)
	}
}

func TestCheckOutboundConnectionsBackdoorLocalPort(t *testing.T) {
	// We are LISTENING on backdoor port 31337, remote connects to us
	data := procTCPHeader +
		tcpLine("0",
			hexAddr(192, 168, 1, 100, 31337), // local: backdoor port
			hexAddr(203, 0, 113, 5, 54321),   // remote: attacker
			"01")

	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			return []byte(data), nil
		},
	})
	cfg := &config.Config{
		BackdoorPorts: []int{31337},
	}
	findings := CheckOutboundConnections(context.Background(), cfg, nil)

	found := false
	for _, f := range findings {
		if f.Check == "backdoor_port" {
			found = true
			if f.Severity != alert.Critical {
				t.Errorf("backdoor severity = %v, want Critical", f.Severity)
			}
			if !strings.Contains(f.Message, "31337") {
				t.Errorf("message should contain port 31337, got %q", f.Message)
			}
		}
	}
	if !found {
		t.Errorf("expected backdoor_port finding, got %v", findings)
	}
}

func TestCheckOutboundConnectionsBackdoorOutbound(t *testing.T) {
	// Reverse shell: we connect OUT to remote backdoor port 4444
	// Our local port is ephemeral (not a known service)
	data := procTCPHeader +
		tcpLine("0",
			hexAddr(192, 168, 1, 100, 49152), // local: ephemeral
			hexAddr(203, 0, 113, 5, 4444),    // remote: backdoor port
			"01")

	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			return []byte(data), nil
		},
	})
	cfg := &config.Config{
		BackdoorPorts: []int{4444},
	}
	findings := CheckOutboundConnections(context.Background(), cfg, nil)

	found := false
	for _, f := range findings {
		if f.Check == "backdoor_port_outbound" {
			found = true
			if f.Severity != alert.High {
				t.Errorf("outbound backdoor severity = %v, want High", f.Severity)
			}
			if !strings.Contains(f.Message, "4444") {
				t.Errorf("message should contain port 4444, got %q", f.Message)
			}
		}
	}
	if !found {
		t.Errorf("expected backdoor_port_outbound finding, got %v", findings)
	}
}

func TestCheckOutboundConnectionsBackdoorOutboundSkippedForKnownService(t *testing.T) {
	// Local port is known service (80) -- outbound backdoor check is skipped
	data := procTCPHeader +
		tcpLine("0",
			hexAddr(192, 168, 1, 100, 80), // local: HTTP (known service)
			hexAddr(203, 0, 113, 5, 4444), // remote: backdoor port
			"01")

	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			return []byte(data), nil
		},
	})
	cfg := &config.Config{
		BackdoorPorts: []int{4444},
	}
	findings := CheckOutboundConnections(context.Background(), cfg, nil)

	for _, f := range findings {
		if f.Check == "backdoor_port_outbound" {
			t.Errorf("known service local port should skip outbound check, got finding: %v", f)
		}
	}
}

func TestCheckOutboundConnectionsBackdoorOutboundSkippedForInfraIP(t *testing.T) {
	// Remote is an infrastructure IP -- outbound backdoor should be skipped
	data := procTCPHeader +
		tcpLine("0",
			hexAddr(192, 168, 1, 100, 49152), // local: ephemeral
			hexAddr(10, 0, 0, 5, 4444),       // remote: infra IP on backdoor port
			"01")

	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			return []byte(data), nil
		},
	})
	cfg := &config.Config{
		BackdoorPorts: []int{4444},
		InfraIPs:      []string{"10.0.0.0/8"},
	}
	findings := CheckOutboundConnections(context.Background(), cfg, nil)

	for _, f := range findings {
		if f.Check == "backdoor_port_outbound" {
			t.Errorf("infra IP should skip outbound backdoor check, got finding: %v", f)
		}
	}
}

func TestCheckOutboundConnectionsBackdoorOutboundSkippedForExactInfraIP(t *testing.T) {
	// InfraIPs as exact IP match (not CIDR)
	data := procTCPHeader +
		tcpLine("0",
			hexAddr(192, 168, 1, 100, 49152),
			hexAddr(203, 0, 113, 5, 4444),
			"01")

	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			return []byte(data), nil
		},
	})
	cfg := &config.Config{
		BackdoorPorts: []int{4444},
		InfraIPs:      []string{"203.0.113.5"},
	}
	findings := CheckOutboundConnections(context.Background(), cfg, nil)

	for _, f := range findings {
		if f.Check == "backdoor_port_outbound" {
			t.Errorf("exact infra IP should skip outbound backdoor check, got finding: %v", f)
		}
	}
}

func TestCheckOutboundConnectionsMultipleFindings(t *testing.T) {
	// One C2 connection + one backdoor listener + one outbound backdoor
	data := procTCPHeader +
		// C2 connection: from known service port so outbound check is skipped
		tcpLine("0",
			hexAddr(192, 168, 1, 100, 443),
			hexAddr(10, 66, 77, 88, 8080),
			"01") +
		// Backdoor listener on port 31337
		tcpLine("1",
			hexAddr(192, 168, 1, 100, 31337),
			hexAddr(203, 0, 113, 10, 54321),
			"01") +
		// Outbound to backdoor port 4444
		tcpLine("2",
			hexAddr(192, 168, 1, 100, 49200),
			hexAddr(198, 51, 100, 20, 4444),
			"01")

	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			return []byte(data), nil
		},
	})
	cfg := &config.Config{
		C2Blocklist:   []string{"10.66.77.88"},
		BackdoorPorts: []int{31337, 4444},
	}
	findings := CheckOutboundConnections(context.Background(), cfg, nil)

	checks := map[string]bool{}
	for _, f := range findings {
		checks[f.Check] = true
	}
	if !checks["c2_connection"] {
		t.Error("expected c2_connection finding")
	}
	if !checks["backdoor_port"] {
		t.Error("expected backdoor_port finding")
	}
	if !checks["backdoor_port_outbound"] {
		t.Error("expected backdoor_port_outbound finding")
	}
}

func TestCheckOutboundConnectionsSafeTraffic(t *testing.T) {
	// Normal web traffic: local ephemeral -> remote 443 (no blocklist/backdoor match)
	data := procTCPHeader +
		tcpLine("0",
			hexAddr(192, 168, 1, 100, 49000),
			hexAddr(93, 184, 216, 34, 443),
			"01")

	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			return []byte(data), nil
		},
	})
	cfg := &config.Config{
		C2Blocklist:   []string{"10.20.30.40"},
		BackdoorPorts: []int{4444, 31337},
	}
	findings := CheckOutboundConnections(context.Background(), cfg, nil)
	if len(findings) != 0 {
		t.Errorf("safe traffic should produce 0 findings, got %d", len(findings))
	}
}

func TestCheckOutboundConnectionsSkipsZeroRemoteIP(t *testing.T) {
	// Remote 0.0.0.0 should be skipped
	data := procTCPHeader +
		tcpLine("0",
			hexAddr(192, 168, 1, 100, 80),
			hexAddr(0, 0, 0, 0, 0),
			"01")

	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			return []byte(data), nil
		},
	})
	cfg := &config.Config{
		C2Blocklist:   []string{"0.0.0.0"},
		BackdoorPorts: []int{80},
	}
	findings := CheckOutboundConnections(context.Background(), cfg, nil)
	if len(findings) != 0 {
		t.Errorf("0.0.0.0 remote should be skipped, got %d findings", len(findings))
	}
}

func TestCheckOutboundConnectionsMalformedLines(t *testing.T) {
	// Short lines or malformed data should not crash
	data := procTCPHeader +
		"short line\n" +
		"   0: BADDATA\n" +
		"   1: AA BB\n"

	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			return []byte(data), nil
		},
	})
	cfg := &config.Config{
		C2Blocklist:   []string{"10.20.30.40"},
		BackdoorPorts: []int{4444},
	}
	findings := CheckOutboundConnections(context.Background(), cfg, nil)
	if len(findings) != 0 {
		t.Errorf("malformed lines should produce 0 findings, got %d", len(findings))
	}
}

// =========================================================================
// parseHexAddr unit tests
// =========================================================================

func TestParseHexAddr(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantIP   string
		wantPort int
	}{
		{
			name:     "localhost port 80",
			input:    "0100007F:0050",
			wantIP:   "127.0.0.1",
			wantPort: 80,
		},
		{
			name:     "192.168.1.1 port 443",
			input:    "0101A8C0:01BB",
			wantIP:   "192.168.1.1",
			wantPort: 443,
		},
		{
			name:     "10.20.30.40 port 4444",
			input:    "281E140A:115C",
			wantIP:   "10.20.30.40",
			wantPort: 4444,
		},
		{
			name:     "0.0.0.0 port 0",
			input:    "00000000:0000",
			wantIP:   "0.0.0.0",
			wantPort: 0,
		},
		{
			name:     "missing colon",
			input:    "0100007F0050",
			wantIP:   "",
			wantPort: 0,
		},
		{
			name:     "short hex IP",
			input:    "01:0050",
			wantIP:   "",
			wantPort: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotIP, gotPort := parseHexAddr(tt.input)
			if gotIP != tt.wantIP {
				t.Errorf("parseHexAddr(%q) IP = %q, want %q", tt.input, gotIP, tt.wantIP)
			}
			if gotPort != tt.wantPort {
				t.Errorf("parseHexAddr(%q) port = %d, want %d", tt.input, gotPort, tt.wantPort)
			}
		})
	}
}

// =========================================================================
// isInfraIP unit tests
// =========================================================================

func TestIsInfraIP(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		infraIPs []string
		want     bool
	}{
		{
			name:     "CIDR match",
			ip:       "10.0.0.5",
			infraIPs: []string{"10.0.0.0/8"},
			want:     true,
		},
		{
			name:     "CIDR no match",
			ip:       "192.168.1.1",
			infraIPs: []string{"10.0.0.0/8"},
			want:     false,
		},
		{
			name:     "exact IP match",
			ip:       "1.2.3.4",
			infraIPs: []string{"1.2.3.4"},
			want:     true,
		},
		{
			name:     "exact IP no match",
			ip:       "1.2.3.5",
			infraIPs: []string{"1.2.3.4"},
			want:     false,
		},
		{
			name:     "empty list",
			ip:       "10.0.0.1",
			infraIPs: nil,
			want:     false,
		},
		{
			name:     "invalid IP returns false",
			ip:       "not-an-ip",
			infraIPs: []string{"10.0.0.0/8"},
			want:     false,
		},
	}

	// Clear any Cloudflare nets to isolate this test
	SetCloudflareNets(nil)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isInfraIP(tt.ip, tt.infraIPs)
			if got != tt.want {
				t.Errorf("isInfraIP(%q, %v) = %v, want %v", tt.ip, tt.infraIPs, got, tt.want)
			}
		})
	}
}

func TestIsInfraIPCloudflare(t *testing.T) {
	SetCloudflareNets([]string{"173.245.48.0/20", "103.21.244.0/22"})
	t.Cleanup(func() { SetCloudflareNets(nil) })

	if !isInfraIP("173.245.48.1", nil) {
		t.Error("Cloudflare IP 173.245.48.1 should be infra")
	}
	if isInfraIP("8.8.8.8", nil) {
		t.Error("8.8.8.8 should not be infra")
	}
}
