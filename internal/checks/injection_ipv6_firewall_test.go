package checks

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// checkIPv6Firewall behaviour:
//   - /proc/net/if_inet6 missing → pass (no IPv6)
//   - file present, only loopback/link-local → pass (no IPv6)
//   - IPv6 active + nft policy drop on inet/ip6 input chain → pass
//   - IPv6 active + ip6tables INPUT policy DROP → pass
//   - IPv6 active + neither → fail

func TestCheckIPv6FirewallNoProcFileReturnsPass(t *testing.T) {
	withMockOS(t, &mockOS{
		readFile: func(string) ([]byte, error) { return nil, errors.New("no /proc on this host") },
	})
	got := checkIPv6Firewall()
	if len(got) != 1 || got[0].Status != "pass" {
		t.Fatalf("expected single pass result, got %+v", got)
	}
	if !strings.Contains(got[0].Message, "IPv6 not active") {
		t.Errorf("message should explain inactivity: %s", got[0].Message)
	}
}

func TestCheckIPv6FirewallOnlyLoopbackReturnsPass(t *testing.T) {
	// /proc/net/if_inet6 columns: address ifindex prefix scope flags ifname.
	// Loopback should be ignored entirely.
	content := "00000000000000000000000000000001 01 80 10 80 lo\n"
	withMockOS(t, &mockOS{
		readFile: func(string) ([]byte, error) { return []byte(content), nil },
	})
	got := checkIPv6Firewall()
	if len(got) != 1 || got[0].Status != "pass" {
		t.Fatalf("expected pass for loopback-only, got %+v", got)
	}
	if !strings.Contains(got[0].Message, "No non-link-local IPv6") {
		t.Errorf("unexpected message: %s", got[0].Message)
	}
}

func TestCheckIPv6FirewallOnlyLinkLocalReturnsPass(t *testing.T) {
	content := "fe80000000000000000000000000abcd 02 40 20 80 eth0\n"
	withMockOS(t, &mockOS{
		readFile: func(string) ([]byte, error) { return []byte(content), nil },
	})
	got := checkIPv6Firewall()
	if got[0].Status != "pass" {
		t.Errorf("link-local should be treated as no IPv6, got %+v", got)
	}
}

func TestCheckIPv6FirewallActiveNftDropReturnsPass(t *testing.T) {
	content := "20010db8000000000000000000000001 02 40 00 80 eth0\n"
	withMockOS(t, &mockOS{
		readFile: func(string) ([]byte, error) { return []byte(content), nil },
	})
	withMockCmd(t, &mockCmd{
		runContext: func(_ context.Context, name string, args ...string) ([]byte, error) {
			if name == "nft" {
				return []byte(strings.Join([]string{
					"table inet filter {",
					"  chain input {",
					"    type filter hook input priority filter; policy drop;",
					"  }",
					"}",
				}, "\n")), nil
			}
			return nil, errors.New("unexpected: " + name)
		},
	})
	got := checkIPv6Firewall()
	if got[0].Status != "pass" {
		t.Fatalf("expected pass with nft default-drop, got %+v", got)
	}
	if !strings.Contains(got[0].Message, "default-deny") {
		t.Errorf("message should mention default-deny: %s", got[0].Message)
	}
}

func TestCheckIPv6FirewallActiveIp6tablesDropReturnsPass(t *testing.T) {
	content := "20010db8000000000000000000000001 02 40 00 80 eth0\n"
	withMockOS(t, &mockOS{
		readFile: func(string) ([]byte, error) { return []byte(content), nil },
	})
	withMockCmd(t, &mockCmd{
		runContext: func(_ context.Context, name string, args ...string) ([]byte, error) {
			switch name {
			case "nft":
				return nil, errors.New("nft not installed")
			case "ip6tables":
				return []byte("Chain INPUT (policy DROP)\n"), nil
			}
			return nil, errors.New("unexpected")
		},
	})
	got := checkIPv6Firewall()
	if got[0].Status != "pass" {
		t.Fatalf("expected pass with ip6tables DROP policy, got %+v", got)
	}
	if !strings.Contains(got[0].Message, "ip6tables") {
		t.Errorf("message should mention ip6tables: %s", got[0].Message)
	}
}

func TestCheckIPv6FirewallActiveNoPolicyReturnsFail(t *testing.T) {
	content := "20010db8000000000000000000000001 02 40 00 80 eth0\n"
	withMockOS(t, &mockOS{
		readFile: func(string) ([]byte, error) { return []byte(content), nil },
	})
	withMockCmd(t, &mockCmd{
		runContext: func(_ context.Context, name string, args ...string) ([]byte, error) {
			switch name {
			case "nft":
				return []byte("table ip filter {\n}\n"), nil
			case "ip6tables":
				return []byte("Chain INPUT (policy ACCEPT)\n"), nil
			}
			return nil, errors.New("unexpected")
		},
	})
	got := checkIPv6Firewall()
	if got[0].Status != "fail" {
		t.Fatalf("expected fail with no default-deny anywhere, got %+v", got)
	}
	if !strings.Contains(got[0].Fix, "DROP") {
		t.Errorf("fix should mention DROP: %s", got[0].Fix)
	}
}
