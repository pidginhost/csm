package checks

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/state"
)

// Tests for source paths newly reachable after switching exec.Command
// calls to cmdExec (firewall.go, emailpasswd.go, plugincheck.go).

// --- CheckFirewall: full structural validation success path -------------

func TestCheckFirewallAllComponentsPresentNoStructuralFinding(t *testing.T) {
	// nft output containing every required component in the structural
	// check list. Function should report no firewall findings.
	nftOut := `table inet csm {
	chain input { }
	chain output { }
	set blocked_ips { type ipv4_addr; }
	set allowed_ips { type ipv4_addr; }
	set infra_ips { type ipv4_addr; }
}`
	withMockCmd(t, &mockCmd{
		runAllowNonZero: func(name string, args ...string) ([]byte, error) {
			if name == "nft" {
				return []byte(nftOut), nil
			}
			return nil, nil
		},
	})

	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()

	cfg := &config.Config{}
	cfg.Firewall = &firewall.FirewallConfig{Enabled: true, TCPIn: []int{22, 80}}
	findings := CheckFirewall(context.Background(), cfg, st)

	for _, f := range findings {
		if f.Check == "firewall" {
			t.Errorf("unexpected firewall finding when all components present: %+v", f)
		}
	}
}

// --- CheckFirewall: detects missing component --------------------------

func TestCheckFirewallMissingComponentEmitsFinding(t *testing.T) {
	// nft output missing "set infra_ips" — function should flag it.
	nftOut := `table inet csm {
	chain input { }
	chain output { }
	set blocked_ips { type ipv4_addr; }
	set allowed_ips { type ipv4_addr; }
}`
	withMockCmd(t, &mockCmd{
		runAllowNonZero: func(name string, args ...string) ([]byte, error) {
			return []byte(nftOut), nil
		},
	})

	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()

	cfg := &config.Config{}
	cfg.Firewall = &firewall.FirewallConfig{Enabled: true}
	findings := CheckFirewall(context.Background(), cfg, st)

	found := false
	for _, f := range findings {
		if f.Check == "firewall" && strings.Contains(f.Message, "infra_ips") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected finding mentioning missing 'infra_ips', got: %+v", findings)
	}
}

// --- CheckFirewall: detects nftables ruleset modification --------------

func TestCheckFirewallDetectsRuleHashChange(t *testing.T) {
	withMockCmd(t, &mockCmd{
		runAllowNonZero: func(name string, args ...string) ([]byte, error) {
			return []byte("table inet csm {\n  chain input { }\n  chain output { }\n  set blocked_ips { }\n  set allowed_ips { }\n  set infra_ips { }\n}"), nil
		},
	})

	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()

	cfg := &config.Config{}
	cfg.Firewall = &firewall.FirewallConfig{Enabled: true}

	// First run establishes baseline hash.
	_ = CheckFirewall(context.Background(), cfg, st)

	// Second run with DIFFERENT nft output (simulating manual modification).
	withMockCmd(t, &mockCmd{
		runAllowNonZero: func(name string, args ...string) ([]byte, error) {
			return []byte("table inet csm {\n  chain input { }\n  chain output { }\n  chain forward { }\n  set blocked_ips { }\n  set allowed_ips { }\n  set infra_ips { }\n}"), nil
		},
	})
	findings := CheckFirewall(context.Background(), cfg, st)

	found := false
	for _, f := range findings {
		if strings.Contains(f.Message, "modified outside of CSM") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected 'ruleset modified' finding when nft output changes between runs")
	}
}

// --- verifyDoveadm: success and failure paths --------------------------

func TestVerifyDoveadmSuccess(t *testing.T) {
	withMockCmd(t, &mockCmd{
		run: func(name string, args ...string) ([]byte, error) {
			if name == "doveadm" {
				return nil, nil // exit 0 = match
			}
			return nil, errors.New("unexpected cmd")
		},
	})
	if !verifyDoveadm("{CRYPT}$6$salt$hashedwordhere", "secret123") {
		t.Error("expected verifyDoveadm to return true when doveadm succeeds")
	}
}

func TestVerifyDoveadmFailure(t *testing.T) {
	withMockCmd(t, &mockCmd{
		run: func(name string, args ...string) ([]byte, error) {
			return nil, errors.New("doveadm: password mismatch")
		},
	})
	if verifyDoveadm("{CRYPT}$6$salt$hash", "wrongpass") {
		t.Error("expected verifyDoveadm to return false when doveadm errors")
	}
}

// --- extractWPDomain: wp-cli success and fallback paths ----------------

func TestExtractWPDomainWPCLISuccessReturnsURL(t *testing.T) {
	withMockCmd(t, &mockCmd{
		runContext: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			return []byte("https://example.com/blog\n"), nil
		},
	})
	got := extractWPDomain(context.Background(), "/home/alice/public_html/blog", "alice")
	if got != "example.com/blog" {
		t.Errorf("got %q, want example.com/blog", got)
	}
}

func TestExtractWPDomainWPCLIFailsFallsBackToDirName(t *testing.T) {
	withMockCmd(t, &mockCmd{
		runContext: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			return nil, errors.New("wp-cli: command not found")
		},
	})
	// wpPath ends in /public_html/blog → fallback should pick "blog".
	got := extractWPDomain(context.Background(), "/home/alice/public_html/blog", "alice")
	if got != "blog" {
		t.Errorf("got %q, want blog", got)
	}
}

func TestExtractWPDomainStripsHTTPPrefix(t *testing.T) {
	withMockCmd(t, &mockCmd{
		runContext: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			return []byte("http://plain.example.org\n"), nil
		},
	})
	got := extractWPDomain(context.Background(), "/home/bob/public_html", "bob")
	if got != "plain.example.org" {
		t.Errorf("got %q, want plain.example.org", got)
	}
}
