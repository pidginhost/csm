package firewall

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseCloudflareResponse(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid CIDRs",
			input: "173.245.48.0/20\n103.21.244.0/22\n103.22.200.0/22\n",
			want:  []string{"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22"},
		},
		{
			name:  "with blank lines and comments",
			input: "# Cloudflare IPs\n\n173.245.48.0/20\n\n# more\n103.21.244.0/22\n",
			want:  []string{"173.245.48.0/20", "103.21.244.0/22"},
		},
		{
			name:  "with invalid entries",
			input: "173.245.48.0/20\nnot-a-cidr\n103.21.244.0/22\n999.999.999.999/32\n",
			want:  []string{"173.245.48.0/20", "103.21.244.0/22"},
		},
		{
			name:  "ipv6 CIDRs",
			input: "2400:cb00::/32\n2606:4700::/32\n2803:f800::/32\n",
			want:  []string{"2400:cb00::/32", "2606:4700::/32", "2803:f800::/32"},
		},
		{
			name:  "whitespace trimming",
			input: "  173.245.48.0/20  \n\t103.21.244.0/22\t\n",
			want:  []string{"173.245.48.0/20", "103.21.244.0/22"},
		},
		{
			name:  "empty input",
			input: "",
			want:  nil,
		},
		{
			name:  "only comments and blanks",
			input: "# comment\n\n# another comment\n",
			want:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanner := bufio.NewScanner(strings.NewReader(tt.input))
			got := parseCloudflareResponse(scanner)

			if len(got) != len(tt.want) {
				t.Fatalf("got %d CIDRs, want %d: %v", len(got), len(tt.want), got)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("index %d: got %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestSaveLoadCFState(t *testing.T) {
	dir := t.TempDir()

	ipv4 := []string{"173.245.48.0/20", "103.21.244.0/22"}
	ipv6 := []string{"2400:cb00::/32", "2606:4700::/32"}
	now := time.Now().Truncate(time.Second)

	SaveCFState(dir, ipv4, ipv6, now)

	// Verify file was created
	stateFile := filepath.Join(dir, "firewall", "cf_whitelist.txt")
	if _, err := os.Stat(stateFile); os.IsNotExist(err) {
		t.Fatalf("state file not created at %s", stateFile)
	}

	// Load back
	gotIPv4, gotIPv6 := LoadCFState(dir)

	if len(gotIPv4) != len(ipv4) {
		t.Fatalf("IPv4: got %d CIDRs, want %d", len(gotIPv4), len(ipv4))
	}
	for i := range gotIPv4 {
		if gotIPv4[i] != ipv4[i] {
			t.Errorf("IPv4 index %d: got %q, want %q", i, gotIPv4[i], ipv4[i])
		}
	}

	if len(gotIPv6) != len(ipv6) {
		t.Fatalf("IPv6: got %d CIDRs, want %d", len(gotIPv6), len(ipv6))
	}
	for i := range gotIPv6 {
		if gotIPv6[i] != ipv6[i] {
			t.Errorf("IPv6 index %d: got %q, want %q", i, gotIPv6[i], ipv6[i])
		}
	}

	// Verify refresh time
	gotTime := LoadCFRefreshTime(dir)
	if !gotTime.Equal(now) {
		t.Errorf("refresh time: got %v, want %v", gotTime, now)
	}
}

func TestLoadCFStateNotFound(t *testing.T) {
	dir := t.TempDir()

	ipv4, ipv6 := LoadCFState(dir)
	if ipv4 != nil || ipv6 != nil {
		t.Errorf("expected nil for non-existent state, got %v, %v", ipv4, ipv6)
	}

	refreshed := LoadCFRefreshTime(dir)
	if !refreshed.IsZero() {
		t.Errorf("expected zero time for non-existent state, got %v", refreshed)
	}
}
