package checks

import (
	"testing"

	"github.com/pidginhost/csm/internal/alert"
)

// Detectors run inside an account scope but often emit findings with
// empty TenantID. The correlator then keys them by weaker identities,
// fragmenting one account's compromise across multiple incidents.
// stampTenantIDIfEmpty must fill in the gap from the known scope while
// leaving detector-attributed findings alone.
func TestStampTenantIDIfEmpty_FillsEmpty(t *testing.T) {
	in := []alert.Finding{
		{Check: "webshell"},
		{Check: "php_content", FilePath: "/home/alice/public_html/x.php"},
		{Check: "audit", TenantID: "preset-by-detector"},
	}

	out := stampTenantIDIfEmpty(in, "alice")

	if out[0].TenantID != "alice" {
		t.Errorf("findings[0].TenantID = %q, want alice", out[0].TenantID)
	}
	if out[1].TenantID != "alice" {
		t.Errorf("findings[1].TenantID = %q, want alice", out[1].TenantID)
	}
	if out[2].TenantID != "preset-by-detector" {
		t.Errorf("findings[2] overwrite: TenantID = %q, want preset-by-detector", out[2].TenantID)
	}
}

func TestStampTenantIDIfEmpty_EmptyAccountIsNoop(t *testing.T) {
	in := []alert.Finding{{Check: "a"}, {Check: "b", TenantID: "manual"}}
	out := stampTenantIDIfEmpty(in, "")
	if out[0].TenantID != "" {
		t.Errorf("empty-account stamp leaked: TenantID = %q", out[0].TenantID)
	}
	if out[1].TenantID != "manual" {
		t.Errorf("explicit TenantID dropped: %q", out[1].TenantID)
	}
}

func TestAccountScanFindingInScopeUsesStructuredFilePath(t *testing.T) {
	tests := []struct {
		name string
		in   alert.Finding
		want bool
	}{
		{
			name: "target account file path",
			in:   alert.Finding{Check: "webshell", FilePath: "/home/alice/public_html/shell.php", Message: "Webshell detected"},
			want: true,
		},
		{
			name: "other account file path",
			in:   alert.Finding{Check: "webshell", FilePath: "/home/bob/public_html/shell.php", Message: "Webshell detected"},
			want: false,
		},
		{
			name: "structured other account overrides target message",
			in: alert.Finding{
				Check:    "webshell",
				FilePath: "/home/bob/public_html/shell.php",
				Message:  "Linked from /home/alice/public_html/index.php",
			},
			want: false,
		},
		{
			name: "target account on numbered home root",
			in:   alert.Finding{Check: "webshell", FilePath: "/home2/alice/public_html/shell.php"},
			want: true,
		},
		{
			name: "other account on numbered home root",
			in:   alert.Finding{Check: "webshell", FilePath: "/home2/bob/public_html/shell.php"},
			want: false,
		},
		{
			name: "other account in message",
			in:   alert.Finding{Check: "webshell", Message: "Webshell detected in /home/bob/public_html/shell.php"},
			want: false,
		},
		{
			name: "target account in numbered home message",
			in:   alert.Finding{Check: "webshell", Message: "Webshell detected in /home2/alice/public_html/shell.php"},
			want: true,
		},
		{
			name: "other account in numbered home details",
			in:   alert.Finding{Check: "webshell", Details: "File: /home2/bob/public_html/shell.php"},
			want: false,
		},
		{
			name: "no home path",
			in:   alert.Finding{Check: "check_timeout", Message: "Account scan check timed out"},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := accountScanFindingInScope(tt.in, "alice"); got != tt.want {
				t.Fatalf("accountScanFindingInScope() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAccountFromHomePathSupportsNumberedHomeRoots(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{path: "/home/alice/public_html/index.php", want: "alice"},
		{path: "/home2/bob/public_html/index.php", want: "bob"},
		{path: "/home22/carol", want: "carol"},
		{path: "/homeold/dave/public_html/index.php", want: ""},
		{path: "/var/www/example/index.php", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if got := accountFromHomePath(tt.path); got != tt.want {
				t.Fatalf("accountFromHomePath() = %q, want %q", got, tt.want)
			}
		})
	}
}
