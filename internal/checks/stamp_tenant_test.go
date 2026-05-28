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
