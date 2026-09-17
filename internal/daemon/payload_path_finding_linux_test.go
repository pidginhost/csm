//go:build linux

package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/signatures"
)

// A loader finding that names only the modified PHP file leaves the operator
// to hunt for the payload by hand. The included non-executable file has to
// travel with the finding.
func TestRealtimeSignatureFindingNamesTheIncludedPayload(t *testing.T) {
	previous := signatures.SetGlobal(signatures.NewScanner(filepath.Join("..", "..", "configs")))
	t.Cleanup(func() { signatures.SetGlobal(previous) })

	const payloadPath = "/home/site/public_html/wp-content/plugins/demo/assets/lib/images/light_square/btn.png"
	loader := []byte(`<?php if(isset($_COOKIE["sess_kx"])){$incName="` + payloadPath + `"; include($incName); exit;} ?>` + "\n<?php get_header(); ?>\n")

	root := t.TempDir()
	path := filepath.Join(root, "header.php")
	if err := os.WriteFile(path, loader, 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	alerts := make(chan alert.Finding, 8)
	fm := &FileMonitor{cfg: &config.Config{StatePath: root}, alertCh: alerts}
	if !fm.runSignatureScanWithSize(loader, int64(len(loader)), path, ".php", "", info) {
		t.Fatal("the cookie-gated image loader produced no realtime finding")
	}

	found := false
	for len(alerts) > 0 {
		finding := <-alerts
		if finding.Check != "signature_match_realtime" {
			continue
		}
		found = true
		if !strings.Contains(finding.Details, payloadPath) {
			t.Errorf("finding does not name the payload: %q", finding.Details)
		}
	}
	if !found {
		t.Fatal("no signature_match_realtime finding was published")
	}
}
