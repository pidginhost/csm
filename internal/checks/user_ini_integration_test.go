package checks

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

// -----------------------------------------------------------------------------
// Integration: scanWPConfigs honours the cPanel-managed .user.ini
// signature.
//
// A file carrying the cPanel MultiPHP INI Editor header represents
// operator intent. Values in such a file (max_execution_time=0 for a
// backup importer, display_errors=On for a staging environment) are
// not attacker actions; they are choices made through the cPanel UI.
// The scanner suppresses findings for those values so operators do
// not receive alerts for their own configuration.
//
// A file WITHOUT the header may have been hand-edited by the owner OR
// planted by an attacker. The original finding and its severity are
// preserved in that case because we have no independent authority to
// distinguish the two — an operator reviewing the HIGH finding can
// confirm it is benign in seconds but we must not auto-silence it.
//
// The cPanel-managed suppression is scoped strictly to .user.ini. The
// same signature appearing in php.ini or .htaccess is not authoritative
// (cPanel does not write those files) and is ignored for severity
// purposes.
// -----------------------------------------------------------------------------

// wpConfigTestHarness wires up a minimal filesystem tree and config so
// CheckWPConfig can run against it without mocking osFS. Each test
// starts from a fresh temp dir and fresh state store so the 60-minute
// throttle does not suppress the first run.
type wpConfigTestHarness struct {
	t        *testing.T
	root     string
	iniPath  string
	findings []alert.Finding
}

func newWpConfigTestHarness(t *testing.T, iniFilename, iniContent string) *wpConfigTestHarness {
	t.Helper()
	tmp := t.TempDir()
	root := filepath.Join(tmp, "home", "acct", "public_html")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	wpCfg := `<?php
define('DB_NAME','db');
define('DB_USER','u');
define('DB_PASSWORD','p');
define('DB_HOST','localhost');
$table_prefix = 'wp_';
`
	if err := os.WriteFile(filepath.Join(root, "wp-config.php"), []byte(wpCfg), 0o644); err != nil {
		t.Fatal(err)
	}
	iniPath := filepath.Join(root, iniFilename)
	if err := os.WriteFile(iniPath, []byte(iniContent), 0o644); err != nil {
		t.Fatal(err)
	}
	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	cfg := &config.Config{AccountRoots: []string{root}}
	cfg.Performance.WPMemoryLimitMaxMB = 1024
	return &wpConfigTestHarness{
		t:        t,
		root:     root,
		iniPath:  iniPath,
		findings: CheckWPConfig(context.Background(), cfg, st),
	}
}

// findingFor returns the first finding whose message contains needle,
// and whether it was seen.
func (h *wpConfigTestHarness) findingFor(needle string) (alert.Finding, bool) {
	for _, f := range h.findings {
		if strings.Contains(f.Message, needle) && strings.Contains(f.Details, h.iniPath) {
			return f, true
		}
	}
	return alert.Finding{}, false
}

// -----------------------------------------------------------------------------
// max_execution_time=0
// -----------------------------------------------------------------------------

func TestScanWPConfigs_CpanelManagedMaxExecSuppressed(t *testing.T) {
	cpanelHeader := "; cPanel-generated php ini directives, do not edit\n" +
		"; Manual editing of this file may result in unexpected behavior.\n" +
		"; To make changes to this file, use the cPanel MultiPHP INI Editor\n" +
		"\n[PHP]\nmax_execution_time = 0\n"
	h := newWpConfigTestHarness(t, ".user.ini", cpanelHeader)
	if _, ok := h.findingFor("max_execution_time"); ok {
		t.Errorf("cPanel-managed .user.ini with max_execution_time=0 must NOT emit a finding (operator-set via cPanel UI)")
	}
}

func TestScanWPConfigs_HandEditedMaxExecStaysHigh(t *testing.T) {
	// No cPanel header — the file may have been hand-edited by the
	// owner or planted. Severity must remain High.
	ini := "[PHP]\nmax_execution_time = 0\n"
	h := newWpConfigTestHarness(t, ".user.ini", ini)
	f, ok := h.findingFor("max_execution_time")
	if !ok {
		t.Fatal("expected a finding for max_execution_time=0 in hand-edited .user.ini")
	}
	if f.Severity != alert.High {
		t.Errorf("hand-edited .user.ini must preserve High severity; got %v", f.Severity)
	}
}

func TestScanWPConfigs_PhpIniDownloadIgnoresCpanelSignature(t *testing.T) {
	// The cPanel-managed downgrade applies ONLY to .user.ini. A file
	// named php.ini that happens to contain the cPanel signature (e.g.
	// copy-pasted) does not get the downgrade: cPanel does not write
	// php.ini itself, so the signature there is not authoritative.
	cpanelHeader := "; cPanel-generated php ini directives, do not edit\n" +
		"[PHP]\nmax_execution_time = 0\n"
	h := newWpConfigTestHarness(t, "php.ini", cpanelHeader)
	f, ok := h.findingFor("max_execution_time")
	if !ok {
		t.Fatal("expected a finding for max_execution_time=0 in php.ini")
	}
	if f.Severity != alert.High {
		t.Errorf("php.ini with forged cPanel signature must still emit High severity; got %v", f.Severity)
	}
}

// -----------------------------------------------------------------------------
// display_errors=On
// -----------------------------------------------------------------------------

func TestScanWPConfigs_CpanelManagedDisplayErrorsSuppressed(t *testing.T) {
	cpanelHeader := "; cPanel-generated php ini directives, do not edit\n" +
		"[PHP]\ndisplay_errors = On\n"
	h := newWpConfigTestHarness(t, ".user.ini", cpanelHeader)
	if _, ok := h.findingFor("display_errors"); ok {
		t.Errorf("cPanel-managed .user.ini with display_errors=On must NOT emit a finding (operator-set via cPanel UI)")
	}
}

func TestScanWPConfigs_HandEditedDisplayErrorsStaysWarning(t *testing.T) {
	ini := "[PHP]\ndisplay_errors = On\n"
	h := newWpConfigTestHarness(t, ".user.ini", ini)
	f, ok := h.findingFor("display_errors")
	if !ok {
		t.Fatal("expected a finding for display_errors=On in hand-edited .user.ini")
	}
	// The original severity for display_errors is Warning, not High.
	if f.Severity != alert.Warning {
		t.Errorf("hand-edited display_errors=On must preserve Warning severity; got %v", f.Severity)
	}
}
