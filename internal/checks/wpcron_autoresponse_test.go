package checks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

type wpCronUserdataOverlay struct {
	OS
	content string
}

func (o wpCronUserdataOverlay) ReadFile(name string) ([]byte, error) {
	if name == userdataDomainsPath {
		return []byte(o.content), nil
	}
	return o.OS.ReadFile(name)
}

func wpCronFinding(path string) alert.Finding {
	return alert.Finding{
		Check:   "perf_wp_cron",
		Message: "WP-Cron not disabled for alice",
		Details: "File: " + path + " - add define('DISABLE_WP_CRON', true); and use a real cron job instead",
	}
}

func TestAutoFixWPCronDisabledReturnsNil(t *testing.T) {
	cfg := &config.Config{}
	actions, fixed := AutoFixWPCron(cfg, []alert.Finding{wpCronFinding("/home/alice/public_html/wp-config.php")})
	if actions != nil || fixed != nil {
		t.Errorf("disabled auto-response should yield (nil, nil), got %v / %v", actions, fixed)
	}
}

func TestAutoFixWPCronFlagOffReturnsNil(t *testing.T) {
	cfg := &config.Config{}
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.FixWPCron = false
	actions, fixed := AutoFixWPCron(cfg, []alert.Finding{wpCronFinding("/home/alice/public_html/wp-config.php")})
	if actions != nil || fixed != nil {
		t.Errorf("fix_wp_cron=false should yield (nil, nil), got %v / %v", actions, fixed)
	}
}

func TestAutoFixWPCronIgnoresUnrelatedChecks(t *testing.T) {
	cfg := &config.Config{}
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.FixWPCron = true
	actions, fixed := AutoFixWPCron(cfg, []alert.Finding{
		{Check: "webshell", Message: "/home/x/shell.php"},
	})
	if len(actions) != 0 || len(fixed) != 0 {
		t.Errorf("unrelated checks should be ignored, got %v / %v", actions, fixed)
	}
}

func TestAutoFixWPCronAppliesAndReportsAction(t *testing.T) {
	cfgPath, docroot := wpCronTestEnv(t, sampleWPConfig)
	withPerfFixRoots(t, filepath.Join(realTempDir(t), "unrelated"))
	rec := &crontabRecorder{}
	withMockCmd(t, rec.mock())

	cfg := &config.Config{}
	cfg.AccountRoots = []string{docroot}
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.FixWPCron = true
	cfg.Performance.WPCronFix.IntervalMinutes = 5
	cfg.Performance.WPCronFix.PHPBin = "/usr/local/bin/php"

	f := wpCronFinding(cfgPath)
	actions, fixed := AutoFixWPCron(cfg, []alert.Finding{f})

	if len(actions) != 1 || len(fixed) != 1 {
		t.Fatalf("expected 1 action + 1 fixed key, got %v / %v", actions, fixed)
	}
	// The fixed key must be the finding's dismissal key so the caller's
	// DismissLatestFinding clears it; perf_wp_cron findings carry Details, so a
	// bare Check:Message would never match the stored finding's Key().
	if fixed[0] != f.Key() {
		t.Errorf("fixed key %q should equal finding Key() %q", fixed[0], f.Key())
	}
	if actions[0].Check != "auto_response" || !strings.Contains(actions[0].Message, "AUTO-FIX") {
		t.Errorf("unexpected action finding: %+v", actions[0])
	}
	body, _ := os.ReadFile(cfgPath)
	if !strings.Contains(string(body), "DISABLE_WP_CRON") {
		t.Errorf("wp-config.php should have the define after auto-fix")
	}
}

func TestAutoFixWPCronAllowsValidatedAddonDomainRoot(t *testing.T) {
	root := realTempDir(t)
	home := filepath.Join(root, "home")
	main := filepath.Join(home, "alice", "public_html")
	addon := filepath.Join(home, "alice", "shop.example.com")
	if err := os.MkdirAll(main, 0o755); err != nil {
		t.Fatal(err)
	}
	cfgPath := writeWPCronScanInstall(t, addon, wpCronScanConfig)
	withWPCronOwner(t, "alice")
	rec := &crontabRecorder{}
	withMockCmd(t, rec.mock())

	mapData := "shop.example.com: alice==root==addon==example.com==" + addon + "==192.0.2.10:80==192.0.2.10:443====0==ea-php82"
	withMockOS(t, wpCronUserdataOverlay{OS: realOS{}, content: mapData})
	cfg := &config.Config{AccountRoots: []string{main}}
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.FixWPCron = true
	cfg.Performance.WPCronFix.PHPBin = "/usr/local/bin/php"

	f := wpCronFinding(cfgPath)
	actions, fixed := AutoFixWPCron(cfg, []alert.Finding{f})
	if len(actions) != 1 || len(fixed) != 1 || fixed[0] != f.Key() {
		t.Fatalf("addon-domain auto-fix did not complete: actions=%+v fixed=%v", actions, fixed)
	}
	body, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if !wpCronHasActiveDisableDefine(body) || rec.installCalls != 1 {
		t.Fatalf("addon-domain fix did not edit config and cron: installs=%d body=%s", rec.installCalls, body)
	}
}

func TestExtractWPConfigPath(t *testing.T) {
	cases := []struct{ in, want string }{
		{"File: /home/alice/public_html/wp-config.php - add define(...)", "/home/alice/public_html/wp-config.php"},
		{"File: /home/bob/wp-config.php", "/home/bob/wp-config.php"},
		{"no file here", ""},
	}
	for _, c := range cases {
		if got := extractWPConfigPath(c.in); got != c.want {
			t.Errorf("extractWPConfigPath(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
