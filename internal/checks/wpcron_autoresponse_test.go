package checks

import (
	"os"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

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
	cfgPath, _ := wpCronTestEnv(t, sampleWPConfig)
	rec := &crontabRecorder{}
	withMockCmd(t, rec.mock())

	cfg := &config.Config{}
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.FixWPCron = true
	cfg.Performance.WPCronFix.IntervalMinutes = 5
	cfg.Performance.WPCronFix.PHPBin = "/usr/local/bin/php"

	f := wpCronFinding(cfgPath)
	actions, fixed := AutoFixWPCron(cfg, []alert.Finding{f})

	if len(actions) != 1 || len(fixed) != 1 {
		t.Fatalf("expected 1 action + 1 fixed key, got %v / %v", actions, fixed)
	}
	if fixed[0] != f.Check+":"+f.Message {
		t.Errorf("fixed key mismatch: %q", fixed[0])
	}
	if actions[0].Check != "auto_response" || !strings.Contains(actions[0].Message, "AUTO-FIX") {
		t.Errorf("unexpected action finding: %+v", actions[0])
	}
	body, _ := os.ReadFile(cfgPath)
	if !strings.Contains(string(body), "DISABLE_WP_CRON") {
		t.Errorf("wp-config.php should have the define after auto-fix")
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
