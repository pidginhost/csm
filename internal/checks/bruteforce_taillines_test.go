package checks

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/platform"
)

func TestEffectiveDomlogTailLines(t *testing.T) {
	if got := effectiveDomlogTailLines(nil); got != domlogTailLines {
		t.Errorf("nil cfg -> %d, want default %d", got, domlogTailLines)
	}
	cfg := &config.Config{}
	if got := effectiveDomlogTailLines(cfg); got != domlogTailLines {
		t.Errorf("zero cfg -> %d, want default %d", got, domlogTailLines)
	}
	cfg.Thresholds.DomlogTailLines = -1
	if got := effectiveDomlogTailLines(cfg); got != domlogTailLines {
		t.Errorf("negative -> %d, want default %d", got, domlogTailLines)
	}
	cfg.Thresholds.DomlogTailLines = 750
	if got := effectiveDomlogTailLines(cfg); got != 750 {
		t.Errorf("positive override -> %d, want 750", got)
	}
}

// A larger DomlogTailLines must let CheckWPBruteForce count attempts that
// fall outside the built-in 500-line window. Build a log with an attacker
// burst at the head, followed by 600 unrelated lines. Default tail of
// 500 drops the burst; raised tail of 1000 keeps it.
func TestCheckWPBruteForce_LongerTailLinesCatchesEarlierBurst(t *testing.T) {
	platform.ResetForTest()
	platform.SetOverrides(platform.Overrides{DomlogGlobs: []string{"/home/*/access-logs/*-ssl_log", "/home/*/access-logs/*_log"}})
	t.Cleanup(platform.ResetForTest)

	tmp := t.TempDir()
	log := filepath.Join(tmp, "victim.log")

	var lines []string
	for i := 0; i < 25; i++ {
		lines = append(lines, `203.0.113.99 - - [14/Apr/2026:10:00:00 +0000] "POST /wp-login.php HTTP/1.1" 401 0 "-" "-"`)
	}
	for i := 0; i < 600; i++ {
		lines = append(lines, fmt.Sprintf(`198.51.100.%d - - [14/Apr/2026:10:00:00 +0000] "GET /index.html HTTP/1.1" 200 100 "-" "browser"`, (i%200)+1))
	}
	if err := os.WriteFile(log, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(log, time.Now(), time.Now()); err != nil {
		t.Fatal(err)
	}

	withMockOS(t, &mockOS{
		glob: func(string) ([]string, error) { return []string{log}, nil },
		stat: os.Stat,
		open: func(name string) (*os.File, error) {
			if strings.Contains(name, "/apache/") || strings.Contains(name, "apache2") || strings.Contains(name, "/var/log/") {
				return nil, os.ErrNotExist
			}
			return os.Open(name)
		},
	})

	defaultCfg := &config.Config{}
	if hasWPLoginBruteForce(CheckWPBruteForce(context.Background(), defaultCfg, nil)) {
		t.Error("default DomlogTailLines should miss the early burst, but caught it")
	}

	wideCfg := &config.Config{}
	wideCfg.Thresholds.DomlogTailLines = 1000
	if !hasWPLoginBruteForce(CheckWPBruteForce(context.Background(), wideCfg, nil)) {
		t.Error("raised DomlogTailLines=1000 should catch the early burst, but did not")
	}
}

func hasWPLoginBruteForce(findings []alert.Finding) bool {
	for _, f := range findings {
		if f.Check == "wp_login_bruteforce" {
			return true
		}
	}
	return false
}
