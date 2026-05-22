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

func TestEffectiveDomlogMaxAge(t *testing.T) {
	if got := effectiveDomlogMaxAge(nil); got != domlogMaxAge {
		t.Errorf("nil cfg -> %s, want default %s", got, domlogMaxAge)
	}
	cfg := &config.Config{}
	if got := effectiveDomlogMaxAge(cfg); got != domlogMaxAge {
		t.Errorf("zero cfg -> %s, want default %s", got, domlogMaxAge)
	}
	cfg.Thresholds.DomlogMaxAgeMin = -1
	if got := effectiveDomlogMaxAge(cfg); got != domlogMaxAge {
		t.Errorf("negative -> %s, want default %s", got, domlogMaxAge)
	}
	cfg.Thresholds.DomlogMaxAgeMin = 120
	want := 120 * time.Minute
	if got := effectiveDomlogMaxAge(cfg); got != want {
		t.Errorf("positive override -> %s, want %s", got, want)
	}
}

// A larger DomlogMaxAgeMin must let CheckWPBruteForce pick up logs that
// the default 30-minute cutoff would have dropped. Build a fresh log
// 45 minutes old and pin that the default skips it, raised accepts it.
func TestCheckWPBruteForce_LongerMaxAgeIncludesOlderLog(t *testing.T) {
	platform.ResetForTest()
	platform.SetOverrides(platform.Overrides{DomlogGlobs: []string{"/home/*/access-logs/*-ssl_log", "/home/*/access-logs/*_log"}})
	t.Cleanup(platform.ResetForTest)

	tmp := t.TempDir()
	log := filepath.Join(tmp, "older.log")
	var burst []string
	for i := 0; i < 25; i++ {
		burst = append(burst, `203.0.113.55 - - [14/Apr/2026:10:00:00 +0000] "POST /wp-login.php HTTP/1.1" 401 0 "-" "-"`)
	}
	if err := os.WriteFile(log, []byte(strings.Join(burst, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-45 * time.Minute)
	if err := os.Chtimes(log, old, old); err != nil {
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
		t.Error("default 30-min cutoff should drop the 45-min-old log, but caught it")
	}

	wideCfg := &config.Config{}
	wideCfg.Thresholds.DomlogMaxAgeMin = 60
	if !hasWPLoginBruteForce(CheckWPBruteForce(context.Background(), wideCfg, nil)) {
		t.Error("raised DomlogMaxAgeMin=60 should include the 45-min-old log, but did not")
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
