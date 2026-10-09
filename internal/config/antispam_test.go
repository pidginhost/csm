package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func loadAntispam(t *testing.T, body string) (*Config, error) {
	t.Helper()
	return LoadBytes([]byte("email_protection:\n  antispam:\n" + body))
}

func TestLoadBytesAntispamDefaults(t *testing.T) {
	cfg, err := LoadBytes([]byte(""))
	if err != nil {
		t.Fatal(err)
	}
	as := cfg.EmailProtection.Antispam
	if as.Enabled {
		t.Error("antispam must default off")
	}
	if !as.DryRun {
		t.Error("antispam must default to dry_run=true")
	}
	if as.RspamdSocket != "/run/rspamd/csm-normal.sock" || as.RejectScore != 15 || as.TagScore != 6 {
		t.Errorf("defaults = %+v", as)
	}
}

func TestLoadBytesAntispamNullFieldsTakeDefaults(t *testing.T) {
	cfg, err := loadAntispam(t, "    enabled: true\n    dry_run: null\n    rspamd_socket: ~\n    reject_score: null\n    tag_score:\n")
	if err != nil {
		t.Fatal(err)
	}
	as := cfg.EmailProtection.Antispam
	if !as.DryRun || as.RspamdSocket != "/run/rspamd/csm-normal.sock" || as.RejectScore != 15 || as.TagScore != 6 {
		t.Errorf("null fields did not take defaults: %+v", as)
	}
}

func TestLoadBytesAntispamExplicitValuesKept(t *testing.T) {
	cfg, err := loadAntispam(t, "    enabled: true\n    dry_run: false\n    rspamd_socket: /var/run/rspamd/scan.sock\n    reject_score: 20\n    tag_score: 8\n")
	if err != nil {
		t.Fatal(err)
	}
	want := AntispamConfig{Enabled: true, DryRun: false, RspamdSocket: "/var/run/rspamd/scan.sock", RejectScore: 20, TagScore: 8}
	if cfg.EmailProtection.Antispam != want {
		t.Errorf("got %+v, want %+v", cfg.EmailProtection.Antispam, want)
	}
}

func TestLoadBytesAntispamEnabledRejectsBadValues(t *testing.T) {
	for name, body := range map[string]string{
		"zero reject":          "    reject_score: 0\n",
		"zero tag":             "    tag_score: 0\n",
		"negative tag":         "    tag_score: -1\n",
		"tag not below reject": "    reject_score: 6\n    tag_score: 6\n",
		"reject over max":      "    reject_score: 1001\n",
		"empty socket":         "    rspamd_socket: \"\"\n",
		"relative socket":      "    rspamd_socket: run/x.sock\n",
		"expansion in socket":  "    rspamd_socket: \"/run/$x.sock\"\n",
		"newline in socket":    "    rspamd_socket: |\n      /run/x.sock\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := loadAntispam(t, "    enabled: true\n"+body); err == nil {
				t.Fatal("invalid antispam config accepted")
			}
		})
	}
}

// yaml.v3 truncates 6.5 into an int field silently, so fractional scores need
// their own check. A quoted number is not an integer node either; a list
// socket fails in the decoder.
func TestLoadBytesAntispamTypeErrorsFailEvenWhenDisabled(t *testing.T) {
	for name, tc := range map[string]struct{ body, want string }{
		"fractional score":     {"    reject_score: 6.5\n", "whole number"},
		"fractional via alias": {"    reject_score: &r 6.5\n    tag_score: *r\n", "whole number"},
		"string score":         {"    tag_score: \"6\"\n", "whole number"},
		"list socket":          {"    rspamd_socket: [x]\n", "cannot unmarshal"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := loadAntispam(t, "    enabled: false\n"+tc.body)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

func TestLoadBytesAntispamDisabledSkipsRangeChecks(t *testing.T) {
	if _, err := loadAntispam(t, "    enabled: false\n    reject_score: 0\n    rspamd_socket: \"\"\n"); err != nil {
		t.Fatalf("dormant values blocked a disabled config: %v", err)
	}
}

func TestAntispamObserveModeConflict(t *testing.T) {
	_, err := LoadBytes([]byte("mode: observe\nemail_protection:\n  antispam:\n    enabled: true\n"))
	if err == nil || !strings.Contains(err.Error(), "email_protection.antispam.enabled") {
		t.Fatalf("err = %v, want observe conflict naming email_protection.antispam.enabled", err)
	}
}

func TestLoadWithDirAntispamFragmentKeepsDefaults(t *testing.T) {
	dir := t.TempDir()
	main := filepath.Join(dir, "csm.yaml")
	confd := filepath.Join(dir, "conf.d")
	must(t, os.MkdirAll(confd, 0o700))
	must(t, os.WriteFile(main, []byte("hostname: main-host\n"), 0o600))
	must(t, os.WriteFile(filepath.Join(confd, "20-antispam.yaml"), []byte("email_protection:\n  antispam:\n    enabled: true\n"), 0o600))

	cfg, err := LoadWithDir(main, confd)
	if err != nil {
		t.Fatal(err)
	}
	as := cfg.EmailProtection.Antispam
	if !as.Enabled || !as.DryRun || as.RspamdSocket != "/run/rspamd/csm-normal.sock" || as.RejectScore != 15 || as.TagScore != 6 {
		t.Errorf("fragment lost defaults: %+v", as)
	}
}

func TestAntispamChangesAreHotReloadable(t *testing.T) {
	load := func(body string) *Config {
		cfg, err := LoadBytes([]byte("hostname: x\nemail_protection:\n  antispam:\n" + body))
		if err != nil {
			t.Fatal(err)
		}
		return cfg
	}
	off := load("    enabled: false\n")
	on := load("    enabled: true\n    dry_run: false\n    reject_score: 20\n")
	if RestartRequired(Diff(off, on)) {
		t.Fatal("antispam changes must apply on reload; the reconciler handles them")
	}
}
