package checks

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

// canonicalDrupalSettings returns a Drupal 8+ settings.php carrying
// the standard $databases entry. Used by tests as a known-good
// fixture for credential extraction.
func canonicalDrupalSettings() string {
	return `<?php
$databases['default']['default'] = [
    'driver' => 'mysql',
    'database' => 'drupal_db',
    'username' => 'drupal_user',
    'password' => 'pw',
    'host' => 'localhost',
    'port' => '3306',
    'prefix' => '',
];
`
}

// fakeDrupalOS stubs Glob, ReadFile, and Stat so CheckDrupalContent
// finds exactly one D8+ install.
type fakeDrupalOS struct {
	mockOS
	settingsBody string
	hasDrupalPHP bool
}

func (m *fakeDrupalOS) Glob(pattern string) ([]string, error) {
	if strings.Contains(pattern, "settings.php") {
		return []string{"/home/alice/public_html/sites/default/settings.php"}, nil
	}
	return nil, nil
}

func (m *fakeDrupalOS) ReadFile(name string) ([]byte, error) {
	if name == "/home/alice/public_html/sites/default/settings.php" {
		return []byte(m.settingsBody), nil
	}
	return nil, nil
}

func (m *fakeDrupalOS) Stat(name string) (os.FileInfo, error) {
	if strings.HasSuffix(name, "/core/lib/Drupal.php") && m.hasDrupalPHP {
		return drupalStatStub{}, nil
	}
	return nil, errors.New("not found")
}

// drupalStatStub is the minimum FileInfo Stat needs to return a
// non-error: looksLikeDrupal8Plus only checks err.
type drupalStatStub struct{}

func (drupalStatStub) Name() string       { return "Drupal.php" }
func (drupalStatStub) Size() int64        { return 0 }
func (drupalStatStub) Mode() os.FileMode  { return 0 }
func (drupalStatStub) ModTime() time.Time { return time.Time{} }
func (drupalStatStub) IsDir() bool        { return false }
func (drupalStatStub) Sys() any           { return nil }

// --- looksLikeDrupal8Plus -------------------------------------------------

func TestLooksLikeDrupal8PlusPositive(t *testing.T) {
	withMockOS(t, &fakeDrupalOS{hasDrupalPHP: true})
	if !looksLikeDrupal8Plus("/home/alice/public_html") {
		t.Error("expected D8+ marker to be detected")
	}
}

func TestLooksLikeDrupal8PlusD7Negative(t *testing.T) {
	// D7 sites have settings.php but no core/lib/Drupal.php.
	withMockOS(t, &fakeDrupalOS{hasDrupalPHP: false})
	if looksLikeDrupal8Plus("/home/alice/public_html") {
		t.Error("D7 install (no core/lib/Drupal.php) misidentified as D8+")
	}
}

// --- parseDrupalSettings --------------------------------------------------

func TestParseDrupalSettingsExtractsAllFields(t *testing.T) {
	withMockOS(t, &fakeDrupalOS{settingsBody: canonicalDrupalSettings(), hasDrupalPHP: true})
	creds := parseDrupalSettings("/home/alice/public_html/sites/default/settings.php")
	if creds.dbName != "drupal_db" {
		t.Errorf("dbName = %q", creds.dbName)
	}
	if creds.dbUser != "drupal_user" {
		t.Errorf("dbUser = %q", creds.dbUser)
	}
	if creds.dbPass != "pw" {
		t.Errorf("dbPass = %q", creds.dbPass)
	}
	if creds.dbHost != "localhost" {
		t.Errorf("dbHost = %q", creds.dbHost)
	}
}

func TestParseDrupalSettingsAcceptsArrayLongForm(t *testing.T) {
	// D7-era code that hung on into D8+ uses array() rather than
	// short []. Both shapes satisfy our regex.
	body := `<?php
$databases['default']['default'] = array(
    'driver' => 'mysql',
    'database' => 'd7db',
    'username' => 'd7user',
    'password' => 'd7pw',
    'host' => '10.0.0.5',
);
`
	withMockOS(t, &fakeDrupalOS{settingsBody: body, hasDrupalPHP: true})
	creds := parseDrupalSettings("/home/alice/public_html/sites/default/settings.php")
	if creds.dbName != "d7db" || creds.dbUser != "d7user" || creds.dbHost != "10.0.0.5" {
		t.Errorf("creds = %+v", creds)
	}
}

func TestParseDrupalSettingsDefaultsHostWhenMissing(t *testing.T) {
	body := `<?php
$databases['default']['default'] = [
    'database' => 'd',
    'username' => 'u',
    'password' => 'p',
];
`
	withMockOS(t, &fakeDrupalOS{settingsBody: body, hasDrupalPHP: true})
	creds := parseDrupalSettings("/home/alice/public_html/sites/default/settings.php")
	if creds.dbHost != "localhost" {
		t.Errorf("dbHost = %q, want localhost (default)", creds.dbHost)
	}
}

// --- CheckDrupalContent end-to-end ---------------------------------------

func TestCheckDrupalContentSkipsD7Sites(t *testing.T) {
	withMockOS(t, &fakeDrupalOS{
		settingsBody: canonicalDrupalSettings(),
		hasDrupalPHP: false, // D7: no core/lib/Drupal.php
	})
	withMockCmd(t, &mockCmd{
		runWithEnv: func(string, []string, ...string) ([]byte, error) {
			t.Errorf("mysql called for D7 install (v1 covers D8+ only)")
			return nil, nil
		},
	})
	got := CheckDrupalContent(context.Background(), &config.Config{}, &state.Store{})
	if len(got) != 0 {
		t.Errorf("findings = %d, want 0 for D7 install", len(got))
	}
}

func TestCheckDrupalContentEmitsFromAllThreeScans(t *testing.T) {
	withMockOS(t, &fakeDrupalOS{settingsBody: canonicalDrupalSettings(), hasDrupalPHP: true})

	withMockCmd(t, &mockCmd{
		runWithEnv: func(name string, args []string, _ ...string) ([]byte, error) {
			joined := strings.Join(args, " ")
			switch {
			case strings.Contains(joined, "FROM config"):
				return []byte("system.site\t" + evalToken + "(base64_decode('cGF5bG9hZA==')); // evil\n"), nil
			case strings.Contains(joined, "FROM node_revision__body"):
				return []byte("42\t<?php " + evalToken + "($_POST['x']); ?>\n"), nil
			case strings.Contains(joined, "users_field_data"):
				// Legitimate admin row.
				return []byte("1\tadmin\tadmin@example.com\n"), nil
			}
			return nil, nil
		},
	})

	got := CheckDrupalContent(context.Background(), &config.Config{}, &state.Store{})

	categories := map[string]int{}
	for _, f := range got {
		categories[f.Check]++
	}
	if categories["drupal_settings_injection"] != 1 {
		t.Errorf("drupal_settings_injection = %d, want 1", categories["drupal_settings_injection"])
	}
	if categories["drupal_content_injection"] != 1 {
		t.Errorf("drupal_content_injection = %d, want 1", categories["drupal_content_injection"])
	}
	if categories["drupal_admin_injection"] != 1 {
		t.Errorf("drupal_admin_injection = %d, want 1", categories["drupal_admin_injection"])
	}
}

func TestCheckDrupalContentMalformedSettingsSkipsScan(t *testing.T) {
	withMockOS(t, &fakeDrupalOS{
		settingsBody: `<?php
// malformed: no $databases declaration at all
echo 'hi';
`,
		hasDrupalPHP: true,
	})
	withMockCmd(t, &mockCmd{
		runWithEnv: func(string, []string, ...string) ([]byte, error) {
			t.Errorf("mysql called with no parsed credentials")
			return nil, nil
		},
	})
	got := CheckDrupalContent(context.Background(), &config.Config{}, &state.Store{})
	if len(got) != 0 {
		t.Errorf("findings = %d, want 0 with malformed settings.php", len(got))
	}
}

// Regression: the script-only post-filter must apply equally to
// Drupal config blobs. classifyMalwareRow already handles this --
// this test confirms the Drupal scanner uses the predicate.
func TestCheckDrupalContentSuppressesScriptOnlyConfigFP(t *testing.T) {
	withMockOS(t, &fakeDrupalOS{settingsBody: canonicalDrupalSettings(), hasDrupalPHP: true})

	withMockCmd(t, &mockCmd{
		runWithEnv: func(name string, args []string, _ ...string) ([]byte, error) {
			joined := strings.Join(args, " ")
			if strings.Contains(joined, "FROM config") {
				// system.site config row carrying a Tag Manager
				// embed -- legitimate, must not flag.
				return []byte("system.site\t<script src=\"https://www.googletagmanager.com/gtag/js?id=G-XYZ\"></script>\n"), nil
			}
			return nil, nil
		},
	})

	got := CheckDrupalContent(context.Background(), &config.Config{}, &state.Store{})
	for _, f := range got {
		if f.Check == "drupal_settings_injection" {
			t.Errorf("Tag Manager embed in config classified as malicious: %+v", f)
		}
	}
}
