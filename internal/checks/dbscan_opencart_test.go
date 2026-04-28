package checks

import (
	"context"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

// canonicalOpenCartConfig returns a config.php carrying the
// canonical OC define() set. Used by tests as a known-good fixture.
func canonicalOpenCartConfig() string {
	return `<?php
// Database Configuration
define('DB_DRIVER', 'mysqli');
define('DB_HOSTNAME', 'localhost');
define('DB_USERNAME', 'oc_user');
define('DB_PASSWORD', 'oc_pw');
define('DB_DATABASE', 'oc_shop');
define('DB_PREFIX', 'oc_');
`
}

// fakeOpenCartOS stubs Glob + ReadFile so CheckOpenCartContent
// finds either:
//
//	rootBody only      a non-OpenCart PHP site
//	rootBody + adminBody  a real OpenCart install
type fakeOpenCartOS struct {
	mockOS
	rootBody  string
	adminBody string
	skipAdmin bool // when true, admin/config.php read returns ""
}

func (m *fakeOpenCartOS) Glob(pattern string) ([]string, error) {
	if strings.Contains(pattern, "config.php") && !strings.Contains(pattern, "admin") {
		return []string{"/home/alice/public_html/config.php"}, nil
	}
	return nil, nil
}

func (m *fakeOpenCartOS) ReadFile(name string) ([]byte, error) {
	switch name {
	case "/home/alice/public_html/config.php":
		return []byte(m.rootBody), nil
	case "/home/alice/public_html/admin/config.php":
		if m.skipAdmin {
			return nil, nil
		}
		return []byte(m.adminBody), nil
	}
	return nil, nil
}

// --- looksLikeOpenCart ----------------------------------------------------

func TestLooksLikeOpenCartPositive(t *testing.T) {
	withMockOS(t, &fakeOpenCartOS{
		rootBody:  canonicalOpenCartConfig(),
		adminBody: canonicalOpenCartConfig(),
	})
	if !looksLikeOpenCart("/home/alice/public_html/config.php") {
		t.Error("expected OpenCart marker pair to be detected")
	}
}

func TestLooksLikeOpenCartRequiresBothFiles(t *testing.T) {
	// A plain PHP site with a root-level config.php that happens
	// to mention DB_DRIVER, but no admin/config.php. Must not be
	// classified as OpenCart.
	withMockOS(t, &fakeOpenCartOS{
		rootBody:  "<?php define('DB_DRIVER', 'mysqli');\n",
		skipAdmin: true,
	})
	if looksLikeOpenCart("/home/alice/public_html/config.php") {
		t.Error("non-OpenCart PHP site misidentified (no admin/config.php)")
	}
}

func TestLooksLikeOpenCartNegative(t *testing.T) {
	// Random PHP file with no DB_DRIVER reference.
	withMockOS(t, &fakeOpenCartOS{
		rootBody: "<?php echo 'hello';\n",
	})
	if looksLikeOpenCart("/home/alice/public_html/config.php") {
		t.Error("non-OC config.php misidentified")
	}
}

// --- parseOpenCartConfig --------------------------------------------------

func TestParseOpenCartConfigExtractsAllFields(t *testing.T) {
	withMockOS(t, &fakeOpenCartOS{
		rootBody:  canonicalOpenCartConfig(),
		adminBody: canonicalOpenCartConfig(),
	})
	creds := parseOpenCartConfig("/home/alice/public_html/config.php")
	if creds.dbName != "oc_shop" {
		t.Errorf("dbName = %q, want oc_shop", creds.dbName)
	}
	if creds.dbUser != "oc_user" {
		t.Errorf("dbUser = %q, want oc_user", creds.dbUser)
	}
	if creds.dbPass != "oc_pw" {
		t.Errorf("dbPass = %q, want oc_pw", creds.dbPass)
	}
	if creds.dbHost != "localhost" {
		t.Errorf("dbHost = %q, want localhost", creds.dbHost)
	}
	if creds.dbPrefix != "oc_" {
		t.Errorf("dbPrefix = %q, want oc_", creds.dbPrefix)
	}
}

func TestParseOpenCartConfigDefaultsHostWhenMissing(t *testing.T) {
	body := `<?php
define('DB_DRIVER', 'mysqli');
define('DB_USERNAME', 'u');
define('DB_PASSWORD', 'p');
define('DB_DATABASE', 'd');
define('DB_PREFIX', 'oc_');
`
	withMockOS(t, &fakeOpenCartOS{rootBody: body, adminBody: body})
	creds := parseOpenCartConfig("/home/alice/public_html/config.php")
	if creds.dbHost != "localhost" {
		t.Errorf("missing DB_HOSTNAME should default to localhost, got %q", creds.dbHost)
	}
}

// --- CheckOpenCartContent end-to-end -------------------------------------

func TestCheckOpenCartContentSkipsNonOpenCart(t *testing.T) {
	withMockOS(t, &fakeOpenCartOS{
		rootBody:  "<?php echo 'plain';",
		skipAdmin: true,
	})
	withMockCmd(t, &mockCmd{
		runWithEnv: func(string, []string, ...string) ([]byte, error) {
			t.Errorf("mysql called for non-OpenCart config.php")
			return nil, nil
		},
	})
	got := CheckOpenCartContent(context.Background(), &config.Config{}, &state.Store{})
	if len(got) != 0 {
		t.Errorf("findings = %d, want 0", len(got))
	}
}

func TestCheckOpenCartContentEmitsAcrossThreeScans(t *testing.T) {
	withMockOS(t, &fakeOpenCartOS{
		rootBody:  canonicalOpenCartConfig(),
		adminBody: canonicalOpenCartConfig(),
	})

	withMockCmd(t, &mockCmd{
		runWithEnv: func(name string, args []string, _ ...string) ([]byte, error) {
			joined := strings.Join(args, " ")
			switch {
			case strings.Contains(joined, "FROM oc_setting"):
				return []byte("config_url\t" + evalToken + "(base64_decode('cGF5bG9hZA==')); // evil\n"), nil
			case strings.Contains(joined, "FROM oc_product_description"):
				return []byte("42\t<?php " + evalToken + "($_POST['x']); ?>\n"), nil
			case strings.Contains(joined, "FROM oc_information_description"):
				return nil, nil
			case strings.Contains(joined, "FROM oc_user"):
				return []byte("1\tadmin\tadmin@example.com\n"), nil
			}
			return nil, nil
		},
	})

	got := CheckOpenCartContent(context.Background(), &config.Config{}, &state.Store{})

	categories := map[string]int{}
	for _, f := range got {
		categories[f.Check]++
	}
	if categories["opencart_settings_injection"] != 1 {
		t.Errorf("opencart_settings_injection = %d, want 1", categories["opencart_settings_injection"])
	}
	if categories["opencart_content_injection"] < 1 {
		t.Errorf("opencart_content_injection = %d, want >= 1", categories["opencart_content_injection"])
	}
	if categories["opencart_admin_injection"] != 1 {
		t.Errorf("opencart_admin_injection = %d, want 1", categories["opencart_admin_injection"])
	}
}

func TestCheckOpenCartContentRespectsCustomDBPrefix(t *testing.T) {
	body := strings.ReplaceAll(canonicalOpenCartConfig(), "'oc_'", "'shop9_'")
	withMockOS(t, &fakeOpenCartOS{rootBody: body, adminBody: body})

	queries := []string{}
	withMockCmd(t, &mockCmd{
		runWithEnv: func(name string, args []string, _ ...string) ([]byte, error) {
			queries = append(queries, strings.Join(args, " "))
			return nil, nil
		},
	})

	_ = CheckOpenCartContent(context.Background(), &config.Config{}, &state.Store{})

	for _, want := range []string{"shop9_setting", "shop9_product_description", "shop9_information_description", "shop9_user"} {
		seen := false
		for _, q := range queries {
			if strings.Contains(q, want) {
				seen = true
				break
			}
		}
		if !seen {
			t.Errorf("query for %q never executed (custom DB_PREFIX not honoured)", want)
		}
	}
}

// Regression: confirm the post-filter applies to OpenCart settings
// rows. config_url with a Tag Manager embed must not flag.
func TestCheckOpenCartContentSuppressesScriptOnlySettingsFP(t *testing.T) {
	withMockOS(t, &fakeOpenCartOS{
		rootBody:  canonicalOpenCartConfig(),
		adminBody: canonicalOpenCartConfig(),
	})

	withMockCmd(t, &mockCmd{
		runWithEnv: func(name string, args []string, _ ...string) ([]byte, error) {
			joined := strings.Join(args, " ")
			if strings.Contains(joined, "FROM oc_setting") {
				return []byte("config_url\t<script src=\"https://www.googletagmanager.com/gtag/js?id=G-XYZ\"></script>\n"), nil
			}
			return nil, nil
		},
	})

	got := CheckOpenCartContent(context.Background(), &config.Config{}, &state.Store{})
	for _, f := range got {
		if f.Check == "opencart_settings_injection" {
			t.Errorf("Tag Manager embed in oc_setting classified as malicious: %+v", f)
		}
	}
}

// TestCheckOpenCartContentFiltersLanguageID guards against the
// multilingual duplicate-row issue: oc_product_description and
// oc_information_description carry one row per language per
// product/page, so a multilingual storefront would emit N
// opencart_content_injection findings for the same row without
// the language_id = 1 filter.
func TestCheckOpenCartContentFiltersLanguageID(t *testing.T) {
	withMockOS(t, &fakeOpenCartOS{
		rootBody:  canonicalOpenCartConfig(),
		adminBody: canonicalOpenCartConfig(),
	})

	var seenProduct, seenInformation string
	withMockCmd(t, &mockCmd{
		runWithEnv: func(name string, args []string, _ ...string) ([]byte, error) {
			joined := strings.Join(args, " ")
			switch {
			case strings.Contains(joined, "FROM oc_product_description"):
				seenProduct = joined
			case strings.Contains(joined, "FROM oc_information_description"):
				seenInformation = joined
			}
			return nil, nil
		},
	})

	_ = CheckOpenCartContent(context.Background(), &config.Config{}, &state.Store{})

	for label, q := range map[string]string{"product": seenProduct, "information": seenInformation} {
		if q == "" {
			t.Errorf("%s description query never executed", label)
			continue
		}
		if !strings.Contains(q, "language_id = 1") {
			t.Errorf("%s description query missing language_id filter (multilingual sites would emit duplicates):\n%s", label, q)
		}
	}
}
