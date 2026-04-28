package checks

import (
	"context"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

func canonicalM1XML() string {
	return `<?xml version="1.0"?>
<config>
  <global>
    <resources>
      <db>
        <table_prefix><![CDATA[m1_]]></table_prefix>
      </db>
      <default_setup>
        <connection>
          <host><![CDATA[localhost]]></host>
          <username><![CDATA[m1user]]></username>
          <password><![CDATA[m1pw]]></password>
          <dbname><![CDATA[magento_db]]></dbname>
        </connection>
      </default_setup>
    </resources>
  </global>
</config>
`
}

func canonicalM2EnvPHP() string {
	return `<?php
return [
    'db' => [
        'connection' => [
            'default' => [
                'host' => 'localhost',
                'dbname' => 'magento2_db',
                'username' => 'm2user',
                'password' => 'm2pw',
            ],
        ],
        'table_prefix' => 'm2_',
    ],
];
`
}

// fakeMagentoOS toggles between M1 (local.xml present, env.php
// absent) and M2 (env.php present) via the discovered files.
type fakeMagentoOS struct {
	mockOS
	m1Body string // local.xml content; "" means file absent
	m2Body string // env.php content; "" means file absent
}

func (m *fakeMagentoOS) Glob(pattern string) ([]string, error) {
	switch {
	case strings.Contains(pattern, "env.php"):
		if m.m2Body == "" {
			return nil, nil
		}
		return []string{"/home/alice/public_html/app/etc/env.php"}, nil
	case strings.Contains(pattern, "local.xml"):
		if m.m1Body == "" {
			return nil, nil
		}
		return []string{"/home/alice/public_html/app/etc/local.xml"}, nil
	}
	return nil, nil
}

func (m *fakeMagentoOS) ReadFile(name string) ([]byte, error) {
	switch name {
	case "/home/alice/public_html/app/etc/env.php":
		return []byte(m.m2Body), nil
	case "/home/alice/public_html/app/etc/local.xml":
		return []byte(m.m1Body), nil
	}
	return nil, nil
}

// --- parseMagentoM1 ------------------------------------------------------

func TestParseMagentoM1ExtractsCredentialsAndPrefix(t *testing.T) {
	withMockOS(t, &fakeMagentoOS{m1Body: canonicalM1XML()})
	creds := parseMagentoM1("/home/alice/public_html/app/etc/local.xml")
	if creds.version != "M1" {
		t.Errorf("version = %q, want M1", creds.version)
	}
	if creds.dbName != "magento_db" || creds.dbUser != "m1user" || creds.dbPass != "m1pw" {
		t.Errorf("creds = %+v", creds)
	}
	if creds.dbPrefix != "m1_" {
		t.Errorf("dbPrefix = %q, want m1_", creds.dbPrefix)
	}
	if creds.dbHost != "localhost" {
		t.Errorf("dbHost = %q", creds.dbHost)
	}
}

func TestParseMagentoM1HandlesNonCDATAFields(t *testing.T) {
	body := `<?xml version="1.0"?>
<config>
  <global>
    <resources>
      <default_setup>
        <connection>
          <host>db.example.com</host>
          <username>plain_user</username>
          <password>plain_pw</password>
          <dbname>plain_db</dbname>
        </connection>
      </default_setup>
    </resources>
  </global>
</config>
`
	withMockOS(t, &fakeMagentoOS{m1Body: body})
	creds := parseMagentoM1("/home/alice/public_html/app/etc/local.xml")
	if creds.dbHost != "db.example.com" || creds.dbUser != "plain_user" || creds.dbName != "plain_db" {
		t.Errorf("plain (non-CDATA) XML not parsed: %+v", creds)
	}
}

func TestParseMagentoM1MalformedReturnsZero(t *testing.T) {
	withMockOS(t, &fakeMagentoOS{m1Body: "<not-config>broken"})
	creds := parseMagentoM1("/home/alice/public_html/app/etc/local.xml")
	if creds.dbName != "" {
		t.Errorf("malformed XML should return zero creds, got %+v", creds)
	}
}

// --- parseMagentoM2 ------------------------------------------------------

func TestParseMagentoM2ExtractsCredentialsAndPrefix(t *testing.T) {
	withMockOS(t, &fakeMagentoOS{m2Body: canonicalM2EnvPHP()})
	creds := parseMagentoM2("/home/alice/public_html/app/etc/env.php")
	if creds.version != "M2" {
		t.Errorf("version = %q, want M2", creds.version)
	}
	if creds.dbName != "magento2_db" || creds.dbUser != "m2user" || creds.dbPass != "m2pw" {
		t.Errorf("creds = %+v", creds)
	}
	if creds.dbPrefix != "m2_" {
		t.Errorf("dbPrefix = %q, want m2_", creds.dbPrefix)
	}
}

func TestParseMagentoM2DoubleQuotedFields(t *testing.T) {
	body := `<?php
return [
    'db' => [
        'connection' => [
            'default' => [
                "host" => "mysql.internal",
                "dbname" => "shop",
                "username" => "u",
                "password" => "p",
            ],
        ],
    ],
];
`
	withMockOS(t, &fakeMagentoOS{m2Body: body})
	creds := parseMagentoM2("/home/alice/public_html/app/etc/env.php")
	if creds.dbHost != "mysql.internal" || creds.dbName != "shop" {
		t.Errorf("double-quoted env.php not parsed: %+v", creds)
	}
}

// --- CheckMagentoContent end-to-end --------------------------------------

func TestCheckMagentoContentSkipsHostsWithNeitherFile(t *testing.T) {
	withMockOS(t, &fakeMagentoOS{}) // no env.php, no local.xml
	withMockCmd(t, &mockCmd{
		runWithEnv: func(string, []string, ...string) ([]byte, error) {
			t.Errorf("mysql called when neither M1 nor M2 file present")
			return nil, nil
		},
	})
	got := CheckMagentoContent(context.Background(), &config.Config{}, &state.Store{})
	if len(got) != 0 {
		t.Errorf("findings = %d, want 0", len(got))
	}
}

func TestCheckMagentoContentM2EmitsAcrossSettingsContentAndAdmin(t *testing.T) {
	withMockOS(t, &fakeMagentoOS{m2Body: canonicalM2EnvPHP()})
	withMockCmd(t, &mockCmd{
		runWithEnv: func(name string, args []string, _ ...string) ([]byte, error) {
			joined := strings.Join(args, " ")
			switch {
			case strings.Contains(joined, "core_config_data"):
				return []byte("web/unsecure/base_url\t" + evalToken + "(base64_decode('cGF5bG9hZA==')); // evil\n"), nil
			case strings.Contains(joined, "cms_page"):
				return []byte("12\t<?php " + evalToken + "($_POST['x']); ?>\n"), nil
			case strings.Contains(joined, "admin_user"):
				return []byte("1\tadmin\tadmin@example.com\n"), nil
			}
			return nil, nil
		},
	})

	got := CheckMagentoContent(context.Background(), &config.Config{}, &state.Store{})

	categories := map[string]int{}
	for _, f := range got {
		categories[f.Check]++
	}
	if categories["magento_settings_injection"] != 1 {
		t.Errorf("magento_settings_injection = %d, want 1", categories["magento_settings_injection"])
	}
	if categories["magento_content_injection"] < 1 {
		t.Errorf("magento_content_injection = %d, want >= 1", categories["magento_content_injection"])
	}
	if categories["magento_admin_injection"] != 1 {
		t.Errorf("magento_admin_injection = %d, want 1", categories["magento_admin_injection"])
	}
}

func TestCheckMagentoContentM1FallbackWhenOnlyXMLPresent(t *testing.T) {
	withMockOS(t, &fakeMagentoOS{m1Body: canonicalM1XML()})

	prefixSeen := false
	withMockCmd(t, &mockCmd{
		runWithEnv: func(name string, args []string, _ ...string) ([]byte, error) {
			joined := strings.Join(args, " ")
			if strings.Contains(joined, "m1_core_config_data") || strings.Contains(joined, "m1_admin_user") {
				prefixSeen = true
			}
			return nil, nil
		},
	})

	_ = CheckMagentoContent(context.Background(), &config.Config{}, &state.Store{})

	if !prefixSeen {
		t.Error("M1 fallback never queried with m1_ prefix; XML credentials not picked up")
	}
}

// Regression: a host carrying both env.php and local.xml after a
// half-finished M1 to M2 migration should not trigger duplicate
// scans (one for each version's creds).
func TestCheckMagentoContentDeduplicatesAcrossVersions(t *testing.T) {
	withMockOS(t, &fakeMagentoOS{
		m1Body: canonicalM1XML(),
		m2Body: canonicalM2EnvPHP(),
	})

	prefixCounts := map[string]int{}
	withMockCmd(t, &mockCmd{
		runWithEnv: func(name string, args []string, _ ...string) ([]byte, error) {
			joined := strings.Join(args, " ")
			switch {
			case strings.Contains(joined, "m1_core_config_data"):
				prefixCounts["m1"]++
			case strings.Contains(joined, "m2_core_config_data"):
				prefixCounts["m2"]++
				return []byte("web/unsecure/base_url\t" + evalToken + "(decode); // evil\n"), nil
			}
			return nil, nil
		},
	})

	_ = CheckMagentoContent(context.Background(), &config.Config{}, &state.Store{})

	// M2 must have been queried (env.php is the active version).
	if prefixCounts["m2"] == 0 {
		t.Error("M2 path not queried despite env.php presence")
	}
	// M1 path must NOT have been queried -- alreadyScanned skipped.
	if prefixCounts["m1"] > 0 {
		t.Errorf("M1 fallback queried even though M2 already produced findings (count=%d)", prefixCounts["m1"])
	}
}

// Regression: confirm the post-filter applies to Magento config
// rows just like Joomla / Drupal.
func TestCheckMagentoContentSuppressesScriptOnlyConfigFP(t *testing.T) {
	withMockOS(t, &fakeMagentoOS{m2Body: canonicalM2EnvPHP()})
	withMockCmd(t, &mockCmd{
		runWithEnv: func(name string, args []string, _ ...string) ([]byte, error) {
			joined := strings.Join(args, " ")
			if strings.Contains(joined, "core_config_data") {
				return []byte("design/header/welcome\t<script src=\"https://www.googletagmanager.com/gtag/js?id=G-XYZ\"></script>\n"), nil
			}
			return nil, nil
		},
	})
	got := CheckMagentoContent(context.Background(), &config.Config{}, &state.Store{})
	for _, f := range got {
		if f.Check == "magento_settings_injection" {
			t.Errorf("Tag Manager embed in core_config_data classified as malicious: %+v", f)
		}
	}
}

// Regression: the previous dedup scanned prior findings for an
// "Account: <name>" marker, which only appeared after a finding
// fired. A clean M2 install (env.php parses, scans complete, zero
// findings) would still let the M1 fallback re-scan the same
// host with stale local.xml credentials. The seenAccounts map
// prevents that.
func TestCheckMagentoContentDedupSurvivesZeroFindingM2(t *testing.T) {
	withMockOS(t, &fakeMagentoOS{
		m1Body: canonicalM1XML(),
		m2Body: canonicalM2EnvPHP(),
	})

	prefixCounts := map[string]int{}
	withMockCmd(t, &mockCmd{
		runWithEnv: func(name string, args []string, _ ...string) ([]byte, error) {
			joined := strings.Join(args, " ")
			switch {
			case strings.Contains(joined, "m1_"):
				prefixCounts["m1"]++
			case strings.Contains(joined, "m2_"):
				prefixCounts["m2"]++
				// Return nothing -- M2 path produces zero findings.
			}
			return nil, nil
		},
	})

	_ = CheckMagentoContent(context.Background(), &config.Config{}, &state.Store{})

	if prefixCounts["m2"] == 0 {
		t.Error("M2 path not queried despite env.php presence")
	}
	if prefixCounts["m1"] > 0 {
		t.Errorf("M1 fallback re-scanned a host already covered by M2 (count=%d)", prefixCounts["m1"])
	}
}
