package checks

import (
	"context"
	"os"
	"testing"

	"github.com/pidginhost/csm/internal/mysqlclient"
)

// cmsVerifyOS stubs osFS for the non-WordPress CMS DB re-checks: ReadFile serves
// canned config files and Stat answers the Drupal core marker probe.
type cmsVerifyOS struct {
	mockOS
	files  map[string]string
	statOK map[string]bool
}

func (m *cmsVerifyOS) ReadFile(name string) ([]byte, error) {
	if c, ok := m.files[name]; ok {
		return []byte(c), nil
	}
	return nil, os.ErrNotExist
}

func (m *cmsVerifyOS) Stat(name string) (os.FileInfo, error) {
	if m.statOK[name] {
		return os.Stat(os.TempDir())
	}
	return nil, os.ErrNotExist
}

func withCMSVerifyOS(t *testing.T, files map[string]string, statOK map[string]bool) {
	t.Helper()
	old := osFS
	osFS = &cmsVerifyOS{files: files, statOK: statOK}
	t.Cleanup(func() { osFS = old })
}

const drupalSettings = `<?php
$databases['default']['default'] = array('database' => 'drupal_db', 'username' => 'du', 'password' => 'p', 'host' => 'localhost');
`

const joomlaConfig = `<?php class JConfig {
public $host = 'localhost';
public $user = 'ju';
public $password = 'p';
public $db = 'joomla_db';
public $dbprefix = 'jos_';
}`

const magentoEnv = `<?php return ['db' => ['connection' => ['default' => ['host' => 'localhost', 'username' => 'mu', 'password' => 'p', 'dbname' => 'magento_db', 'table_prefix' => '']]]];`

const opencartConfig = `<?php
define('DB_DRIVER', 'mysqli');
define('DB_HOSTNAME', 'localhost');
define('DB_USERNAME', 'ou');
define('DB_PASSWORD', 'p');
define('DB_DATABASE', 'oc_db');
define('DB_PREFIX', 'oc_');
`

func drupalFiles() (map[string]string, map[string]bool) {
	return map[string]string{
			"/home/bob/public_html/sites/default/settings.php": drupalSettings,
		}, map[string]bool{
			"/home/bob/public_html/core/lib/Drupal.php": true,
		}
}

func joomlaFiles() map[string]string {
	return map[string]string{"/home/bob/public_html/configuration.php": joomlaConfig}
}

func magentoFiles() map[string]string {
	return map[string]string{"/home/bob/public_html/app/etc/env.php": magentoEnv}
}

func opencartFiles() map[string]string {
	return map[string]string{
		"/home/bob/public_html/config.php":       opencartConfig,
		"/home/bob/public_html/admin/config.php": opencartConfig,
	}
}

// cmsCase is one table-driven CMS verifier scenario.
type cmsCase struct {
	name    string
	verify  func(message, details string) VerifyResult
	message string
	details string
	schema  string
}

func runCMSResolvedUnresolved(t *testing.T, setup func(t *testing.T), c cmsCase) {
	t.Helper()
	t.Run(c.name+"/resolved", func(t *testing.T) {
		setup(t)
		withRootQuery(t, func(schema, query string, _ ...any) ([]string, error) {
			if c.schema != "" && schema != c.schema {
				t.Errorf("schema = %q, want %q", schema, c.schema)
			}
			return nil, nil // row gone
		})
		res := c.verify(c.message, c.details)
		if !res.Checked || !res.Resolved {
			t.Errorf("want checked+resolved, got %+v", res)
		}
	})
	t.Run(c.name+"/unresolved", func(t *testing.T) {
		setup(t)
		withRootQuery(t, func(_, query string, _ ...any) ([]string, error) {
			return []string{"bad eval(base64_decode($x))"}, nil
		})
		res := c.verify(c.message, c.details)
		if !res.Checked || res.Resolved {
			t.Errorf("want checked+unresolved, got %+v", res)
		}
	})
	t.Run(c.name+"/query-error-not-checked", func(t *testing.T) {
		setup(t)
		withRootQuery(t, func(_, _ string, _ ...any) ([]string, error) {
			return nil, context.DeadlineExceeded
		})
		res := c.verify(c.message, c.details)
		if res.Checked {
			t.Errorf("query error must not be checked, got %+v", res)
		}
	})
}

func TestVerifyDrupalInjection(t *testing.T) {
	setup := func(t *testing.T) {
		f, s := drupalFiles()
		withCMSVerifyOS(t, f, s)
	}
	runCMSResolvedUnresolved(t, setup, cmsCase{
		name:    "settings",
		verify:  verifyDrupalSettingsInjection,
		message: "Drupal config injection on bob: system.site (eval)",
		details: "Account: bob\nConfig name: system.site\nMatch: eval",
		schema:  "drupal_db",
	})
	runCMSResolvedUnresolved(t, setup, cmsCase{
		name:    "content",
		verify:  verifyDrupalContentInjection,
		message: "Drupal article content injection on bob: node 42 (eval)",
		details: "Account: bob\nNode entity_id: 42\nMatch: eval",
		schema:  "drupal_db",
	})
}

func TestVerifyJoomlaInjection(t *testing.T) {
	setup := func(t *testing.T) { withCMSVerifyOS(t, joomlaFiles(), nil) }
	runCMSResolvedUnresolved(t, setup, cmsCase{
		name:    "extensions",
		verify:  verifyJoomlaExtensionsInjection,
		message: "Joomla extension params injection on bob: com_foo (eval)",
		details: "Account: bob\nExtension: com_foo\nMatch: eval",
		schema:  "joomla_db",
	})
	runCMSResolvedUnresolved(t, setup, cmsCase{
		name:    "content",
		verify:  verifyJoomlaContentInjection,
		message: "Joomla article content injection on bob: id=7 title=\"x\" (eval)",
		details: "Account: bob\nArticle ID: 7\nTitle: x\nMatch: eval",
		schema:  "joomla_db",
	})
}

func TestVerifyMagentoInjection(t *testing.T) {
	setup := func(t *testing.T) { withCMSVerifyOS(t, magentoFiles(), nil) }
	runCMSResolvedUnresolved(t, setup, cmsCase{
		name:    "settings",
		verify:  verifyMagentoSettingsInjection,
		message: "Magento M2 settings injection on bob: web/unsecure/base_url (eval)",
		details: "Account: bob\nConfig path: web/unsecure/base_url\nMatch: eval",
		schema:  "magento_db",
	})
	runCMSResolvedUnresolved(t, setup, cmsCase{
		name:    "content",
		verify:  verifyMagentoContentInjection,
		message: "Magento M2 content injection on bob: cms_block id=3 (eval)",
		details: "Account: bob\nTable: cms_block\nRow id: 3\nMatch: eval",
		schema:  "magento_db",
	})
}

func TestVerifyOpenCartInjection(t *testing.T) {
	setup := func(t *testing.T) { withCMSVerifyOS(t, opencartFiles(), nil) }
	runCMSResolvedUnresolved(t, setup, cmsCase{
		name:    "settings",
		verify:  verifyOpenCartSettingsInjection,
		message: "OpenCart settings injection on bob: config_url (eval)",
		details: "Account: bob\nSetting key: config_url\nMatch: eval",
		schema:  "oc_db",
	})
	runCMSResolvedUnresolved(t, setup, cmsCase{
		name:    "content",
		verify:  verifyOpenCartContentInjection,
		message: "OpenCart content injection on bob: product_description id=9 (eval)",
		details: "Account: bob\nTable: product_description\nRow id: 9\nMatch: eval",
		schema:  "oc_db",
	})
}

func TestVerifyCMSNotLocatable(t *testing.T) {
	// No config files present -> cannot discover -> Checked:false, never resolved.
	withCMSVerifyOS(t, map[string]string{}, nil)
	mysqlclient.SetRootQueryForTest(func(_ context.Context, _, _ string, _ ...any) ([]string, error) {
		t.Fatal("query must not run without discovery")
		return nil, nil
	})
	t.Cleanup(func() { mysqlclient.SetRootQueryForTest(nil) })
	res := verifyJoomlaContentInjection(
		"Joomla article content injection on bob: id=7",
		"Account: bob\nArticle ID: 7")
	if res.Checked {
		t.Errorf("missing discovery must not be checked, got %+v", res)
	}
}

func TestVerifyMagentoContentRejectsUnknownTable(t *testing.T) {
	withCMSVerifyOS(t, magentoFiles(), nil)
	res := verifyMagentoContentInjection(
		"Magento content injection on bob",
		"Account: bob\nTable: evil_table\nRow id: 3")
	if res.Checked {
		t.Errorf("unknown table must not be checked, got %+v", res)
	}
}
