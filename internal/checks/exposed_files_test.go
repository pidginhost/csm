package checks

import (
	"testing"

	"github.com/pidginhost/csm/internal/alert"
)

// classifyExposedFile is the pure name-based classifier for the web-exposed
// sensitive-file detector. These cases are taken from real docroot contents
// observed on a production cPanel host: the benign long tail (wp-config-sample,
// .env.example) dwarfs the real leaks, and files whose final extension still
// executes under the PHP handler are NOT source leaks.
func TestClassifyExposedFile(t *testing.T) {
	cases := []struct {
		name string
		want exposedClass
	}{
		// Database dumps served as raw downloads.
		{"softsql.sql", classDBDump},
		{"hospitalitycult_91.sql.zip", classDBDump},
		{"backup.sql.gz", classDBDump},
		{"cluster.sql.bz2", classDBDump},
		{"database.dump", classDBDump},
		{"site.mysql", classDBDump},

		// Full-site backup archives.
		{"Backup Apr 24 2024.tar.gz", classBackupArchive},
		{"site.wpress", classBackupArchive},
		{"public_html-backup.zip", classBackupArchive},
		{"wpvivid-backup-2024.zip", classBackupArchive},
		{"updraft-full.tar", classBackupArchive},

		// Config / secret leaks (credential exposure) served as text.
		{".env", classConfigLeak},
		{".env.local", classConfigLeak},
		{".env.production", classConfigLeak},
		{"wp-config.php.bak-20260515-124446", classConfigLeak},
		{"wp-config.php.broken", classConfigLeak},
		{"wp-config.php.save", classConfigLeak},
		{"config.php.old", classConfigLeak},
		{"configuration.php.bak", classConfigLeak},

		// Generic PHP source backups served as text (logic + often creds).
		{"body.php.old", classSourceBackup},
		{"meniu-jos.inc.php.old", classSourceBackup},
		{"index.php.bak", classSourceBackup},
		{"functions.php~", classSourceBackup},
		{"header.php.orig", classSourceBackup},

		// Diagnostics (info disclosure), detected by name.
		{"phpinfo.php", classPHPInfo},
		{"info.php", classPHPInfo},

		// Benign long tail -- MUST NOT flag (these are the FP class that
		// swamps a naive detector: 272 of 274 config-backup hits were samples).
		{"wp-config-sample.php", classNone},
		{".env.example", classNone},
		{".env.sample", classNone},
		{".env.dist", classNone},
		{"wp-config.php", classNone}, // live config, executes -> no source leak
		{"config.php", classNone},    // live config, executes
		{"index.php", classNone},     // ordinary script
		{"style.css", classNone},     // ordinary asset
		{"readme.html", classNone},   // ships with WordPress
		{"backup.php", classNone},    // .php executes; not a dump
		{".htaccess", classNone},     // not our class

		// Backups whose FINAL extension still executes under PHP are NOT
		// source leaks -- the handler runs them and emits no source.
		{"wp-config-backup-60e8994dc80a08.php", classNone},
		{"wp-config.php.original.php", classNone},
	}

	for _, tc := range cases {
		if got := classifyExposedFile(tc.name); got != tc.want {
			t.Errorf("classifyExposedFile(%q) = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestExposedClassSeverity(t *testing.T) {
	cases := []struct {
		class exposedClass
		want  alert.Severity
	}{
		{classConfigLeak, alert.Critical},
		{classDBDump, alert.Critical},
		{classBackupArchive, alert.Critical},
		{classSourceBackup, alert.High},
		{classPHPInfo, alert.Warning},
	}
	for _, tc := range cases {
		if got := tc.class.severity(); got != tc.want {
			t.Errorf("%v.severity() = %v, want %v", tc.class, got, tc.want)
		}
	}
}

func TestExposedClassFindingNameStable(t *testing.T) {
	// Finding names are the registry keys and the audit-log contract; they
	// must be stable and distinct per class.
	seen := map[string]bool{}
	for _, c := range []exposedClass{classConfigLeak, classDBDump, classBackupArchive, classSourceBackup, classPHPInfo} {
		name := c.findingName()
		if name == "" {
			t.Errorf("class %v has empty finding name", c)
		}
		if seen[name] {
			t.Errorf("duplicate finding name %q", name)
		}
		seen[name] = true
	}
}
