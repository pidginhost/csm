package checks

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
)

// Framework/vendor/downloaded-project sample schemas are still served (a real
// exposure) but are lower-risk than a customer database dump. Demotion needs
// sample-specific file and directory context so ambiguous dumps remain
// Critical.
func TestIsSampleSQLPath(t *testing.T) {
	cases := []struct {
		rel  string
		want bool
	}{
		// Framework/sample/vendor/downloaded-project directory markers.
		{"/ajaxCRUD/examples/example.sql", true},
		{"/cacti/docs/audit_schema.sql", true},
		{"/guestbook/doc/db_update_v22-23.sql", true},
		{"/crud-php-simple-master/database.sql", true},
		{"/wp-content/plugins/thing-main/install.sql", true},
		{"/vendor/acme/orm/schema.sql", true},
		{"/node_modules/pkg/fixtures/seed.sql", true},
		{"/Examples/Demo/setup.sql", true}, // case-insensitive

		// Real customer dumps -- must NOT be demoted.
		{"/softsql.sql", false},                 // docroot root
		{"/db/wizarddesign_wp8.sql", false},     // db/ is not a marker
		{"/napa/mxtskbtehv.sql", false},         // arbitrary app dir
		{"/backups/customerdb.sql.zip", false},  // real backup dir
		{"/database/dump.sql", false},           // database/ is not a marker
		{"/crud/calendar/database.sql", false},  // no marker segment
		{"/private/exports/clients.sql", false}, // exports != examples
		{"/examples/customer.sql", false},       // directory alone is insufficient
		{"/docs/customer-backup.sql", false},    // customer-named dump
		{"/vendor/prod.dump", false},            // only plain .sql schemas demote
		{"/testdata/rows.sql.gz", false},        // compressed contents are ambiguous
		{"/examples/schema.sql.old", false},     // renamed files are ambiguous
		{"/shop-main/customer.sql", false},      // archive suffix alone is insufficient
		{"/-main/database.sql", false},          // suffix needs a project name
	}
	for _, c := range cases {
		if got := isSampleSQLPath(c.rel); got != c.want {
			t.Errorf("isSampleSQLPath(%q)=%v want %v", c.rel, got, c.want)
		}
	}
}

func TestDemoteSampleSQL(t *testing.T) {
	cases := []struct {
		name string
		in   exposedClass
		rel  string
		want exposedClass
	}{
		{"db dump in examples demotes", classDBDump, "/x/examples/example.sql", classSampleSQL},
		{"db dump real stays", classDBDump, "/db/customer.sql", classDBDump},
		{"customer dump in examples stays", classDBDump, "/examples/customer.sql", classDBDump},
		{"archived sample stays", classDBDump, "/examples/example.sql.gz", classDBDump},
		{"renamed sample stays", classDBDump, "/examples/schema.sql.old", classDBDump},
		{"backup archive never demoted", classBackupArchive, "/examples/full.zip", classBackupArchive},
		{"config leak never demoted", classConfigLeak, "/examples/.env", classConfigLeak},
		{"source backup never demoted", classSourceBackup, "/docs/index.php.old", classSourceBackup},
		{"none stays none", classNone, "/examples/x.sql", classNone},
	}
	for _, c := range cases {
		if got := demoteSampleSQL(c.in, c.rel); got != c.want {
			t.Errorf("%s: demoteSampleSQL(%v,%q)=%v want %v", c.name, c.in, c.rel, got, c.want)
		}
	}
}

func TestScanVhostsDemotesOnlySpecificSampleSQL(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "examples", "example.sql"), "-- schema\n")
	mustWrite(t, filepath.Join(root, "examples", "customer.sql"), "-- dump\n")
	mustWrite(t, filepath.Join(root, "examples", "schema.sql.old"), "-- renamed dump\n")
	mustWrite(t, filepath.Join(root, "docs", "schema.sql.gz"), "compressed dump")

	withFakeProbe(t, &fakeProbe{byPath: map[string]probeResult{
		"/examples/example.sql":  {status: 200, contentType: "text/x-sql", reachable: true},
		"/examples/customer.sql": {status: 200, contentType: "text/x-sql", reachable: true},
		"/examples/schema.sql.old": {
			status: 200, contentType: "text/x-sql", reachable: true,
		},
		"/docs/schema.sql.gz": {status: 200, contentType: "application/gzip", reachable: true},
	}})

	findings := scanVhostsForExposure(context.Background(), []vhost{{
		domain: "example.com", user: "alice", typ: "main", docroot: root, ip: "192.0.2.10",
	}}, nil)
	if len(findings) != 4 {
		t.Fatalf("findings = %+v, want four confirmed exposures", findings)
	}

	counts := map[string]int{}
	for _, finding := range findings {
		counts[finding.Check]++
		if finding.Check == "web_exposed_sample_sql" && finding.Severity != alert.Warning {
			t.Errorf("sample finding severity = %v, want Warning", finding.Severity)
		}
		if finding.Check == "web_exposed_db_dump" && finding.Severity != alert.Critical {
			t.Errorf("database dump severity = %v, want Critical", finding.Severity)
		}
	}
	if counts["web_exposed_sample_sql"] != 1 || counts["web_exposed_db_dump"] != 3 {
		t.Fatalf("finding counts = %v, want one sample warning and three critical dumps", counts)
	}
}

func TestSampleSQLClassMeta(t *testing.T) {
	if got := classSampleSQL.severity(); got != alert.Warning {
		t.Errorf("classSampleSQL severity=%v want Warning", got)
	}
	if got := classSampleSQL.findingName(); got != "web_exposed_sample_sql" {
		t.Errorf("classSampleSQL findingName=%q want web_exposed_sample_sql", got)
	}
	if got := exposureLabel(classSampleSQL); got == "" || got == "sensitive file" {
		t.Errorf("classSampleSQL exposureLabel=%q want specific label", got)
	}
}

// A confirmed, raw-served sample .sql is still a real reachable file, so
// confirmExposure must treat it like any other non-executing leak class.
func TestSampleSQLConfirmed(t *testing.T) {
	pr := probeResult{status: 200, contentType: "application/octet-stream", reachable: true}
	if !confirmExposure(classSampleSQL, pr) {
		t.Error("raw-served sample .sql should be confirmed")
	}
	html := probeResult{status: 200, contentType: "text/html", reachable: true}
	if confirmExposure(classSampleSQL, html) {
		t.Error("html-served sample .sql should not be confirmed")
	}
}
