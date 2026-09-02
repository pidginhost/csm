package checks

import (
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/store"
)

// The structural classifier only flags attacker markers (raw IP, abused TLD,
// plaintext HTTP, exfil hosts). A loader on an unremarkable HTTPS host on a
// mainstream TLD never produced a db_options finding, which is exactly the
// shape a careful injection takes. Hosts that are neither known-safe nor
// structurally malicious are reported once, as a Warning, when they first
// appear after the site's baseline.
func TestNewExternalScriptHostsInOptionsReportedOnceAsWarning(t *testing.T) {
	seen := map[string]bool{"widget_text|cdn.vendor.example": true}
	firstSeen := func(option, host string) bool {
		key := option + "|" + host
		if seen[key] {
			return false
		}
		seen[key] = true
		return true
	}
	value := `<script src="https://cdn.vendor.example/w.js"></script>` +
		`<script src="https://static.loader-example.com/t.js"></script>` +
		`<script src="https://www.googletagmanager.com/gtm.js"></script>`

	findings := newExternalScriptFindings("alice", wpDBCreds{dbName: "alice_wp"}, "wp_", "widget_text", value, firstSeen)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want exactly one for the unseen non-safe host: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Check != "db_options_new_external_script" || f.Severity != alert.Warning {
		t.Fatalf("finding = %s/%s, want db_options_new_external_script/Warning", f.Check, f.Severity)
	}
	if !strings.Contains(f.Details, "Script host: static.loader-example.com") || strings.Contains(f.Details, "Script host: cdn.vendor.example") {
		t.Fatalf("details name the wrong host: %s", f.Details)
	}
	if again := newExternalScriptFindings("alice", wpDBCreds{dbName: "alice_wp"}, "wp_", "widget_text", value, firstSeen); len(again) != 0 {
		t.Fatalf("host reported again on the next scan: %+v", again)
	}
}

func TestExternalScriptBaselineWaitsForSuccessfulQuery(t *testing.T) {
	withFreshStore(t)
	sdb := store.Global()
	failed := false
	previous := runMySQLQuery
	runMySQLQuery = func(_ wpDBCreds, query string) []string {
		if strings.Contains(query, "option_value LIKE '%<script%src%'") {
			failed = true
		}
		return nil
	}
	t.Cleanup(func() { runMySQLQuery = previous })

	creds := wpDBCreds{dbName: "alice_wp", queryFailed: &failed}
	_ = checkWPOptions("alice", creds, "wp_")
	isNew, err := sdb.MarkExternalScriptSeen(externalScriptSiteKey(creds.dbName, "wp_"), "widget_text", "cdn.example", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if isNew {
		t.Fatal("failed wp_options query incorrectly completed the external-script baseline")
	}
}

// A structurally malicious loader stays on the Critical path and is not
// duplicated as a new-host warning.
func TestNewExternalScriptHostsSkipStructurallyMaliciousLoaders(t *testing.T) {
	value := `<script src="http://203.0.113.9/x.js"></script>`
	findings := newExternalScriptFindings("alice", wpDBCreds{dbName: "alice_wp"}, "wp_", "widget_text", value, func(string, string) bool { return true })
	if len(findings) != 0 {
		t.Fatalf("raw-IP loader duplicated as a new-host warning: %+v", findings)
	}
}
