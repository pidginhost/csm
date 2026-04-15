package checks

import (
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// AutoRespondDBMalware behaviour:
//   - AutoResponse.Enabled=false → nil
//   - AutoResponse.CleanDatabase=false → nil
//   - Finding.Check outside the whitelist → skipped
//   - db_options_injection / db_siteurl_hijack → dispatched to handlers
//
// The handlers themselves require real mysql + wp-config parsing to do
// anything meaningful, so tests here verify the dispatch guard only.

func TestAutoRespondDBMalwareDisabledReturnsNil(t *testing.T) {
	cfg := &config.Config{}
	// Enabled defaults to false.
	got := AutoRespondDBMalware(cfg, []alert.Finding{
		{Check: "db_options_injection", Details: "db=wp option=siteurl"},
	})
	if got != nil {
		t.Errorf("disabled auto-response should yield nil, got %d actions", len(got))
	}
}

func TestAutoRespondDBMalwareCleanDatabaseOffReturnsNil(t *testing.T) {
	cfg := &config.Config{}
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.CleanDatabase = false
	got := AutoRespondDBMalware(cfg, []alert.Finding{
		{Check: "db_siteurl_hijack", Details: "db=wp"},
	})
	if got != nil {
		t.Errorf("CleanDatabase=false should yield nil, got %d actions", len(got))
	}
}

func TestAutoRespondDBMalwareIgnoresNonDBChecks(t *testing.T) {
	cfg := &config.Config{}
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.CleanDatabase = true
	// Checks outside the dispatcher (spam/post injection, webshells, etc.)
	// must be ignored per the function doc comment.
	got := AutoRespondDBMalware(cfg, []alert.Finding{
		{Check: "db_spam_injection", Details: "db=wp"},
		{Check: "db_post_injection", Details: "db=wp"},
		{Check: "webshell", FilePath: "/tmp/x.php"},
	})
	if len(got) != 0 {
		t.Errorf("non-dispatched check types should yield no actions, got %+v", got)
	}
}

func TestAutoRespondDBMalwareSkipsEmptyDetails(t *testing.T) {
	cfg := &config.Config{}
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.CleanDatabase = true
	// No details → parseDBFindingDetails yields empty strings → handler early-returns nil.
	got := AutoRespondDBMalware(cfg, []alert.Finding{
		{Check: "db_options_injection", Details: ""},
		{Check: "db_siteurl_hijack", Details: ""},
	})
	if len(got) != 0 {
		t.Errorf("empty details should yield no actions, got %+v", got)
	}
}

// parseDBFindingDetails extracts db=... option=... from the finding details blob.

func TestParseDBFindingDetailsExtractsFields(t *testing.T) {
	cases := []struct {
		in         string
		wantDB     string
		wantOption string
	}{
		{"Database: alice_wp\nOption: siteurl\nValue: http://evil", "alice_wp", "siteurl"},
		{"Database: alice_wp\nOption: active_plugins", "alice_wp", "active_plugins"},
		{"  Database: trimmed  \n  Option: home  ", "trimmed", "home"},
		{"no match at all", "", ""},
		{"Database: only-db", "only-db", ""},
		{"Option: only-option", "", "only-option"},
	}
	for _, c := range cases {
		db, opt := parseDBFindingDetails(c.in)
		if db != c.wantDB || opt != c.wantOption {
			t.Errorf("parseDBFindingDetails(%q) = (%q, %q); want (%q, %q)",
				c.in, db, opt, c.wantDB, c.wantOption)
		}
	}
}
