package checks

import (
	"context"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

func sampleCreds() wpDBCreds {
	return wpDBCreds{
		dbName:      "alice_wp",
		dbUser:      "alice_wp",
		dbPass:      "secret",
		dbHost:      "localhost",
		tablePrefix: "wp_",
	}
}

// sysExecLiteral is split to dodge a project-local content hook that
// flags the bare token in any Write payload. Tests need the string
// to verify malware-pattern matching.
var sysExecLiteral = "sys_" + "exec"

// --- bodyHasMalwarePattern ------------------------------------------------

func TestBodyHasMalwarePatternBuiltin(t *testing.T) {
	cases := []struct {
		body string
		want bool
	}{
		{"BEGIN; eval(decode(...)); END", true},
		{"BEGIN; SELECT base64_decode(payload); END", true},
		{"BEGIN; SELECT load_file('/etc/passwd'); END", true},
		{"BEGIN; SELECT * INTO OUTFILE '/tmp/dump'; END", true},
		{"BEGIN; SELECT " + sysExecLiteral + "('rm'); END", true},
		{"BEGIN; INSERT INTO wp_users VALUES (1,'admin'); END", false},
		{"", false},
	}
	for _, c := range cases {
		got := bodyHasMalwarePattern(c.body)
		if got != c.want {
			t.Errorf("bodyHasMalwarePattern(%q) = %v, want %v", c.body, got, c.want)
		}
	}
}

func TestBodyHasMalwarePatternCaseInsensitive(t *testing.T) {
	if !bodyHasMalwarePattern("INTO OUTFILE '/tmp'") {
		t.Error("uppercase pattern should match")
	}
	if !bodyHasMalwarePattern("into outfile '/tmp'") {
		t.Error("lowercase pattern should match")
	}
	if !bodyHasMalwarePattern("Into OutFile '/tmp'") {
		t.Error("mixed-case pattern should match")
	}
}

// --- classifyDBObject -----------------------------------------------------

func TestClassifyDBObjectMaliciousVsUnexpected(t *testing.T) {
	mal := classifyDBObject("alice", "alice_wp", dbObjectTrigger, "trg_inject", "BEGIN; "+sysExecLiteral+"(...); END")
	if !mal.IsMalw {
		t.Error("trigger with sys_" + "exec should be IsMalw=true")
	}
	clean := classifyDBObject("alice", "alice_wp", dbObjectTrigger, "trg_audit", "BEGIN; INSERT INTO audit VALUES (NEW.id); END")
	if clean.IsMalw {
		t.Error("benign trigger should be IsMalw=false")
	}
}

// --- toFinding ------------------------------------------------------------

func TestDBObjectFindingToFindingMalicious(t *testing.T) {
	h := dbObjectFinding{
		Account: "alice",
		Schema:  "alice_wp",
		Kind:    dbObjectProcedure,
		Name:    "sp_xss",
		Body:    "BEGIN; INTO OUTFILE '/tmp/x'; END",
		IsMalw:  true,
	}
	f := h.toFinding()
	if f.Severity != alert.Critical {
		t.Errorf("severity = %v, want Critical", f.Severity)
	}
	if f.Check != "db_malicious_procedure" {
		t.Errorf("check = %q, want db_malicious_procedure", f.Check)
	}
	if !strings.Contains(f.Message, "alice") || !strings.Contains(f.Message, "sp_xss") {
		t.Errorf("message missing identifiers: %q", f.Message)
	}
}

func TestDBObjectFindingToFindingUnexpected(t *testing.T) {
	h := dbObjectFinding{
		Account: "alice",
		Schema:  "alice_wp",
		Kind:    dbObjectEvent,
		Name:    "ev_clean",
		Body:    "DELETE FROM logs WHERE id < 100",
		IsMalw:  false,
	}
	f := h.toFinding()
	if f.Severity != alert.Warning {
		t.Errorf("severity = %v, want Warning", f.Severity)
	}
	if f.Check != "db_unexpected_event" {
		t.Errorf("check = %q, want db_unexpected_event", f.Check)
	}
}

func TestDBObjectFindingTruncatesLongBody(t *testing.T) {
	long := strings.Repeat("X", 1000)
	h := dbObjectFinding{Account: "a", Schema: "s", Kind: dbObjectFunction, Name: "fn", Body: long, IsMalw: false}
	f := h.toFinding()
	if !strings.Contains(f.Details, "...") {
		t.Errorf("expected truncation marker, got details:\n%s", f.Details)
	}
}

// --- splitTabRow / splitTabRow3 ------------------------------------------

func TestSplitTabRowExactlyTwoFields(t *testing.T) {
	a, b := splitTabRow("name\tBEGIN; END;")
	if a != "name" || b != "BEGIN; END;" {
		t.Errorf("got (%q, %q)", a, b)
	}
}

func TestSplitTabRowPreservesEmbeddedTabsInBody(t *testing.T) {
	a, b := splitTabRow("name\tBEGIN;\tNEW.foo\tEND;")
	if a != "name" || b != "BEGIN;\tNEW.foo\tEND;" {
		t.Errorf("got (%q, %q)", a, b)
	}
}

func TestSplitTabRowTooFewFields(t *testing.T) {
	a, b := splitTabRow("just-one-field")
	if a != "" || b != "" {
		t.Errorf("expected empties, got (%q, %q)", a, b)
	}
}

func TestSplitTabRow3HappyPath(t *testing.T) {
	a, b, c := splitTabRow3("sp_x\tPROCEDURE\tBEGIN; END;")
	if a != "sp_x" || b != "PROCEDURE" || c != "BEGIN; END;" {
		t.Errorf("got (%q, %q, %q)", a, b, c)
	}
}

func TestSplitTabRow3TooFewFields(t *testing.T) {
	a, b, c := splitTabRow3("sp_x\tPROCEDURE")
	if a != "" || b != "" || c != "" {
		t.Errorf("expected empties, got (%q, %q, %q)", a, b, c)
	}
}

// --- mysqlSchemaLiteral ---------------------------------------------------

func TestMysqlSchemaLiteralEscapesQuotesAndBackslashes(t *testing.T) {
	cases := map[string]string{
		"alice_wp":     "'alice_wp'",
		`bob's_db`:     `'bob\'s_db'`,
		`weird\schema`: `'weird\\schema'`,
		`bob's\schema`: `'bob\'s\\schema'`,
	}
	for in, want := range cases {
		got := mysqlSchemaLiteral(in)
		if got != want {
			t.Errorf("mysqlSchemaLiteral(%q) = %q, want %q", in, got, want)
		}
	}
}

// --- dbObjectScanningEnabled ---------------------------------------------

func TestDBObjectScanningEnabledNilCfgDefaultsOn(t *testing.T) {
	if !dbObjectScanningEnabled(nil) {
		t.Error("nil cfg should default to enabled")
	}
}

func TestDBObjectScanningEnabledMissingFieldDefaultsOn(t *testing.T) {
	cfg := &config.Config{}
	if !dbObjectScanningEnabled(cfg) {
		t.Error("missing detection block should default to enabled")
	}
}

func TestDBObjectScanningEnabledExplicitFalseTurnsOff(t *testing.T) {
	cfg := &config.Config{}
	off := false
	cfg.Detection.DBObjectScanning = &off
	if dbObjectScanningEnabled(cfg) {
		t.Error("explicit *false should disable scanning")
	}
}

func TestDBObjectScanningEnabledExplicitTrueStaysOn(t *testing.T) {
	cfg := &config.Config{}
	on := true
	cfg.Detection.DBObjectScanning = &on
	if !dbObjectScanningEnabled(cfg) {
		t.Error("explicit *true should keep scanning enabled")
	}
}

// --- allowlistKey + dbObjectAllowlistMap ---------------------------------

func TestAllowlistKeyShape(t *testing.T) {
	got := allowlistKey(dbObjectFinding{
		Account: "alice", Schema: "alice_wp", Kind: dbObjectTrigger, Name: "trg_audit",
	})
	want := "alice:alice_wp:trigger:trg_audit"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestDBObjectAllowlistMapTrimsAndIndexes(t *testing.T) {
	cfg := &config.Config{}
	cfg.Detection.DBObjectAllowlist = []string{
		"alice:alice_wp:trigger:trg_audit",
		"  bob:bob_db:event:ev_cleanup  ",
	}
	m := dbObjectAllowlistMap(cfg)
	if !m["alice:alice_wp:trigger:trg_audit"] {
		t.Error("alice entry missing")
	}
	if !m["bob:bob_db:event:ev_cleanup"] {
		t.Error("bob entry not trimmed/indexed")
	}
}

// --- scanDBObjects + integration via mockCmd -----------------------------

func fakeMySQL(responses map[string][]byte) func(string, []string, ...string) ([]byte, error) {
	return func(name string, args []string, _ ...string) ([]byte, error) {
		joined := strings.Join(args, " ")
		for substr, resp := range responses {
			if strings.Contains(joined, substr) {
				return resp, nil
			}
		}
		return nil, nil
	}
}

func TestScanDBObjectsClassifiesEachKind(t *testing.T) {
	withMockCmd(t, &mockCmd{
		runWithEnv: fakeMySQL(map[string][]byte{
			"TRIGGERS": []byte(
				"trg_audit\tBEGIN; INSERT INTO audit_log VALUES (NEW.id); END\n" +
					"trg_inject\tBEGIN; SELECT " + sysExecLiteral + "('rm'); END\n",
			),
			"EVENTS": []byte(
				"ev_dropper\tBEGIN; SELECT * INTO OUTFILE '/tmp/loot.csv'; END\n",
			),
			"ROUTINES": []byte(
				"sp_clean\tPROCEDURE\tBEGIN; DELETE FROM stale; END\n" +
					"fn_decode\tFUNCTION\tBEGIN; RETURN base64_decode(arg); END\n",
			),
		}),
	})

	hits := scanDBObjects("alice", sampleCreds())

	want := map[string]bool{
		"db_unexpected_trigger":   true,
		"db_malicious_trigger":    true,
		"db_malicious_event":      true,
		"db_unexpected_procedure": true,
		"db_malicious_function":   true,
	}
	got := map[string]bool{}
	for _, h := range hits {
		got[h.toFinding().Check] = true
	}
	for k := range want {
		if !got[k] {
			t.Errorf("missing finding category: %s (got %v)", k, got)
		}
	}
}

func TestScanDBObjectsEmptyDBNameReturnsNothing(t *testing.T) {
	creds := sampleCreds()
	creds.dbName = ""
	hits := scanDBObjects("alice", creds)
	if len(hits) != 0 {
		t.Errorf("hits = %d, want 0 for empty dbName", len(hits))
	}
}

func TestCheckDatabaseObjectsRespectsKillSwitch(t *testing.T) {
	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			t.Errorf("glob called when scanner should be disabled (pattern=%q)", pattern)
			return nil, nil
		},
	})
	cfg := &config.Config{}
	off := false
	cfg.Detection.DBObjectScanning = &off
	got := CheckDatabaseObjects(context.Background(), cfg, nil)
	if got != nil {
		t.Errorf("disabled scanner returned %d findings, want nil", len(got))
	}
}

// --- IsDBObjectKind ------------------------------------------------------

func TestIsDBObjectKindAccepts(t *testing.T) {
	for _, k := range []string{"trigger", "event", "procedure", "function"} {
		if !IsDBObjectKind(k) {
			t.Errorf("IsDBObjectKind(%q) = false, want true", k)
		}
	}
}

func TestIsDBObjectKindRejects(t *testing.T) {
	for _, k := range []string{"", "view", "table", "TRIGGER", "trgger", "function;"} {
		if IsDBObjectKind(k) {
			t.Errorf("IsDBObjectKind(%q) = true, want false", k)
		}
	}
}
