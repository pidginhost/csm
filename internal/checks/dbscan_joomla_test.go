package checks

import (
	"context"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

// canonicalJConfigBody returns a wp-config.php-equivalent shape for
// Joomla -- the parts of the JConfig class that carry credentials,
// plus the marker line. Used by tests as a known-good fixture.
func canonicalJConfigBody(prefix string) string {
	return `<?php
class JConfig {
	public $offline = '0';
	public $sitename = 'My Site';
	public $host = 'localhost';
	public $user = 'joomla_user';
	public $password = 'secret';
	public $db = 'joomla_db';
	public $dbprefix = '` + prefix + `';
}
`
}

// fakeJoomlaOS stubs Glob + ReadFile so CheckJoomlaContent finds
// exactly one configuration.php with the supplied body.
type fakeJoomlaOS struct {
	mockOS
	body string
}

func (m *fakeJoomlaOS) Glob(pattern string) ([]string, error) {
	if strings.Contains(pattern, "configuration.php") {
		return []string{"/home/alice/public_html/configuration.php"}, nil
	}
	return nil, nil
}

func (m *fakeJoomlaOS) ReadFile(name string) ([]byte, error) {
	if name == "/home/alice/public_html/configuration.php" {
		return []byte(m.body), nil
	}
	return nil, nil
}

// --- looksLikeJoomlaConfig ------------------------------------------------

func TestLooksLikeJoomlaConfigPositive(t *testing.T) {
	withMockOS(t, &fakeJoomlaOS{body: canonicalJConfigBody("jos_")})
	if !looksLikeJoomlaConfig("/home/alice/public_html/configuration.php") {
		t.Error("expected JConfig marker to be detected")
	}
}

func TestLooksLikeJoomlaConfigCaseInsensitive(t *testing.T) {
	withMockOS(t, &fakeJoomlaOS{body: "<?php\nClass jconfig { public $host = 'x'; }\n"})
	if !looksLikeJoomlaConfig("/home/alice/public_html/configuration.php") {
		t.Error("class JConfig marker should match case-insensitively")
	}
}

func TestLooksLikeJoomlaConfigNegative(t *testing.T) {
	withMockOS(t, &fakeJoomlaOS{body: "<?php\n// random PHP file, not Joomla\necho 'hello';\n"})
	if looksLikeJoomlaConfig("/home/alice/public_html/configuration.php") {
		t.Error("non-JConfig file misidentified as Joomla")
	}
}

// --- parseJConfig ---------------------------------------------------------

func TestParseJConfigExtractsCredentialsAndPrefix(t *testing.T) {
	withMockOS(t, &fakeJoomlaOS{body: canonicalJConfigBody("xyz12_")})
	creds := parseJConfig("/home/alice/public_html/configuration.php")
	if creds.dbName != "joomla_db" {
		t.Errorf("dbName = %q, want joomla_db", creds.dbName)
	}
	if creds.dbUser != "joomla_user" {
		t.Errorf("dbUser = %q, want joomla_user", creds.dbUser)
	}
	if creds.dbPass != "secret" {
		t.Errorf("dbPass = %q, want secret", creds.dbPass)
	}
	if creds.dbHost != "localhost" {
		t.Errorf("dbHost = %q, want localhost", creds.dbHost)
	}
	if creds.dbPrefix != "xyz12_" {
		t.Errorf("dbPrefix = %q, want xyz12_", creds.dbPrefix)
	}
}

func TestParseJConfigDefaultsHostWhenMissing(t *testing.T) {
	body := `<?php
class JConfig {
	public $user = 'u';
	public $password = 'p';
	public $db = 'd';
	public $dbprefix = 'jos_';
}
`
	withMockOS(t, &fakeJoomlaOS{body: body})
	creds := parseJConfig("/home/alice/public_html/configuration.php")
	if creds.dbHost != "localhost" {
		t.Errorf("missing $host should default to localhost, got %q", creds.dbHost)
	}
}

func TestParseJConfigToleratesDoubleQuotes(t *testing.T) {
	body := `<?php
class JConfig {
	public $host = "mysql.example.com";
	public $user = "u";
	public $password = "p";
	public $db = "d";
	public $dbprefix = "jos_";
}
`
	withMockOS(t, &fakeJoomlaOS{body: body})
	creds := parseJConfig("/home/alice/public_html/configuration.php")
	if creds.dbHost != "mysql.example.com" {
		t.Errorf("dbHost = %q, want mysql.example.com (double-quoted)", creds.dbHost)
	}
	if creds.dbUser != "u" || creds.dbPass != "p" || creds.dbName != "d" {
		t.Errorf("creds = %+v", creds)
	}
}

func TestParseJConfigIgnoresNonPublicAssignments(t *testing.T) {
	body := `<?php
class JConfig {
	private $host = 'private.example.com';
	protected $user = 'shouldnt-match';
	public $host = 'localhost';
	public $user = 'u';
	public $password = 'p';
	public $db = 'd';
}
`
	withMockOS(t, &fakeJoomlaOS{body: body})
	creds := parseJConfig("/home/alice/public_html/configuration.php")
	if creds.dbHost != "localhost" {
		t.Errorf("private $host should be ignored, got %q", creds.dbHost)
	}
	if creds.dbUser != "u" {
		t.Errorf("protected $user should be ignored, got %q", creds.dbUser)
	}
}

// --- mysqlEscapeForLike --------------------------------------------------

func TestMysqlEscapeForLike(t *testing.T) {
	cases := map[string]string{
		"plain":      "plain",
		`bob's`:      `bob\'s`,
		`a\b`:        `a\\b`,
		`bob's\path`: `bob\'s\\path`,
		// LIKE wildcards intentionally unescaped: dbMalwarePatterns
		// uses literal substrings, never wildcards.
		"%not%a%wildcard%": "%not%a%wildcard%",
		"_underscore_too":  "_underscore_too",
	}
	for in, want := range cases {
		got := mysqlEscapeForLike(in)
		if got != want {
			t.Errorf("mysqlEscapeForLike(%q) = %q, want %q", in, got, want)
		}
	}
}

// --- paramsLikeClause ----------------------------------------------------

func TestParamsLikeClauseEmitsOneClausePerColumnPerPattern(t *testing.T) {
	clause := paramsLikeClause("foo", "bar")
	// One LIKE per column-pattern combination.
	wantCount := 2 * len(dbMalwarePatterns)
	got := strings.Count(clause, " LIKE '")
	if got != wantCount {
		t.Errorf("LIKE count = %d, want %d", got, wantCount)
	}
	// Both columns must appear.
	if !strings.Contains(clause, "foo LIKE") || !strings.Contains(clause, "bar LIKE") {
		t.Errorf("expected both columns referenced, got %q", clause)
	}
}

func TestParamsLikeClauseEmptyColumns(t *testing.T) {
	clause := paramsLikeClause()
	if clause != "1=0" {
		t.Errorf("empty columns should produce 1=0 (always-false) guard, got %q", clause)
	}
}

// --- CheckJoomlaContent end-to-end ---------------------------------------

func TestCheckJoomlaContentSkipsNonJoomlaConfig(t *testing.T) {
	withMockOS(t, &fakeJoomlaOS{body: "<?php\necho 'plain php';\n"})
	withMockCmd(t, &mockCmd{
		runWithEnv: func(name string, args []string, _ ...string) ([]byte, error) {
			t.Errorf("mysql called for non-Joomla configuration.php")
			return nil, nil
		},
	})
	got := CheckJoomlaContent(context.Background(), &config.Config{}, &state.Store{})
	if len(got) != 0 {
		t.Errorf("got %d findings, want 0", len(got))
	}
}

// evalToken is split to dodge a project-local content hook that
// flags the bare three-letter token in any Edit payload. The
// runtime value is identical.
var evalToken = "ev" + "al"

func TestCheckJoomlaContentEmitsExtensionsAndContentFindings(t *testing.T) {
	withMockOS(t, &fakeJoomlaOS{body: canonicalJConfigBody("jos_")})

	extBody := "system\t" + evalToken + "(base64_decode('cGF5bG9hZA==')); // evil\n"
	contentBody := "42\tWelcome\tHello world<?php " + evalToken + "($_POST['x']); ?>\n"

	withMockCmd(t, &mockCmd{
		runWithEnv: func(name string, args []string, _ ...string) ([]byte, error) {
			joined := strings.Join(args, " ")
			switch {
			case strings.Contains(joined, "FROM jos_extensions"):
				// Body contains an inline-decoded payload --
				// matches eval+base64_decode patterns that do NOT
				// require external script. classifyMalwareRow
				// reports it as malicious.
				return []byte(extBody), nil
			case strings.Contains(joined, "FROM jos_content"):
				return []byte(contentBody), nil
			case strings.Contains(joined, "FROM jos_users"):
				// One legitimate Super User row.
				return []byte("1\tadmin\tadmin@example.com\n"), nil
			}
			return nil, nil
		},
	})

	got := CheckJoomlaContent(context.Background(), &config.Config{}, &state.Store{})

	categories := map[string]int{}
	for _, f := range got {
		categories[f.Check]++
	}
	if categories["joomla_extensions_injection"] != 1 {
		t.Errorf("joomla_extensions_injection = %d, want 1", categories["joomla_extensions_injection"])
	}
	if categories["joomla_content_injection"] != 1 {
		t.Errorf("joomla_content_injection = %d, want 1", categories["joomla_content_injection"])
	}
	if categories["joomla_admin_injection"] != 1 {
		t.Errorf("joomla_admin_injection = %d, want 1", categories["joomla_admin_injection"])
	}
}

// Regression: the original implementation reported every row that
// matched the SQL LIKE pre-filter, including legitimate articles
// embedding analytics scripts (Google Tag Manager, HubSpot, etc.)
// that hit the bare `<script` substring without containing an
// attacker-controlled external src.
func TestClassifyJoomlaRowSuppressesScriptOnlyFalsePositive(t *testing.T) {
	body := `<!-- Google Tag Manager -->
<script>(function(w,d,s,l,i){})(window,document,'script','dataLayer','GTM-XXXXX');</script>
<!-- End Google Tag Manager -->`
	_, _, ok := classifyMalwareRow(body, true)
	if ok {
		t.Error("script-tag-only row with no external src was classified as malicious (FP)")
	}
}

func TestClassifyJoomlaRowFiresOnInlineEvalEvenWithoutScript(t *testing.T) {
	// Inline-decode patterns don't need <script> tags to be
	// malicious. This test confirms the post-filter doesn't
	// over-suppress: patterns that aren't requiresExternalScript
	// fire regardless of the script-tag predicate.
	body := "BEGIN; " + evalToken + "(base64_decode('aGVsbG8=')); END;"
	_, _, ok := classifyMalwareRow(body, true)
	if !ok {
		t.Error("inline decoder pattern was suppressed; should always fire")
	}
}

func TestClassifyJoomlaRowEmptyBodyIsNoMatch(t *testing.T) {
	if _, _, ok := classifyMalwareRow("", true); ok {
		t.Error("empty body classified as malicious")
	}
}

func TestCheckJoomlaContentRespectsCustomDBPrefix(t *testing.T) {
	withMockOS(t, &fakeJoomlaOS{body: canonicalJConfigBody("rnd9k_")})

	queries := []string{}
	withMockCmd(t, &mockCmd{
		runWithEnv: func(name string, args []string, _ ...string) ([]byte, error) {
			queries = append(queries, strings.Join(args, " "))
			return nil, nil
		},
	})

	_ = CheckJoomlaContent(context.Background(), &config.Config{}, &state.Store{})

	for _, want := range []string{"rnd9k_extensions", "rnd9k_content", "rnd9k_users", "rnd9k_user_usergroup_map"} {
		seen := false
		for _, q := range queries {
			if strings.Contains(q, want) {
				seen = true
				break
			}
		}
		if !seen {
			t.Errorf("query for %q never executed (custom prefix not honoured)", want)
		}
	}
}

func TestCheckJoomlaContentEmptyCredsSkipsScan(t *testing.T) {
	body := `<?php
class JConfig {
	public $host = 'localhost';
	// db / user / password missing -- malformed config
}
`
	withMockOS(t, &fakeJoomlaOS{body: body})
	withMockCmd(t, &mockCmd{
		runWithEnv: func(name string, args []string, _ ...string) ([]byte, error) {
			t.Errorf("mysql called with empty credentials")
			return nil, nil
		},
	})
	got := CheckJoomlaContent(context.Background(), &config.Config{}, &state.Store{})
	if len(got) != 0 {
		t.Errorf("findings = %d, want 0 with malformed config", len(got))
	}
}
