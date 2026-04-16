package checks

import (
	"regexp"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// --- extractMaliciousScriptURL ---

func TestExtractMaliciousScriptURL_Malicious(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    string
	}{
		{
			name:    "staticsx.top injection",
			content: `</style><script src=https://staticsx.top/l.js></script><style>`,
			want:    "https://staticsx.top/l.js",
		},
		{
			// .top is on the abused-TLD list (Spamhaus recurring).
			// The classifier should flag on TLD alone regardless of
			// whether the host happens to appear on an allowlist.
			name:    "abused TLD with quotes",
			content: `<script src="https://evil-domain.top/payload.js"></script>`,
			want:    "https://evil-domain.top/payload.js",
		},
		{
			// Raw IP address host — attackers commonly use IPs to
			// dodge domain reputation. Single-quote form covered as
			// a regression against the regex's quote-style handling.
			name:    "raw IP single quotes",
			content: `<script src='https://192.0.2.42/inject.js'></script>`,
			want:    "https://192.0.2.42/inject.js",
		},
		{
			name:    "http not https",
			content: `<script src=http://badsite.ru/x.js></script>`,
			want:    "http://badsite.ru/x.js",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractMaliciousScriptURL(tt.content)
			if got != tt.want {
				t.Errorf("extractMaliciousScriptURL() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestExtractMaliciousScriptURL_Safe(t *testing.T) {
	tests := []struct {
		name    string
		content string
	}{
		{
			name:    "Google Tag Manager",
			content: `<script src="https://www.googletagmanager.com/gtag/js?id=G-XXXXX"></script>`,
		},
		{
			name:    "Google Analytics",
			content: `<script src="https://www.google-analytics.com/analytics.js"></script>`,
		},
		{
			name:    "Facebook Pixel",
			content: `<script src="https://connect.facebook.net/en_US/fbevents.js"></script>`,
		},
		{
			name:    "Mailchimp",
			content: `<script src="https://chimpstatic.com/mcjs-connected/js/users/abc123.js"></script>`,
		},
		{
			name:    "Hotjar",
			content: `<script src="https://static.hotjar.com/c/hotjar-12345.js"></script>`,
		},
		{
			name:    "jQuery CDN",
			content: `<script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>`,
		},
		{
			name:    "jsDelivr",
			content: `<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.0.0/dist/js/bootstrap.min.js"></script>`,
		},
		{
			name:    "Cloudflare CDN",
			content: `<script src="https://cdnjs.cloudflare.com/ajax/libs/lodash.js/4.17.21/lodash.min.js"></script>`,
		},
		{
			name:    "Stripe",
			content: `<script src="https://js.stripe.com/v3/"></script>`,
		},
		{
			name:    "Hubspot",
			content: `<script src="https://js.hs-scripts.com/12345.js"></script>`,
		},
		{
			name:    "no script tag at all",
			content: `just some regular text content without any scripts`,
		},
		{
			name:    "inline script no src",
			content: `<script>console.log("hello")</script>`,
		},
		{
			name:    "empty string",
			content: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractMaliciousScriptURL(tt.content)
			if got != "" {
				t.Errorf("extractMaliciousScriptURL() = %q, want empty (safe content)", got)
			}
		})
	}
}

func TestExtractMaliciousScriptURL_MixedSafeAndMalicious(t *testing.T) {
	// Content with both safe and malicious scripts — should return the malicious one.
	content := `<script src="https://www.googletagmanager.com/gtag/js?id=G-XX"></script>
<script src="https://evil-inject.top/steal.js"></script>
<script src="https://cdn.jsdelivr.net/npm/vue@3"></script>`

	got := extractMaliciousScriptURL(content)
	if got != "https://evil-inject.top/steal.js" {
		t.Errorf("got %q, want malicious URL", got)
	}
}

// --- isSafeScriptDomain ---

func TestIsSafeScriptDomain(t *testing.T) {
	tests := []struct {
		url  string
		safe bool
	}{
		{"https://www.googletagmanager.com/gtag/js", true},
		{"https://googletagmanager.com/gtag/js", true},
		{"https://sub.google-analytics.com/collect", true},
		{"https://connect.facebook.net/en_US/sdk.js", true},
		{"https://chimpstatic.com/mcjs/abc.js", true},
		{"https://static.hotjar.com/c/hotjar.js", true},
		{"https://js.stripe.com/v3/", true},
		{"https://staticsx.top/l.js", false},
		{"https://evil.example.com/malware.js", false},
		{"http://badsite.ru/payload.js", false},
		{"https://google.com.evil.com/fake.js", false}, // evil.com, not google.com
		{"https://notgoogletagmanager.com/x.js", false},
	}
	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			got := isSafeScriptDomain(tt.url)
			if got != tt.safe {
				t.Errorf("isSafeScriptDomain(%q) = %v, want %v", tt.url, got, tt.safe)
			}
		})
	}
}

// --- isValidOptionName ---

func TestIsValidOptionName(t *testing.T) {
	tests := []struct {
		name  string
		valid bool
	}{
		{"siteurl", true},
		{"td_live_css_local_storage", true},
		{"ihaf_insert_header", true},
		{"wp_options:backup", true},
		{"theme-mods-flavor", true},
		{"option.with.dots", true},

		// Invalid — SQL injection attempts
		{"'; DROP TABLE wp_options; --", false},
		{"option' OR '1'='1", false},
		{"name\x00null", false},
		{"option\nvalue", false},
		{"", false},

		// Too long
		{string(make([]byte, 200)), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isValidOptionName(tt.name)
			if got != tt.valid {
				t.Errorf("isValidOptionName(%q) = %v, want %v", tt.name, got, tt.valid)
			}
		})
	}
}

// --- parseDBFindingDetails ---

func TestParseDBFindingDetails(t *testing.T) {
	tests := []struct {
		name       string
		details    string
		wantDB     string
		wantOption string
	}{
		{
			name:       "standard format",
			details:    "Database: filmetaricom_3qxJhxS5VoB\nOption: td_live_css_local_storage\nContent preview: ...",
			wantDB:     "filmetaricom_3qxJhxS5VoB",
			wantOption: "td_live_css_local_storage",
		},
		{
			name:       "no option",
			details:    "Database: mydb\nSome other info",
			wantDB:     "mydb",
			wantOption: "",
		},
		{
			name:       "empty",
			details:    "",
			wantDB:     "",
			wantOption: "",
		},
		{
			name:       "extra whitespace",
			details:    "  Database: testdb  \n  Option: test_option  \n",
			wantDB:     "testdb",
			wantOption: "test_option",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, opt := parseDBFindingDetails(tt.details)
			if db != tt.wantDB {
				t.Errorf("dbName = %q, want %q", db, tt.wantDB)
			}
			if opt != tt.wantOption {
				t.Errorf("optionName = %q, want %q", opt, tt.wantOption)
			}
		})
	}
}

// --- removeMaliciousScripts ---

func TestRemoveMaliciousScripts(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		changed bool
	}{
		{
			name:    "style-break injection",
			input:   `a:1:{s:3:"css";s:62:"</style><script src=https://staticsx.top/l.js></script><style>";}`,
			want:    `a:1:{s:3:"css";s:62:"";}`,
			changed: true,
		},
		{
			name:    "standalone malicious script",
			input:   `some content <script src="https://evil.com/payload.js"></script> more content`,
			want:    `some content  more content`,
			changed: true,
		},
		{
			name:    "safe script preserved",
			input:   `<script src="https://www.googletagmanager.com/gtag/js?id=G-XX"></script>`,
			want:    `<script src="https://www.googletagmanager.com/gtag/js?id=G-XX"></script>`,
			changed: false,
		},
		{
			name:    "mixed safe and malicious",
			input:   `<script src="https://cdn.jsdelivr.net/npm/vue@3"></script><script src="https://evil.xyz/x.js"></script>`,
			want:    `<script src="https://cdn.jsdelivr.net/npm/vue@3"></script>`,
			changed: true,
		},
		{
			name:    "no scripts",
			input:   `just regular text`,
			want:    `just regular text`,
			changed: false,
		},
		{
			name:    "empty",
			input:   "",
			want:    "",
			changed: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := removeMaliciousScripts(tt.input)
			if got != tt.want {
				t.Errorf("removeMaliciousScripts()\ngot:  %q\nwant: %q", got, tt.want)
			}
			if (got != tt.input) != tt.changed {
				t.Errorf("changed = %v, want %v", got != tt.input, tt.changed)
			}
		})
	}
}

// --- escapeSQLString ---

func TestEscapeSQLString(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"hello", "hello"},
		{"it's a test", `it\'s a test`},
		{`back\slash`, `back\\slash`},
		{"null\x00byte", `null\0byte`},
		{"new\nline", `new\nline`},
		{"carriage\rreturn", `carriage\rreturn`},
		{"ctrl\x1az", `ctrl\Zz`},
		{"'; DROP TABLE --", `\'; DROP TABLE --`},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := escapeSQLString(tt.input)
			if got != tt.want {
				t.Errorf("escapeSQLString(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// --- AutoRespondDBMalware integration ---

func TestAutoRespondDBMalware_Disabled(t *testing.T) {
	cfg := &config.Config{}
	cfg.AutoResponse.Enabled = false
	cfg.AutoResponse.CleanDatabase = false

	findings := []alert.Finding{
		{Check: "db_options_injection", Details: "Database: test\nOption: test"},
	}
	actions := AutoRespondDBMalware(cfg, findings)
	if len(actions) != 0 {
		t.Errorf("expected no actions when disabled, got %d", len(actions))
	}
}

func TestAutoRespondDBMalware_EnabledButNotCleanDB(t *testing.T) {
	cfg := &config.Config{}
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.CleanDatabase = false

	findings := []alert.Finding{
		{Check: "db_options_injection", Details: "Database: test\nOption: test"},
	}
	actions := AutoRespondDBMalware(cfg, findings)
	if len(actions) != 0 {
		t.Errorf("expected no actions when clean_database=false, got %d", len(actions))
	}
}

func TestAutoRespondDBMalware_IgnoresNonDBChecks(t *testing.T) {
	cfg := &config.Config{}
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.CleanDatabase = true

	findings := []alert.Finding{
		{Check: "wp_login_bruteforce", Message: "brute force from 1.2.3.4"},
		{Check: "db_spam_injection", Details: "spam"},
		{Check: "db_post_injection", Details: "script tag"},
		{Check: "webshell", Message: "shell detected"},
	}
	actions := AutoRespondDBMalware(cfg, findings)
	if len(actions) != 0 {
		t.Errorf("expected no actions for non-target checks, got %d", len(actions))
	}
}

func TestAutoRespondDBMalware_SkipsInvalidOptionName(t *testing.T) {
	cfg := &config.Config{}
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.CleanDatabase = true

	findings := []alert.Finding{
		{
			Check:   "db_options_injection",
			Details: "Database: testdb\nOption: '; DROP TABLE wp_options; --\nContent preview: <script src=\"https://evil.com/x.js\">",
		},
	}
	actions := AutoRespondDBMalware(cfg, findings)
	if len(actions) != 0 {
		t.Errorf("expected no actions for SQL injection in option name, got %d", len(actions))
	}
}

// --- extractSuspiciousSessionIPs (unit test with mock data) ---

func TestExtractSuspiciousSessionIPs_ParsesSerializedPHP(t *testing.T) {
	// This tests the IP regex against real WordPress serialized session data.
	sessionData := `a:2:{s:64:"abc123";a:4:{s:10:"expiration";i:1775817506;s:2:"ip";s:14:"216.26.248.31";s:2:"ua";s:100:"Mozilla/5.0";s:5:"login";i:1775644706;}s:64:"def456";a:4:{s:10:"expiration";i:1775817506;s:2:"ip";s:13:"104.207.35.50";s:2:"ua";s:100:"Mozilla/5.0";s:5:"login";i:1775644706;}}`

	ipRe := ipSessionRe()
	matches := ipRe.FindAllStringSubmatch(sessionData, -1)

	var ips []string
	for _, m := range matches {
		if len(m) >= 2 {
			ips = append(ips, m[1])
		}
	}

	if len(ips) != 2 {
		t.Fatalf("expected 2 IPs, got %d: %v", len(ips), ips)
	}
	if ips[0] != "216.26.248.31" {
		t.Errorf("first IP = %q, want 216.26.248.31", ips[0])
	}
	if ips[1] != "104.207.35.50" {
		t.Errorf("second IP = %q, want 104.207.35.50", ips[1])
	}
}

// ipSessionRe returns the regex used for extracting IPs from WP session data.
// Duplicated here to test the pattern without needing a DB connection.
func ipSessionRe() *regexp.Regexp {
	return regexp.MustCompile(`"ip";s:\d+:"([^"]+)"`)
}
