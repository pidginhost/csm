package checks

import (
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
)

// A cache plugin's own status options are rendered into the admin dashboard
// as notices. Markup there is never legitimate, so the injection is Critical
// on the option's identity alone -- no host reputation, no first-seen
// baseline. Both sinks the campaign writes to are covered.
func TestPluginNoticeInjectionReportsLiteSpeedSinks(t *testing.T) {
	for _, option := range []string{"litespeed.cdn_setup._summary", "litespeed.admin_display.messages"} {
		value := `{"cdn_setup_err":"<script src=https:\/\/dijasa.com\/wp-includes\/js\/jquery_v2.js><\/script>"}`

		finding := pluginNoticeInjectionFinding("cbsoft", wpDBCreds{dbName: "cbsoft_wp"}, "wp_2_", option, value)

		if finding == nil {
			t.Fatalf("%s: no finding for a script tag in a plugin notice sink", option)
		}
		if finding.Check != "db_options_plugin_notice_injection" || finding.Severity != alert.Critical {
			t.Fatalf("%s: finding = %s/%s, want db_options_plugin_notice_injection/Critical", option, finding.Check, finding.Severity)
		}
		if !strings.Contains(finding.Details, "dijasa.com") {
			t.Fatalf("%s: details do not name the loader host: %s", option, finding.Details)
		}
		if !strings.Contains(finding.Message, option) {
			t.Fatalf("%s: message does not name the option: %s", option, finding.Message)
		}
	}
}

// The same sink holding the error string LiteSpeed actually writes must stay
// silent, or every site that once failed a CDN setup alerts forever.
func TestPluginNoticeInjectionIgnoresGenuineErrorText(t *testing.T) {
	value := `{"cdn_setup_err":"There was an error during CDN setup: cURL error 28: Operation timed out"}`

	if finding := pluginNoticeInjectionFinding("alice", wpDBCreds{dbName: "alice_wp"}, "wp_", "litespeed.cdn_setup._summary", value); finding != nil {
		t.Fatalf("genuine LiteSpeed error text reported: %+v", finding)
	}
}

// A script tag in a content option is ordinary: site owners paste tracking
// and widget code there. Those stay with the reputation-and-baseline path;
// this check must not claim them.
func TestPluginNoticeInjectionIgnoresContentOptions(t *testing.T) {
	value := `a:1:{i:2;a:1:{s:7:"content";s:54:"<script src="https://mny.ro/npId.js" type="text/javascript">";}}`

	if finding := pluginNoticeInjectionFinding("alice", wpDBCreds{dbName: "alice_wp"}, "wp_", "widget_block", value); finding != nil {
		t.Fatalf("content option reported as a plugin notice injection: %+v", finding)
	}
}

// WordPress option_name collation is case-insensitive, so a differently-cased
// row satisfies the same get_option() lookup and must not slip the check.
func TestPluginNoticeInjectionMatchesSinkCaseInsensitively(t *testing.T) {
	value := `{"cdn_setup_err":"<script src=https:\/\/movie88.my.id\/system4\/speed.js><\/script>"}`

	if finding := pluginNoticeInjectionFinding("alice", wpDBCreds{dbName: "alice_wp"}, "wp_", "LiteSpeed.CDN_Setup._Summary", value); finding == nil {
		t.Fatal("differently-cased sink option not reported")
	}
}

// An injection that carries no src attribute -- inline script, or a
// javascript: handler -- is the same defect in the same sink.
func TestPluginNoticeInjectionReportsInlineScriptWithoutSrc(t *testing.T) {
	value := `["<div class=\"notice notice-error\"><p>CDN Setup is running<\/p><script>eval(atob('ZXZpbA=='))<\/script><\/div>"]`

	finding := pluginNoticeInjectionFinding("alice", wpDBCreds{dbName: "alice_wp"}, "wp_", "litespeed.admin_display.messages", value)
	if finding == nil {
		t.Fatal("inline script in a notice sink not reported")
	}
	if finding.Severity != alert.Critical {
		t.Fatalf("severity = %s, want Critical", finding.Severity)
	}
}

// The options scan must query the notice sinks directly. The generic script
// query caps its result set, and a LIKE that requires a src attribute misses
// an inline payload, so the sink rows need their own bounded lookup.
func TestOptionsScanQueriesPluginNoticeSinks(t *testing.T) {
	withFreshStore(t)
	previous := runMySQLQuery
	var sinkQueried bool
	runMySQLQuery = func(_ wpDBCreds, query string) []string {
		if strings.Contains(query, "litespeed.cdn_setup._summary") && strings.Contains(query, "<script") {
			sinkQueried = true
			return []string{"litespeed.cdn_setup._summary\t" +
				`{"cdn_setup_err":"<script src=https:\/\/dijasa.com\/wp-includes\/js\/jquery_v2.js><\/script>"}`}
		}
		return nil
	}
	t.Cleanup(func() { runMySQLQuery = previous })

	findings := checkWPOptions("cbsoft", wpDBCreds{dbName: "cbsoft_wp"}, "wp_")

	if !sinkQueried {
		t.Fatal("options scan never queried the plugin notice sinks")
	}
	var got *alert.Finding
	for i := range findings {
		if findings[i].Check == "db_options_plugin_notice_injection" {
			got = &findings[i]
		}
	}
	if got == nil {
		t.Fatalf("no db_options_plugin_notice_injection finding: %+v", findings)
	}
	if got.Severity != alert.Critical || !strings.Contains(got.Details, "dijasa.com") {
		t.Fatalf("finding = %s, details = %s", got.Severity, got.Details)
	}
}
