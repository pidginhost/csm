package checks

import (
	"fmt"
	"testing"

	"github.com/pidginhost/csm/internal/platform"
)

func TestHTTPRewriteApacheLogDirectoryOverride(t *testing.T) {
	for _, directive := range []string{"CustomLog", "GlobalLog", "TransferLog"} {
		for _, quote := range []string{"", "\"", "'"} {
			t.Run(directive+quote, func(t *testing.T) {
				log := directive + " " + quote + "${APACHE_LOG_DIR}/access" + quote
				if directive != "TransferLog" {
					log += " combined"
				}
				log += "\n"
				format := "LogFormat \"%v %{X-Client}i %t\" combined\nLogFormat combined\n"
				cases := []struct {
					name, body string
					state      RewriteState
				}{
					{"stock directory", log, RewriteNone},
					{"pipe override", "Define APACHE_LOG_DIR \"|splitlogs --suffix=\"\n" + log, RewriteUnknown},
					{"indirect override", "Define APACHE_LOG_DIR ${logger}\n" + log, RewriteUnknown},
					{"undefined directory", "UnDefine APACHE_LOG_DIR\n" + log, RewriteUnknown},
					{"conditional override", "<IfModule log_config_module>\nDefine APACHE_LOG_DIR \"|splitlogs --suffix=\"\n</IfModule>\n" + log, RewriteUnknown},
					{"macro override", "<Macro Logging $target>\nDefine APACHE_LOG_DIR $target\n" + log + "</Macro>\nUse Logging \"|splitlogs --suffix=\"\n", RewriteUnknown},
					{"macro variable name", "<Macro Logging $name>\nDefine $name \"|splitlogs --suffix=\"\n" + log + "</Macro>\nUse Logging APACHE_LOG_DIR\n", RewriteUnknown},
					{"override before macro use", "<Macro Logging>\n" + log + "</Macro>\nDefine APACHE_LOG_DIR \"|splitlogs --suffix=\"\nUse Logging\n", RewriteUnknown},
					{"different variable", "Define OTHER_DIR \"|splitlogs --suffix=\"\n" + log, RewriteNone},
					{"different case", "Define apache_log_dir \"|splitlogs --suffix=\"\n" + log, RewriteNone},
					{"unused override", "Define APACHE_LOG_DIR \"|splitlogs\"\nCustomLog logs/access combined\n", RewriteNone},
					{"literal pipe with override", "Define APACHE_LOG_DIR \"|splitlogs\"\nCustomLog \"|splitlogs\" combined\n", RewriteActive},
					{"active beside unknown", "Define APACHE_LOG_DIR \"|splitlogs\"\n" + log + "CustomLog \"|splitlogs\" combined\n", RewriteActive},
				}
				for _, tt := range cases {
					t.Run(tt.name, func(t *testing.T) {
						conf := writeRewriteFile(t, t.TempDir(), "httpd.conf", format+tt.body)
						for _, server := range []platform.WebServer{platform.WSApache, platform.WSLiteSpeed} {
							got := detectHTTPRewrite(rewriteSources{server: server, apacheConfig: conf})
							if got.State != tt.state {
								t.Errorf("server %s: rewrite = %+v, want %v", server, got, tt.state)
							}
						}
					})
				}
			})
		}
	}
}

func TestHTTPRewriteApacheLogTargetBoundaries(t *testing.T) {
	cases := []struct {
		target string
		state  RewriteState
	}{
		{`${OTHER}/access`, RewriteUnknown},
		{`"${OTHER}/access"`, RewriteUnknown},
		{`'${OTHER}/access'`, RewriteUnknown},
		{`" ${OTHER}/access"`, RewriteNone},
		{`"${APACHE_LOG_DIR}/access log"`, RewriteNone},
		{`${APACHE_LOG_DIR}/access${suffix}`, RewriteNone},
		{`${APACHE_LOG_DIR}/|splitlogs`, RewriteNone},
		{`"|splitlogs --main=${host}"`, RewriteActive},
		{`"|${logger}"`, RewriteUnknown},
		{`" |splitlogs"`, RewriteNone},
	}
	for _, directive := range []string{"CustomLog", "GlobalLog", "TransferLog"} {
		for i, tt := range cases {
			t.Run(fmt.Sprintf("%s/%d", directive, i), func(t *testing.T) {
				body := "LogFormat \"%v %{X-Client}i %t\"\n" + directive + " \t " + tt.target
				if directive != "TransferLog" {
					body += " \"%v %{X-Client}i %t\""
				}
				conf := writeRewriteFile(t, t.TempDir(), "httpd.conf", body+"\n")
				got := detectHTTPRewrite(rewriteSources{server: platform.WSApache, apacheConfig: conf})
				if got.State != tt.state {
					t.Errorf("target %s: rewrite = %+v, want %v", tt.target, got, tt.state)
				}
			})
		}
	}
}
