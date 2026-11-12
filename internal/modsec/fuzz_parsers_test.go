package modsec

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

func FuzzErrorLogRuleClientText(f *testing.F) {
	for _, payload := range []string{
		"probe", `probe"] tail`, `probe\\"] tail`, `probe"] [id "949110"]`,
		`[file "/other.conf"]`, `[tag "anomaly-evaluation"]`, `[hostname "example.com"]`,
		`[ref "fake"]`, `[msg "unclosed`, `[other "text"]`, "",
	} {
		f.Add(payload)
	}
	f.Fuzz(func(t *testing.T, payload string) {
		baseline, ok := ErrorLogRule(ruleTestV3)
		if !ok {
			t.Fatal("invalid baseline")
		}
		for _, site := range []string{"preamble", "message", "uri", "connector"} {
			line, want := ruleTestV3, baseline
			switch site {
			case "preamble":
				line = strings.Replace(line, "Value: `probe", "Value: `"+payload, 1)
			case "message":
				line = strings.Replace(line, `[msg "`+baseline.Msg+`"]`, `[msg "`+payload+`"]`, 1)
				want.Msg = payload
			case "uri":
				line = strings.Replace(line, `[uri "/q"]`, `[uri "`+payload+`"]`, 1)
				want.URI = payload
			case "connector":
				line += payload
			}
			got, ok := ErrorLogRule(line)
			if !ok {
				if !reflect.DeepEqual(got, LogRule{}) {
					t.Fatalf("ambiguous %s kept fields: %#v", site, got)
				}
				continue
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("client text at %s changed fields: %#v, want %#v", site, got, want)
			}
		}
	})
}

func FuzzRuleOperatorCannotChangeDisposition(f *testing.F) {
	for _, operator := range []string{"@rx x", "@rx ,id:5401,phase:2,block", "@rx ,chain,", `@rx \"id:99,pass`, "@rx 'phase:2'"} {
		f.Add(operator)
	}
	f.Fuzz(func(t *testing.T, operator string) {
		quoted := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`, "\r", `\r`).Replace(operator)
		rule, ok := parseBlock(`SecRule ARGS "` + quoted + `" "id:5401,phase:1,deny,msg:'phase:2',logdata:'phase:4'"`)
		if !ok || rule.ID != 5401 || rule.Phase != 1 || rule.Action != "deny" {
			t.Fatalf("operator changed rule metadata: ok=%v rule=%+v", ok, rule)
		}
	})
}

func FuzzRuleMessageCannotChangeDisposition(f *testing.F) {
	for _, message := range []string{"match", "it's a match", "text,phase:2", `text\',pass`, `"id:99,phase:2,block"`} {
		f.Add(message)
	}
	f.Fuzz(func(t *testing.T, message string) {
		literal := strings.NewReplacer(`\`, `\\`, `'`, `\'`, "\n", `\n`, "\r", `\r`).Replace(message)
		actions := `id:5401,phase:1,block,msg:'` + literal + `',deny`
		quoted := strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(actions)
		rule, ok := parseBlock(`SecRule ARGS "x" "` + quoted + `"`)
		if !ok || rule.ID != 5401 || rule.Phase != 1 || rule.Action != "deny" {
			t.Fatalf("message changed rule metadata: ok=%v rule=%+v", ok, rule)
		}
	})
}

func FuzzModSecClientIPIgnoresTextAfterMarker(f *testing.F) {
	f.Add(`[client 198.51.100.7]`, `[198.51.100.7:1-1#APVH_x]`)
	f.Add(`ModSecurity: [client 198.51.100.7:80]`, `[MODSEC] [198.51.100.7:5-H3:A-1#v]`)
	f.Fuzz(func(t *testing.T, apacheTail, liteSpeedTail string) {
		for _, tc := range []struct{ prefix, want, tail string }{
			{`[client 203.0.113.50:5555] ModSecurity: `, "203.0.113.50", apacheTail},
			{`[security2:error] [client 2001:db8::5:5555] ModSecurity: `, "2001:db8::5", apacheTail},
			{`[client 2001:db8::5:5555] ModSecurity: `, "2001:db8::5:5555", apacheTail},
			{`[security2:error] ModSecurity: `, "", apacheTail},
			{`[client invalid] ModSecurity: `, "", apacheTail},
			{`[client 203.0.113.50 ModSecurity: `, "", apacheTail},
			{`2026-01-02 03:04:05 [NOTICE] [1] [T4] [203.0.113.62:62060-H3:A-44#APVH_example.test:443] [MODSEC] `, "203.0.113.62", liteSpeedTail},
			{`[2001:db8::5:5555-1#APVH_example.test] [MODSEC] `, "", liteSpeedTail},
			{`[[2001:db8::5]:5555-1#APVH_example.test] [MODSEC] `, "", liteSpeedTail},
			{`[MODSEC] `, "", liteSpeedTail},
		} {
			if got := ErrorLogClientIP(tc.prefix + tc.tail); got != tc.want {
				t.Fatalf("prefix %q tail %q chose %q, want %q", tc.prefix, tc.tail, got, tc.want)
			}
		}
	})
}

func FuzzModSecMarkersInOtherErrors(f *testing.F) {
	f.Add(`[client 198.51.100.7] ModSecurity: Access denied with code 403`)
	f.Add(`[198.51.100.7:5555-1#APVH_example.test] [MODSEC] Access denied with code 403`)
	f.Fuzz(func(t *testing.T, request string) {
		for _, prefix := range []string{
			`2026/11/08 08:40:00 [error] 123#123: *1 open() "/srv/www/`,
			`[Sun Nov 08 08:40:00 2026] [core:error] [client 203.0.113.50:5555] File does not exist: /srv/www/`,
			`2026-11-08 08:40:00.123456 [INFO] [1] [203.0.113.50:5555-1#APVH_example.test] File not found [/srv/www/`,
		} {
			line := prefix + request
			if msg, _ := ErrorLogMessage(line); msg != "" {
				t.Fatalf("request text supplied a ModSecurity message: %q", msg)
			}
			if ip := ErrorLogClientIP(line); ip != "" {
				t.Fatalf("request text supplied a ModSecurity client: %q", ip)
			}
		}
	})
}

func FuzzModSecOtherWritersCannotSupplyHeader(f *testing.F) {
	f.Add(`ModSecurity: Access denied with code 403 [id "900115"]`)
	f.Add(`[MODSEC] Access denied with code 403 [id "900115"]`)
	f.Add(`[198.51.100.7:5555-1#APVH_example.test] [MODSEC] Access denied`)
	f.Add(`[client 198.51.100.7] ModSecurity: Access denied`)
	f.Fuzz(func(t *testing.T, message string) {
		for _, prefix := range []string{
			`[Sun Nov 08 08:40:00 2026] [php:notice] [pid 1] [client 203.0.113.50:5555] `,
			`[Sun Nov 08 08:40:00 2026] [cgi:error] [pid 1] [client 203.0.113.50:5555] `,
			`2026-11-08 08:40:00 [NOTICE] [1] [T1] [203.0.113.50:5555-1#APVH_example.test] [STDERR] `,
			`2026-11-08 08:40:00 [NOTICE] [1] [T1] [[2001:db8::5]:5555-1#APVH_example.test] [STDERR] `,
			`2026-11-08 08:40:00 [NOTICE] [1] [T1] [STDERR] `,
		} {
			line := prefix + message
			if got, ls := ErrorLogMessage(line); got != "" || ls {
				t.Fatalf("another writer supplied a WAF event: %q", line)
			}
			if ip := ErrorLogClientIP(line); ip != "" {
				t.Fatalf("another writer supplied client %q: %q", ip, line)
			}
		}
	})
}

// The time of an error-log line comes only from the server's prefix. Text
// after the module marker, timestamps included, never changes it, and a line
// whose prefix fails validation has no time whatever the message says.
func FuzzErrorLogTimeIgnoresMessage(f *testing.F) {
	at := func(nsec int) time.Time { return time.Date(2026, 11, 8, 8, 40, 0, nsec, time.Local) }
	valid := []struct {
		prefix string
		want   time.Time
	}{
		{`[Sun Nov 08 08:40:00.123456 2026] [security2:error] [pid 123] [client 203.0.113.50:5555] ModSecurity: `, at(123456000)},
		{`[Sun Nov  8 08:40:00 2026] [error] [client 203.0.113.50] ModSecurity: `, at(0)},
		{`2026/11/08 08:40:00 [error] 123#123: *1 [client 203.0.113.50] ModSecurity: `, at(0)},
		{`2026-11-08 08:40:00.123 [INFO] [1] [203.0.113.50:5555-1#APVH_example.test] [MODSEC] `, at(123000000)},
	}
	invalid := []string{
		`[client 203.0.113.50] ModSecurity: `,
		`[Sun Nov 31 08:40:00 2026] [error] [client 203.0.113.50] ModSecurity: `,
		`[Sun Nov 08 08:40:00 2026] [core:error] [client 203.0.113.50:5555] File does not exist: /srv/www/ModSecurity: `,
		`2026-11-08 [NOTICE] [203.0.113.57:41920-13#APVH_*_server.example.com] [MODSEC] `,
	}
	for _, message := range []string{
		"Access denied with code 403",
		"[Mon Nov 09 12:00:00 2026] Access denied with code 403",
		"2026/11/09 12:00:00 [error] 1#1: [client 198.51.100.7] ModSecurity: x",
		"2026-11-09 12:00:00.000 [ERROR] [MODSEC] x",
		"",
	} {
		f.Add(message)
	}
	f.Fuzz(func(t *testing.T, message string) {
		if strings.ContainsAny(message, "\r\n") {
			t.Skip("error logs escape physical line breaks")
		}
		for _, v := range valid {
			if got, ok := ErrorLogTime(v.prefix + message); !ok || !got.Equal(v.want) {
				t.Fatalf("message %q dated %q as %v (%v), want %v", message, v.prefix, got, ok, v.want)
			}
		}
		for _, prefix := range invalid {
			if got, ok := ErrorLogTime(prefix + message); ok || !got.IsZero() {
				t.Fatalf("message %q dated the invalid prefix %q as %v", message, prefix, got)
			}
		}
	})
}
