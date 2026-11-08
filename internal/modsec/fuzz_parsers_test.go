package modsec

import (
	"strings"
	"testing"
)

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
