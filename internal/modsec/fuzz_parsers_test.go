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
