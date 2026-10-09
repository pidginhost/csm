package antispam

import (
	"encoding/json"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func FuzzParseRspamdVersion(f *testing.F) {
	for _, seed := range []string{"Rspamd daemon version 4.2.1\n", "Rspamadm 3.8\n", "Rspamadm 4.2.1-git\n", "Rspamadm 4.2.12345\n", "", "command not found"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, out string) {
		version, major, err := ParseRspamdVersion(out)
		if err != nil {
			if version != "" || major != 0 {
				t.Fatalf("error returned partial version %q, %d", version, major)
			}
			return
		}
		parts := strings.Split(version, ".")
		if len(parts) < 2 || len(parts) > 3 {
			t.Fatalf("invalid dotted version %q", version)
		}
		for i, part := range parts {
			n, parseErr := strconv.Atoi(part)
			if parseErr != nil || len(part) == 0 || len(part) > 4 || n < 0 || (i == 0 && n != major) {
				t.Fatalf("invalid version component %q in %q (major %d)", part, version, major)
			}
		}
		got, gotMajor, err := ParseRspamdVersion("Rspamadm " + version + "\n")
		if err != nil || got != version || gotMajor != major {
			t.Fatalf("round trip changed %q, %d to %q, %d, %v", version, major, got, gotMajor, err)
		}
	})
}

func FuzzEnabledModules(f *testing.F) {
	for _, seed := range []string{modulesState, "Modules enabled:\n", "Modules enabled: asn, rbl, asn\r\n", "", "Modules disabled (explicitly): rbl\n"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, out string) {
		set, err := EnabledModules(out)
		if err != nil {
			if set != nil {
				t.Fatalf("error returned partial modules %v", set)
			}
			return
		}
		names := make([]string, 0, len(set))
		for name, enabled := range set {
			if !enabled || name == "" || strings.TrimSpace(name) != name {
				t.Fatalf("invalid enabled module %q: %v", name, enabled)
			}
			names = append(names, name)
		}
		got, err := EnabledModules("Modules enabled: " + strings.Join(names, ", ") + "\n")
		if err != nil || !reflect.DeepEqual(got, set) {
			t.Fatalf("round trip changed modules %v to %v, %v", set, got, err)
		}
	})
}

func FuzzParseActions(f *testing.F) {
	for _, seed := range []string{
		`{"reject":15,"add_header":6,"greylist":null,"rewrite_subject":null}`,
		`{"reject":20.5,"add header":8,"rewrite subject":10}`,
		`{"rewrite_subject":null,"rewrite subject":8}`,
		`{"reject":"high"}`, `null`, `{}`, ``,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, out []byte) {
		a, err := ParseActions(out)
		if err != nil {
			if a != (Actions{}) {
				t.Fatalf("error returned partial actions %+v", a)
			}
			return
		}
		encoded, err := json.Marshal(map[string]*float64{
			"reject": a.Reject, "add_header": a.AddHeader,
			"greylist": a.Greylist, "rewrite_subject": a.RewriteSubject,
		})
		if err != nil {
			t.Fatalf("parsed non-JSON thresholds: %v", err)
		}
		got, err := ParseActions(encoded)
		if err != nil || !reflect.DeepEqual(got, a) {
			t.Fatalf("round trip changed actions %+v to %+v, %v", a, got, err)
		}
	})
}
