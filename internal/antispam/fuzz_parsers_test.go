package antispam

import (
	"encoding/json"
	"errors"
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

// The Exim parsers read operator-written files inside the daemon, so any input
// must finish without a panic and within the expansion bounds.
func FuzzEximConfigParsers(f *testing.F) {
	for _, seed := range []string{
		generatedConf,
		"A = x\n" + strings.Repeat("A == A A\n", 26) + "begin acl\nacl_smtp_data:\n  warn condition = A\n",
		"M = a\n.ifdef X\nM = b\n.elifdef Y\nM = c\n.endif\nbegin acl\nacl_smtp_data:\nwarn\n  condition = M M M\n",
		"begin acl\nacl_smtp_data:\n" + MarkerBegin + "\nwarn\n" + MarkerEnd + "\n  add_header = X: $spam_score_int\n",
		"begin acl\nacl_smtp_data:\n.include /etc/x\n",
		"line \\\n# c\ncontinued\n",
		"EXTRA = .include /etc/exim_extra.conf\nhosts_lookup = example.invalid \\\nEXTRA\n",
		"if \"$sp\\\n  am_score_int\" is above 50 then finish endif\n",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, conf string) {
		total := strings.Count(conf, "\n") + 1
		lines, err := UngatedSpamUses(conf)
		if err != nil && !errors.Is(err, ErrUnverifiable) {
			t.Fatalf("UngatedSpamUses error %v is not ErrUnverifiable", err)
		}
		for _, n := range lines {
			if n < 1 || n > total {
				t.Fatalf("line %d outside 1..%d", n, total)
			}
		}
		previous := 0
		for _, n := range FilterSpamUses(conf) {
			if n <= previous || n > total {
				t.Fatalf("filter line %d outside %d..%d", n, previous+1, total)
			}
			previous = n
		}
		if _, errC := HasCutthrough(conf); errC != nil && !errors.Is(errC, ErrUnverifiable) {
			t.Fatalf("HasCutthrough error %v is not ErrUnverifiable", errC)
		}
		if _, errF := ForeignSpamdAddress(conf); errF != nil && !errors.Is(errF, ErrUnverifiable) {
			t.Fatalf("ForeignSpamdAddress error %v is not ErrUnverifiable", errF)
		}
		blocks, errL := LocateBlocks(conf)
		for _, b := range blocks {
			if errL != nil || b.Begin < 1 || b.End <= b.Begin || b.End > total {
				t.Fatalf("block %+v with err %v outside 1..%d", b, errL, total)
			}
		}
	})
}

// The worker decodes requests from a root-owned boundary: any input must be
// rejected or produce a request that re-encodes to settings that validate.
func FuzzDecodeRequest(f *testing.F) {
	for _, seed := range []string{
		`{"operation":"apply","enabled":true,"dry_run":false,"rspamd_socket":"/run/rspamd/csm-normal.sock","reject_score":15,"tag_score":6}`,
		`{"operation":"remove"}`,
		`{"operation":"remove","operation":"apply"}`,
		`{"Operation":"remove"}`,
		`{"operation":"apply","enabled":true,"dry_run":false,"rspamd_socket":"/x","reject_score":2,"tag_score":1}{}`,
		`null`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		req, s, err := DecodeRequest(data)
		if err != nil {
			return
		}
		switch req.Operation {
		case OpApply:
			if s.Validate() != nil {
				t.Fatalf("accepted invalid settings %+v", s)
			}
			again, err := json.Marshal(ApplyRequest(s))
			if err != nil {
				t.Fatal(err)
			}
			if _, s2, err := DecodeRequest(again); err != nil || s2 != s {
				t.Fatalf("re-encoded apply: %+v %v", s2, err)
			}
		case OpRemove:
			if s != (Settings{}) {
				t.Fatalf("remove carried settings %+v", s)
			}
		default:
			t.Fatalf("accepted operation %q", req.Operation)
		}
	})
}
