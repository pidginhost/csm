package antispam

import (
	"encoding/json"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func FuzzParseEximSize(f *testing.F) {
	for _, seed := range []string{"50M", "+50M", "-0", "-0K", "52428800", " 100k ", "1G", "", "-1", "+-0", "8589934592G", "${if def:x{1}{2}}"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		n, err := ParseEximSize(input)
		if err != nil {
			if n != 0 {
				t.Fatalf("rejected size returned %d", n)
			}
			return
		}
		if n < 0 || n+sizeHeadroom <= n {
			t.Fatalf("size %d cannot accommodate headroom", n)
		}
		if got, err := ParseEximSize(strconv.FormatInt(n, 10)); err != nil || got != n {
			t.Fatalf("round trip changed %d to %d, %v", n, got, err)
		}
	})
}

func FuzzMaxMessage(f *testing.F) {
	for _, seed := range []string{
		`{"max_message":62914560}`, `{"max_message":0}`, `{"task_timeout":8.0}`,
		`{"max_message":6.5e7}`, `{"max_message":53477375.99}`, `{"max_message":0.5}`,
		`{"max_message":9223372036854775807}`, `{"max_message":1e1000}`,
		`{"dns":{"nameserver":[]},"max_message":62914560}`,
		`{"max_message":1,"max_message":0}`, `{"max_message":0} trailing`,
		`{"max_message":-1}`, `{"max_message":null}`, `null`, ``,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		n, err := MaxMessage(input)
		if err != nil {
			if n != 0 {
				t.Fatalf("rejected options returned %d", n)
			}
			return
		}
		if n < 0 || !json.Valid(input) {
			t.Fatalf("accepted invalid options with size %d", n)
		}
		if _, err := MaxMessage(append(append([]byte(nil), input...), []byte("{}")...)); err == nil {
			t.Fatal("accepted trailing object")
		}
		encoded := []byte(`{"max_message":` + strconv.FormatInt(n, 10) + `}`)
		if got, err := MaxMessage(encoded); err != nil || got != n {
			t.Fatalf("round trip changed %d to %d, %v", n, got, err)
		}
	})
}

func FuzzEximLogFirstDestination(f *testing.F) {
	for _, seed := range []string{"/var/log/exim_%slog", "syslog", "", ":", ": /var/log/exim_%slog", "${primary_hostname}", "<;"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, suffix string) {
		// A later destination or an escaped colon cannot redirect the first
		// file destination to the monitored path.
		for _, prefix := range []string{"/var/log/other_%slog : ", "/var/log/other::"} {
			raw := prefix + suffix
			got := checkEximLog(map[string]string{"log_file_path": raw}, "/var/log/exim_mainlog")
			want := Definite
			if strings.ContainsAny(raw, "$<") {
				want = Temporary
			}
			if len(got) != 1 || got[0].Code != CodeEximLog || got[0].Severity != want {
				t.Fatalf("unmonitored first destination %q reported %+v, want one exim_log/%d problem", raw, got, want)
			}
		}
	})
}

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
		hookBlocks, hookErr := locateBlocks(conf, "acl", "csm_hook", false)
		for _, b := range hookBlocks {
			if hookErr != nil || b.Begin < 1 || b.End <= b.Begin || b.End > total {
				t.Fatalf("hook block %+v with err %v outside 1..%d", b, hookErr, total)
			}
		}
	})
}

func FuzzOneConfigSection(f *testing.F) {
	for _, seed := range []string{
		"@CONFIG@\n", "@AUTH@\n\n@CONFIG@\n\n@DIRECTOREND@\n",
		"@CONFIG@\n@CONFIG@\n", " @CONFIG@\n", "@CONFIG@\r\n", "",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, conf string) {
		if !oneConfigSection(conf) {
			return
		}
		if oneConfigSection("@CONFIG@\n"+conf) || oneConfigSection(conf+"\n@CONFIG@\n") {
			t.Fatal("accepted another CONFIG section")
		}
		if oneConfigSection(strings.ReplaceAll(conf, "@CONFIG@", " @CONFIG@")) {
			t.Fatal("accepted an indented CONFIG section")
		}
		if oneConfigSection(strings.ReplaceAll(conf, "@CONFIG@", "@AUTH@")) {
			t.Fatal("accepted a file without its CONFIG section")
		}
	})
}

func FuzzCheckGenerated(f *testing.F) {
	h, err := RenderExim(defaults(false))
	if err != nil {
		f.Fatal(err)
	}
	conf := rebuiltConf(h.Config, h.RCPT, h.Scan, h.Post)
	for _, seed := range []string{
		conf,
		"Yes = No\n" + conf,
		".ifdef OPTIONAL_HOOKS\n" + conf + ".endif\n",
		strings.Replace(conf, "acl_smtp_data:", "unexpected_acl:", 1),
		"A = x\n" + strings.Repeat("A == A A\n", 26) + conf,
		"",
	} {
		f.Add(seed, "acl_smtp_rcpt", "acl_smtp_data")
	}
	f.Fuzz(func(t *testing.T, conf, rcptACL, dataACL string) {
		if err := CheckGenerated(conf, h, rcptACL, dataACL); err != nil {
			return
		}
		if rcptACL == "" || dataACL == "" || rcptACL == dataACL {
			t.Fatal("accepted invalid ACL names")
		}
		for name, block := range map[string]string{"config": h.Config, "rcpt": h.RCPT, "scan": h.Scan, "post": h.Post} {
			if count := strings.Count(conf, block); count != 1 {
				t.Fatalf("accepted configuration with %d copies of the rendered %s block", count, name)
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
			if req != (Request{}) || s != (Settings{}) {
				t.Fatal("rejected input returned a partial request")
			}
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

func FuzzParseResult(f *testing.F) {
	for _, seed := range []string{
		`{"operation":"apply","ok":true,"generation":"g1"}`,
		`{"operation":"remove","ok":true}`,
		`{"operation":"apply","ok":false,"busy":true,"failed_step":"lock","rollback":"none"}`,
		`{"ok":false,"failed_step":"request","rollback":"none","error":"invalid request"}`,
		`{"operation":"remove","ok":false,"failed_step":"reload","rollback":"failed"}`,
		`{"operation":"apply","ok":false,"ok":true,"generation":"g1"}`,
		`{"operation":"apply","OK":true,"generation":"g1"}`,
		`null`, `{}`, `{"ok":null}`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		r, err := ParseResult(data)
		if err != nil {
			if r != (Result{}) {
				t.Fatal("rejected output returned a partial result")
			}
			return
		}
		encoded, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		if again, err := ParseResult(encoded); err != nil || again != r {
			t.Fatalf("round trip changed %+v to %+v, %v", r, again, err)
		}
		duplicate := string(encoded[:len(encoded)-1]) + `,"ok":true}`
		if _, err := ParseResult([]byte(duplicate)); err == nil {
			t.Fatal("accepted a duplicate success field")
		}
	})
}

func FuzzSetBlock(f *testing.F) {
	h, err := RenderExim(Settings{Socket: DefaultSocket, RejectScore: 15, TagScore: 6})
	if err != nil {
		f.Fatal(err)
	}
	for _, seed := range []string{"", "warn\n  log_message = x\n", h.Post + "deny\n", "@CONFIG@\n", "@AUTH@\n@CONFIG@\n" + h.Config, MarkerBegin + "\n", "  message = x\n"} {
		f.Add(seed, false, false)
		f.Add(seed, true, true)
	}
	f.Fuzz(func(t *testing.T, content string, local, remove bool) {
		kind, block := TargetEximHook, h.Post
		if local {
			kind, block = TargetEximLocal, h.Config
		}
		if remove {
			block = ""
		}
		out, err := SetBlock(kind, content, block)
		if err != nil {
			return
		}
		blocks, err := fileBlocks(kind, out)
		if err != nil {
			t.Fatalf("edited file does not parse: %v", err)
		}
		if remove && len(blocks) != 0 {
			t.Fatal("removal left a CSM block")
		}
		if text, ok := BlockText(kind, out); !remove && (!ok || text != block) {
			t.Fatalf("block reads back as %q, %t", text, ok)
		}
		if again, err := SetBlock(kind, out, block); err != nil || again != out {
			t.Fatalf("second edit changed the file: %v", err)
		}
	})
}
