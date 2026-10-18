package antispam

import (
	"encoding/json"
	"errors"
	"net/netip"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
)

func FuzzCheckIPMapLoaded(f *testing.F) {
	for _, seed := range []string{
		`{"CSM_IP":{"type":"ip","map":"/var/lib/csm-rspamd/csm_ip.map","score":5,"symbols":["CSM_IP_DROP","CSM_IP_BLOCKED","CSM_IP_MAIL_AUTH","CSM_IP_SPAM","CSM_IP_BLOCKLISTDE","CSM_IP_CINS","CSM_IP_CANARY"]}}`,
		`{"CSM_IP":{"type":"ip","type":"from"}}`, `{"CSM_IP":null}`, `{}`, `null`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		on := map[string]bool{"multimap": true}
		if len(CheckIPMapLoaded(nil, data)) == 0 {
			t.Fatal("accepted a disabled module")
		}
		if len(CheckIPMapLoaded(on, data)) != 0 {
			return
		}
		var sections map[string]json.RawMessage
		if err := json.Unmarshal(data, &sections); err != nil {
			t.Fatal("accepted invalid JSON")
		}
		var rule map[string]json.RawMessage
		if err := json.Unmarshal(sections["CSM_IP"], &rule); err != nil || rule == nil {
			t.Fatal("accepted a non-object rule")
		}
		for _, key := range []string{"type", "map", "symbols", "score"} {
			value := rule[key]
			delete(rule, key)
			mutated, err := json.Marshal(map[string]any{"CSM_IP": rule})
			if err != nil {
				t.Fatal(err)
			}
			if len(CheckIPMapLoaded(on, mutated)) == 0 {
				t.Fatalf("accepted a rule without %s", key)
			}
			rule[key] = value
		}
	})
}

func FuzzRspamdComPaths(f *testing.F) {
	for _, seed := range []string{
		`{"multimap":"https://maps.rspamd.com/custom.txt"}`,
		`{"multimap":{"custom":{"map":"https://maps.rspamd.com/custom.txt"}}}`,
		`{"multimap":{"custom":{"map":"glob;/etc/rspamd/maps.rspamd.com.txt"}}}`,
		`{"multimap":{"custom":{"map":{"url":["sign+https://maps.rspamd.com/map","/etc/local"]}}}}`,
		`{"multimap":{"` + testKey + `":{"map":"https://maps.rspamd.com/"}}}`,
		`{"multimap":{"value":1e1000}}`, `null`, `[]`, `{}`, ``,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, dump []byte) {
		on := map[string]bool{"multimap": true}
		paths, err := RspamdComPaths(dump, on)
		if err != nil {
			if len(paths) != 0 || strings.Contains(err.Error(), testKey) {
				t.Fatal("invalid config returned paths or exposed configuration")
			}
			return
		}
		var root map[string]any
		if json.Unmarshal(dump, &root) != nil || root == nil || !slices.IsSorted(paths) {
			t.Fatal("accepted a non-object or returned unsorted paths")
		}
		for _, p := range paths {
			if p != "multimap" && !strings.HasPrefix(p, "multimap.") || strings.Contains(p, testKey) {
				t.Fatal("path is outside the enabled module or exposes configuration")
			}
		}
		if again, err := RspamdComPaths(dump, on); err != nil || !slices.Equal(again, paths) {
			t.Fatal("path ordering is not stable")
		}
		if off, err := RspamdComPaths(dump, nil); err != nil || len(off) != 0 {
			t.Fatal("disabled modules returned paths")
		}
	})
}

func FuzzNameservers(f *testing.F) {
	for _, options := range []string{
		`{}`, `null`, `{"dns":null}`,
		`{"dns":{"nameserver":["127.0.0.1","192.0.2.53"]}}`,
		`{"dns":{"nameserver":"master-slave:[::1]:53:10;192.0.2.53:53:1"}}`,
		`{"dns":{"server":["2001:db8::53"]}}`,
		`{"dns_nameserver":"192.0.2.53"}`,
		`{"dns":{"nameserver":"192.0.2.53","nameserver":"127.0.0.1"}}`,
		`{"dns":{"nameserver":"[::1]:invalid"}}`,
	} {
		f.Add(options, "nameserver 127.0.0.1\n")
	}
	f.Fuzz(func(t *testing.T, options, resolv string) {
		got, err := Nameservers([]byte(options), resolv)
		if err != nil {
			if len(got) != 0 {
				t.Fatal("unreadable nameservers returned a partial list")
			}
			return
		}
		if len(got) == 0 {
			t.Fatal("accepted an empty resolver list")
		}
		var entries []string
		for _, addr := range got {
			if !addr.IsValid() {
				t.Fatal("accepted an invalid resolver endpoint")
			}
			entries = append(entries, addr.String())
		}
		encoded, err := json.Marshal(map[string]any{"dns": map[string]string{"nameserver": strings.Join(entries, ";")}})
		if err != nil {
			t.Fatal(err)
		}
		if again, err := Nameservers(encoded, ""); err != nil || !slices.Equal(again, got) {
			t.Fatal("resolver list changed after re-encoding")
		}
	})
}

func FuzzLoadedRBLRules(f *testing.F) {
	for _, seed := range []string{
		`{"rbls":{"csm_psbl":{}},"rules":{}}`,
		`{"rbls":{"csm_psbl":{"enabled":false}}}`,
		`{"rbls":{"csm_psbl":{"disabled":true}}}`,
		`{"rbls":{"csm_psbl":{}},"rules":{"foreign":{}}}`,
		`{"rbls":{"csm_psbl":{},"csm_psbl":{}}}`,
		`{"rbls":{"csm_psbl":null}}`, `{"rbls":{}}`, `null`, ``,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		names, err := LoadedRBLRules(data)
		if err != nil {
			if names != nil {
				t.Fatal("unverifiable inventory returned rule names")
			}
			return
		}
		if !json.Valid(data) || !slices.IsSorted(names) || len(slices.Compact(slices.Clone(names))) != len(names) {
			t.Fatal("accepted invalid JSON or returned unsorted or duplicate rule names")
		}
		duplicate := strings.TrimSpace(string(data))
		duplicate = duplicate[:len(duplicate)-1] + `,"rbls":{}}`
		if _, err := LoadedRBLRules([]byte(duplicate)); err == nil {
			t.Fatal("accepted a duplicate rule inventory")
		}
		if _, err := LoadedRBLRules(append(append([]byte(nil), data...), []byte("{}")...)); err == nil {
			t.Fatal("accepted a trailing object")
		}
	})
}

func FuzzLoadDQSKey(f *testing.F) {
	for _, key := range []string{testKey, "", testKey[:25], testKey + "a", strings.ToUpper(testKey),
		strings.Repeat("0", 26), strings.Repeat("9", 26), strings.Repeat("z", 26),
		testKey[:25] + "\x00", testKey[:25] + "\"", testKey[:25] + "\n"} {
		f.Add(key)
	}
	f.Fuzz(func(t *testing.T, content string) {
		wantValid := len(content) == 26 && strings.Trim(content, "abcdefghijklmnopqrstuvwxyz0123456789") == ""
		key, err := LoadDQSKey(KeyFacts{Path: "/etc/csm/k", UID: 0, Mode: 0o600, Key: NewSecret(content)})
		if (err == nil) != wantValid {
			t.Fatal("key validation disagrees with the required alphabet and length")
		}
		if err != nil {
			if key.Reveal() != "" {
				t.Fatal("rejected input returned a key")
			}
			return
		}
		if key.Reveal() != content {
			t.Fatal("validated key changed its content")
		}
	})
}

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

func FuzzPhishtankEnabled(f *testing.F) {
	for _, seed := range []string{
		`{"phishtank_enabled":false}`, `{"phishtank_enabled":true}`,
		`{"phishtank_enabled":0}`, `{"phishtank_enabled":"false"}`,
		`{"phishtank_enabled":[]}`, `{"phishtank_enabled":null}`,
		`{"phishtank_enabled":false,"phishtank_enabled":true}`,
		`{"phishtank_enabled":false} trailing`, `{}`, `null`, ``,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		on, err := PhishtankEnabled(data)
		if err != nil {
			if on {
				t.Fatal("rejected setting returned enabled")
			}
			return
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(data, &fields); err != nil {
			t.Fatalf("accepted invalid JSON: %v", err)
		}
		var value *bool
		if err := json.Unmarshal(fields["phishtank_enabled"], &value); err != nil || value == nil || *value != on {
			t.Fatalf("accepted a missing, non-boolean or mismatched setting: %q", data)
		}
		duplicate := strings.TrimSpace(string(data))
		duplicate = duplicate[:len(duplicate)-1] + `,"phishtank_enabled":false}`
		if _, err := PhishtankEnabled([]byte(duplicate)); err == nil {
			t.Fatal("accepted a duplicate setting")
		}
		if _, err := PhishtankEnabled(append(append([]byte(nil), data...), []byte("{}")...)); err == nil {
			t.Fatal("accepted a trailing object")
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
		strings.TrimSuffix(validApply, "}") + `,"feeds":"psbl,spamhaus_dqs","skip_maps":"whitelist","dqs_key_file":"/etc/csm/dqs.key"}`,
		strings.TrimSuffix(validApply, "}") + `,"feeds":null}`,
		strings.TrimSuffix(validApply, "}") + `,"skip_maps":null}`,
		strings.TrimSuffix(validApply, "}") + `,"dqs_key_file":null}`,
		strings.TrimSuffix(validApply, "}") + `,"feeds":"psbl,"}`,
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
			if !reflect.DeepEqual(req, Request{}) || !reflect.DeepEqual(s, Settings{}) {
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
			if _, s2, err := DecodeRequest(again); err != nil || !reflect.DeepEqual(s2, s) {
				t.Fatalf("re-encoded apply: %+v %v", s2, err)
			}
		case OpRemove:
			if !reflect.DeepEqual(s, Settings{}) {
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
	for _, seed := range []string{
		"", "warn\n  log_message = x\n", h.Post + "deny\n", "@CONFIG@\n",
		"@AUTH@\n@CONFIG@\n" + h.Config, MarkerBegin + "\n", "  message = x\n",
		"@CONFIG@\n" + MarkerBegin + "\n@ROUTERSTART@\n" + MarkerEnd + "\n",
	} {
		for _, local := range []bool{false, true} {
			for _, remove := range []bool{false, true} {
				f.Add(seed, local, remove)
			}
		}
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

func FuzzDecodeRecord(f *testing.F) {
	for _, seed := range []string{
		`{"format":1,"generation":null}`,
		`{"format":1,"generation":"` + strings.Repeat("ab", 32) + `"}`,
		`{"format":1,"format":1,"generation":null}`,
		`{"format":1.0,"generation":null}`,
		`{"Format":1,"generation":null}`,
		`null`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		r, err := DecodeRecord(data)
		if err != nil {
			if r != (Record{}) {
				t.Fatal("rejected record returned a partial value")
			}
			return
		}
		gen := ""
		if r.Complete() {
			gen = *r.Generation
		}
		again, err := DecodeRecord(EncodeRecord(gen))
		if err != nil || again.Complete() != r.Complete() || again.Complete() && *again.Generation != gen {
			t.Fatalf("round trip changed %+v to %+v, %v", r, again, err)
		}
	})
}

func FuzzScanMarker(f *testing.F) {
	for _, seed := range []string{
		markerPrefix + `CSM-ANTISPAM event=scan mode=enforce policy=on result=ok score=0 action="no action" decision=none`,
		markerPrefix + `CSM-ANTISPAM event=scan mode=dry-run policy=off result=error score=none action="unavailable" decision=none`,
		"2026-10-09 08:19:03 H=(CSM-ANTISPAM event=scan) [192.0.2.1]",
		"0000-10-01\r0:00:00 0-0-0 CSM-ANTISPAM event=scan mode=enforce policy=on result=ok score=0 action=\"\" decision=none",
		strings.Replace(markerPrefix, " ", "\u0085", 1) + `CSM-ANTISPAM event=scan mode=enforce policy=on result=ok score=0 action="" decision=none`,
		"", "CSM-ANTISPAM", " CSM-ANTISPAM ",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, line string) {
		marker, ok := ScanMarker(line)
		if ok && !marker {
			t.Fatal("a successful scan outside a marker")
		}
		if marker && (!strings.Contains(line, " CSM-ANTISPAM event=scan mode=") || strings.ContainsAny(line, "\r\n")) {
			t.Fatalf("accepted %q", line)
		}
		if marker {
			for _, r := range line {
				if r < ' ' || r > '~' {
					t.Fatalf("accepted non-printable ASCII character %U", r)
				}
			}
		}
	})
}

// Cover every renderer branch with scores from Exim's signed integer output
// and arbitrary scanner actions sanitized by the hook's [^a-z ] replacement.
func FuzzScanMarkerValues(f *testing.F) {
	for _, score := range []int32{-2147483648, -1, 0, 59, 60, 149, 150, 2147483647} {
		for _, action := range []string{"", "no action", "add header", "soft reject", "reject", "A_1-\"\r\n\x00\u0085"} {
			f.Add(score, action)
		}
	}
	f.Fuzz(func(t *testing.T, score int32, action string) {
		var sanitized strings.Builder
		for i := 0; i < len(action); i++ {
			c := action[i]
			if c != ' ' && (c < 'a' || c > 'z') {
				c = '_'
			}
			sanitized.WriteByte(c)
		}
		for _, mode := range []string{"enforce", "dry-run"} {
			for _, policy := range []string{"on", "off"} {
				decision := "none"
				switch {
				case policy == "off":
					decision = "unfiltered"
				case score >= DefaultRejectScore*10:
					decision = "reject"
				case score >= DefaultTagScore*10:
					decision = "tag"
				}
				prefix := markerPrefix + "CSM-ANTISPAM event=scan mode=" + mode + " policy=" + policy
				line := prefix + " result=ok score=" + strconv.FormatInt(int64(score), 10) + ` action="` + sanitized.String() + `" decision=` + decision
				if marker, ok := ScanMarker(line); !marker || !ok {
					t.Fatalf("rejected successful scan %q: %t, %t", line, marker, ok)
				}
				line = prefix + ` result=error score=none action="unavailable" decision=none`
				if marker, ok := ScanMarker(line); !marker || ok {
					t.Fatalf("rejected scan error %q: %t, %t", line, marker, ok)
				}
			}
		}
	})
}

func FuzzParseScan(f *testing.F) {
	for _, seed := range []string{
		markerPrefix + `CSM-ANTISPAM event=scan mode=dry-run policy=on result=ok score=150 action="reject" decision=reject ip=198.51.100.7`,
		markerPrefix + `CSM-ANTISPAM event=scan mode=enforce policy=off result=ok score=-5 action="no action" decision=unfiltered ip=2001:db8::25`,
		markerPrefix + `CSM-ANTISPAM event=scan mode=enforce policy=on result=error score=none action="unavailable" decision=none ip=203.0.113.9`,
		markerPrefix + `CSM-ANTISPAM event=scan mode=enforce policy=on result=ok score=0 action="no action" decision=none ip=192.0.2.256`,
		markerPrefix + `CSM-ANTISPAM event=scan mode=enforce policy=on result=error score=none action="unavailable" decision=none ip=2001:db8:::1`,
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, line string) {
		s, marker := ParseScan(line)
		if m, ok := ScanMarker(line); m != marker || ok != s.OK {
			t.Fatalf("ScanMarker = %v, %v; ParseScan = %+v, %v", m, ok, s, marker)
		}
		if marker {
			if _, rawIP, present := strings.Cut(line, " ip="); present && rawIP != "" {
				if _, err := netip.ParseAddr(rawIP); err != nil || !s.IP.IsValid() {
					t.Fatalf("accepted malformed sender %q: %+v", rawIP, s)
				}
			}
		}
		if s.IP.IsValid() {
			i := strings.LastIndex(line, " ip=")
			if i < 0 {
				t.Fatalf("sender %v without an ip= field in %q", s.IP, line)
			}
			if a, err := netip.ParseAddr(line[i+len(" ip="):]); err != nil || a.Unmap() != s.IP {
				t.Fatalf("sender %v does not match the ip= field in %q", s.IP, line)
			}
		}
		if int(int32(s.Score)) != s.Score {
			t.Fatalf("score %d overflows int32", s.Score)
		}
	})
}

func FuzzParseControllerConfig(f *testing.F) {
	for _, seed := range []string{
		workerDump(`{"bind_socket":"localhost:11334","count":1,"password":"q1","secure_ip":["127.0.0.1","::1"]}`),
		workerDump(`{"bind_socket":["/run/rspamd/csm-controller.sock mode=0600","localhost:11334"],"secure_ip":[]}`),
		`{"worker":{"controller":{"bind_socket":"*:11334"}}}`,
		workerDump(`{"bind_socket":"[::1]:11334 ssl","password":null}`),
		workerDump(`{"bind_socket":"/run/x.sock,owner=_rspamd,MODE=0600"}`),
		workerDump(`{"bind_socket":"systemd:0"}`),
		workerDump(`{"bind_socket":"[2001:db8::1]:11334","secure_ip":[null]}`),
		workerDump(`{"bind_socket":"localhost:11334","password":"x","pass\u0077ord":""}`),
		`{"worker":[{"controller":{"bind_socket":"/run/x.sock mode=`,
		`{}`,
		``,
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, dump string) {
		cfg, err := ParseControllerConfig([]byte(dump))
		if err != nil {
			if !reflect.DeepEqual(cfg, ControllerConfig{}) {
				t.Fatal("error returned a partial controller config")
			}
			return
		}
		for _, l := range cfg.Listeners {
			if l.Unix && (l.Path == "" || !strings.HasPrefix(l.Path, "/")) {
				t.Fatalf("Unix listener without an absolute path: %+v", l)
			}
			if !l.Unix && l.HostPort == "" {
				t.Fatalf("TCP listener without host:port: %+v", l)
			}
			if l.Unix && (len(l.Path) > maxSocketPath || l.HostPort != "") {
				t.Fatal("Unix listener has an oversized path or TCP address")
			}
			if !l.Unix && (strings.HasPrefix(l.HostPort, "systemd:") || l.Path != "" || l.Mode != 0) {
				t.Fatal("TCP listener contains an unresolved endpoint or Unix fields")
			}
		}
		if cfg.Present && len(cfg.Listeners) == 0 {
			t.Fatalf("controller present without listeners: %+v", cfg)
		}
	})
}

func FuzzControllerTrustEntries(f *testing.F) {
	for _, entry := range []string{
		"203.0.113.10", "203.0.113.129/24", "::ffff:203.0.113.10",
		"::ffff:203.0.113.129/120", "::ffff:203.0.113.10/95", "::/0",
		"::1%lo", "2001:db8::10%eth0/128", "file:///trusted.map", "",
	} {
		f.Add(entry, uint8(10))
	}
	f.Fuzz(func(t *testing.T, entry string, last uint8) {
		addr := netip.AddrFrom4([4]byte{203, 0, 113, last})
		facts := hostFacts()
		facts.Addrs = []netip.Prefix{netip.PrefixFrom(addr, 32)}
		cfg := tcpController([]string{entry}, true, true)
		got := ControllerExposure(cfg, facts)
		facts.Addrs = []netip.Prefix{netip.PrefixFrom(netip.AddrFrom16(addr.As16()), 128)}
		if mapped := ControllerExposure(cfg, facts); !reflect.DeepEqual(got, mapped) {
			t.Fatalf("mapped interface changed exposure: %+v != %+v", got, mapped)
		}
		prefix, ok := trustPrefix(entry)
		if !ok {
			onlyReason(t, got, "localhost:11334", exposureUnresolved)
			return
		}
		if !prefix.IsValid() || prefix != prefix.Masked() || strings.Contains(entry, "%") {
			t.Fatal("accepted a zoned address or produced a non-canonical prefix")
		}
		cfg.TrustEntries = []string{prefix.String()}
		if canonical := ControllerExposure(cfg, facts); !reflect.DeepEqual(got, canonical) {
			t.Fatalf("canonical trust changed exposure: %+v != %+v", got, canonical)
		}
	})
}
