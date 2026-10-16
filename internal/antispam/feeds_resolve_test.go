package antispam

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"net/netip"
	"slices"
	"strings"
	"testing"
)

func TestResolveFeedsPreservesRequestedSettings(t *testing.T) {
	for _, failure := range []string{"resolver", "key", "optional file"} {
		t.Run(failure, func(t *testing.T) {
			s := dqsSettings()
			s.Feeds = append(s.Feeds, FeedRspamdMaps)
			want := slices.Clone(s.Feeds)
			remaining := []string{FeedRspamdMaps}
			f := feedFacts()
			switch failure {
			case "resolver":
				f.ResolvConf = "nameserver 198.51.100.53\n"
			case "key":
				f.DQSKey.Missing = true
				remaining = []string{FeedPSBL, FeedRspamdMaps}
			case "optional file":
				for i := range f.Targets {
					if f.Targets[i].Path == FeedRBLPath {
						f.Targets[i].Err = fs.ErrPermission
					}
				}
			}
			got, problems := ResolveFeeds(s, f)
			if len(problems) != len(want)-len(remaining) || !slices.Equal(got.Feeds, remaining) {
				t.Fatal("host failure did not drop exactly the affected feeds")
			}
			for _, p := range problems {
				if p.Code != CodeFeed || p.Severity != Warning {
					t.Fatal("feed failure blocks core")
				}
			}
			if !slices.Equal(s.Feeds, want) {
				t.Fatalf("requested feeds changed: %v; want %v", s.Feeds, want)
			}
			got, problems = ResolveFeeds(s, feedFacts())
			if len(problems) != 0 || !slices.Equal(got.Feeds, want) {
				t.Fatal("healthy host did not restore all requested feeds")
			}
		})
	}
}

func TestNameserversReadsEveryUpstream(t *testing.T) {
	for _, prefix := range []string{"", "master-slave:", "round-robin:", "random:", "hash:"} {
		for _, sep := range []string{",", ";", " ", "\t", "\n", "\r", ",; \t"} {
			options, err := json.Marshal(map[string]any{"dns": map[string]string{
				"nameserver": prefix + "[::1]:53:10" + sep + "192.0.2.53:53:1",
			}})
			if err != nil {
				t.Fatal(err)
			}
			got, err := Nameservers(options, "")
			want := []netip.Addr{netip.MustParseAddr("::1"), netip.MustParseAddr("192.0.2.53")}
			if err != nil || !slices.Equal(got, want) {
				t.Errorf("prefix %q, separator %q: got %v, %v; want %v", prefix, sep, got, err, want)
			}
		}
	}
}

func TestNameserversAliases(t *testing.T) {
	for _, options := range []string{
		`{"dns_nameserver":"192.0.2.53"}`,
		`{"dns":{"server":["192.0.2.53"]}}`,
	} {
		got, err := Nameservers([]byte(options), "nameserver 127.0.0.1\n")
		if err != nil || !slices.Equal(got, []netip.Addr{netip.MustParseAddr("192.0.2.53")}) {
			t.Errorf("alias ignored: got %v, %v", got, err)
		}
	}
}

func TestNameserversRejectsAmbiguousOptions(t *testing.T) {
	for _, options := range []string{
		`null`,
		`{"dns":null}`,
		`{"dns":{"nameserver":"192.0.2.53","nameserver":"127.0.0.1"}}`,
		`{"dns":{"nameserver":"192.0.2.53"},"dns":{"nameserver":"127.0.0.1"}}`,
		`{"dns_nameserver":"192.0.2.53","dns":{"nameserver":"127.0.0.1"}}`,
		`{"dns":{"server":"192.0.2.53","nameserver":"127.0.0.1"}}`,
	} {
		if got, err := Nameservers([]byte(options), "nameserver 127.0.0.1\n"); err == nil || len(got) != 0 {
			t.Errorf("ambiguous resolver configuration accepted: %s", options)
		}
	}
}

func TestNameserversRejectsMalformedEndpoint(t *testing.T) {
	for _, endpoint := range []string{
		"127.0.0.1:invalid", "127.0.0.1:53:invalid", "127.0.0.1:65536",
		"127.0.0.1:", "127.0.0.1:53:", "127.0.0.1:53:1:2",
		"[::1]junk", "[::1]:invalid", "[::1]:53:invalid", "[::1]:65536",
	} {
		options, err := json.Marshal(map[string]any{"dns": map[string]string{"nameserver": endpoint}})
		if err != nil {
			t.Fatal(err)
		}
		if got, err := Nameservers(options, ""); err == nil || len(got) != 0 {
			t.Errorf("malformed endpoint accepted: %q", endpoint)
		}
	}
}

func TestResolveFeedsRejectsPublicUpstreamForms(t *testing.T) {
	for _, options := range []string{
		`{"dns":{"nameserver":"127.0.0.1:53;198.51.100.53"}}`,
		`{"dns":{"nameserver":"[::1]:53 198.51.100.53"}}`,
		`{"dns_nameserver":"198.51.100.53"}`,
		`{"dns":{"server":"198.51.100.53"}}`,
		`{"dns":{"nameserver":"198.51.100.53","Nameserver":"127.0.0.1"}}`,
	} {
		f := feedFacts()
		f.RspamdOptions.Stdout = options
		got, problems := ResolveFeeds(dqsSettings(), f)
		if len(got.Feeds) != 0 || len(problems) != 2 || got.DQSKey.Reveal() != "" {
			t.Errorf("DNS feeds retained with a public upstream: %s", options)
		}
	}
}

func TestNameserversErrorsDoNotEchoInput(t *testing.T) {
	for _, entry := range []string{testKey, "127.0.0.1:" + testKey, "[::1]:" + testKey} {
		options, err := json.Marshal(map[string]any{"dns": map[string]string{"nameserver": entry}})
		if err != nil {
			t.Fatal(err)
		}
		_, err = Nameservers(options, "")
		if err == nil || strings.Contains(err.Error(), testKey) {
			t.Fatal("resolver error is missing or exposes input")
		}
	}
}

func TestNameservers(t *testing.T) {
	addrs := func(ss ...string) []netip.Addr {
		var out []netip.Addr
		for _, s := range ss {
			out = append(out, netip.MustParseAddr(s))
		}
		return out
	}
	for _, tc := range []struct {
		options, resolv string
		want            []netip.Addr
		wantErr         bool
	}{
		{`{"dns":{"timeout":1.0}}`, "# c\nnameserver 192.0.2.53\nnameserver 2001:db8::53\nsearch example.com\n", addrs("192.0.2.53", "2001:db8::53"), false},
		{`{"dns":{"nameserver":"127.0.0.1"}}`, "nameserver 192.0.2.53\n", addrs("127.0.0.1"), false},
		{`{"dns":{"nameserver":["127.0.0.1:53:10","10.0.0.2"]}}`, "", addrs("127.0.0.1", "10.0.0.2"), false},
		{`{"dns":{"nameserver":"master-slave:127.0.0.1,192.168.1.1"}}`, "", addrs("127.0.0.1", "192.168.1.1"), false},
		{`{"dns":{"nameserver":"round-robin:[::1]:53,10.1.1.1"}}`, "", addrs("::1", "10.1.1.1"), false},
		{`{"dns":{"nameserver":"ns1.example.com"}}`, "", nil, true},
		{`{"dns":{}}`, "search example.com\n", nil, true},
		{`{"dns":{}}`, "nameserver fe80::1%eth0\n", addrs("fe80::1"), false},
		{`{"dns":{}}`, "nameserver 192.0.2.53#resolver\n", addrs("192.0.2.53"), false},
		{`not json`, "nameserver 127.0.0.1\n", nil, true},
	} {
		got, err := Nameservers([]byte(tc.options), tc.resolv)
		if (err != nil) != tc.wantErr || !slices.Equal(got, tc.want) {
			t.Errorf("Nameservers(%s, %q) = %v, %v; want %v, err %v", tc.options, tc.resolv, got, err, tc.want, tc.wantErr)
		}
	}
}

// feedFacts is a host where every optional file can be written, rspamd uses
// a loopback resolver and the DQS key file is valid.
func feedFacts() HostFacts {
	var targets []TargetFacts
	for _, tgt := range MutationTargets() {
		targets = append(targets, TargetFacts{Target: tgt, Missing: true, Parents: protectedParents()})
	}
	return HostFacts{
		Targets:       targets,
		RspamdOptions: CommandResult{Stdout: `{"dns":{}}`},
		ResolvConf:    "nameserver 127.0.0.1\n",
		RspamdGID:     974,
		DQSKey:        KeyFacts{Path: "/etc/csm/k", UID: 0, Mode: 0o600, Key: NewSecret(testKey)},
	}
}

func dqsSettings() Settings {
	s := defaults(false)
	s.Feeds = []string{FeedPSBL, FeedSpamhausDQS}
	s.DQSKeyFile = "/etc/csm/k"
	return s
}

func TestResolveFeedsKeepsEverythingOnAGoodHost(t *testing.T) {
	got, problems := ResolveFeeds(dqsSettings(), feedFacts())
	if len(problems) != 0 || !slices.Equal(got.Feeds, []string{FeedPSBL, FeedSpamhausDQS}) || got.DQSKey.Reveal() != testKey || len(got.SkipMaps) != 0 {
		t.Fatalf("got %+v, problems %+v", got, problems)
	}
}

func TestResolveFeedsDropsDNSFeedsOnPublicResolver(t *testing.T) {
	f := feedFacts()
	f.ResolvConf = "nameserver 127.0.0.1\nnameserver 198.51.100.53\n"
	s := dqsSettings()
	s.Feeds = append(s.Feeds, FeedRspamdMaps)
	got, problems := ResolveFeeds(s, f)
	if !slices.Equal(got.Feeds, []string{FeedRspamdMaps}) {
		t.Fatalf("feeds = %v", got.Feeds)
	}
	if len(problems) != 2 || problems[0].Key != FeedPSBL || problems[1].Key != FeedSpamhausDQS {
		t.Fatalf("problems = %+v", problems)
	}
	for _, p := range problems {
		if p.Code != CodeFeed || p.Severity != Warning || !strings.Contains(p.Detail, "local.d/options.inc") {
			t.Errorf("problem %+v", p)
		}
	}
}

func TestResolveFeedsDropsDNSFeedsWhenOverrideFileUnusable(t *testing.T) {
	f := feedFacts()
	for i := range f.Targets {
		if f.Targets[i].Path == FeedRBLGroupPath {
			f.Targets[i].Missing, f.Targets[i].File, f.Targets[i].Content = false, PathFacts{Path: FeedRBLGroupPath, Mode: 0o644}, "operator\n"
		}
		if f.Targets[i].Path == FeedRBLPath {
			f.Targets[i].Err = fmt.Errorf("lstat: %w", fs.ErrNotExist)
		}
	}
	got, problems := ResolveFeeds(dqsSettings(), f)
	if len(got.Feeds) != 0 || len(problems) != 2 {
		t.Fatalf("feeds %v, problems %+v", got.Feeds, problems)
	}
}

func TestResolveFeedsSkipsForeignRedirect(t *testing.T) {
	f := feedFacts()
	p := RedirectPath(RedirectWhitelist)
	for i := range f.Targets {
		if f.Targets[i].Path == p {
			f.Targets[i].Missing, f.Targets[i].File, f.Targets[i].Content = false, PathFacts{Path: p, Mode: 0o644}, "operator\n"
		}
	}
	got, problems := ResolveFeeds(defaults(false), f)
	if !slices.Equal(got.SkipMaps, []string{RedirectWhitelist}) || len(problems) != 1 || problems[0].Key != FeedRspamdMaps || !strings.Contains(problems[0].Detail, p) {
		t.Fatalf("got %+v, problems %+v", got, problems)
	}
	s := defaults(false)
	s.Feeds = []string{FeedRspamdMaps}
	if got, problems := ResolveFeeds(s, f); len(got.SkipMaps) != 0 || len(problems) != 0 {
		t.Fatalf("rspamd_maps needs no redirect files: %+v %+v", got, problems)
	}
}

func TestResolveFeedsDropsOnlyDQSForKeyProblems(t *testing.T) {
	for name, mutate := range map[string]func(*HostFacts){
		"world readable": func(f *HostFacts) { f.DQSKey.Mode = 0o644 },
		"bad key":        func(f *HostFacts) { f.DQSKey.Key = NewSecret("short") },
		"missing":        func(f *HostFacts) { f.DQSKey = KeyFacts{Path: "/etc/csm/k", Missing: true} },
		"unknown group":  func(f *HostFacts) { f.RspamdGID = -1 },
	} {
		f := feedFacts()
		mutate(&f)
		got, problems := ResolveFeeds(dqsSettings(), f)
		if !slices.Equal(got.Feeds, []string{FeedPSBL}) || got.DQSKey.Reveal() != "" || len(problems) != 1 || problems[0].Key != FeedSpamhausDQS {
			t.Errorf("%s: got %+v, problems %+v", name, got, problems)
		}
		if strings.Contains(fmt.Sprint(problems), testKey) {
			t.Errorf("%s: problem carries the key", name)
		}
	}
}

// A local resolver on a cPanel host often cannot use port 53, which
// PowerDNS holds, so the probe must ask the port rspamd uses.
func TestProbeServerKeepsThePort(t *testing.T) {
	for _, tc := range []struct {
		options, resolv, want string
	}{
		{`{"dns":{"nameserver":"127.0.0.1:5353:10"}}`, "", "127.0.0.1:5353"},
		{`{"dns":{"nameserver":["[::1]:5300","10.0.0.2"]}}`, "", "[::1]:5300"},
		{`{"dns":{"nameserver":"master-slave:10.0.0.2,127.0.0.1:5353"}}`, "", "10.0.0.2:53"},
		{`{"dns":{}}`, "nameserver 127.0.0.1\n", "127.0.0.1:53"},
	} {
		got, err := ProbeServer([]byte(tc.options), tc.resolv)
		if err != nil || got.String() != tc.want {
			t.Errorf("ProbeServer(%s, %q) = %v, %v; want %s", tc.options, tc.resolv, got, err, tc.want)
		}
	}
	if _, err := ProbeServer([]byte(`{"dns":{"nameserver":"ns1.example.com"}}`), ""); err == nil {
		t.Error("accepted a host name")
	}
}
