package antispam

import (
	"errors"
	"fmt"
	"io/fs"
	"reflect"
	"strings"
	"testing"
)

const statsUnixPath = "/run/rspamd/c.sock"

func statsFacts(listeners ...ControllerListener) HostFacts {
	return HostFacts{
		RspamdVersion:  CommandResult{Stdout: "Rspamd daemon version 3.9.1\n\nCPU architecture x86_64\n"},
		Controller:     ControllerConfig{Present: true, Listeners: listeners, PasswordSet: true},
		ControllerHost: ControllerHostFacts{RspamdUID: 990, Sockets: map[string]SocketFacts{}},
	}
}

func statsTCP(hostPort string) ControllerListener {
	return ControllerListener{Raw: hostPort, HostPort: hostPort}
}

func statsUnix() ControllerListener {
	return ControllerListener{Raw: statsUnixPath + " mode=0600", Unix: true, Path: statsUnixPath, Mode: 0o600}
}

func statsSocket(uid int) SocketFacts {
	return SocketFacts{Socket: PathFacts{Path: statsUnixPath, UID: uid, Mode: fs.ModeSocket | 0o600}}
}

func TestStatsEndpointPrefersUnix(t *testing.T) {
	// The TCP listener comes first and is trusted; the socket still wins.
	f := statsFacts(statsTCP("127.0.0.1:11334"), statsUnix())
	f.Controller.TrustEntries = []string{"127.0.0.1"}
	f.ControllerHost.Sockets[statsUnixPath] = statsSocket(990)
	ep, reason := StatsEndpointFor(f)
	want := StatsEndpoint{Unix: true, Address: statsUnixPath, RspamdUID: 990, Version: "3.9.1"}
	if ep != want || reason != "" {
		t.Fatalf("endpoint %+v reason %q, want %+v", ep, reason, want)
	}
}

// A socket CSM cannot show is rspamd's is skipped: ControllerGet would
// refuse it anyway, and the TCP listener may still serve.
func TestStatsEndpointUnixNeedsRspamdSocket(t *testing.T) {
	for name, tc := range map[string]struct {
		socket    *SocketFacts
		rspamdUID int
	}{
		"owned by root":     {&SocketFacts{Socket: PathFacts{Path: statsUnixPath, UID: 0, Mode: fs.ModeSocket | 0o600}}, 990},
		"missing":           {&SocketFacts{Missing: true}, 990},
		"stat error":        {&SocketFacts{Err: errors.New("permission denied")}, 990},
		"no facts":          {nil, 990},
		"unknown rspamd id": {&SocketFacts{Socket: PathFacts{Path: statsUnixPath, UID: -1, Mode: fs.ModeSocket | 0o600}}, -1},
	} {
		t.Run(name, func(t *testing.T) {
			f := statsFacts(statsUnix(), statsTCP("127.0.0.1:11334"))
			f.Controller.TrustEntries = []string{"127.0.0.1"}
			f.ControllerHost.RspamdUID = tc.rspamdUID
			if tc.socket != nil {
				f.ControllerHost.Sockets[statsUnixPath] = *tc.socket
			}
			ep, reason := StatsEndpointFor(f)
			want := StatsEndpoint{Address: "127.0.0.1:11334", Version: "3.9.1"}
			if ep != want || reason != "" {
				t.Fatalf("endpoint %+v reason %q, want %+v", ep, reason, want)
			}
		})
	}
}

func TestStatsEndpointLoopbackNeedsSecureIP(t *testing.T) {
	for _, tc := range []struct {
		hostPort string
		trust    []string
		want     string
	}{
		{"127.0.0.1:11334", []string{"127.0.0.1"}, "127.0.0.1:11334"},
		{"localhost:11334", []string{"127.0.0.1"}, "127.0.0.1:11334"},
		{"LocalHost:11334", []string{"127.0.0.1"}, "127.0.0.1:11334"},
		{"[::1]:11334", []string{"::1"}, "[::1]:11334"},
		{"127.0.0.1:11334", []string{"127.0.0.0/8"}, "127.0.0.1:11334"},
		{"127.0.0.1:11334", []string{"::ffff:127.0.0.1"}, "127.0.0.1:11334"},
		{"127.0.0.1:11334", []string{"192.0.2.1", "127.0.0.1"}, "127.0.0.1:11334"},
		{"127.0.0.1:11334", nil, ""},
		{"127.0.0.1:11334", []string{"192.0.2.1"}, ""},
		{"127.0.0.1:11334", []string{"localhost"}, ""},
		{"127.0.0.1:11334", []string{"/etc/rspamd/secure.map"}, ""},
		{"localhost:11334", []string{"::1"}, ""},
		{"[::1]:11334", []string{"127.0.0.1"}, ""},
		{"0.0.0.0:11334", []string{"0.0.0.0/0"}, ""},
		{"*:11334", []string{"127.0.0.1"}, ""},
		{"*v4:11334", []string{"127.0.0.1"}, ""},
		{"192.0.2.10:11334", []string{"192.0.2.10"}, ""},
		{"127.0.0.2:11334", []string{"127.0.0.0/8"}, ""},
		{"[::ffff:127.0.0.1]:11334", []string{"127.0.0.1"}, ""},
		{"127.0.0.1", []string{"127.0.0.1"}, ""},
		{"127.0.0.1:0", []string{"127.0.0.1"}, ""},
		{"127.0.0.1:11334:1", []string{"127.0.0.1"}, ""},
	} {
		f := statsFacts(statsTCP(tc.hostPort))
		f.Controller.TrustEntries = tc.trust
		ep, reason := StatsEndpointFor(f)
		want := StatsEndpoint{Address: tc.want, Version: "3.9.1"}
		wantReason := ""
		if tc.want == "" {
			wantReason = statsNoListener
		}
		if ep != want || reason != wantReason {
			t.Errorf("%s trust %q: endpoint %+v reason %q, want %+v %q", tc.hostPort, tc.trust, ep, reason, want, wantReason)
		}
	}
}

func TestStatsEndpointReasons(t *testing.T) {
	if statsNoListener != "rspamd's controller has no listener CSM can read without a password; add a private Unix socket (mode 0600, owned by rspamd)" {
		t.Fatalf("no-listener reason changed: %q", statsNoListener)
	}
	noWorker := statsFacts()
	noWorker.Controller = ControllerConfig{}
	dumpFailed := statsFacts()
	dumpFailed.Controller, dumpFailed.ControllerErr = ControllerConfig{}, errors.New("rspamadm configdump failed")
	unverifiable := statsFacts()
	unverifiable.Controller, unverifiable.ControllerUnverifiable = ControllerConfig{}, errors.New("bind_socket is missing")
	for name, tc := range map[string]struct {
		f    HostFacts
		want string
	}{
		"no controller worker": {noWorker, statsNoListener},
		"no listeners":         {statsFacts(), statsNoListener},
		"dump failed":          {dumpFailed, statsControllerUnknown},
		"unverifiable":         {unverifiable, statsControllerUnknown},
	} {
		ep, reason := StatsEndpointFor(tc.f)
		if ep != (StatsEndpoint{Version: "3.9.1"}) || reason != tc.want {
			t.Errorf("%s: endpoint %+v reason %q, want %q", name, ep, reason, tc.want)
		}
	}
	// Interface addresses do not matter to a loopback read.
	f := statsFacts(statsTCP("127.0.0.1:11334"))
	f.Controller.TrustEntries = []string{"127.0.0.1"}
	f.ControllerErr = errors.New("host interface addresses unavailable")
	if ep, reason := StatsEndpointFor(f); ep.Address != "127.0.0.1:11334" || reason != "" {
		t.Fatalf("endpoint %+v reason %q with a readable controller", ep, reason)
	}
}

func TestStatsEndpointVersion(t *testing.T) {
	for _, tc := range []struct {
		result CommandResult
		want   string
	}{
		{CommandResult{Stdout: "Rspamd daemon version 3.9.1\n\nCPU architecture x86_64\n"}, "3.9.1"},
		{CommandResult{Stdout: "  3.9.1 \r\nRspamd daemon version 9.9.9\n"}, "3.9.1"},
		{CommandResult{Stdout: "rspamd 3.9.1-custom\n"}, "rspamd 3.9.1-custom"},
		{CommandResult{Stdout: "Rspamd daemon version 3.9.1\n", Err: errors.New("exit status 1")}, ""},
		{CommandResult{}, ""},
	} {
		f := statsFacts()
		f.RspamdVersion = tc.result
		if ep, _ := StatsEndpointFor(f); ep.Version != tc.want {
			t.Errorf("%q: version %q, want %q", tc.result.Stdout, ep.Version, tc.want)
		}
	}
}

func TestParseRspamdStat(t *testing.T) {
	body := []byte(`{"scanned":1200,"learned":30,"ham_count":20,"spam_count":10,"uptime":86400,"version":"3.9.1","actions":{"reject":41,"add header":9},` +
		`"connections":7,"control_connections":2,"statfiles":[{"symbol":"BAYES_SPAM","revision":3}],"total_learns":30,"fuzzy_hashes":{"local":12},"read_only":false}`)
	got, err := ParseRspamdStat(body)
	if err != nil {
		t.Fatal(err)
	}
	want := RspamdStats{Scanned: 1200, Learned: 30, HamCount: 20, SpamCount: 10, UptimeSeconds: 86400, Version: "3.9.1",
		Actions: map[string]int64{"reject": 41, "add header": 9}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

// The controller can be spoofed on TCP, so display strings are bounded: a
// version over 32 characters is dropped for the host's, and an action name
// over 64 characters is skipped.
func TestParseRspamdStatBoundsStrings(t *testing.T) {
	version, name := strings.Repeat("9", 32), strings.Repeat("a", 64)
	body := fmt.Sprintf(`{"version":%q,"actions":{%q:1,%q:2,"reject":3}}`, version, name, name+"b")
	got, err := ParseRspamdStat([]byte(body))
	want := RspamdStats{Version: version, Actions: map[string]int64{name: 1, "reject": 3}}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v err %v, want %+v", got, err, want)
	}
	got, err = ParseRspamdStat([]byte(fmt.Sprintf(`{"version":%q,"scanned":4}`, version+"1")))
	if err != nil || !reflect.DeepEqual(got, RspamdStats{Scanned: 4}) {
		t.Fatalf("long version: got %+v err %v", got, err)
	}
	// Characters, not bytes: a 32-character version of two-byte runes stays.
	wide := strings.Repeat("\u00e9", 32)
	if got, err := ParseRspamdStat([]byte(fmt.Sprintf(`{"version":%q}`, wide))); err != nil || got.Version != wide {
		t.Fatalf("wide version: got %+v err %v", got, err)
	}
}

func TestParseRspamdStatToleratesAbsentFields(t *testing.T) {
	for _, tc := range []struct {
		body string
		want RspamdStats
	}{
		{`{}`, RspamdStats{}},
		{"\n {\"scanned\":5} \n", RspamdStats{Scanned: 5}},
		{`{"uptime":86400.75}`, RspamdStats{UptimeSeconds: 86400}},
		{`{"uptime":-3}`, RspamdStats{}},
		{`{"uptime":1e300}`, RspamdStats{}},
		{`{"scanned":null,"version":null}`, RspamdStats{}},
		// Output-only names in a reply are not read.
		{`{"top_rules":[{"symbol":"X","hits":1}],"uptime_seconds":9}`, RspamdStats{}},
	} {
		got, err := ParseRspamdStat([]byte(tc.body))
		if err != nil || !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%q: got %+v err %v, want %+v", tc.body, got, err, tc.want)
		}
	}
}

func TestParseRspamdStatRejectsGarbage(t *testing.T) {
	for _, b := range []string{"", "  ", "not json", `{"scanned":"many"}`, `[]`, `null`, `"stat"`, `12`,
		`{"scanned":1.5}`, `{"version":3}`, `{"actions":{"reject":"many"}}`, `{"actions":[]}`, `{"scanned":1} trailing`, `{"scanned":`} {
		got, err := ParseRspamdStat([]byte(b))
		if err == nil {
			t.Errorf("%q accepted as %+v", b, got)
			continue
		}
		if !reflect.DeepEqual(got, RspamdStats{}) {
			t.Errorf("%q: error returned partial stats %+v", b, got)
		}
		if strings.TrimSpace(b) != "" && strings.Contains(err.Error(), b) || strings.Contains(err.Error(), "many") {
			t.Errorf("%q: error repeats the reply: %v", b, err)
		}
	}
}

func TestParseRspamdCountersTop(t *testing.T) {
	long := strings.Repeat("S", 128)
	body := []byte(`[
		{"symbol":"R_A","weight":1,"frequency":0.1,"hits":5,"time":0.001},
		{"symbol":"R_B","hits":90},
		{"symbol":"R_C","hits":40},
		{"symbol":"R_D","hits":40},
		{"symbol":"R_E","hits":3},
		{"symbol":"R_F","hits":70},
		{"symbol":"R_G","hits":1},
		{"symbol":"R_H","hits":2},
		{"symbol":"R_I","hits":60},
		{"symbol":"R_J","hits":4},
		{"weight":1,"hits":1000},
		{"symbol":"","hits":999},
		{"symbol":"R_ZERO","hits":0},
		null,
		{"symbol":"R_GHOST","weight":0.0,"hits":0.0},
		{"symbol":"R_K","hits":12.0},
		{"symbol":"R_FRAC","hits":500.5},
		{"symbol":"` + long + `","hits":80},
		{"symbol":"` + long + `X","hits":1000}
	]`)
	got, err := ParseRspamdCounters(body, 8)
	if err != nil {
		t.Fatal(err)
	}
	// rspamd prints some counts as doubles (0.0 for virtual symbols): an
	// integral double counts, a fraction drops only its own entry, and a
	// symbol over 128 characters is not shown.
	want := []RuleHits{{"R_B", 90}, {long, 80}, {"R_F", 70}, {"R_I", 60}, {"R_C", 40}, {"R_D", 40}, {"R_K", 12}, {"R_A", 5}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	// A symbol that never fired is not a top rule, even on a short list.
	if got, err := ParseRspamdCounters([]byte(`[{"symbol":"R_ZERO","hits":0},{"symbol":"R_A","hits":1},{"symbol":"R_NEG","hits":-1}]`), 8); err != nil || !reflect.DeepEqual(got, []RuleHits{{"R_A", 1}}) {
		t.Fatalf("short list: %+v %v", got, err)
	}
	if got, err := ParseRspamdCounters([]byte(`[]`), 8); err != nil || len(got) != 0 {
		t.Fatalf("empty list: %+v %v", got, err)
	}
}

func TestParseRspamdCountersRejectsGarbage(t *testing.T) {
	for _, b := range []string{"", "not json", `{}`, `null`, `[1]`, `["R_A"]`, `[{"symbol":"R_A","hits":"many"}]`,
		`[{"symbol":5,"hits":1}]`, `[{"symbol":"R_A","hits":"12"}]`, `[] trailing`} {
		got, err := ParseRspamdCounters([]byte(b), 8)
		if err == nil {
			t.Errorf("%q accepted as %+v", b, got)
			continue
		}
		if got != nil {
			t.Errorf("%q: error returned partial rules %+v", b, got)
		}
		if strings.Contains(err.Error(), "many") || strings.Contains(err.Error(), "R_A") {
			t.Errorf("%q: error repeats the reply: %v", b, err)
		}
	}
}
