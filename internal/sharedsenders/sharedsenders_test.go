package sharedsenders

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/mailranges"
)

// The daemon passes the system resolver.
var _ Resolver = net.DefaultResolver

var testNow = time.Unix(1_793_000_000, 0)

const day = 24 * time.Hour

// fakeResolver answers from its maps; a name missing from a map is not found.
// errs, keyed "txt:", "ptr:" or "ip:" plus the name, overrides the answer.
type fakeResolver struct {
	txt         map[string][]string
	ptr         map[string][]string
	fwd         map[string][]net.IP
	errs        map[string]error
	calls       []string
	ptrDeadline time.Time
}

func notFoundErr(name string) error {
	return &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

func (f *fakeResolver) start(ctx context.Context, key string) error {
	f.calls = append(f.calls, key)
	if err := ctx.Err(); err != nil {
		return err
	}
	return f.errs[key]
}

func (f *fakeResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	if err := f.start(ctx, "txt:"+name); err != nil {
		return nil, err
	}
	if v, ok := f.txt[name]; ok {
		return v, nil
	}
	return nil, notFoundErr(name)
}

func (f *fakeResolver) LookupAddr(ctx context.Context, addr string) ([]string, error) {
	f.ptrDeadline, _ = ctx.Deadline()
	if err := f.start(ctx, "ptr:"+addr); err != nil {
		return nil, err
	}
	if v, ok := f.ptr[addr]; ok {
		return v, nil
	}
	return nil, notFoundErr(addr)
}

func (f *fakeResolver) LookupIP(ctx context.Context, network, host string) ([]net.IP, error) {
	if network != "ip" {
		return nil, fmt.Errorf("unexpected network %q", network)
	}
	if err := f.start(ctx, "ip:"+host); err != nil {
		return nil, err
	}
	if v, ok := f.fwd[host]; ok {
		return v, nil
	}
	return nil, notFoundErr(host)
}

func providerNames() []string { return slices.Sorted(maps.Keys(providers)) }

// allProviders returns a policy for every provider: the one in extra, or an
// empty one.
func allProviders(extra map[string]mailranges.Policy) map[string]mailranges.Policy {
	m := make(map[string]mailranges.Policy, len(providers))
	for _, name := range providerNames() {
		m[name] = extra[name]
	}
	return m
}

func mustNet(t *testing.T, cidr string) *net.IPNet {
	t.Helper()
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func addr(s string) netip.Addr { return netip.MustParseAddr(s) }

func ips(ss ...string) []net.IP {
	out := make([]net.IP, 0, len(ss))
	for _, s := range ss {
		out = append(out, net.ParseIP(s))
	}
	return out
}

// ptrGuard is ready and protects names under mail.example.net through yahoo.
func ptrGuard() *Guard {
	return NewForTest(allProviders(map[string]mailranges.Policy{
		"yahoo": {PTRDomains: []string{"mail.example.net"}},
	}), testNow)
}

// spfTrees answers every provider root with a ptr-only record naming
// <provider><suffix>.
func spfTrees(suffix string) map[string][]string {
	txt := make(map[string][]string, len(providers))
	for name, root := range providers {
		txt[root] = []string{"v=spf1 ptr:" + name + suffix + " -all"}
	}
	return txt
}

// validCache has every provider resolved at testNow, one prefix for google and
// one ptr domain for yahoo.
func validCache() cacheFile {
	c := cacheFile{Version: 1, Providers: make(map[string]cacheProvider, len(providers))}
	for name, root := range providers {
		c.Providers[name] = cacheProvider{Root: root, ResolvedAt: testNow.Unix()}
	}
	g := c.Providers["google"]
	g.Nets = []string{"198.51.100.0/24"}
	c.Providers["google"] = g
	y := c.Providers["yahoo"]
	y.PTR = []string{"mail.example.net"}
	c.Providers["yahoo"] = y
	return c
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func writeCache(t *testing.T, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "shared_senders.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// padTo appends JSON whitespace until data is n bytes long.
func padTo(data []byte, n int) []byte {
	return append(data, bytes.Repeat([]byte(" "), n-len(data))...)
}

func repeat(s string, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = s
	}
	return out
}

func TestGuardIsNotReadyUntilEveryProviderResolved(t *testing.T) {
	g := New(filepath.Join(t.TempDir(), "shared_senders.json"))
	if err := g.Load(testNow); err != nil {
		t.Fatalf("Load without a cache file: %v", err)
	}
	if g.Ready(testNow) {
		t.Fatal("guard without a cache is ready")
	}
	if !g.Covers(addr("198.51.100.7"), testNow) {
		t.Fatal("guard without a cache does not cover 198.51.100.7")
	}

	all := allProviders(nil)
	if full := NewForTest(all, testNow); !full.Ready(testNow) || full.Covers(addr("198.51.100.7"), testNow) {
		t.Fatal("guard with every provider resolved now is not ready, or covers an address outside every prefix")
	}
	for _, missing := range providerNames() {
		seven := maps.Clone(all)
		delete(seven, missing)
		partial := NewForTest(seven, testNow)
		if partial.Ready(testNow) {
			t.Errorf("guard without %s is ready", missing)
		}
		if !partial.Covers(addr("198.51.100.7"), testNow) {
			t.Errorf("guard without %s does not cover 198.51.100.7", missing)
		}
	}

	if !NewForTest(all, testNow.Add(-7*day)).Ready(testNow) {
		t.Error("providers resolved exactly 7 days ago are not ready")
	}
	if NewForTest(all, testNow.Add(-7*day-time.Second)).Ready(testNow) {
		t.Error("providers resolved more than 7 days ago are ready")
	}
	if NewForTest(all, testNow.Add(time.Second)).Ready(testNow) {
		t.Error("providers resolved after now are ready")
	}

	c := validCache()
	y := c.Providers["yahoo"]
	y.ResolvedAt = testNow.Add(-8 * day).Unix()
	c.Providers["yahoo"] = y
	g = New(writeCache(t, mustJSON(t, c)))
	if err := g.Load(testNow); err != nil {
		t.Fatalf("Load with yahoo resolved 8 days ago: %v", err)
	}
	if g.Ready(testNow) {
		t.Fatal("guard with yahoo resolved 8 days ago is ready")
	}
	if !g.Covers(addr("203.0.113.7"), testNow) {
		t.Fatal("guard with yahoo resolved 8 days ago does not cover 203.0.113.7")
	}
}

func TestGuardCoversEachProvider(t *testing.T) {
	for _, name := range providerNames() {
		t.Run(name, func(t *testing.T) {
			g := NewForTest(allProviders(map[string]mailranges.Policy{
				// A 16-byte IPv4 address, as net.ParseIP returns it.
				name: {Nets: []*net.IPNet{
					{IP: net.ParseIP("198.51.100.0"), Mask: net.CIDRMask(24, 32)},
					mustNet(t, "2001:db8:1::/48"),
				}},
			}), testNow)
			for _, tc := range []struct {
				ip   string
				want bool
			}{
				{"198.51.100.7", true},
				{"::ffff:198.51.100.7", true},
				{"2001:db8:1::7", true},
				{"203.0.113.7", false},
				{"2001:db8::7", false},
			} {
				if got := g.Covers(addr(tc.ip), testNow); got != tc.want {
					t.Errorf("Covers(%s) = %v, want %v", tc.ip, got, tc.want)
				}
			}
			if !g.Covers(netip.Addr{}, testNow) {
				t.Error("Covers(invalid address) = false, want true")
			}
			r := &fakeResolver{}
			if !g.Shared(context.Background(), r, addr("198.51.100.7"), testNow) {
				t.Error("Shared(198.51.100.7) = false for an address in a provider prefix")
			}
			if len(r.calls) != 0 {
				t.Errorf("Shared on a covered address made DNS lookups %q", r.calls)
			}
		})
	}
}

func TestSharedForwardConfirmsPTR(t *testing.T) {
	g := ptrGuard()
	r := &fakeResolver{
		ptr: map[string][]string{
			"203.0.113.7":  {"mx1.mail.example.net."},
			"203.0.113.8":  {"mx2.mail.example.net."},
			"203.0.113.11": {"notmail.example.net."},
			"203.0.113.12": {"mail.example.net.example.org."},
			"203.0.113.13": {"MX3.Mail.Example.NET."},
			"203.0.113.14": {"mail.example.net"},
			"203.0.113.15": {"gone.mail.example.net.", "mx5.mail.example.net."},
			"203.0.113.16": {"gone.mail.example.net."},
			"2001:db8::25": {"mx6.mail.example.net."},
		},
		fwd: map[string][]net.IP{
			"mx1.mail.example.net.":         ips("203.0.113.7"),
			"mx2.mail.example.net.":         ips("203.0.113.9"),
			"notmail.example.net.":          ips("203.0.113.11"),
			"mail.example.net.example.org.": ips("203.0.113.12"),
			"mx3.mail.example.net.":         ips("203.0.113.13"),
			"mail.example.net.":             ips("203.0.113.14"),
			"mx5.mail.example.net.":         ips("192.0.2.1", "203.0.113.15"),
			"mx6.mail.example.net.":         ips("2001:db8::25"),
		},
	}
	for _, tc := range []struct {
		desc  string
		ip    string
		want  bool
		calls []string
	}{
		{"PTR resolves back", "203.0.113.7", true, []string{"ptr:203.0.113.7", "ip:mx1.mail.example.net."}},
		{"IPv4-mapped address", "::ffff:203.0.113.7", true, []string{"ptr:203.0.113.7", "ip:mx1.mail.example.net."}},
		{"spoofed PTR resolves elsewhere", "203.0.113.8", false, []string{"ptr:203.0.113.8", "ip:mx2.mail.example.net."}},
		{"name only ends with the domain text", "203.0.113.11", false, []string{"ptr:203.0.113.11"}},
		{"domain inside a longer name", "203.0.113.12", false, []string{"ptr:203.0.113.12"}},
		{"no PTR", "203.0.113.10", false, []string{"ptr:203.0.113.10"}},
		{"mixed-case PTR", "203.0.113.13", true, []string{"ptr:203.0.113.13", "ip:mx3.mail.example.net."}},
		{"PTR is the domain itself", "203.0.113.14", true, []string{"ptr:203.0.113.14", "ip:mail.example.net."}},
		{"not-found forward skips the name", "203.0.113.15", true, []string{"ptr:203.0.113.15", "ip:gone.mail.example.net.", "ip:mx5.mail.example.net."}},
		{"only name not found forward", "203.0.113.16", false, []string{"ptr:203.0.113.16", "ip:gone.mail.example.net."}},
		{"IPv6 PTR resolves back", "2001:db8::25", true, []string{"ptr:2001:db8::25", "ip:mx6.mail.example.net."}},
	} {
		r.calls = nil
		before := time.Now()
		got := g.Shared(context.Background(), r, addr(tc.ip), testNow)
		after := time.Now()
		if got != tc.want {
			t.Errorf("%s: Shared(%s) = %v, want %v", tc.desc, tc.ip, got, tc.want)
		}
		if !slices.Equal(r.calls, tc.calls) {
			t.Errorf("%s: lookups %q, want %q", tc.desc, r.calls, tc.calls)
		}
		if r.ptrDeadline.Before(before.Add(5*time.Second)) || r.ptrDeadline.After(after.Add(5*time.Second)) {
			t.Errorf("%s: PTR lookup deadline %v is not 5 seconds after the call (%v to %v)", tc.desc, r.ptrDeadline, before, after)
		}
	}
}

func TestSharedFailsClosed(t *testing.T) {
	servfail := &net.DNSError{Err: "server misbehaving", Name: "x.example", IsTemporary: true}
	expired, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	names := func(n int, suffix string) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = fmt.Sprintf("h%d%s", i, suffix)
		}
		return out
	}
	tenUnder := names(10, ".mail.example.net.")
	tenFwd := make(map[string][]net.IP, len(tenUnder))
	for i, n := range tenUnder {
		tenFwd[n] = ips(fmt.Sprintf("192.0.2.%d", i+1))
	}
	seven := allProviders(nil)
	delete(seven, "yahoo")

	const ip = "203.0.113.20"
	for _, tc := range []struct {
		desc  string
		g     *Guard
		ctx   context.Context
		r     *fakeResolver
		want  bool
		calls int
	}{
		{"PTR timeout", ptrGuard(), context.Background(), &fakeResolver{errs: map[string]error{"ptr:" + ip: &net.DNSError{Err: "i/o timeout", Name: ip, IsTimeout: true}}}, true, 1},
		{"PTR past the caller's deadline", ptrGuard(), expired, &fakeResolver{ptr: map[string][]string{ip: {"mx1.mail.example.net."}}}, true, 1},
		{"PTR servfail", ptrGuard(), context.Background(), &fakeResolver{errs: map[string]error{"ptr:" + ip: servfail}}, true, 1},
		{"PTR not found but temporary", ptrGuard(), context.Background(), &fakeResolver{errs: map[string]error{"ptr:" + ip: &net.DNSError{Err: "no such host", Name: ip, IsNotFound: true, IsTemporary: true}}}, true, 1},
		{"PTR error that is not a DNS error", ptrGuard(), context.Background(), &fakeResolver{errs: map[string]error{"ptr:" + ip: errors.New("resolver closed")}}, true, 1},
		{"forward servfail", ptrGuard(), context.Background(), &fakeResolver{ptr: map[string][]string{ip: {"mx1.mail.example.net."}}, errs: map[string]error{"ip:mx1.mail.example.net.": servfail}}, true, 2},
		{"11 PTR names", ptrGuard(), context.Background(), &fakeResolver{ptr: map[string][]string{ip: names(11, ".example.org.")}}, true, 1},
		{"guard not ready", NewForTest(seven, testNow), context.Background(), &fakeResolver{}, true, 0},
		// Controls: the same shapes without a failure are not shared.
		{"10 PTR names, none resolving back", ptrGuard(), context.Background(), &fakeResolver{ptr: map[string][]string{ip: tenUnder}, fwd: tenFwd}, false, 11},
		{"PTR not found", ptrGuard(), context.Background(), &fakeResolver{}, false, 1},
	} {
		if got := tc.g.Shared(tc.ctx, tc.r, addr(ip), testNow); got != tc.want {
			t.Errorf("%s: Shared = %v, want %v", tc.desc, got, tc.want)
		}
		if len(tc.r.calls) != tc.calls {
			t.Errorf("%s: lookups %q, want %d", tc.desc, tc.r.calls, tc.calls)
		}
	}
}

func TestRefreshKeepsLastGoodAndPersists(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "shared_senders.json")
	g := New(path)
	if err := g.Refresh(ctx, &fakeResolver{txt: spfTrees(".example")}, testNow); err != nil {
		t.Fatalf("first Refresh: %v", err)
	}
	if !g.Ready(testNow) {
		t.Fatal("not ready after every provider resolved")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Fatalf("cache mode %o, want 600", mode)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var c cacheFile
	if err = json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	if c.Version != 1 || len(c.Providers) != len(providers) {
		t.Fatalf("cache version %d with %d providers, want 1 with %d", c.Version, len(c.Providers), len(providers))
	}
	for name, root := range providers {
		p := c.Providers[name]
		if p.Root != root || p.ResolvedAt != testNow.Unix() || len(p.Nets) != 0 || !slices.Equal(p.PTR, []string{name + ".example"}) {
			t.Errorf("cached %s = %+v", name, p)
		}
	}

	// yahoo fails the second time; Covers keeps running so -race sees a
	// reader during the publish.
	later := testNow.Add(time.Hour)
	r := &fakeResolver{
		txt:  spfTrees(".example.net"),
		errs: map[string]error{"txt:" + providers["yahoo"]: &net.DNSError{Err: "server misbehaving", Name: providers["yahoo"], IsTemporary: true}},
	}
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
				g.Covers(addr("203.0.113.7"), later)
			}
		}
	}()
	err = g.Refresh(ctx, r, later)
	close(stop)
	<-done
	if err == nil {
		t.Fatal("Refresh with a failing provider returned nil")
	}
	for _, name := range providerNames() {
		if named := strings.Contains(err.Error(), "provider "+name+":"); named != (name == "yahoo") {
			t.Errorf("error %q names %s: %v", err, name, named)
		}
	}
	if !g.Ready(later) {
		t.Fatal("not ready after one provider failed")
	}

	reloaded := New(path)
	if err := reloaded.Load(later); err != nil {
		t.Fatalf("Load: %v", err)
	}
	for _, guard := range []*Guard{g, reloaded} {
		s := guard.current()
		for _, name := range providerNames() {
			wantPTR, wantAt := name+".example.net", later.Unix()
			if name == "yahoo" {
				wantPTR, wantAt = "yahoo.example", testNow.Unix()
			}
			if p := s[name].cache; !slices.Equal(p.PTR, []string{wantPTR}) || p.ResolvedAt != wantAt {
				t.Errorf("%s = ptr %q at %d, want %q at %d", name, p.PTR, p.ResolvedAt, wantPTR, wantAt)
			}
		}
	}
	if !reloaded.Ready(later) {
		t.Fatal("reloaded guard is not ready")
	}
	if reloaded.Ready(testNow.Add(8 * day)) {
		t.Fatal("reloaded guard is ready 8 days after yahoo last resolved")
	}
}

func TestRefreshPublishesNothingWhenTheCacheIsNotWritten(t *testing.T) {
	ctx := context.Background()
	later := testNow.Add(time.Hour)
	unchanged := func(t *testing.T, g *Guard, wantPTR func(name string) []string, wantAt int64) {
		t.Helper()
		s := g.current()
		for _, name := range providerNames() {
			if p := s[name].cache; !slices.Equal(p.PTR, wantPTR(name)) || p.ResolvedAt != wantAt {
				t.Errorf("%s = ptr %q at %d after a failed write, want %q at %d", name, p.PTR, p.ResolvedAt, wantPTR(name), wantAt)
			}
		}
	}

	t.Run("write fails", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "shared_senders.json")
		g := New(path)
		if err := g.Refresh(ctx, &fakeResolver{txt: spfTrees(".example")}, testNow); err != nil {
			t.Fatal(err)
		}
		// A directory in the cache file's place makes the rename fail.
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
		err := g.Refresh(ctx, &fakeResolver{txt: spfTrees(".example.net")}, later)
		if err == nil || !strings.Contains(err.Error(), "write cache") {
			t.Fatalf("Refresh = %v, want a cache write error", err)
		}
		unchanged(t, g, func(name string) []string { return []string{name + ".example"} }, testNow.Unix())
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 1 {
			t.Errorf("state dir holds %d entries after a failed write, want only the blocking directory", len(entries))
		}
	})

	t.Run("cache over 1 MiB", func(t *testing.T) {
		// Seven providers at the prefix limit with long IPv6 prefixes make a
		// cache Load would refuse.
		big := map[string]mailranges.Policy{}
		for _, name := range providerNames() {
			if name == "google" {
				continue
			}
			nets := make([]*net.IPNet, maxNets)
			for i := range nets {
				nets[i] = mustNet(t, fmt.Sprintf("2001:db8:aaaa:bbbb:cccc:dddd:eeee:%x/128", i))
			}
			big[name] = mailranges.Policy{Nets: nets}
		}
		g := NewForTest(allProviders(big), testNow)
		g.path = filepath.Join(t.TempDir(), "shared_senders.json")
		// Only google resolves; the others keep their large last good policies.
		r := &fakeResolver{txt: map[string][]string{providers["google"]: {"v=spf1 ptr:google.example -all"}}}
		err := g.Refresh(ctx, r, later)
		if err == nil || !strings.Contains(err.Error(), "write cache") {
			t.Fatalf("Refresh = %v, want a cache write error", err)
		}
		if _, err := os.Stat(g.path); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("cache file stat = %v, want not exist", err)
		}
		unchanged(t, g, func(string) []string { return nil }, testNow.Unix())
	})

	t.Run("no cache path", func(t *testing.T) {
		g := NewForTest(allProviders(nil), testNow)
		r := &fakeResolver{txt: spfTrees(".example")}
		if err := g.Refresh(ctx, r, later); err == nil {
			t.Fatal("Refresh on a guard without a cache path returned nil")
		}
		if len(r.calls) != 0 {
			t.Errorf("Refresh without a cache path made lookups %q", r.calls)
		}
		unchanged(t, g, func(string) []string { return nil }, testNow.Unix())
	})
}

func TestLoadRejectsBadCache(t *testing.T) {
	withProvider := func(name string, edit func(*cacheProvider)) func(t *testing.T) []byte {
		return func(t *testing.T) []byte {
			c := validCache()
			p := c.Providers[name]
			edit(&p)
			c.Providers[name] = p
			return mustJSON(t, c)
		}
	}
	for _, tc := range []struct {
		desc string
		data func(t *testing.T) []byte
	}{
		{"wrong root", withProvider("google", func(p *cacheProvider) { p.Root = "wrong.example" })},
		{"prefix length over 32", withProvider("google", func(p *cacheProvider) { p.Nets = []string{"198.51.100.0/33"} })},
		{"host bits set", withProvider("google", func(p *cacheProvider) { p.Nets = []string{"198.51.100.7/24"} })},
		{"IPv4-mapped prefix", withProvider("google", func(p *cacheProvider) { p.Nets = []string{"::ffff:198.51.100.0/120"} })},
		{"address without a length", withProvider("google", func(p *cacheProvider) { p.Nets = []string{"198.51.100.0"} })},
		{"upper-case ptr domain", withProvider("yahoo", func(p *cacheProvider) { p.PTR = []string{"Mail.Example.net"} })},
		{"ptr domain with a trailing dot", withProvider("yahoo", func(p *cacheProvider) { p.PTR = []string{"mail.example.net."} })},
		{"IPv4 literal ptr domain", withProvider("yahoo", func(p *cacheProvider) { p.PTR = []string{"192.0.2.1"} })},
		{"empty ptr domain", withProvider("yahoo", func(p *cacheProvider) { p.PTR = []string{""} })},
		{"empty ptr label", withProvider("yahoo", func(p *cacheProvider) { p.PTR = []string{"mail..example.net"} })},
		{"too many prefixes", withProvider("google", func(p *cacheProvider) { p.Nets = repeat("198.51.100.0/24", 4097) })},
		{"too many ptr domains", withProvider("yahoo", func(p *cacheProvider) { p.PTR = repeat("mail.example.net", 129) })},
		{"version 2", func(t *testing.T) []byte {
			c := validCache()
			c.Version = 2
			return mustJSON(t, c)
		}},
		{"over 1 MiB", func(t *testing.T) []byte { return padTo(mustJSON(t, validCache()), 1<<20+1) }},
		{"truncated JSON", func(*testing.T) []byte { return []byte(`{"version":1,"providers":`) }},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			g := New(writeCache(t, tc.data(t)))
			if err := g.Load(testNow); err == nil {
				t.Fatal("Load accepted a bad cache")
			}
			if g.Ready(testNow) {
				t.Fatal("ready after a rejected cache")
			}
		})
	}

	for _, tc := range []struct {
		desc string
		data func(t *testing.T) []byte
	}{
		{"valid", func(t *testing.T) []byte { return mustJSON(t, validCache()) }},
		{"at the limits", func(t *testing.T) []byte {
			c := validCache()
			g, y := c.Providers["google"], c.Providers["yahoo"]
			g.Nets, y.PTR = repeat("198.51.100.0/24", 4096), repeat("mail.example.net", 128)
			c.Providers["google"], c.Providers["yahoo"] = g, y
			return mustJSON(t, c)
		}},
		{"exactly 1 MiB", func(t *testing.T) []byte { return padTo(mustJSON(t, validCache()), 1<<20) }},
		{"unknown provider", func(t *testing.T) []byte {
			c := validCache()
			c.Providers["other"] = cacheProvider{Root: "other.example", ResolvedAt: testNow.Unix() + 1, Nets: []string{"203.0.113.0/24", "not-a-prefix"}}
			return mustJSON(t, c)
		}},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			g := New(writeCache(t, tc.data(t)))
			if err := g.Load(testNow); err != nil {
				t.Fatalf("Load: %v", err)
			}
			if !g.Ready(testNow) {
				t.Fatal("not ready after a valid cache")
			}
			if !g.Covers(addr("198.51.100.7"), testNow) || g.Covers(addr("203.0.113.7"), testNow) {
				t.Fatal("loaded guard does not cover exactly google's prefix")
			}
			if got := g.current()["yahoo"].cache.PTR; len(got) == 0 || got[0] != "mail.example.net" {
				t.Fatalf("yahoo ptr domains %q, want mail.example.net first", got)
			}
		})
	}
}

// failDNS fails the test on any lookup and answers with a servfail, so a
// lookup would also turn the result into shared.
type failDNS struct{ t *testing.T }

func (f failDNS) fail(kind, name string) error {
	f.t.Errorf("unexpected %s lookup of %q", kind, name)
	return &net.DNSError{Err: "server misbehaving", Name: name, IsTemporary: true}
}

func (f failDNS) LookupTXT(_ context.Context, name string) ([]string, error) {
	return nil, f.fail("TXT", name)
}

func (f failDNS) LookupAddr(_ context.Context, addr string) ([]string, error) {
	return nil, f.fail("PTR", addr)
}

func (f failDNS) LookupIP(_ context.Context, _, host string) ([]net.IP, error) {
	return nil, f.fail("forward", host)
}

func TestSharedSkipsDNSWithoutPTRDomains(t *testing.T) {
	g := NewForTest(allProviders(map[string]mailranges.Policy{
		"google": {Nets: []*net.IPNet{mustNet(t, "198.51.100.0/24")}},
	}), testNow)
	if g.Shared(context.Background(), failDNS{t}, addr("203.0.113.7"), testNow) {
		t.Error("Shared(203.0.113.7) = true with no ptr domain to match")
	}
	if !g.Shared(context.Background(), failDNS{t}, addr("198.51.100.7"), testNow) {
		t.Error("Shared(198.51.100.7) = false for an address in a provider prefix")
	}
}

func TestLoadKeepsAFutureStamp(t *testing.T) {
	c := validCache()
	p := c.Providers["google"]
	p.ResolvedAt = testNow.Unix() + 5
	c.Providers["google"] = p
	g := New(writeCache(t, mustJSON(t, c)))
	if err := g.Load(testNow); err != nil {
		t.Fatalf("Load with google stamped 5 seconds ahead: %v", err)
	}
	if g.Ready(testNow) {
		t.Fatal("ready before the clock reaches google's stamp")
	}
	if !g.Ready(testNow.Add(5 * time.Second)) {
		t.Fatal("not ready once the clock reaches google's stamp")
	}
}

func TestCacheWritesEmptyListsAsArrays(t *testing.T) {
	want := `{"version":1,"providers":{"yahoo":{"root":"` + providers["yahoo"] + `","resolved_at":1793000000,"nets":[],"ptr":[]}}}`
	fromLoad, err := parseCache([]byte(`{"version":1,"providers":{"yahoo":{"root":"` + providers["yahoo"] + `","resolved_at":1793000000,"nets":null}}}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		desc string
		s    snapshot
	}{
		{"resolved policy", NewForTest(map[string]mailranges.Policy{"yahoo": {}}, testNow).current()},
		{"loaded cache with null and missing lists", fromLoad},
	} {
		got, err := encodeCache(tc.s)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != want {
			t.Errorf("%s: cache\n%s\nwant\n%s", tc.desc, got, want)
		}
	}
}
