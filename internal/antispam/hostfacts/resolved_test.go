package hostfacts

import (
	"context"
	"errors"
	"io/fs"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/antispam"
)

const resolvedDNSCommand = "busctl --system --auto-start=no --no-pager get-property org.freedesktop.resolve1 /org/freedesktop/resolve1 org.freedesktop.resolve1.Manager DNS"

// The generated file omits route-only servers and servers on other ports.
// Feed decisions must use the service's complete inventory instead.
func TestCollectChecksAllResolvedNameservers(t *testing.T) {
	for _, tc := range []struct {
		name, file, live string
		err              error
		wantFeed         bool
	}{
		{"hidden global server", "nameserver 192.0.2.53\n", "a(iiay) 2 0 2 4 192 0 2 53 0 2 4 198 51 100 53", nil, false},
		{"hidden link server", "nameserver 192.0.2.53\n", "a(iiay) 2 0 2 4 192 0 2 53 2 2 4 198 51 100 53", nil, false},
		{"unreadable inventory", "nameserver 192.0.2.53\n", "", errors.New("bus unavailable"), false},
		{"malformed inventory", "nameserver 192.0.2.53\n", "a(iiay) 2 0 2 4 192 0 2 53", nil, false},
		{"own server omitted from file", "# no compatible servers\n", "a(iiay) 1 0 2 4 192 0 2 53", nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := t.TempDir()
			write(t, filepath.Join(d, "resolv.conf"), "nameserver 127.0.0.53\n")
			write(t, filepath.Join(d, "resolved-upstream.conf"), tc.file)
			run := &fakeRun{results: map[string]antispam.CommandResult{
				"rspamadm configdump -j options": {Stdout: `{}`},
				"rspamd --version":               {Stdout: "Rspamd daemon version 4.2.2\n"},
				resolvedDNSCommand:               {Stdout: tc.live, Err: tc.err},
			}}
			f := testCollector(d, run).collect(context.Background(), filepath.Join(d, "sock"))
			f.InfraNets = antispam.ParseInfraNets([]string{"192.0.2.53"})
			for _, target := range antispam.MutationTargets(antispam.StackExim) {
				f.Targets = append(f.Targets, antispam.TargetFacts{Target: target, Missing: true,
					Parents: []antispam.PathFacts{{Path: "/", Mode: fs.ModeDir | 0o755}}})
			}
			s := antispam.Settings{Feeds: []string{antispam.FeedPSBL, antispam.FeedRspamdMaps}}
			got, problems := antispam.ResolveFeeds(s, f)
			want := []string{antispam.FeedRspamdMaps}
			if tc.wantFeed {
				want = s.Feeds
			}
			if !slices.Equal(got.Feeds, want) || len(problems) != len(s.Feeds)-len(want) {
				t.Fatalf("feeds %v, problems %+v; want %v", got.Feeds, problems, want)
			}
		})
	}
}

func TestCollectDoesNotQueryUnusedResolved(t *testing.T) {
	d := t.TempDir()
	run := &fakeRun{results: map[string]antispam.CommandResult{
		"rspamadm configdump -j options": {Stdout: `{"dns":{"nameserver":"192.0.2.53"}}`},
	}}
	write(t, filepath.Join(d, "resolv.conf"), "nameserver 127.0.0.53\n")
	testCollector(d, run).collect(context.Background(), filepath.Join(d, "sock"))
	for _, call := range run.calls {
		if strings.HasPrefix(call, "busctl ") {
			t.Fatalf("queried unused systemd-resolved: %s", call)
		}
	}
}

func TestResolvedDNSIncludesFallbackWhenNeeded(t *testing.T) {
	for _, tc := range []struct {
		name, dns, route, fallback string
		want                       []netip.Addr
		wantErr                    bool
	}{
		{"default link", "a(iiay) 1 2 2 4 192 0 2 53", "b true", "", []netip.Addr{netip.MustParseAddr("192.0.2.53")}, false},
		{"route-only link", "a(iiay) 1 2 2 4 192 0 2 53", "b false", "a(iiay) 1 0 2 4 198 51 100 53", []netip.Addr{netip.MustParseAddr("192.0.2.53"), netip.MustParseAddr("198.51.100.53")}, false},
		{"fallback only", "a(iiay) 0", "", "a(iiay) 1 0 2 4 192 0 2 53", []netip.Addr{netip.MustParseAddr("192.0.2.53")}, false},
		{"no servers", "a(iiay) 0", "", "a(iiay) 0", nil, false},
		{"unreadable routing", "a(iiay) 1 2 2 4 192 0 2 53", "", "", nil, true},
		{"malformed routing", "a(iiay) 1 2 2 4 192 0 2 53", "b maybe", "", nil, true},
		{"unreadable fallback", "a(iiay) 0", "", "", nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			run := &fakeRun{results: map[string]antispam.CommandResult{
				resolvedDNSCommand: {Stdout: tc.dns},
			}}
			if tc.route != "" {
				run.results["busctl --system --auto-start=no --no-pager get-property org.freedesktop.resolve1 /org/freedesktop/resolve1/link/_32 org.freedesktop.resolve1.Link DefaultRoute"] = antispam.CommandResult{Stdout: tc.route}
			}
			if tc.fallback != "" {
				run.results[strings.TrimSuffix(resolvedDNSCommand, "DNS")+"FallbackDNS"] = antispam.CommandResult{Stdout: tc.fallback}
			}
			got, err := testCollector(t.TempDir(), run).resolvedDNS(context.Background())
			if (err != nil) != tc.wantErr || !slices.Equal(got, tc.want) {
				t.Fatalf("got %v, %v; want %v, error %t", got, err, tc.want, tc.wantErr)
			}
		})
	}
}

func TestParseResolvedDNS(t *testing.T) {
	got, err := parseResolvedDNS("a(iiay) 2 0 2 4 192 0 2 53 2 10 16 32 1 13 184 0 0 0 0 0 0 0 0 0 0 0 53\n")
	want := []resolvedServer{{0, netip.MustParseAddr("192.0.2.53")}, {2, netip.MustParseAddr("2001:db8::35")}}
	if err != nil || !slices.Equal(got, want) {
		t.Fatalf("got %v, %v; want %v", got, err, want)
	}
	for _, invalid := range []string{
		"", "a(iiay)", "a(iiay) -1", "a(iiay) 4294967296", "a(iiay) 1",
		"a(iiay) 1 0 2 4 192 0 2", "a(iiay) 0 0 2 4 192 0 2 53",
		"a(iiay) 1 -1 2 4 192 0 2 53", "a(iiay) 1 2147483648 2 4 192 0 2 53",
		"a(iiay) 1 0 99 4 192 0 2 53", "a(iiay) 1 0 10 4 192 0 2 53",
		"a(iiay) 1 0 2 5 192 0 2 53 1", "a(iiay) 1 0 2 4 192 0 2 256",
		"a(iiay) 1 0 2 4 192 0 2 -1", "a(iiay) 1 0 2 4 192 0 2 nope",
		"a(iiay) 2 0 2 4 192 0 2 53", "a(iiay) 1 0 2 4 192 0 2 53 trailing",
		"a(iiayqs) 1 0 2 4 192 0 2 53 53 resolver.example.com",
	} {
		if got, err := parseResolvedDNS(invalid); err == nil || got != nil {
			t.Errorf("malformed inventory accepted: %q; got %v, %v", invalid, got, err)
		}
	}
}

func TestResolvedDNSKnownDefaultRouteSurvivesOtherLinkError(t *testing.T) {
	want := []netip.Addr{netip.MustParseAddr("192.0.2.53"), netip.MustParseAddr("198.51.100.53")}
	// Both possible query orders must agree, even if a link disappears
	// between the inventory query and the default-route query.
	for _, link := range []string{"2", "3"} {
		t.Run(link, func(t *testing.T) {
			run := &fakeRun{results: map[string]antispam.CommandResult{
				resolvedDNSCommand: {Stdout: "a(iiay) 2 2 2 4 192 0 2 53 3 2 4 198 51 100 53"},
				"busctl --system --auto-start=no --no-pager get-property org.freedesktop.resolve1 /org/freedesktop/resolve1/link/_3" + link + " org.freedesktop.resolve1.Link DefaultRoute": {Stdout: "b true"},
			}}
			got, err := testCollector(t.TempDir(), run).resolvedDNS(context.Background())
			if err != nil || !slices.Equal(got, want) {
				t.Fatalf("known default route was lost: got %v, %v; want %v", got, err, want)
			}
		})
	}
}

// systemd escapes the leading digit of a link's bus label, so link 2 lives
// at /link/_32; a plain /link/_2 is an unknown object.
func TestResolvedLinkPathEscapesLeadingDigit(t *testing.T) {
	for link, want := range map[int]string{2: "/link/_32", 9: "/link/_39", 12: "/link/_312", 123: "/link/_3123"} {
		if got := resolvedLinkPath(link); got != want {
			t.Errorf("resolvedLinkPath(%d) = %q, want %q", link, got, want)
		}
	}
}
