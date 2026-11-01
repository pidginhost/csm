package antispam

import (
	"slices"
	"testing"
)

// proxyWorkers is `rspamadm configdump -j worker` as rspamd 4.2 prints it:
// one object per worker, keyed by worker type.
const proxyWorkers = `{"normal": {"bind_socket": "localhost:11333"}}
{"controller": {"bind_socket": "localhost:11334", "count": 1}}
{"rspamd_proxy": {"bind_socket": "localhost:11332", "milter": true, "timeout": 120.0}}
`

func TestParsePostconf(t *testing.T) {
	milters, action, size, err := ParsePostconf("inet:127.0.0.1:11332\naccept\n52428800\n")
	if err != nil || !slices.Equal(milters, []string{"inet:127.0.0.1:11332"}) || action != "accept" || size != 52428800 {
		t.Fatalf("got %q %q %d %v", milters, action, size, err)
	}
	for _, tc := range []struct {
		name, line string
		want       []string
	}{
		{"spaces", "inet:127.0.0.1:8891 unix:/run/rspamd/milter.sock", []string{"inet:127.0.0.1:8891", "unix:/run/rspamd/milter.sock"}},
		{"commas", "inet:127.0.0.1:8891,inet:localhost:11332", []string{"inet:127.0.0.1:8891", "inet:localhost:11332"}},
		{"commas and spaces", "inet:127.0.0.1:8891, inet:localhost:11332", []string{"inet:127.0.0.1:8891", "inet:localhost:11332"}},
		{"per-milter settings", "{inet:localhost:11332, connect_timeout=10s, default_action=accept}", []string{"inet:localhost:11332"}},
		{"none", "", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			milters, _, _, err := ParsePostconf(tc.line + "\ntempfail\n10240000\n")
			if err != nil || !slices.Equal(milters, tc.want) {
				t.Fatalf("got %q, %v; want %q", milters, err, tc.want)
			}
		})
	}
	for _, out := range []string{
		"inet:127.0.0.1:11332\naccept\n50M\n",
		"inet:127.0.0.1:11332\naccept\n-1\n",
		"inet:127.0.0.1:11332\naccept\n\n",
		"inet:127.0.0.1:11332\naccept\n",
		"inet:127.0.0.1:11332\naccept\n52428800\nextra\n",
		"",
	} {
		if milters, action, size, err := ParsePostconf(out); err == nil || milters != nil || action != "" || size != 0 {
			t.Errorf("ParsePostconf(%q) = %q %q %d %v; want only an error", out, milters, action, size, err)
		}
	}
}

func TestProxyMilterAddrs(t *testing.T) {
	for _, tc := range []struct {
		name, dump string
		want       []string
	}{
		{"milter proxy", proxyWorkers, []string{"localhost:11332"}},
		{"proxy without milter", `{"rspamd_proxy": {"bind_socket": "localhost:11332"}}`, nil},
		{"milter off", `{"rspamd_proxy": {"bind_socket": "localhost:11332", "milter": false}}`, nil},
		{"milter as integer", `{"rspamd_proxy": {"bind_socket": "localhost:11332", "milter": 1}}`, []string{"localhost:11332"}},
		{"type attribute", `{"type": "rspamd_proxy", "bind_socket": "*:11332", "milter": true}`, []string{"*:11332"}},
		{"several binds", `{"rspamd_proxy": {"bind_socket": ["localhost:11332", "/run/rspamd/milter.sock mode=0666"], "milter": true}}`,
			[]string{"localhost:11332", "/run/rspamd/milter.sock mode=0666"}},
		{"listen alias", `{"rspamd_proxy": {"listen": "localhost:11332", "milter": true}}`, []string{"localhost:11332"}},
		{"disabled", `{"rspamd_proxy": {"bind_socket": "localhost:11332", "milter": true, "enabled": false}}`, nil},
		{"no workers run", `{"rspamd_proxy": {"bind_socket": "localhost:11332", "milter": true, "count": 0}}`, nil},
		{"two proxies", proxyWorkers + `{"rspamd_proxy": {"bind_socket": "/run/rspamd/milter.sock", "milter": true}}`,
			[]string{"localhost:11332", "/run/rspamd/milter.sock"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ProxyMilterAddrs([]byte(tc.dump))
			if err != nil || !slices.Equal(got, tc.want) {
				t.Fatalf("got %q, %v; want %q", got, err, tc.want)
			}
		})
	}
	for _, dump := range []string{
		"",
		"Section worker NOT FOUND\n",
		`[{"rspamd_proxy": {"bind_socket": "localhost:11332", "milter": true}}]`,
		`{"rspamd_proxy": {"bind_socket": "localhost:11332", "milter": "yes"}}`,
		`{"rspamd_proxy": {"bind_socket": 11332, "milter": true}}`,
		`{"rspamd_proxy": {"milter": true}}`,
		`{"rspamd_proxy": {"bind_socket": "localhost:11332", "milter": true, "milter": false}}`,
		`{"type": 1, "bind_socket": "localhost:11332"}`,
		`{"rspamd_proxy": {"bind_socket": "localhost:11332", "milter": true}} trailing`,
	} {
		if got, err := ProxyMilterAddrs([]byte(dump)); err == nil || got != nil {
			t.Errorf("ProxyMilterAddrs(%q) = %q, %v; want only an error", dump, got, err)
		}
	}
}

func TestMilterWired(t *testing.T) {
	for _, tc := range []struct {
		name           string
		milters, binds []string
		want           bool
	}{
		{"same address", []string{"inet:127.0.0.1:11332"}, []string{"127.0.0.1:11332"}, true},
		{"localhost bind", []string{"inet:127.0.0.1:11332"}, []string{"localhost:11332"}, true},
		{"wildcard bind", []string{"inet:127.0.0.1:11332"}, []string{"*:11332"}, true},
		{"localhost milter", []string{"inet:localhost:11332"}, []string{"localhost:11332"}, true},
		{"localhost milter, loopback bind", []string{"inet:localhost:11332"}, []string{"127.0.0.1:11332"}, true},
		{"localhost milter, wildcard bind", []string{"inet:localhost:11332"}, []string{"*:11332"}, true},
		{"IPv6 loopback", []string{"inet:[::1]:11332"}, []string{"[::1]:11332"}, true},
		{"second milter", []string{"inet:127.0.0.1:8891", "inet:127.0.0.1:11332"}, []string{"localhost:11332"}, true},
		{"another port", []string{"inet:127.0.0.1:8891"}, []string{"localhost:11332"}, false},
		{"IPv4 milter, IPv6 bind", []string{"inet:127.0.0.1:11332"}, []string{"[::1]:11332"}, false},
		// The wildcard listens here; a remote milter host is another rspamd.
		{"remote milter, wildcard bind", []string{"inet:198.51.100.7:11332"}, []string{"*:11332"}, false},
		{"same unix path", []string{"unix:/run/rspamd/milter.sock"}, []string{"/run/rspamd/milter.sock mode=0666"}, true},
		{"another unix path", []string{"unix:/run/rspamd/other.sock"}, []string{"/run/rspamd/milter.sock"}, false},
		{"unix milter, TCP bind", []string{"unix:/run/rspamd/milter.sock"}, []string{"localhost:11332"}, false},
		{"relative unix milter, TCP bind", []string{"unix:localhost:11332"}, []string{"localhost:11332"}, false},
		{"TCP milter, unix bind", []string{"inet:127.0.0.1:11332"}, []string{"/run/rspamd/milter.sock"}, false},
		{"no transport", []string{"127.0.0.1:11332"}, []string{"127.0.0.1:11332"}, false},
		{"no milters", nil, []string{"localhost:11332"}, false},
		{"no proxy", []string{"inet:127.0.0.1:11332"}, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := MilterWired(tc.milters, tc.binds); got != tc.want {
				t.Fatalf("MilterWired(%q, %q) = %t, want %t", tc.milters, tc.binds, got, tc.want)
			}
		})
	}
}
