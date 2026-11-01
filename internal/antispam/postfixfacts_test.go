package antispam

import (
	"errors"
	"reflect"
	"slices"
	"testing"
)

// proxyWorkers is `rspamadm configdump -j worker` as rspamd 4.2 prints it:
// one object per worker, keyed by worker type.
const proxyWorkers = `{"normal": {"bind_socket": "localhost:11333"}}
{"controller": {"bind_socket": "localhost:11334", "count": 1}}
{"rspamd_proxy": {"bind_socket": "localhost:11332", "milter": true, "timeout": 120.0}}
`

// postconfOut is `postconf -x -h` for PostconfNames on a Postfix 3 host.
func postconfOut(milters, sizeLimit string) string {
	return milters + "\naccept\n" + sizeLimit + "\n/var/spool/postfix\n3.7.11\n"
}

func TestParsePostconf(t *testing.T) {
	got, err := ParsePostconf(postconfOut("inet:127.0.0.1:11332", "52428800"))
	want := Postconf{Milters: []string{"inet:127.0.0.1:11332"}, DefaultAction: "accept", SizeLimit: 52428800,
		QueueDirectory: "/var/spool/postfix", Version: "3.7.11"}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, %v; want %+v", got, err, want)
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
			got, err := ParsePostconf(postconfOut(tc.line, "10240000"))
			if err != nil || !slices.Equal(got.Milters, tc.want) {
				t.Fatalf("got %q, %v; want %q", got.Milters, err, tc.want)
			}
		})
	}
	for _, out := range []string{
		postconfOut("inet:127.0.0.1:11332", "50M"),
		postconfOut("inet:127.0.0.1:11332", "-1"),
		postconfOut("inet:127.0.0.1:11332", ""),
		"inet:127.0.0.1:11332\naccept\n52428800\nspool\n3.7.11\n",
		"inet:127.0.0.1:11332\naccept\n52428800\n\n3.7.11\n",
		"inet:127.0.0.1:11332\naccept\n52428800\n/var/spool/postfix\n",
		postconfOut("inet:127.0.0.1:11332", "52428800") + "extra\n",
		"",
	} {
		if got, err := ParsePostconf(out); err == nil || !reflect.DeepEqual(got, Postconf{}) {
			t.Errorf("ParsePostconf(%q) = %+v, %v; want only an error", out, got, err)
		}
	}
}

func TestSmtpdChroot(t *testing.T) {
	for _, tc := range []struct {
		name, out, version string
		want               bool
	}{
		{"smtpd chrooted", "smtp/inet/command = smtpd\nsmtp/inet/chroot = y\n", "3.7.11", true},
		{"smtpd not chrooted", "smtp/inet/command = smtpd\nsmtp/inet/chroot = n\n", "3.7.11", false},
		{"smtpd with options", "smtp/inet/command = smtpd -o smtpd_sasl_auth_enable=no\nsmtp/inet/chroot = y\n", "3.7.11", true},
		{"postscreen passes to smtpd", "smtp/inet/command = postscreen\nsmtp/inet/chroot = n\nsmtpd/pass/chroot = y\n", "3.7.11", true},
		{"default since 3.0", "smtp/inet/command = smtpd\nsmtp/inet/chroot = -\n", "3.0.0", false},
		{"default before 3.0", "smtp/inet/command = smtpd\nsmtp/inet/chroot = -\n", "2.11.3", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := SmtpdChroot(tc.out, tc.version); err != nil || got != tc.want {
				t.Fatalf("got %t, %v; want %t", got, err, tc.want)
			}
		})
	}
	for _, tc := range []struct{ name, out, version string }{
		{"no smtp service", "smtpd/pass/chroot = y\n", "3.7.11"},
		{"postscreen without its smtpd", "smtp/inet/command = postscreen\nsmtp/inet/chroot = y\n", "3.7.11"},
		{"another program", "smtp/inet/command = proxymap\nsmtp/inet/chroot = n\n", "3.7.11"},
		{"unreadable flag", "smtp/inet/command = smtpd\nsmtp/inet/chroot = maybe\n", "3.7.11"},
		{"default, unreadable version", "smtp/inet/command = smtpd\nsmtp/inet/chroot = -\n", "snapshot"},
		{"empty", "", "3.7.11"},
	} {
		if got, err := SmtpdChroot(tc.out, tc.version); err == nil || got {
			t.Errorf("%s: got %t, %v; want only an error", tc.name, got, err)
		}
	}
}

func TestMilterAddrs(t *testing.T) {
	chrooted := CommandResult{Stdout: "smtp/inet/command = smtpd\nsmtp/inet/chroot = y\n"}
	open := CommandResult{Stdout: "smtp/inet/command = smtpd\nsmtp/inet/chroot = n\n"}
	unknown := CommandResult{Err: errors.New("boom")}
	for _, tc := range []struct {
		name     string
		milters  []string
		queue    string
		master   CommandResult
		want     []string
		complete bool
	}{
		// Debian ships smtpd chrooted into the queue directory.
		{"chrooted absolute path", []string{"unix:/rspamd/milter.sock"}, "/var/spool/postfix", chrooted,
			[]string{"unix:/var/spool/postfix/rspamd/milter.sock"}, true},
		{"absolute path", []string{"unix:/run/rspamd/milter.sock"}, "/var/spool/postfix", open,
			[]string{"unix:/run/rspamd/milter.sock"}, true},
		{"relative path", []string{"unix:rspamd/milter.sock"}, "/var/spool/postfix", open,
			[]string{"unix:/var/spool/postfix/rspamd/milter.sock"}, true},
		{"relative path, chroot unknown", []string{"unix:rspamd/milter.sock"}, "/var/spool/postfix/", unknown,
			[]string{"unix:/var/spool/postfix/rspamd/milter.sock"}, true},
		{"inet, chroot unknown", []string{"inet:127.0.0.1:11332"}, "/var/spool/postfix", unknown,
			[]string{"inet:127.0.0.1:11332"}, true},
		{"absolute path, chroot unknown", []string{"inet:127.0.0.1:8891", "unix:/rspamd/milter.sock"}, "/var/spool/postfix", unknown,
			[]string{"inet:127.0.0.1:8891"}, false},
		{"absolute path, chroot unreadable", []string{"unix:/rspamd/milter.sock"}, "/var/spool/postfix",
			CommandResult{Stdout: "smtp/inet/command = smtpd\n"}, nil, false},
		{"unknown transport", []string{"local:/run/x.sock", "inet:127.0.0.1:11332"}, "/var/spool/postfix", open,
			[]string{"inet:127.0.0.1:11332"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := Postconf{Milters: tc.milters, QueueDirectory: tc.queue, Version: "3.7.11"}
			got, complete := p.MilterAddrs(tc.master)
			if !slices.Equal(got, tc.want) || complete != tc.complete {
				t.Fatalf("got %q, complete %t; want %q, %t", got, complete, tc.want, tc.complete)
			}
		})
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
		{"IPv4 any bind", []string{"inet:127.0.0.1:11332"}, []string{"0.0.0.0:11332"}, true},
		{"IPv6 any bind", []string{"inet:[::1]:11332"}, []string{"[::]:11332"}, true},
		{"*v4 bind", []string{"inet:127.0.0.1:11332"}, []string{"*v4:11332"}, true},
		{"*v6 bind", []string{"inet:[::1]:11332"}, []string{"*v6:11332"}, true},
		{"localhost milter, IPv4 any bind", []string{"inet:localhost:11332"}, []string{"0.0.0.0:11332"}, true},
		{"localhost milter, *v6 bind", []string{"inet:localhost:11332"}, []string{"*v6:11332"}, true},
		{"IPv4 milter, *v6 bind", []string{"inet:127.0.0.1:11332"}, []string{"*v6:11332"}, false},
		{"IPv6 milter, IPv4 any bind", []string{"inet:[::1]:11332"}, []string{"0.0.0.0:11332"}, false},
		{"remote milter, IPv4 any bind", []string{"inet:198.51.100.7:11332"}, []string{"0.0.0.0:11332"}, false},
		{"remote milter, *v4 bind", []string{"inet:198.51.100.7:11332"}, []string{"*v4:11332"}, false},
		{"any bind on another port", []string{"inet:127.0.0.1:11332"}, []string{"0.0.0.0:11333"}, false},
		{"another loopback address", []string{"inet:127.0.0.2:11332"}, []string{"127.0.0.1:11332"}, false},
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
