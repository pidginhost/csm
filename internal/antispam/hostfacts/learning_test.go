package hostfacts

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/antispam"
)

func learningCollector(t *testing.T, run *fakeRun) (collector, string) {
	t.Helper()
	d := t.TempDir()
	c := testCollector(d, run)
	c.layout.ProcNetUDP = filepath.Join(d, "udp")
	c.layout.CageFSSkeletonLog = filepath.Join(d, "skeleton", "var", "log", "rspamd")
	c.layout.RoundcubeConfig = filepath.Join(d, "roundcube", "config.inc.php")
	c.layout.CPanelPHP = filepath.Join(d, "php")
	c.layout.CPanelUsers = filepath.Join(d, "users")
	c.redisProbe = func(_ context.Context, endpoint string, _ antispam.Secret, _ int) antispam.RedisFacts {
		return antispam.RedisFacts{Endpoint: endpoint, Port: "0"}
	}
	return c, d
}

const udpHeader = "   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n"

func TestCollectFuzzyListening(t *testing.T) {
	for name, tc := range map[string]struct {
		udp  string
		want bool
	}{
		"listening":   {udpHeader + "  12: 0100007F:2C47 00000000:0000 07 00000000:00000000 00:00000000 00000000   979        0 1 2 0000000000000000 0\n", true},
		"other port":  {udpHeader + "  12: 0100007F:2C46 00000000:0000 07 00000000:00000000 00:00000000 00000000   979        0 1 2 0000000000000000 0\n", false},
		"any address": {udpHeader + "  12: 00000000:2C47 00000000:0000 07 00000000:00000000 00:00000000 00000000   979        0 1 2 0000000000000000 0\n", false},
		"wrong state": {udpHeader + "  12: 0100007F:2C47 00000000:0000 01 00000000:00000000 00:00000000 00000000   979        0 1 2 0000000000000000 0\n", false},
		"header only": {udpHeader, false},
	} {
		t.Run(name, func(t *testing.T) {
			c, _ := learningCollector(t, &fakeRun{})
			if err := os.WriteFile(c.layout.ProcNetUDP, []byte(tc.udp), 0o600); err != nil {
				t.Fatal(err)
			}
			got, err := c.fuzzyListening()
			if err != nil || got != tc.want {
				t.Fatalf("listening=%v err=%v, want %v", got, err, tc.want)
			}
		})
	}
	c, _ := learningCollector(t, &fakeRun{})
	if _, err := c.fuzzyListening(); err == nil {
		t.Fatal("missing /proc/net/udp read as not listening")
	}
}

func TestCollectCageFS(t *testing.T) {
	ok := map[string]antispam.CommandResult{
		"cagefsctl --cagefs-status":     {Stdout: "Enabled\n"},
		"cagefsctl --display-user-mode": {Stdout: "Mode: Enable All\n"},
		"cagefsctl --list-disabled":     {Stdout: ""},
	}
	c, _ := learningCollector(t, &fakeRun{results: ok})
	got := c.cageFS(context.Background())
	if got.Err != nil || !got.Enabled || got.DisabledUsers != 0 || got.SkeletonHasRspamdLog {
		t.Fatalf("all enabled: %+v", got)
	}
	if err := os.MkdirAll(c.layout.CageFSSkeletonLog, 0o755); err != nil {
		t.Fatal(err)
	}
	if got := c.cageFS(context.Background()); !got.SkeletonHasRspamdLog {
		t.Fatalf("skeleton log not seen: %+v", got)
	}
	disabled := map[string]antispam.CommandResult{
		"cagefsctl --cagefs-status":     {Stdout: "Enabled\n"},
		"cagefsctl --display-user-mode": {Stdout: "Mode: Enable All\n"},
		"cagefsctl --list-disabled":     {Stdout: "alpha\nbravo\n"},
	}
	c, _ = learningCollector(t, &fakeRun{results: disabled})
	if got := c.cageFS(context.Background()); got.Err != nil || got.DisabledUsers != 2 {
		t.Fatalf("two disabled: %+v", got)
	}
	for name, results := range map[string]map[string]antispam.CommandResult{
		"not installed": {},
		"disabled":      {"cagefsctl --cagefs-status": {Stdout: "Disabled\n"}},
		"disable all": {
			"cagefsctl --cagefs-status":     {Stdout: "Enabled\n"},
			"cagefsctl --display-user-mode": {Stdout: "Mode: Disable All\n"},
			"cagefsctl --list-disabled":     {Stdout: ""},
		},
	} {
		other, _ := learningCollector(t, &fakeRun{results: results})
		if got := other.cageFS(context.Background()); got.Enabled {
			t.Errorf("%s: %+v counts as enabled for all", name, got)
		}
	}
	odd := map[string]antispam.CommandResult{
		"cagefsctl --cagefs-status":     {Stdout: "Enabled\n"},
		"cagefsctl --display-user-mode": {Stdout: "Mode: Enable All\n"},
		"cagefsctl --list-disabled":     {Stdout: "2 users are disabled:\n"},
	}
	c, _ = learningCollector(t, &fakeRun{results: odd})
	if got := c.cageFS(context.Background()); got.Err == nil {
		t.Fatalf("unreadable disabled list accepted: %+v", got)
	}
}

func TestCollectRoundcubeMechanism(t *testing.T) {
	c, _ := learningCollector(t, &fakeRun{})
	mustMkdir := func(p string) {
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	mustMkdir(filepath.Dir(c.layout.RoundcubeConfig))
	glob := `$incfiles = glob("/usr/local/cpanel/base/3rdparty/roundcube/config/inc.d/*.php");` + "\n"
	if err := os.WriteFile(c.layout.RoundcubeConfig, []byte("<?php\n$config = [];\n"+glob), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(c.layout.CPanelPHP, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	f := antispam.HostFacts{Targets: []antispam.TargetFacts{{Target: antispam.Target{Path: antispam.RoundcubeIncludePath, Kind: antispam.TargetRoundcube}, Missing: true}}}
	got := c.roundcube(f)
	if got.Err != nil || !got.IncludeMechanism || !got.PHP || got.Include.Path != antispam.RoundcubeIncludePath {
		t.Fatalf("mechanism present: %+v", got)
	}
	if err := os.WriteFile(c.layout.RoundcubeConfig, []byte("<?php\n$config = [];\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := c.roundcube(f); got.IncludeMechanism {
		t.Fatalf("mechanism absent: %+v", got)
	}
	if err := os.Chmod(c.layout.CPanelPHP, 0o644); err != nil {
		t.Fatal(err)
	}
	if got := c.roundcube(f); got.PHP {
		t.Fatal("non-executable php counted")
	}
	if err := os.Remove(c.layout.RoundcubeConfig); err != nil {
		t.Fatal(err)
	}
	if got := c.roundcube(f); got.IncludeMechanism || got.Err == nil {
		t.Fatalf("missing Roundcube: %+v", got)
	}
}

func TestCollectControlSocket(t *testing.T) {
	c, d := learningCollector(t, &fakeRun{})
	sock := serve(t, d, pong)
	f := antispam.HostFacts{RspamdOptions: antispam.CommandResult{Stdout: `{"control_socket": "` + sock + ` mode=0600", "dns": {}}`}}
	c.controlSocket(&f)
	if f.ControlSocket.Err != nil || f.ControlSocket.Missing || f.ControlSocket.Socket.Path != sock || f.ControlSocket.Socket.Mode&os.ModeSocket == 0 {
		t.Fatalf("control socket = %+v", f.ControlSocket)
	}
	for name, options := range map[string]antispam.CommandResult{
		"unset":      {Stdout: `{"dns": {}}`},
		"not path":   {Stdout: `{"control_socket": "localhost:11334"}`},
		"command":    {Err: errors.New("exit status 1")},
		"bad json":   {Stdout: `{`},
		"not string": {Stdout: `{"control_socket": 7}`},
	} {
		f := antispam.HostFacts{RspamdOptions: options}
		c.controlSocket(&f)
		if f.ControlSocket.Err == nil {
			t.Errorf("%s: control socket accepted: %+v", name, f.ControlSocket)
		}
	}
}

func fuzzyWorkerDump(extra string) string {
	return `{"worker":[{"normal":{"bind_socket":"localhost:11333"}},{"fuzzy":{"bind_socket":"127.0.0.1:11335"` + extra + `}}],"options":{}}`
}

func TestCollectLearningDumpsError(t *testing.T) {
	results := map[string]antispam.CommandResult{
		"rspamadm configdump -j fuzzy_check": {Stdout: `{"rule":{}}`},
		"rspamadm configdump -j group":       {Stdout: `{"fuzzy":{}}`},
		"rspamadm configdump -j redis":       {Stdout: `{"servers":"/run/redis-rspamd/redis.sock"}`},
	}
	c, _ := learningCollector(t, &fakeRun{results: results})
	f := antispam.HostFacts{RspamdConfig: antispam.CommandResult{Stdout: fuzzyWorkerDump("")}}
	c.learningDumps(context.Background(), &f)
	d := f.LearningDumps
	if d.Err != nil || string(d.FuzzyCheck) != `{"rule":{}}` || !strings.Contains(string(d.Worker), "11335") || len(d.Group) == 0 || len(d.Redis) == 0 {
		t.Fatalf("dumps = %+v", d)
	}
	for _, missing := range []string{"rspamadm configdump -j fuzzy_check", "rspamadm configdump -j group", "rspamadm configdump -j redis"} {
		partial := map[string]antispam.CommandResult{}
		for k, v := range results {
			if k != missing {
				partial[k] = v
			}
		}
		pc, _ := learningCollector(t, &fakeRun{results: partial})
		pf := antispam.HostFacts{RspamdConfig: antispam.CommandResult{Stdout: fuzzyWorkerDump("")}}
		pc.learningDumps(context.Background(), &pf)
		if pf.LearningDumps.Err == nil {
			t.Errorf("%s failing left no error", missing)
		}
	}
	f = antispam.HostFacts{RspamdConfig: antispam.CommandResult{Err: errors.New("exit status 1")}}
	c.learningDumps(context.Background(), &f)
	if f.LearningDumps.Err == nil {
		t.Error("unreadable full dump left no error")
	}
}

func TestCollectRedisEndpoint(t *testing.T) {
	for name, tc := range map[string]struct {
		worker, redis, endpoint string
		unix, err               bool
	}{
		"global socket":   {"", `{"servers":"/run/redis-rspamd/redis.sock","password":"p"}`, "/run/redis-rspamd/redis.sock", true, false},
		"worker override": {`,"servers":"/run/other/redis.sock"`, `{"servers":"/run/redis-rspamd/redis.sock"}`, "/run/other/redis.sock", true, false},
		"tcp":             {"", `{"servers":"127.0.0.1:6379"}`, "127.0.0.1:6379", false, false},
		"several":         {"", `{"servers":"/a.sock,/b.sock"}`, "", false, true},
		"split read":      {"", `{"read_servers":"/a.sock","write_servers":"/b.sock"}`, "", false, true},
		"none":            {"", `{}`, "", false, true},
	} {
		t.Run(name, func(t *testing.T) {
			dumps := antispam.LearningDumps{Redis: []byte(tc.redis)}
			full := fuzzyWorkerDump(tc.worker)
			endpoint, unix, _, err := redisEndpoint(dumps, []byte(full))
			if (err != nil) != tc.err || endpoint != tc.endpoint || unix != tc.unix {
				t.Fatalf("endpoint=%q unix=%v err=%v", endpoint, unix, err)
			}
		})
	}
	_, _, password, err := redisEndpoint(antispam.LearningDumps{Redis: []byte(`{"servers":"/r.sock","password":"synthetic-pw"}`)}, []byte(fuzzyWorkerDump("")))
	if err != nil || password.Reveal() != "synthetic-pw" {
		t.Fatalf("password not read: %v", err)
	}
}

func TestCollectAccountNames(t *testing.T) {
	c, _ := learningCollector(t, &fakeRun{})
	if err := os.MkdirAll(c.layout.CPanelUsers, 0o755); err != nil {
		t.Fatal(err)
	}
	// The plan pins admission.ValidAccountName; its wider alphabet only
	// counts more names as accounts, the safe direction.
	for _, n := range []string{"alpha", "bravo2", "Bad Name", "semi;colon"} {
		if err := os.WriteFile(filepath.Join(c.layout.CPanelUsers, n), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	got, err := c.accountNames()
	if err != nil || len(got) != 2 || !got["alpha"] || !got["bravo2"] {
		t.Fatalf("accounts = %v err = %v", got, err)
	}
	c.layout.CPanelUsers = filepath.Join(t.TempDir(), "absent")
	if _, err := c.accountNames(); err == nil {
		t.Fatal("unreadable users directory accepted")
	}
}

// CSM sends the Redis password only to a socket nobody but its owner or root
// could have created, owned by a user that is not a cPanel account.
func TestCollectRedisProbesOnlyProtectedSockets(t *testing.T) {
	setup := func(t *testing.T, dirMode os.FileMode, owner string, accounts ...string) (collector, antispam.HostFacts, *int) {
		// owner is the user name the test's uid resolves to: "redis" is a
		// pinned Redis service user, anything else is not.
		t.Helper()
		c, d := learningCollector(t, &fakeRun{})
		probes := 0
		c.redisProbe = func(_ context.Context, endpoint string, _ antispam.Secret, peer int) antispam.RedisFacts {
			probes++
			if peer != os.Getuid() {
				t.Errorf("probe expects peer %d, want the socket owner %d", peer, os.Getuid())
			}
			return antispam.RedisFacts{Endpoint: endpoint, Port: "0"}
		}
		c.userName = func(uid string) (string, error) { return owner, nil }
		c.uid = func(name string) (int, error) {
			if name == owner {
				return os.Getuid(), nil
			}
			return -1, errors.New("unknown user")
		}
		dir := filepath.Join(d, "redis")
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		sock := serve(t, dir, pong)
		if err := os.Chmod(dir, dirMode); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(c.layout.CPanelUsers, 0o755); err != nil {
			t.Fatal(err)
		}
		for _, a := range accounts {
			if err := os.WriteFile(filepath.Join(c.layout.CPanelUsers, a), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		f := antispam.HostFacts{
			RspamdConfig:  antispam.CommandResult{Stdout: fuzzyWorkerDump("")},
			LearningDumps: antispam.LearningDumps{Redis: []byte(`{"servers":"` + sock + `","password":"pw"}`)},
		}
		f.AccountNames, f.AccountNamesErr = c.accountNames()
		return c, f, &probes
	}
	c, f, probes := setup(t, 0o750, "redis")
	if r := c.redis(context.Background(), f); r.Err != nil || *probes != 1 {
		t.Fatalf("protected socket: probes=%d facts=%+v", *probes, r)
	}
	c, f, probes = setup(t, 0o777, "redis")
	if r := c.redis(context.Background(), f); r.Err == nil || *probes != 0 {
		t.Fatalf("world-writable parent: probes=%d facts=%+v", *probes, r)
	}
	c, f, probes = setup(t, 0o750, "tenant", "tenant")
	wantProbes := 0
	if os.Getuid() == 0 {
		wantProbes = 1 // Root remains trusted regardless of account names.
	}
	if r := c.redis(context.Background(), f); (r.Err == nil) != (wantProbes == 1) || *probes != wantProbes {
		t.Fatalf("account-owned socket: probes=%d facts=%+v", *probes, r)
	}
	// A cPanel account named redis is a tenant, not the service.
	c, f, probes = setup(t, 0o750, "redis", "redis")
	if r := c.redis(context.Background(), f); r.Err == nil || *probes != 0 {
		t.Fatalf("account named redis: probes=%d facts=%+v", *probes, r)
	}
	// Tenant code can run as shared service users such as nobody.
	c, f, probes = setup(t, 0o750, "nobody")
	if r := c.redis(context.Background(), f); r.Err == nil || *probes != 0 {
		t.Fatalf("socket owned by an unpinned user: probes=%d facts=%+v", *probes, r)
	}
	c, f, probes = setup(t, 0o750, "redis")
	f.LearningDumps.Redis = []byte(`{"servers":"192.0.2.1:6379","password":"pw"}`)
	if r := c.redis(context.Background(), f); *probes != 0 || r.Unix {
		t.Fatalf("TCP endpoint: probes=%d facts=%+v", *probes, r)
	}
}

func TestCollectControlSocketGroup(t *testing.T) {
	c, d := learningCollector(t, &fakeRun{})
	sock := serve(t, d, pong)
	gid := os.Getgid()
	c.readGroup = func() ([]byte, error) { return []byte("ctl:x:" + strconv.Itoa(gid) + ":member\n"), nil }
	c.readPasswd = func() ([]byte, error) { return []byte("root:x:0:0::/root:/bin/sh\n"), nil }
	f := antispam.HostFacts{RspamdOptions: antispam.CommandResult{Stdout: `{"control_socket": "` + sock + `"}`}}
	c.controlSocket(&f)
	c.controlSocketGroup(&f)
	if got := f.ControllerHost.GroupMembers[gid]; len(got) != 1 || got[0] != "member" {
		t.Fatalf("group members = %v", f.ControllerHost.GroupMembers)
	}
}
