package hostfacts

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/antispam"
)

func learningCollector(t *testing.T, run *fakeRun) (collector, string) {
	t.Helper()
	d := t.TempDir()
	c := testCollector(d, run)
	c.layout.ProcNetUDP = filepath.Join(d, "udp")
	c.layout.ProcNetUDP6 = filepath.Join(d, "udp6")
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
	const rspamd = 979
	line := func(addr, state string, uid int) string {
		return fmt.Sprintf("  12: %s 00000000:0000 %s 00000000:00000000 00:00000000 00000000 %5d        0 1 2 0000000000000000 0\n", addr, state, uid)
	}
	for name, tc := range map[string]struct {
		udp                string
		listening, foreign bool
	}{
		"listening":   {udpHeader + line("0100007F:2C47", "07", rspamd), true, false},
		"root":        {udpHeader + line("0100007F:2C47", "07", 0), true, false},
		"other port":  {udpHeader + line("0100007F:2C46", "07", 4321), false, false},
		"wrong state": {udpHeader + line("0100007F:2C47", "01", rspamd), false, false},
		"header only": {udpHeader, false, false},
		// A tenant can bind the unprivileged port while the worker is gone,
		// or next to it: its datagrams would reach the tenant.
		"tenant only":     {udpHeader + line("0100007F:2C47", "07", 4321), false, true},
		"tenant co-bound": {udpHeader + line("0100007F:2C47", "07", rspamd) + line("0100007F:2C47", "07", 4321), true, true},
		"tenant wildcard": {udpHeader + line("0100007F:2C47", "07", rspamd) + line("00000000:2C47", "07", 4321), true, true},
		"rspamd wildcard": {udpHeader + line("00000000:2C47", "07", rspamd), false, false},
	} {
		t.Run(name, func(t *testing.T) {
			c, _ := learningCollector(t, &fakeRun{})
			if err := os.WriteFile(c.layout.ProcNetUDP, []byte(tc.udp), 0o600); err != nil {
				t.Fatal(err)
			}
			listening, foreign, err := c.fuzzyListening(rspamd)
			if err != nil || listening != tc.listening || foreign != tc.foreign {
				t.Fatalf("listening=%v foreign=%v err=%v, want %v %v", listening, foreign, err, tc.listening, tc.foreign)
			}
		})
	}
	c, _ := learningCollector(t, &fakeRun{})
	if _, _, err := c.fuzzyListening(rspamd); err == nil {
		t.Fatal("missing /proc/net/udp read as not listening")
	}
	if err := os.WriteFile(c.layout.ProcNetUDP, []byte(udpHeader+line("0100007F:2C47", "07", rspamd)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.fuzzyListening(-1); err == nil {
		t.Fatal("unknown rspamd uid judged the listener")
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

func TestCollectLearningLogGroups(t *testing.T) {
	c, _ := learningCollector(t, &fakeRun{})
	c.readGroup = func() ([]byte, error) {
		return []byte("log:x:974:alpha\nparent:x:975:bravo\n"), nil
	}
	c.readPasswd = func() ([]byte, error) { return []byte("root:x:0:0::/root:/bin/sh\n"), nil }
	f := antispam.HostFacts{RspamdLog: antispam.LogFacts{
		File:    antispam.PathFacts{GID: 974},
		Parents: []antispam.PathFacts{{GID: 975}},
	}}
	c.learningFacts(context.Background(), &f)
	for gid, member := range map[int]string{974: "alpha", 975: "bravo"} {
		if got := f.ControllerHost.GroupMembers[gid]; len(got) != 1 || got[0] != member {
			t.Errorf("group %d members = %v, want %s", gid, got, member)
		}
	}
}

// Hosts without CloudLinux have no cagefsctl: CageFS is absent, not an
// unreadable fact. Found on the AlmaLinux scratch host.
func TestCollectCageFSNotInstalled(t *testing.T) {
	missing := antispam.CommandResult{Err: &exec.Error{Name: "cagefsctl", Err: exec.ErrNotFound}}
	c, _ := learningCollector(t, &fakeRun{results: map[string]antispam.CommandResult{"cagefsctl --cagefs-status": missing}})
	if got := c.cageFS(context.Background()); got.Err != nil || got.Enabled {
		t.Fatalf("missing cagefsctl: %+v", got)
	}
	// The live runner keeps exec's not-found error for this check to see.
	if r := RunCommand(context.Background(), time.Second, "csm-test-no-such-binary"); !errors.Is(r.Err, exec.ErrNotFound) {
		t.Fatalf("RunCommand lost exec.ErrNotFound: %v", r.Err)
	}
	failing := antispam.CommandResult{Err: errors.New("exit status 1")}
	c, _ = learningCollector(t, &fakeRun{results: map[string]antispam.CommandResult{"cagefsctl --cagefs-status": failing}})
	if got := c.cageFS(context.Background()); got.Err == nil {
		t.Fatalf("failed cagefsctl read as known: %+v", got)
	}
}

// udp6Header is /proc/net/udp6's header line.
const udp6Header = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n"

// A dual-stack or IPv6 socket of another user on the port also receives the
// worker's traffic. A missing udp6 table means IPv6 is off.
func TestCollectFuzzyListeningIPv6(t *testing.T) {
	const rspamd = 979
	v4 := udpHeader + fmt.Sprintf("  12: 0100007F:2C47 00000000:0000 07 00000000:00000000 00:00000000 00000000 %5d        0 1 2 0000000000000000 0\n", rspamd)
	line6 := func(addr string, uid int) string {
		return fmt.Sprintf("  40: %s 00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 00000000 %5d        0 1 2 0000000000000000 0\n", addr, uid)
	}
	for name, tc := range map[string]struct {
		udp6    string
		foreign bool
	}{
		"rspamd wildcard":   {udp6Header + line6("00000000000000000000000000000000:2C47", rspamd), false},
		"tenant wildcard":   {udp6Header + line6("00000000000000000000000000000000:2C47", 4321), true},
		"tenant mapped":     {udp6Header + line6("0000000000000000FFFF00000100007F:2C47", 4321), true},
		"tenant loopback":   {udp6Header + line6("00000000000000000000000001000000:2C47", 4321), true},
		"tenant mapped any": {udp6Header + line6("0000000000000000FFFF000000000000:2C47", 4321), true},
		"tenant other":      {udp6Header + line6("00000000000000000000000000000000:2C46", 4321), false},
	} {
		t.Run(name, func(t *testing.T) {
			c, _ := learningCollector(t, &fakeRun{})
			write(t, c.layout.ProcNetUDP, v4)
			write(t, c.layout.ProcNetUDP6, tc.udp6)
			listening, foreign, err := c.fuzzyListening(rspamd)
			if err != nil || !listening || foreign != tc.foreign {
				t.Fatalf("listening=%v foreign=%v err=%v, want foreign %v", listening, foreign, err, tc.foreign)
			}
		})
	}
	c, _ := learningCollector(t, &fakeRun{})
	write(t, c.layout.ProcNetUDP, v4)
	if listening, foreign, err := c.fuzzyListening(rspamd); err != nil || !listening || foreign {
		t.Fatalf("no udp6 table: listening=%v foreign=%v err=%v", listening, foreign, err)
	}
	write(t, c.layout.ProcNetUDP6, "garbage\n")
	if _, _, err := c.fuzzyListening(rspamd); err == nil {
		t.Fatal("unreadable udp6 table accepted")
	}
}

// While CSM's learning worker file is installed the collector reads the
// effective weights over the one private controller socket, from rspamd.
func TestCollectLearningSymbols(t *testing.T) {
	const ctl = "/run/rspamd/csm-controller.sock"
	facts := func(installed bool) antispam.HostFacts {
		f := antispam.HostFacts{
			Controller: antispam.ControllerConfig{Present: true, PasswordSet: true, Listeners: []antispam.ControllerListener{
				{Raw: ctl + " mode=0600", Unix: true, Path: ctl, Mode: 0o600}}},
			ControllerHost: antispam.ControllerHostFacts{RspamdUID: 979, GroupMembers: map[int][]string{0: {"root"}}, Sockets: map[string]antispam.SocketFacts{
				ctl: {Socket: antispam.PathFacts{Path: ctl, UID: 979, Mode: fs.ModeSocket | 0o600},
					Parents: []antispam.PathFacts{{Path: "/", Mode: fs.ModeDir | 0o755}, {Path: "/run", Mode: fs.ModeDir | 0o755},
						{Path: "/run/rspamd", UID: 979, Mode: fs.ModeDir | 0o755}}}}},
		}
		target := antispam.TargetFacts{Target: antispam.Target{Path: antispam.LearningWorkerPath, Kind: antispam.TargetRspamdOptional}, Missing: true}
		if installed {
			target.Missing, target.Content = false, antispam.ManagedHeader+"\ncount = 1;\n"
		}
		f.Targets = []antispam.TargetFacts{target}
		return f
	}
	c, _ := learningCollector(t, &fakeRun{})
	var calls []string
	c.controllerGet = func(_ context.Context, socket, path string, _ int64, peer int) ([]byte, error) {
		calls = append(calls, fmt.Sprintf("%s %s %d", socket, path, peer))
		return []byte(`[]`), nil
	}
	f := facts(true)
	c.learningSymbols(context.Background(), &f)
	if len(calls) != 1 || calls[0] != ctl+" /symbols 979" || string(f.LearningDumps.Symbols) != "[]" || f.LearningDumps.SymbolsErr != nil {
		t.Fatalf("calls=%v symbols=%q err=%v", calls, f.LearningDumps.Symbols, f.LearningDumps.SymbolsErr)
	}
	calls = nil
	f = facts(false)
	c.learningSymbols(context.Background(), &f)
	if len(calls) != 0 || f.LearningDumps.Symbols != nil || f.LearningDumps.SymbolsErr != nil {
		t.Fatalf("not installed: calls=%v", calls)
	}
	f = facts(true)
	f.Controller.Listeners = nil
	c.learningSymbols(context.Background(), &f)
	if f.LearningDumps.SymbolsErr == nil {
		t.Fatal("no private controller socket left no error")
	}
	c.controllerGet = func(context.Context, string, string, int64, int) ([]byte, error) {
		return nil, errors.New("rspamd's controller socket is not served by rspamd")
	}
	f = facts(true)
	c.learningSymbols(context.Background(), &f)
	if f.LearningDumps.SymbolsErr == nil {
		t.Fatal("failed read left no error")
	}
}

// The collector never runs Roundcube's PHP: a foreign include at CSM's path
// is reported, not evaluated.
func TestCollectRoundcubeNeverEvaluates(t *testing.T) {
	run := &fakeRun{}
	c, _ := learningCollector(t, run)
	if err := os.MkdirAll(filepath.Dir(c.layout.RoundcubeConfig), 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, c.layout.RoundcubeConfig, `<?php $incfiles = glob("/usr/local/cpanel/base/3rdparty/roundcube/config/inc.d/*.php");`)
	if err := os.WriteFile(c.layout.CPanelPHP, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	foreign := antispam.TargetFacts{Target: antispam.Target{Path: antispam.RoundcubeIncludePath, Kind: antispam.TargetRoundcube},
		Content: "<?php\n$config['junk_mbox'] = 'Junk';\n", File: antispam.PathFacts{Path: antispam.RoundcubeIncludePath, Mode: 0o644}}
	got := c.roundcube(antispam.HostFacts{Targets: []antispam.TargetFacts{foreign}})
	if got.Err != nil || !got.PHP || !got.IncludeMechanism {
		t.Fatalf("facts = %+v", got)
	}
	if len(run.calls) != 0 {
		t.Fatalf("collector ran %v", run.calls)
	}
}
