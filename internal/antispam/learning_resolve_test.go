package antispam

import (
	"encoding/json"
	"errors"
	"io/fs"
	"strings"
	"testing"
)

const (
	testRspamdUID = 979
	testRspamdGID = 974
	testRedisUID  = 990
	testRedisGID  = 990
)

func dir(path string, uid, gid int, perm fs.FileMode) PathFacts {
	return PathFacts{Path: path, UID: uid, GID: gid, Mode: fs.ModeDir | perm}
}

func sock(path string, uid, gid int, perm fs.FileMode) PathFacts {
	return PathFacts{Path: path, UID: uid, GID: gid, Mode: fs.ModeSocket | perm}
}

const privateController = "/run/rspamd/csm-controller.sock"

// safeLearningFacts is a host where every learning prerequisite holds and
// nothing of learning is installed yet.
func safeLearningFacts() HostFacts {
	root := []PathFacts{dir("/", 0, 0, 0o755), dir("/run", 0, 0, 0o755)}
	var targets []TargetFacts
	for _, t := range MutationTargets() {
		targets = append(targets, TargetFacts{Target: t, Missing: true, Parents: []PathFacts{dir("/", 0, 0, 0o755)}})
	}
	f := HostFacts{
		Targets:       targets,
		RspamdVersion: CommandResult{Stdout: "Rspamd daemon version 4.2.2\n"},
		RspamdGID:     testRspamdGID,
		Controller: ControllerConfig{Present: true, PasswordSet: true, Listeners: []ControllerListener{
			{Raw: privateController + " mode=0600", Unix: true, Path: privateController, Mode: 0o600},
			{Raw: "localhost:11334", HostPort: "localhost:11334"},
		}},
		ControllerHost: ControllerHostFacts{
			Sockets: map[string]SocketFacts{privateController: {
				Socket:  sock(privateController, testRspamdUID, testRspamdGID, 0o600),
				Parents: append(append([]PathFacts{}, root...), dir("/run/rspamd", testRspamdUID, testRspamdGID, 0o755)),
			}},
			GroupMembers: map[int][]string{0: {"root"}, testRspamdGID: {"_rspamd"}},
			RspamdUID:    testRspamdUID, RspamdGID: testRspamdGID, RspamdUser: "_rspamd",
		},
		ControlSocket: SocketFacts{
			Socket: sock("/var/lib/rspamd/rspamd.sock", 0, 0, 0o600),
			Parents: []PathFacts{dir("/", 0, 0, 0o755), dir("/var", 0, 0, 0o755), dir("/var/lib", 0, 0, 0o755),
				dir("/var/lib/rspamd", testRspamdUID, testRspamdGID, 0o750)},
		},
		Redis: RedisFacts{
			Endpoint: "/run/redis-rspamd/redis.sock", Unix: true,
			Socket: SocketFacts{
				Socket:  sock("/run/redis-rspamd/redis.sock", testRedisUID, testRedisGID, 0o770),
				Parents: append(append([]PathFacts{}, root...), dir("/run/redis-rspamd", testRedisUID, testRedisGID, 0o750)),
			},
			GroupMembers: []string{"redis", "_rspamd"},
			Port:         "0", TLSPort: "0", Policy: "noeviction", AppendOnly: "yes", Save: "", SaveKnown: true,
			MaxMemoryKnown: true,
			Version:        "5.0.3", MaxMemory: 4 << 30, Used: 1 << 20, ServiceUID: testRedisUID,
		},
		RspamdLog: LogFacts{Type: "file", Path: "/var/log/rspamd/rspamd.log",
			File: PathFacts{Path: "/var/log/rspamd/rspamd.log", GID: testRspamdGID, Mode: 0o640},
			Parents: []PathFacts{dir("/", 0, 0, 0o755), dir("/var", 0, 0, 0o755), dir("/var/log", 0, 0, 0o755),
				dir("/var/log/rspamd", testRspamdUID, testRspamdGID, 0o750)}},
		FuzzyListening: true,
		AccountNames:   map[string]bool{"alpha": true},
		LearningDumps: LearningDumps{
			FuzzyCheck: []byte(`{"timeout": 2.0, "rule": {"rspamd.com": {"servers": "service=fuzzy+rspamd.com"}}}`),
			Worker:     []byte(`[{"normal": {"bind_socket": "localhost:11333"}}, {"fuzzy": {"bind_socket": "localhost:11335", "count": -1}}]`),
			Group:      []byte(`{"fuzzy": {"max_score": 12.0}}`),
			Redis:      []byte(`{"servers": "/run/redis-rspamd/redis.sock"}`),
		},
	}
	f.Socket.RspamdUID = testRspamdUID
	for i := range f.Targets {
		if f.Targets[i].Path == RoundcubeIncludePath {
			f.Roundcube = RoundcubeFacts{Include: f.Targets[i], IncludeMechanism: true, PHP: true}
		}
	}
	return f
}

// installLearning marks the learning files as installed by CSM.
func installLearning(t *testing.T, f *HostFacts) {
	t.Helper()
	files, err := RenderLearning(learningSettings())
	if err != nil {
		t.Fatal(err)
	}
	for i := range f.Targets {
		if text, ok := files[f.Targets[i].Path]; ok {
			f.Targets[i].Missing = false
			f.Targets[i].Content = text
			f.Targets[i].File = PathFacts{Path: f.Targets[i].Path, Mode: 0o640, GID: testRspamdGID}
		}
	}
}

func setTarget(f *HostFacts, p string, content string) {
	for i := range f.Targets {
		if f.Targets[i].Path == p {
			f.Targets[i].Missing = false
			f.Targets[i].Content = content
			f.Targets[i].File = PathFacts{Path: p, Mode: 0o644}
			if p == RoundcubeIncludePath {
				f.Roundcube.Include = f.Targets[i]
			}
		}
	}
}

func onlyLearningReason(t *testing.T, problems []Problem, reason string) {
	t.Helper()
	if len(problems) != 1 || problems[0].Code != CodeLearning || problems[0].Key != reason || problems[0].Severity != Warning || problems[0].Detail == "" {
		t.Fatalf("problems = %+v, want one %s warning", problems, reason)
	}
}

func TestResolveLearningSafeBaseline(t *testing.T) {
	s, gate, problems := ResolveLearning(learningSettings(), safeLearningFacts())
	if !gate.Install || !gate.Publish || !gate.Roundcube || len(problems) != 0 {
		t.Fatalf("gate=%+v problems=%+v", gate, problems)
	}
	if !s.Learning || !s.Roundcube {
		t.Fatalf("settings lost learning: %+v", s)
	}
	off, gate, problems := ResolveLearning(defaults(true), safeLearningFacts())
	if off.Learning || gate != (LearningGate{}) || len(problems) != 0 {
		t.Fatalf("learning off: %+v %+v %+v", off, gate, problems)
	}
}

// definite is a fact change that must turn learning off with one reason.
func TestResolveLearningDefiniteFailures(t *testing.T) {
	for name, tc := range map[string]struct {
		change func(*HostFacts)
		reason string
	}{
		"UnsupportedRspamd": {func(f *HostFacts) { f.RspamdVersion.Stdout = "Rspamd daemon version 4.3.0\n" }, ReasonUnsupported},
		"UnsupportedRedis":  {func(f *HostFacts) { f.Redis.Version = "7.2.4" }, ReasonUnsupported},
		"ControllerExposed": {func(f *HostFacts) { f.Controller.PasswordSet = false }, ReasonUnsafe},
		"ControllerUnverifiable": {func(f *HostFacts) {
			f.ControllerUnverifiable = errors.New("configdump worker controller: bind_socket systemd endpoint")
		}, ReasonUnsafe},
		"NoPrivateControllerSocket": {func(f *HostFacts) { f.Controller.Listeners = f.Controller.Listeners[1:] }, ReasonUnsafe},
		"ControllerSocketNotRspamd": {func(f *HostFacts) {
			s := f.ControllerHost.Sockets[privateController]
			s.Socket.UID = 0
			f.ControllerHost.Sockets[privateController] = s
		}, ReasonUnsafe},
		"ControllerSocketMode": {func(f *HostFacts) {
			s := f.ControllerHost.Sockets[privateController]
			s.Socket.Mode = fs.ModeSocket | 0o660
			f.ControllerHost.Sockets[privateController] = s
		}, ReasonUnsafe},
		"ControlSocketLoose": {func(f *HostFacts) { f.ControlSocket.Socket.Mode = fs.ModeSocket | 0o666 }, ReasonUnsafe},
		"RedisTCP":           {func(f *HostFacts) { f.Redis.Port = "6379" }, ReasonUnsafe},
		"RedisTCPEndpoint": {func(f *HostFacts) {
			f.Redis = RedisFacts{Endpoint: "127.0.0.1:6379", ServiceUID: -1}
		}, ReasonUnsafe},
		"RedisGroupMemberIsAccount": {func(f *HostFacts) { f.Redis.GroupMembers = []string{"redis", "alpha"} }, ReasonUnsafe},
		// Tenant code can run as shared users such as nobody or mailnull.
		"RedisGroupMemberShared": {func(f *HostFacts) { f.Redis.GroupMembers = []string{"redis", "_rspamd", "nobody"} }, ReasonUnsafe},
		// A cPanel account can carry a trusted name; then the name proves nothing.
		"RedisGroupAccountNamedRedis": {func(f *HostFacts) { f.AccountNames["redis"] = true }, ReasonUnsafe},
		"RedisGroupAccountsUnread": {func(f *HostFacts) {
			f.AccountNames, f.AccountNamesErr = nil, errors.New("cannot list cPanel accounts")
		}, ReasonUnsafe},
		"RedisTLSPort":        {func(f *HostFacts) { f.Redis.TLSPort = "6380" }, ReasonUnsafe},
		"RedisGroupUnknown":   {func(f *HostFacts) { f.Redis.GroupMembers = nil }, ReasonUnsafe},
		"RedisACL":            {func(f *HostFacts) { f.Redis.Socket.Socket.ExtACL = true }, ReasonUnsafe},
		"RedisParentACL":      {func(f *HostFacts) { f.Redis.Socket.Parents[2].ExtACL = true }, ReasonUnsafe},
		"RedisParentWritable": {func(f *HostFacts) { f.Redis.Socket.Parents[2].Mode = fs.ModeDir | 0o777 }, ReasonUnsafe},
		"RedisSocketOthers":   {func(f *HostFacts) { f.Redis.Socket.Socket.Mode = fs.ModeSocket | 0o777 }, ReasonUnsafe},
		"RedisUnprotected": {func(f *HostFacts) {
			f.Redis.Unprotected, f.Redis.Err = true, errors.New("redis socket is not protected")
		}, ReasonUnsafe},
		"LogsExposed":         {func(f *HostFacts) { f.RspamdLog.File.Mode = 0o644; f.RspamdLog.Parents[3].Mode = fs.ModeDir | 0o755 }, ReasonUnsafe},
		"RedisNoMaxmemory":    {func(f *HostFacts) { f.Redis.MaxMemory = 0 }, ReasonUnsafe},
		"RedisEvictionPolicy": {func(f *HostFacts) { f.Redis.Policy = "allkeys-lru" }, ReasonUnsafe},
		"ForeignFuzzyRule": {func(f *HostFacts) {
			f.LearningDumps.FuzzyCheck = []byte(`{"rule": {"rspamd.com": {}, "ops_rule": {}}}`)
		}, ReasonConfigConflict},
		"ForeignFuzzyWorker": {func(f *HostFacts) {
			f.LearningDumps.Worker = []byte(`[{"fuzzy": {"bind_socket": "localhost:11335", "count": 2}}]`)
		}, ReasonConfigConflict},
		"ForeignOptionalFile":  {func(f *HostFacts) { setTarget(f, LearningWorkerPath, "count = 4;\n") }, ReasonConfigConflict},
		"ForeignLuaFile":       {func(f *HostFacts) { setTarget(f, LearningLuaPath, "-- operator plugin\n") }, ReasonConfigConflict},
		"KeysIncomplete":       {func(f *HostFacts) { f.LearningKeysErr = errors.New("learning keys are incomplete: missing prefix") }, ReasonStateMismatch},
		"FuzzyListenerForeign": {func(f *HostFacts) { f.FuzzyListenForeign = true }, ReasonUnsafe},
	} {
		t.Run(name, func(t *testing.T) {
			f := safeLearningFacts()
			tc.change(&f)
			s, gate, problems := ResolveLearning(learningSettings(), f)
			if gate.Install || gate.Publish || gate.Roundcube || s.Learning || s.Roundcube {
				t.Fatalf("gate=%+v settings learning=%v roundcube=%v", gate, s.Learning, s.Roundcube)
			}
			onlyLearningReason(t, problems, tc.reason)
		})
	}
}

func TestResolveLearningLogsCageFSProtected(t *testing.T) {
	f := safeLearningFacts()
	f.RspamdLog.File.Mode = 0o644
	f.RspamdLog.Parents[3].Mode = fs.ModeDir | 0o755
	f.CageFS = CageFSFacts{Enabled: true, ExcludedLogDir: "/var/log/rspamd"}
	if _, gate, problems := ResolveLearning(learningSettings(), f); !gate.Install || len(problems) != 0 {
		t.Fatalf("CageFS-protected log: gate=%+v problems=%+v", gate, problems)
	}
	for name, cage := range map[string]CageFSFacts{
		"disabled user": {Enabled: true, DisabledUsers: 1},
		"skeleton log":  {Enabled: true, SkeletonHasRspamdLog: true},
		"unreadable":    {Enabled: true, Err: errors.New("cagefsctl --list-disabled failed")},
	} {
		f.CageFS = cage
		if _, gate, problems := ResolveLearning(learningSettings(), f); gate.Install || len(problems) != 1 {
			t.Errorf("%s: gate=%+v problems=%+v", name, gate, problems)
		}
	}
}

// rspamd prints rule as an object with one rule and as a list of single-key
// objects with several (recorded on rspamd 4.2 hosts).
func TestResolveLearningRuleListForm(t *testing.T) {
	f := safeLearningFacts()
	f.LearningDumps.FuzzyCheck = []byte(`{"rule": [{"rspamd.com": {}}, {"ops_rule": {}}]}`)
	if _, gate, problems := ResolveLearning(learningSettings(), f); gate.Install || len(problems) != 1 || problems[0].Key != ReasonConfigConflict {
		t.Fatalf("list-form foreign rule: gate=%+v problems=%+v", gate, problems)
	}
	f.LearningDumps.FuzzyCheck = []byte(`{"rule": [{"rspamd.com": {}}]}`)
	if _, gate, problems := ResolveLearning(learningSettings(), f); !gate.Install || len(problems) != 0 {
		t.Fatalf("list-form stock rule: gate=%+v problems=%+v", gate, problems)
	}
}

func TestResolveLearningStockRuleIsNotConflict(t *testing.T) {
	f := safeLearningFacts()
	f.LearningDumps.FuzzyCheck = []byte(`{"rule": {"rspamd.com": {}}}`)
	f.LearningDumps.Worker = []byte(`[{"fuzzy": {"count": -1}}]`)
	if _, gate, problems := ResolveLearning(learningSettings(), f); !gate.Install || len(problems) != 0 {
		t.Fatalf("stock rule and disabled stock worker: gate=%+v problems=%+v", gate, problems)
	}
	// Once CSM's override is installed, the loaded rules are csm and
	// csm_learn; verification checks them, not the conflict scan.
	withLoadedLearning(t, &f)
	if _, gate, problems := ResolveLearning(learningSettings(), f); !gate.Install || len(problems) != 0 {
		t.Fatalf("installed learning: gate=%+v problems=%+v", gate, problems)
	}
}

func TestResolveLearningRedisPersistence(t *testing.T) {
	f := safeLearningFacts()
	f.Redis.AppendOnly, f.Redis.Save = "no", ""
	_, gate, problems := ResolveLearning(learningSettings(), f)
	if !gate.Install || !gate.Publish {
		t.Fatalf("gate = %+v", gate)
	}
	onlyLearningReason(t, problems, ReasonRedisPersistence)
	f.Redis.Save = "3600 1"
	if _, _, problems := ResolveLearning(learningSettings(), f); len(problems) != 0 {
		t.Fatalf("RDB snapshots count as persistence: %+v", problems)
	}
}

func TestResolveLearningRedisOverGuard(t *testing.T) {
	f := safeLearningFacts()
	f.Redis.Used = f.Redis.MaxMemory * 3 / 4
	_, gate, problems := ResolveLearning(learningSettings(), f)
	if !gate.Install || gate.Publish || !gate.Roundcube {
		t.Fatalf("gate = %+v", gate)
	}
	onlyLearningReason(t, problems, ReasonRedisCapacity)
	f.Redis.Used = f.Redis.MaxMemory * 72 / 100
	f.RedisGuardPaused = true
	if _, gate, _ := ResolveLearning(learningSettings(), f); gate.Publish {
		t.Fatal("paused guard resumed above 70%")
	}
	f.RedisGuardPaused = false
	if _, gate, _ := ResolveLearning(learningSettings(), f); !gate.Publish {
		t.Fatal("72% paused a running guard")
	}
}

func TestRedisGuardHysteresis(t *testing.T) {
	const max = 1000
	for _, tc := range []struct {
		used   uint64
		paused bool
		want   bool
	}{
		{749, false, false}, {750, false, true}, {740, true, true}, {700, true, true},
		{699, true, false}, {0, true, false}, {1, false, false},
	} {
		if got := RedisGuard(tc.used, max, tc.paused); got != tc.want {
			t.Errorf("RedisGuard(%d, %d, %v) = %v, want %v", tc.used, max, tc.paused, got, tc.want)
		}
	}
	if !RedisGuard(0, 0, false) {
		t.Error("no maxmemory must pause")
	}
	if !RedisGuard(1<<62, 1<<62, false) {
		t.Error("overflow-sized values must still pause at the limit")
	}
}

func TestResolveLearningFuzzyNotListening(t *testing.T) {
	f := safeLearningFacts()
	f.FuzzyListening = false
	if _, gate, problems := ResolveLearning(learningSettings(), f); !gate.Install || !gate.Publish || len(problems) != 0 {
		t.Fatalf("before install: gate=%+v problems=%+v", gate, problems)
	}
	withLoadedLearning(t, &f)
	_, gate, problems := ResolveLearning(learningSettings(), f)
	if !gate.Install || gate.Publish {
		t.Fatalf("after install: gate = %+v", gate)
	}
	onlyLearningReason(t, problems, ReasonWorkerAbsent)
}

func TestResolveLearningRoundcube(t *testing.T) {
	for name, change := range map[string]func(*HostFacts){
		"RoundcubeMissing": func(f *HostFacts) {
			f.Roundcube.Err = errors.New("cannot read cPanel's Roundcube configuration")
			f.Roundcube.IncludeMechanism = false
		},
		"RoundcubeNoMechanism": func(f *HostFacts) { f.Roundcube.IncludeMechanism = false },
		"RoundcubeNoPHP":       func(f *HostFacts) { f.Roundcube.PHP = false },
		"RoundcubeUnsafeParent": func(f *HostFacts) {
			f.Roundcube.Include.Parents = []PathFacts{dir("/", 0, 0, 0o777)}
		},
		"RoundcubeForeignFile": func(f *HostFacts) { setTarget(f, RoundcubeIncludePath, "<?php\n$config['junk_mbox'] = 'Junk';\n") },
	} {
		t.Run(name, func(t *testing.T) {
			f := safeLearningFacts()
			change(&f)
			s, gate, problems := ResolveLearning(learningSettings(), f)
			if !gate.Install || !gate.Publish || gate.Roundcube || !s.Learning || s.Roundcube {
				t.Fatalf("gate=%+v learning=%v roundcube=%v", gate, s.Learning, s.Roundcube)
			}
			onlyLearningReason(t, problems, ReasonRoundcube)
		})
	}
}

func TestResolveLearningProbeErrors(t *testing.T) {
	for name, change := range map[string]func(*HostFacts){
		"RedisProbeError": func(f *HostFacts) {
			f.Redis = RedisFacts{Endpoint: f.Redis.Endpoint, Unix: true, Socket: f.Redis.Socket, GroupMembers: f.Redis.GroupMembers, ServiceUID: -1, Err: errors.New("redis: INFO memory failed")}
		},
		"RedisSocketMissing": func(f *HostFacts) {
			f.Redis.Socket = SocketFacts{Missing: true}
			f.Redis.Err = errors.New("redis socket cannot be checked")
		},
		"DumpsUnreadable":   func(f *HostFacts) { f.LearningDumps.Err = errors.New("rspamadm configdump -j fuzzy_check failed") },
		"ControllerUnread":  func(f *HostFacts) { f.ControllerErr = errors.New("rspamadm configdump -j failed") },
		"ControlSocketGone": func(f *HostFacts) { f.ControlSocket = SocketFacts{Missing: true} },
		"LogUnreadable":     func(f *HostFacts) { f.RspamdLog.Err = errors.New("permission denied") },
		"UDPUnreadable":     func(f *HostFacts) { f.FuzzyListenErr = errors.New("cannot read the UDP socket table") },
		"VersionUnknown":    func(f *HostFacts) { f.RspamdVersion = CommandResult{Err: errors.New("exit status 1")} },
	} {
		t.Run(name, func(t *testing.T) {
			for _, installed := range []bool{false, true} {
				f := safeLearningFacts()
				if installed {
					withLoadedLearning(t, &f)
				}
				change(&f)
				s, gate, problems := ResolveLearning(learningSettings(), f)
				if gate.Install != installed || s.Learning != installed || gate.Publish {
					t.Fatalf("installed=%v: gate=%+v learning=%v", installed, gate, s.Learning)
				}
				onlyLearningReason(t, problems, ReasonBackendUnavailable)
			}
		})
	}
}

func TestResolveLearningReportsEachReasonOnce(t *testing.T) {
	f := safeLearningFacts()
	// Three unsafe causes and an unsupported version: one problem each.
	f.Redis.MaxMemory, f.Controller.PasswordSet = 0, false
	f.RspamdLog.File.Mode = 0o644
	f.RspamdLog.Parents[3].Mode = fs.ModeDir | 0o755
	f.Redis.Version = "7.2.4"
	_, gate, problems := ResolveLearning(learningSettings(), f)
	if gate.Install || len(problems) != 2 {
		t.Fatalf("gate=%+v problems=%+v", gate, problems)
	}
	if problems[0].Key == problems[1].Key {
		t.Fatalf("reason reported twice: %+v", problems)
	}
	// Roundcube is judged only while learning installs.
	f = safeLearningFacts()
	f.Roundcube.PHP = false
	f.Redis.Policy = "allkeys-lru"
	if _, _, problems := ResolveLearning(learningSettings(), f); len(problems) != 1 || problems[0].Key != ReasonUnsafe {
		t.Fatalf("problems = %+v", problems)
	}
}

// withLoadedLearning installs CSM's learning files and makes rspamd report
// them loaded exactly as written, in the shapes recorded on rspamd 4.2.
func withLoadedLearning(t *testing.T, f *HostFacts) *loadedDumps {
	t.Helper()
	installLearning(t, f)
	d := newLoadedDumps(syntheticLearningKeys())
	d.apply(f)
	return d
}

func (d *loadedDumps) apply(f *HostFacts) {
	enc := func(v any) []byte { b, _ := json.Marshal(v); return b }
	var group []byte
	for _, g := range d.groups {
		group = append(append(group, enc(g)...), '\n')
	}
	f.LearningDumps.FuzzyCheck, f.LearningDumps.Worker, f.LearningDumps.Group = enc(d.fuzzyCheck), enc(d.worker), group
	f.LearningDumps.Symbols, f.LearningDumps.SymbolsErr = enc(d.symbols), nil
	f.RspamdActions = CommandResult{Stdout: `{"reject": 15, "add_header": 6, "greylist": null, "rewrite_subject": null}`}
}

// After install, rspamd can stop loading what CSM wrote: a runtime weight
// change, a higher-priority group cap or score rescaling. Every pass checks.
func TestResolveLearningKeepVerifiesLoaded(t *testing.T) {
	f := safeLearningFacts()
	withLoadedLearning(t, &f)
	if _, gate, problems := ResolveLearning(learningSettings(), f); !gate.Install || !gate.Publish || len(problems) != 0 {
		t.Fatalf("loaded as written: gate=%+v problems=%+v", gate, problems)
	}
	for name, change := range map[string]func(d *loadedDumps, f *HostFacts){
		"DynamicWeight": func(d *loadedDumps, _ *HostFacts) {
			d.symbols[1].(map[string]any)["rules"].([]any)[0].(map[string]any)["weight"] = 20.0
		},
		"GroupCap":  func(d *loadedDumps, _ *HostFacts) { d.groups[1]["fuzzy"].(map[string]any)["max_score"] = 20.0 },
		"ModuleOff": func(d *loadedDumps, _ *HostFacts) { d.fuzzyCheck["enabled"] = false },
		"GrowFactor": func(_ *loadedDumps, f *HostFacts) {
			f.RspamdActions.Stdout = `{"reject": 15, "add_header": 6, "grow_factor": 1.5}`
		},
	} {
		t.Run(name, func(t *testing.T) {
			facts := safeLearningFacts()
			d := withLoadedLearning(t, &facts)
			change(d, &facts)
			if name != "GrowFactor" {
				d.apply(&facts)
			}
			s, gate, problems := ResolveLearning(learningSettings(), facts)
			if gate.Install || s.Learning {
				t.Fatalf("gate = %+v", gate)
			}
			onlyLearningReason(t, problems, ReasonConfigConflict)
		})
	}
	f = safeLearningFacts()
	withLoadedLearning(t, &f)
	f.LearningDumps.Symbols, f.LearningDumps.SymbolsErr = nil, errors.New("rspamd's controller reply could not be read")
	_, gate, problems := ResolveLearning(learningSettings(), f)
	if !gate.Install || gate.Publish {
		t.Fatalf("symbols unreadable: gate = %+v", gate)
	}
	onlyLearningReason(t, problems, ReasonBackendUnavailable)
	// A drifted CSM file is repaired by the next apply, whose own check
	// verifies the result; the loaded state is not judged meanwhile.
	f = safeLearningFacts()
	d := withLoadedLearning(t, &f)
	d.symbols[1].(map[string]any)["rules"].([]any)[0].(map[string]any)["weight"] = 20.0
	d.apply(&f)
	setTarget(&f, LearningGroupPath, ManagedHeader+"\nmax_score = 12.0;\n")
	if _, gate, problems := ResolveLearning(learningSettings(), f); !gate.Install || len(problems) != 0 {
		t.Fatalf("drifted files: gate=%+v problems=%+v", gate, problems)
	}
}

// A foreign include at CSM's path is reported with the settings Roundcube
// loads from it (spec 6.4).
func TestResolveLearningRoundcubeForeignReportsObserved(t *testing.T) {
	f := safeLearningFacts()
	setTarget(&f, RoundcubeIncludePath, "<?php\n$config['junk_mbox'] = 'Junk';\n")
	f.Roundcube.Observed = &RoundcubeState{JunkMbox: "Junk", MarkAsJunk: true}
	_, gate, problems := ResolveLearning(learningSettings(), f)
	if !gate.Install || gate.Roundcube {
		t.Fatalf("gate = %+v", gate)
	}
	onlyLearningReason(t, problems, ReasonRoundcube)
	if !strings.Contains(problems[0].Detail, `junk_mbox "Junk"`) {
		t.Fatalf("detail = %q", problems[0].Detail)
	}
}
