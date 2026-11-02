package antispam

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/antispam/dovecot"
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
	for _, t := range MutationTargets(StackExim) {
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
	installLearningFor(t, f, learningSettings())
}

// installLearningFor marks the learning files CSM renders for s as
// installed.
func installLearningFor(t *testing.T, f *HostFacts, s Settings) {
	t.Helper()
	files, err := RenderLearning(s)
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

// setLoosenedTarget is setTarget for a file group and others can write.
func setLoosenedTarget(f *HostFacts, p string, content string) {
	setTarget(f, p, content)
	for i := range f.Targets {
		if f.Targets[i].Path == p {
			f.Targets[i].File.Mode = 0o664
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

// postfixLearningFacts is a Postfix and Dovecot host where every learning
// prerequisite holds: a dedicated Redis, no Roundcube, mail stored as vmail.
func postfixLearningFacts() HostFacts {
	f := dedicatedRedisFacts(StackPostfix, dedicatedSocket)
	f.Targets, f.Roundcube = nil, RoundcubeFacts{}
	for _, tg := range MutationTargets(StackPostfix) {
		f.Targets = append(f.Targets, TargetFacts{Target: tg, Missing: true, Parents: []PathFacts{dir("/", 0, 0, 0o755)}})
	}
	f.Dovecot = DovecotFacts{UIDs: []int{5000}}
	return f
}

func postfixLearningSettings() Settings {
	s := learningSettings()
	s.LearningRedisSocket = dedicatedSocket
	return s
}

// Learning runs on a Postfix host that meets its prerequisites, without the
// webmail Junk-button include.
func TestResolveLearningOnPostfix(t *testing.T) {
	s, gate, problems := ResolveLearning(postfixLearningSettings(), postfixLearningFacts())
	if !s.Learning || s.Roundcube || gate != (LearningGate{Install: true, Publish: true}) || len(problems) != 0 {
		t.Fatalf("Postfix: settings %+v, gate %+v, problems %+v", s, gate, problems)
	}
}

// Dovecot's answers decide learning on Postfix (L10-L12): a userdb that
// cannot list users or Dovecot 2.4 turn learning off, a failed or slow
// listing waits, mail stored as rspamd's or Redis's user is unsafe, and
// skipped mailboxes are counted by reason in one warning. No detail carries
// command output or a mailbox name.
func TestResolveLearningPostfixDovecot(t *testing.T) {
	const leaked = "alice@example.com"
	for name, tc := range map[string]struct {
		dovecot DovecotFacts
		reason  string
		detail  string
	}{
		"cannot iterate": {DovecotFacts{Err: fmt.Errorf("listing: %w", dovecot.ErrCannotIterate)}, ReasonUnsupported,
			"Dovecot cannot list its users; learning needs a userdb that supports iteration"},
		"dovecot 2.4": {DovecotFacts{Err: dovecot.ErrDovecot24}, ReasonUnsupported,
			"Dovecot 2.4 mail settings are not supported yet"},
		"timeout": {DovecotFacts{Err: fmt.Errorf("doveadm: %w", context.DeadlineExceeded)}, ReasonBackendUnavailable,
			"listing Dovecot's mailboxes timed out; learning waits for the next check"},
		"exit error": {DovecotFacts{Err: errors.New("doveadm: exit status 75: " + leaked)}, ReasonBackendUnavailable,
			"CSM cannot list Dovecot's mailboxes; learning waits for the next check"},
		"mail as rspamd": {DovecotFacts{UIDs: []int{5000, testRspamdUID}}, ReasonUnsafe,
			"Dovecot stores mail as rspamd's or Redis's user; learning needs a separate mail user"},
		"mail as redis": {DovecotFacts{UIDs: []int{testRedisUID}}, ReasonUnsafe,
			"Dovecot stores mail as rspamd's or Redis's user; learning needs a separate mail user"},
		"skipped": {DovecotFacts{UIDs: []int{5000}, Skips: []dovecot.Skip{
			{User: leaked, Reason: dovecot.SkipDriver}, {User: "bob@example.com", Reason: dovecot.SkipLookupFailed},
			{User: "carol@example.net", Reason: dovecot.SkipDriver}, {Reason: dovecot.SkipInvalidName},
			{User: "dave@example.org", Reason: dovecot.SkipNoJunk}, {User: "erin@example.org", Reason: dovecot.SkipPluginZlib},
		}}, ReasonMailboxesSkipped, "mailboxes not watched for learning: 5 (driver 2, invalid_name 1, lookup_failed 1, plugin_zlib 1)"},
	} {
		t.Run(name, func(t *testing.T) {
			s := postfixLearningSettings()
			// An exempt mailbox is never watched: its skip is no problem.
			s.Exempt = []string{"dave@example.org"}
			f := postfixLearningFacts()
			f.Dovecot = tc.dovecot
			got, gate, problems := ResolveLearning(s, f)
			onlyLearningReason(t, problems, tc.reason)
			if problems[0].Detail != tc.detail {
				t.Fatalf("detail %q, want %q", problems[0].Detail, tc.detail)
			}
			if strings.Contains(problems[0].Detail, leaked) || strings.Contains(problems[0].Detail, "exit status") {
				t.Fatalf("detail leaks command output: %q", problems[0].Detail)
			}
			switch tc.reason {
			case ReasonMailboxesSkipped:
				if !got.Learning || gate != (LearningGate{Install: true, Publish: true}) {
					t.Fatalf("a skipped mailbox stopped learning: %+v %+v", got, gate)
				}
			case ReasonBackendUnavailable:
				if got.Learning || gate != (LearningGate{}) {
					t.Fatalf("a failed listing installed learning: %+v %+v", got, gate)
				}
				// An installed learning stays and stops publishing.
				installed := withLearning(t, f, dedicatedSocket)
				if _, gate, _ = ResolveLearning(s, installed); gate != (LearningGate{Install: true}) {
					t.Fatalf("installed learning on a failed listing: gate %+v", gate)
				}
			default:
				if got.Learning || gate != (LearningGate{}) {
					t.Fatalf("learning stayed on: %+v %+v", got, gate)
				}
			}
		})
	}
	// Exim hosts read nothing from Dovecot and are not judged by it.
	f := safeLearningFacts()
	f.Dovecot = DovecotFacts{Err: dovecot.ErrCannotIterate, UIDs: []int{testRspamdUID}}
	if _, gate, problems := ResolveLearning(learningSettings(), f); !gate.Install || !gate.Publish || len(problems) != 0 {
		t.Fatalf("Exim judged by Dovecot facts: gate %+v problems %+v", gate, problems)
	}
}

// A user that may run tenant code and shares rspamd's uid could reach the
// controller as rspamd: learning refuses on either stack. When CSM cannot
// rule a share out, learning waits instead (ruling P6): an installation
// stays and publishes nothing new, a first one is not made.
func TestResolveLearningRspamdUIDShared(t *testing.T) {
	for stack, pair := range map[MailStack]struct {
		s Settings
		f HostFacts
	}{
		StackExim:    {learningSettings(), safeLearningFacts()},
		StackPostfix: {postfixLearningSettings(), postfixLearningFacts()},
	} {
		shared := pair.f
		shared.RspamdUIDShared = true
		for _, f := range []HostFacts{shared, withLearning(t, shared, pair.s.LearningRedisSocket)} {
			got, gate, problems := ResolveLearning(pair.s, f)
			onlyLearningReason(t, problems, ReasonUnsafe)
			if want := "rspamd's uid is shared with a user that can run tenant code"; problems[0].Detail != want || got.Learning || gate != (LearningGate{}) {
				t.Fatalf("%s: problems %+v gate %+v", stack, problems, gate)
			}
		}
		unknown := pair.f
		unknown.RspamdUIDErr = errors.New("lookup of tenant failed")
		const want = "CSM cannot rule out that another user shares rspamd's uid; learning waits for the next check"
		got, gate, problems := ResolveLearning(pair.s, unknown)
		onlyLearningReason(t, problems, ReasonBackendUnavailable)
		if problems[0].Detail != want || got.Learning || gate != (LearningGate{}) {
			t.Fatalf("%s first install: problems %+v gate %+v", stack, problems, gate)
		}
		got, gate, problems = ResolveLearning(pair.s, withLearning(t, unknown, pair.s.LearningRedisSocket))
		onlyLearningReason(t, problems, ReasonBackendUnavailable)
		// Nothing is removed: on cPanel the Junk-button include stays too.
		if problems[0].Detail != want || !got.Learning || !gate.Install || gate.Publish || gate.Roundcube != (stack == StackExim) {
			t.Fatalf("%s installed: problems %+v gate %+v settings %+v", stack, problems, gate, got)
		}
	}
}

// definite is a fact change that must turn learning off with one reason.
func TestResolveLearningDefiniteFailures(t *testing.T) {
	for name, tc := range map[string]struct {
		change func(*HostFacts)
		reason string
	}{
		"UnsupportedRspamd": {func(f *HostFacts) { f.RspamdVersion.Stdout = "Rspamd daemon version 4.3.0\n" }, ReasonUnsupported},
		"UnsupportedRedis":  {func(f *HostFacts) { f.Redis.Version = "8.0.2" }, ReasonUnsupported},
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
		"LoosenedOptionalFile": {func(f *HostFacts) { setLoosenedTarget(f, LearningWorkerPath, "count = 4;\n") }, ReasonConfigConflict},
		"LoosenedLuaFile":      {func(f *HostFacts) { setLoosenedTarget(f, LearningLuaPath, "-- operator plugin\n") }, ReasonConfigConflict},
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

// The worker backs up and replaces a protected operator file at a learning
// path, so it no longer holds learning back.
func TestResolveLearningTakesOverForeignFiles(t *testing.T) {
	for p, content := range map[string]string{
		LearningWorkerPath: "count = 4;\n",
		LearningLuaPath:    "-- operator plugin\n",
	} {
		f := safeLearningFacts()
		setTarget(&f, p, content)
		s, gate, problems := ResolveLearning(learningSettings(), f)
		if !gate.Install || !gate.Publish || !s.Learning || len(problems) != 0 {
			t.Errorf("%s: gate=%+v learning=%v problems=%+v", p, gate, s.Learning, problems)
		}
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
		"RoundcubeLoosenedFile": func(f *HostFacts) {
			setLoosenedTarget(f, RoundcubeIncludePath, "<?php\n$config['junk_mbox'] = 'Junk';\n")
		},
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
	f.Redis.Version = "8.0.2"
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

// A protected foreign include at CSM's path is backed up and replaced by the
// worker, so the include stays on.
func TestResolveLearningRoundcubeForeignInclude(t *testing.T) {
	f := safeLearningFacts()
	setTarget(&f, RoundcubeIncludePath, "<?php\n$config['junk_mbox'] = 'Junk';\n")
	s, gate, problems := ResolveLearning(learningSettings(), f)
	if !gate.Install || !gate.Roundcube || !s.Roundcube || len(problems) != 0 {
		t.Fatalf("gate = %+v, roundcube = %v, problems = %+v", gate, s.Roundcube, problems)
	}
}

func TestResolveLearningForeignListenerWithProbeFailure(t *testing.T) {
	for _, installed := range []bool{false, true} {
		f := safeLearningFacts()
		if installed {
			withLoadedLearning(t, &f)
		}
		f.FuzzyListenForeign = true
		f.FuzzyListenErr = errors.New("the other UDP table could not be read")
		s, gate, problems := ResolveLearning(learningSettings(), f)
		if s.Learning || gate != (LearningGate{}) {
			t.Fatalf("installed=%v: foreign listener left learning enabled: %+v", installed, gate)
		}
		var unsafe, unavailable bool
		for _, p := range problems {
			unsafe = unsafe || p.Key == ReasonUnsafe
			unavailable = unavailable || p.Key == ReasonBackendUnavailable
		}
		if len(problems) != 2 || !unsafe || !unavailable {
			t.Fatalf("installed=%v: problems=%+v, want unsafe listener and probe failure", installed, problems)
		}
	}
}

// Redis 7 is qualified next to 5.0 and 6.2; anything else, including a
// release-candidate suffix, stays refused.
func TestRedisVersionAccepts7(t *testing.T) {
	for _, v := range []string{"5.0.3", "6.2.14", "7.0.15", "7.2.4", "7.4.1"} {
		f := safeLearningFacts()
		f.Redis.Version = v
		if _, gate, problems := ResolveLearning(learningSettings(), f); !gate.Install || !gate.Publish || len(problems) != 0 {
			t.Errorf("Redis %s: gate=%+v problems=%+v", v, gate, problems)
		}
	}
	for _, v := range []string{"6.0.16", "8.0.2", "7.2", "7.2.4-rc1", "17.0.1", "4.0.14"} {
		f := safeLearningFacts()
		f.Redis.Version = v
		_, gate, problems := ResolveLearning(learningSettings(), f)
		if gate.Install {
			t.Errorf("Redis %s installed learning", v)
		}
		onlyLearningReason(t, problems, ReasonUnsupported)
	}
}

// dedicatedRedisFacts is safeLearningFacts with the dedicated learning Redis
// probed at socket on the given stack.
func dedicatedRedisFacts(stack MailStack, socket string) HostFacts {
	f := safeLearningFacts()
	f.Stack = stack
	f.Redis.Endpoint = socket
	f.Redis.Socket.Socket.Path = socket
	return f
}

const dedicatedSocket = "/run/redis-csm/redis.sock"

// Decision 7: on Postfix only a dedicated Redis named in csm.yaml qualifies.
func TestResolveLearningPostfixNeedsRedisSocket(t *testing.T) {
	s := learningSettings()
	var c learningCheck
	checkLearningRedis(&c, s, dedicatedRedisFacts(StackPostfix, dedicatedSocket))
	onlyLearningReason(t, c.problems, ReasonUnsupported)
	if want := "learning on Postfix needs a dedicated Redis: set email_protection.antispam.learning.redis_socket"; c.problems[0].Detail != want {
		t.Fatalf("detail %q, want %q", c.problems[0].Detail, want)
	}
	s.LearningRedisSocket = dedicatedSocket
	c = learningCheck{}
	if checkLearningRedis(&c, s, dedicatedRedisFacts(StackPostfix, dedicatedSocket)); len(c.problems) != 0 {
		t.Fatalf("dedicated Redis on Postfix: %+v", c.problems)
	}
	// Exim keeps rspamd's Redis when no dedicated one is named.
	c = learningCheck{}
	if checkLearningRedis(&c, learningSettings(), safeLearningFacts()); len(c.problems) != 0 {
		t.Fatalf("Exim without the key: %+v", c.problems)
	}
}

// Roundcube is cPanel's webmail: on Postfix the collector reads nothing
// about it and the resolver neither judges nor reports its include.
func TestResolveLearningPostfixNoRoundcubeWarning(t *testing.T) {
	s := learningSettings()
	s.LearningRedisSocket = dedicatedSocket
	f := dedicatedRedisFacts(StackPostfix, dedicatedSocket)
	f.Targets, f.Roundcube = nil, RoundcubeFacts{}
	for _, tg := range MutationTargets(StackPostfix) {
		f.Targets = append(f.Targets, TargetFacts{Target: tg, Missing: true, Parents: []PathFacts{dir("/", 0, 0, 0o755)}})
	}
	got, gate, problems := resolveLearning(s, f)
	if !gate.Install || !gate.Publish || gate.Roundcube || !got.Learning || got.Roundcube || len(problems) != 0 {
		t.Fatalf("Postfix: settings %+v gate %+v problems %+v", got, gate, problems)
	}
	// The same facts on cPanel still miss the include.
	f.Stack = StackExim
	_, gate, problems = resolveLearning(s, f)
	if !gate.Install || gate.Roundcube {
		t.Fatalf("cPanel: gate %+v", gate)
	}
	onlyLearningReason(t, problems, ReasonRoundcube)
}

// The safety checks judge the dedicated Redis exactly like rspamd's, on
// either stack, and a Redis another rspamd module also uses, or one rspamd's
// global redis settings would reach, is refused. An outage keeps an
// installation but never moves it to a Redis no check has passed.
func TestLearningRedisSocketSafetyChecks(t *testing.T) {
	for name, tc := range map[string]struct {
		change func(*RedisFacts)
		reason string
	}{
		"TCP port":     {func(r *RedisFacts) { r.Port = "6379" }, ReasonUnsafe},
		"TLS port":     {func(r *RedisFacts) { r.TLSPort = "6380" }, ReasonUnsafe},
		"eviction":     {func(r *RedisFacts) { r.Policy = "allkeys-lru" }, ReasonUnsafe},
		"no maxmemory": {func(r *RedisFacts) { r.MaxMemory = 0 }, ReasonUnsafe},
		"socket mode":  {func(r *RedisFacts) { r.Socket.Socket.Mode = fs.ModeSocket | 0o777 }, ReasonUnsafe},
		"socket ACL":   {func(r *RedisFacts) { r.Socket.Socket.ExtACL = true }, ReasonUnsafe},
		"unprotected":  {func(r *RedisFacts) { r.Unprotected, r.Err = true, errors.New("not protected") }, ReasonUnsafe},
		"shared":       {func(r *RedisFacts) { r.Shared = true }, ReasonUnsafe},
		"inherited": {func(r *RedisFacts) {
			r.Inherits = errors.New("redis sentinel backend cannot be identified from config alone")
		}, ReasonUnsafe},
		"inherited down": {func(r *RedisFacts) {
			r.Inherits, r.Socket.Missing = errors.New("redis TLS backend cannot be probed"), true
		}, ReasonUnsafe},
		"version":        {func(r *RedisFacts) { r.Version = "8.0.2" }, ReasonUnsupported},
		"shared unknown": {func(r *RedisFacts) { r.SharedErr = errors.New("dump unreadable") }, ReasonBackendUnavailable},
		"socket missing": {func(r *RedisFacts) { r.Socket.Missing = true }, ReasonBackendUnavailable},
		"probe failed":   {func(r *RedisFacts) { r.Err = errors.New("redis: INFO server failed") }, ReasonBackendUnavailable},
	} {
		t.Run(name, func(t *testing.T) {
			definite := tc.reason != ReasonBackendUnavailable
			for _, stack := range []MailStack{StackExim, StackPostfix} {
				s := learningSettings()
				s.LearningRedisSocket = dedicatedSocket
				f := dedicatedRedisFacts(stack, dedicatedSocket)
				tc.change(&f.Redis)
				var c learningCheck
				checkLearningVersions(&c, f)
				checkLearningRedis(&c, s, f)
				onlyLearningReason(t, c.problems, tc.reason)
				// Nothing installed yet: the worker never writes a worker
				// file naming this Redis.
				if err := CheckLearningRedis(s, f); err == nil {
					t.Fatalf("%v: worker recheck accepted an unchecked new Redis", stack)
				}
				// The installed worker already uses it: only a definite
				// failure stops the worker.
				same := withLearning(t, f, dedicatedSocket)
				if err := CheckLearningRedis(s, same); (err != nil) != definite {
					t.Fatalf("%v: worker recheck on the installed Redis: %v", stack, err)
				}
				if stack != StackExim {
					continue
				}
				// A definite failure removes learning; an outage keeps the
				// installation on the Redis it already uses.
				for installedSocket, installed := range map[string]HostFacts{"": withLearning(t, f, ""), dedicatedSocket: same} {
					got, gate, problems := ResolveLearning(s, installed)
					onlyLearningReason(t, problems, tc.reason)
					if gate.Install == definite || gate.Publish {
						t.Fatalf("installed on %q: gate %+v", installedSocket, gate)
					}
					if !definite && got.LearningRedisSocket != installedSocket {
						t.Fatalf("installed on %q: an outage moved learning to %q", installedSocket, got.LearningRedisSocket)
					}
				}
			}
		})
	}
	s := learningSettings()
	s.LearningRedisSocket = dedicatedSocket
	if err := CheckLearningRedis(s, dedicatedRedisFacts(StackPostfix, dedicatedSocket)); err != nil {
		t.Fatalf("safe dedicated Redis: %v", err)
	}
	f := dedicatedRedisFacts(StackExim, dedicatedSocket)
	f.Redis.Shared = true
	if err := CheckLearningRedis(s, f); err == nil || err.Error() != "the learning Redis is shared with another rspamd module" {
		t.Fatalf("shared Redis: %v", err)
	}
	f = dedicatedRedisFacts(StackExim, dedicatedSocket)
	f.Redis.Inherits = errors.New("redis named-user authentication cannot be probed")
	want := "rspamd's global redis settings would reach the learning Redis: redis named-user authentication cannot be probed"
	if err := CheckLearningRedis(s, f); err == nil || err.Error() != want {
		t.Fatalf("inherited option: %v", err)
	}
}

// withLearning returns f with CSM's learning files installed, and loaded
// as written, for a worker on redisSocket ("" for rspamd's own Redis).
func withLearning(t *testing.T, f HostFacts, redisSocket string) HostFacts {
	t.Helper()
	s := learningSettings()
	s.LearningRedisSocket = redisSocket
	f.Targets = slices.Clone(f.Targets)
	installLearningFor(t, &f, s)
	d := newLoadedDumps(s.LearningKeys)
	if redisSocket != "" {
		d.fuzzyWorker()["servers"], d.fuzzyWorker()["password"] = redisSocket, ""
	}
	d.apply(&f)
	return f
}

// Setting or changing redis_socket moves learning only once the new Redis
// passes every check; meanwhile the installed worker keeps its Redis.
func TestResolveLearningRedisOutageKeepsInstalledTarget(t *testing.T) {
	const old = "/run/redis-old/redis.sock"
	s := learningSettings()
	s.LearningRedisSocket = dedicatedSocket
	for installedSocket, wantOutage := range map[string]string{"": "", old: old, dedicatedSocket: dedicatedSocket} {
		f := withLearning(t, dedicatedRedisFacts(StackExim, dedicatedSocket), installedSocket)
		got, gate, problems := ResolveLearning(s, f)
		if !gate.Install || !gate.Publish || len(problems) != 0 || got.LearningRedisSocket != dedicatedSocket {
			t.Fatalf("verified Redis from %q: socket %q gate %+v problems %+v", installedSocket, got.LearningRedisSocket, gate, problems)
		}
		f.Redis.Socket.Missing = true
		got, gate, problems = ResolveLearning(s, f)
		if !gate.Install || gate.Publish || got.LearningRedisSocket != wantOutage || !got.Learning {
			t.Fatalf("outage from %q: socket %q gate %+v", installedSocket, got.LearningRedisSocket, gate)
		}
		onlyLearningReason(t, problems, ReasonBackendUnavailable)
	}
}
