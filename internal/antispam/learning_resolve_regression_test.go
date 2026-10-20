package antispam

import (
	"errors"
	"io/fs"
	"math/big"
	"testing"
)

func TestResolveLearningIsolationRegressions(t *testing.T) {
	for name, change := range map[string]func(*HostFacts){
		"log group contains tenant": func(f *HostFacts) {
			f.ControllerHost.GroupMembers[testRspamdGID] = []string{"_rspamd", "alpha"}
		},
		"log group unknown": func(f *HostFacts) {
			delete(f.ControllerHost.GroupMembers, testRspamdGID)
		},
		"log root group contains tenant": func(f *HostFacts) {
			f.RspamdLog.File.GID, f.RspamdLog.Parents[3].GID = 0, 0
			f.ControllerHost.GroupMembers[0] = []string{"root", "alpha"}
		},
		"CageFS does not isolate syslog": func(f *HostFacts) {
			f.RspamdLog.Type = "syslog"
			f.CageFS = CageFSFacts{Enabled: true, ExcludedLogDir: "/var/log/rspamd"}
		},
		"CageFS does not isolate custom log": func(f *HostFacts) {
			f.RspamdLog.Path, f.RspamdLog.File.Path = "/var/log/other.log", "/var/log/other.log"
			f.RspamdLog.Parents = f.RspamdLog.Parents[:3]
			f.RspamdLog.File.Mode = 0o644
			f.CageFS = CageFSFacts{Enabled: true, ExcludedLogDir: "/var/log/rspamd"}
		},
		"controller error cannot hide unsafe control socket": func(f *HostFacts) {
			f.ControllerErr = errors.New("interface lookup failed")
			f.ControlSocket.Socket.Mode = fs.ModeSocket | 0o666
		},
		"address probe error cannot hide open controller": func(f *HostFacts) {
			f.ControllerErr = errors.New("interface lookup failed")
			f.Controller.PasswordSet = false
		},
		"private controller with ACL": func(f *HostFacts) {
			s := f.ControllerHost.Sockets[privateController]
			s.Parents[2].Mode = fs.ModeDir | 0o700
			s.Socket.ExtACL = true
			f.ControllerHost.Sockets[privateController] = s
		},
		"private controller through symlink detour": func(f *HostFacts) {
			s := f.ControllerHost.Sockets[privateController]
			s.Parents = append(s.Parents, dir("/run/alias", 0, 0, 0o755))
			f.ControllerHost.Sockets[privateController] = s
		},
		"Redis error cannot hide TCP listener": func(f *HostFacts) {
			f.Redis.Err = errors.New("INFO memory failed")
			f.Redis.Port = "6379"
		},
		"Redis error cannot hide eviction": func(f *HostFacts) {
			f.Redis.Err = errors.New("INFO memory failed")
			f.Redis.Policy = "allkeys-lru"
		},
		"Redis TLS listener": func(f *HostFacts) { f.Redis.TLSPort = "6380" },
		"Redis group permits shared tenant service": func(f *HostFacts) {
			f.Redis.GroupMembers = []string{"redis", "nobody"}
		},
		"Redis error cannot hide unlimited memory": func(f *HostFacts) {
			f.Redis.MaxMemory, f.Redis.MaxMemoryKnown = 0, true
			f.Redis.Err = errors.New("INFO memory failed")
		},
	} {
		t.Run(name, func(t *testing.T) {
			for _, installed := range []bool{false, true} {
				f := safeLearningFacts()
				if installed {
					installLearning(t, &f)
				}
				change(&f)
				s, gate, problems := ResolveLearning(learningSettings(), f)
				if gate != (LearningGate{}) || s.Learning || s.Roundcube {
					t.Fatalf("installed=%v: unsafe learning allowed: gate=%+v", installed, gate)
				}
				found := false
				for _, p := range problems {
					if p.Severity != Warning || p.Code != CodeLearning {
						t.Fatalf("learning must not block core: %+v", p)
					}
					found = found || p.Key == ReasonUnsafe
				}
				if !found {
					t.Fatalf("missing unsafe warning: %+v", problems)
				}
			}
		})
	}
}

func TestResolveLearningTemporaryRegressions(t *testing.T) {
	for name, change := range map[string]func(*HostFacts){
		"unreadable version":    func(f *HostFacts) { f.RspamdVersion.Stdout = "" },
		"unknown Redis version": func(f *HostFacts) { f.Redis.Version = "" },
		"CageFS cannot hide unreadable log": func(f *HostFacts) {
			f.RspamdLog.Err = errors.New("log discovery failed")
			f.CageFS = CageFSFacts{Enabled: true, ExcludedLogDir: "/var/log/rspamd"}
		},
		"unknown rspamd user": func(f *HostFacts) {
			f.ControllerHost.RspamdUID = -1
		},
		"controller socket temporarily absent": func(f *HostFacts) {
			f.ControllerHost.Sockets[privateController] = SocketFacts{Missing: true}
		},
		"controller socket stat failed": func(f *HostFacts) {
			f.ControllerHost.Sockets[privateController] = SocketFacts{Err: errors.New("stat failed")}
		},
	} {
		t.Run(name, func(t *testing.T) {
			for _, installed := range []bool{false, true} {
				f := safeLearningFacts()
				if installed {
					installLearning(t, &f)
				}
				change(&f)
				s, gate, problems := ResolveLearning(learningSettings(), f)
				if gate.Install != installed || s.Learning != installed || gate.Publish {
					t.Fatalf("installed=%v: gate=%+v", installed, gate)
				}
				onlyLearningReason(t, problems, ReasonBackendUnavailable)
			}
		})
	}
}

func TestFuzzyWorkerEnabledSupportedForms(t *testing.T) {
	for name, tc := range map[string]struct {
		dump string
		want bool
	}{
		"absent":                        {"", false},
		"empty list":                    {`[]`, false},
		"empty object":                  {`{}`, false},
		"keyed enabled":                 {`{"fuzzy":{"count":1}}`, true},
		"typed enabled":                 {`[{"type":"fuzzy","count":1}]`, true},
		"disabled then enabled":         {`[{"fuzzy":{"count":-1}},{"fuzzy":{"count":1}}]`, true},
		"disabled boolean":              {`{"fuzzy":{"enabled":false}}`, false},
		"disabled numeric":              {`{"fuzzy":{"enabled":0}}`, false},
		"typed normal with fuzzy field": {`[{"type":"normal","fuzzy":{"count":1}}]`, false},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := fuzzyWorkerEnabled([]byte(tc.dump))
			if err != nil || got != tc.want {
				t.Fatalf("enabled=%v err=%v, want %v", got, err, tc.want)
			}
		})
	}
}

func TestResolveLearningFuzzyConflictParsing(t *testing.T) {
	for name, tc := range map[string]struct{ rules, workers string }{
		"duplicate rule sections":      {rules: `{"rule":{"ops":{}},"rule":{"rspamd.com":{}}}`},
		"duplicate workers":            {workers: `{"fuzzy":{"count":1},"fuzzy":{"count":-1}}`},
		"duplicate counts":             {workers: `{"fuzzy":{"count":1,"count":-1}}`},
		"typed fuzzy with named field": {workers: `[{"type":"fuzzy","count":1,"fuzzy":{"count":-1}}]`},
		"unknown worker type":          {workers: `[{"type":null,"count":1}]`},
		"null worker section":          {workers: `null`},
		"null worker entry":            {workers: `[null]`},
		"null fuzzy rules":             {rules: `null`},
		"null rule map":                {rules: `{"rule":null}`},
	} {
		t.Run(name, func(t *testing.T) {
			f := safeLearningFacts()
			if tc.rules != "" {
				f.LearningDumps.FuzzyCheck = []byte(tc.rules)
			}
			if tc.workers != "" {
				f.LearningDumps.Worker = []byte(tc.workers)
			}
			_, gate, problems := ResolveLearning(learningSettings(), f)
			if gate != (LearningGate{}) {
				t.Fatalf("unverified fuzzy configuration accepted: %+v", gate)
			}
			onlyLearningReason(t, problems, ReasonConfigConflict)
		})
	}
}

func TestRedisGuardExactBoundaries(t *testing.T) {
	for _, max := range []uint64{1, 3, 7, 10, 1000, 1 << 53, 1 << 62, ^uint64(0)} {
		for _, paused := range []bool{false, true} {
			percent := uint64(75)
			if paused {
				percent = 70
			}
			limit := new(big.Int).Mul(new(big.Int).SetUint64(max), new(big.Int).SetUint64(percent))
			floor := new(big.Int).Div(new(big.Int).Set(limit), big.NewInt(100)).Uint64()
			for _, used := range []uint64{0, floor, floor + 1, max} {
				want := new(big.Int).Mul(new(big.Int).SetUint64(used), big.NewInt(100)).Cmp(limit) >= 0
				if got := RedisGuard(used, max, paused); got != want {
					t.Errorf("used=%d max=%d paused=%v: got %v, want %v", used, max, paused, got, want)
				}
			}
			if floor > 0 && RedisGuard(floor-1, max, paused) {
				t.Errorf("paused below boundary: used=%d max=%d paused=%v", floor-1, max, paused)
			}
		}
	}
}
