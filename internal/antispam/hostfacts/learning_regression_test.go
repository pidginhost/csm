package hostfacts

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/pidginhost/csm/internal/antispam"
)

func TestLearningUnreadableFacts(t *testing.T) {
	t.Run("CageFS", func(t *testing.T) {
		for _, stage := range []string{"status", "mode"} {
			for _, result := range []antispam.CommandResult{{Err: errors.New("failed")}, {Stdout: "unexpected"}, {}} {
				run := &fakeRun{results: map[string]antispam.CommandResult{
					"cagefsctl --cagefs-status": {Stdout: "Enabled"},
				}}
				command := "cagefsctl --cagefs-status"
				if stage == "mode" {
					command = "cagefsctl --display-user-mode"
				}
				run.results[command] = result
				c, _ := learningCollector(t, run)
				if got := c.cageFS(context.Background()); got.Err == nil || got.Enabled {
					t.Errorf("unknown CageFS %s returned a known state", stage)
				}
			}
		}
	})
	t.Run("UDP", func(t *testing.T) {
		for _, data := range []string{"", "unexpected\n", udpHeader + "truncated\n", udpHeader + "1: invalid 00000000:0000 07\n"} {
			c, _ := learningCollector(t, &fakeRun{})
			write(t, c.layout.ProcNetUDP, data)
			if _, _, err := c.fuzzyListening(979); err == nil {
				t.Errorf("invalid UDP table accepted: %q", data)
			}
		}
	})
	t.Run("PHP", func(t *testing.T) {
		c, _ := learningCollector(t, &fakeRun{})
		mkdir(t, filepath.Dir(c.layout.RoundcubeConfig))
		write(t, c.layout.RoundcubeConfig, "<?php\n")
		if err := os.Symlink(c.layout.CPanelPHP, c.layout.CPanelPHP); err != nil {
			t.Fatal(err)
		}
		f := antispam.HostFacts{Targets: []antispam.TargetFacts{{Target: antispam.Target{Path: antispam.RoundcubeIncludePath}}}}
		if got := c.roundcube(f); got.Err == nil || got.PHP {
			t.Fatal("unreadable PHP returned a known state")
		}
	})
}

func TestLearningDumpsRejectUnreadableSections(t *testing.T) {
	base := map[string]antispam.CommandResult{
		"rspamadm configdump -j fuzzy_check": {Stdout: `{}`},
		"rspamadm configdump -j group":       {Stdout: "{}\n{}\n"},
		"rspamadm configdump -j redis":       {Stdout: `{}`},
	}
	for command := range base {
		for _, bad := range []string{"", "null", "{", "{} trailing", `{"servers":"/a.sock","servers":"/b.sock"}`} {
			c, _ := learningCollector(t, &fakeRun{results: base})
			saved := base[command]
			base[command] = antispam.CommandResult{Stdout: bad}
			f := antispam.HostFacts{RspamdConfig: antispam.CommandResult{Stdout: fuzzyWorkerDump("")}}
			c.learningDumps(context.Background(), &f)
			if f.LearningDumps.Err == nil {
				t.Errorf("%s accepted unreadable output", command)
			}
			base[command] = saved
		}
	}
	c, _ := learningCollector(t, &fakeRun{results: base})
	for _, bad := range []string{"null", `{}`, `{"worker":null}`, `{"worker":7}`, `{"worker":[],"worker":[]}`} {
		f := antispam.HostFacts{RspamdConfig: antispam.CommandResult{Stdout: bad}}
		c.learningDumps(context.Background(), &f)
		if f.LearningDumps.Err == nil {
			t.Error("unreadable worker section accepted")
		}
	}
	f := antispam.HostFacts{RspamdConfig: antispam.CommandResult{Stdout: fuzzyWorkerDump("")}}
	c.learningDumps(context.Background(), &f)
	if f.LearningDumps.Err != nil || string(f.LearningDumps.Group) != base["rspamadm configdump -j group"].Stdout {
		t.Fatal("concatenated group objects were not preserved")
	}
}

func TestControlSocketWhitespaceAndRefresh(t *testing.T) {
	c, d := learningCollector(t, &fakeRun{})
	sock := serve(t, d, pong)
	options, err := json.Marshal(map[string]string{"control_socket": sock + "\tmode=0600"})
	if err != nil {
		t.Fatal(err)
	}
	f := antispam.HostFacts{RspamdOptions: antispam.CommandResult{Stdout: string(options)}}
	c.controlSocket(&f)
	if f.ControlSocket.Err != nil || f.ControlSocket.Missing || f.ControlSocket.Socket.Path != sock {
		t.Fatal("tab-separated socket option did not resolve")
	}
	f.RspamdOptions = antispam.CommandResult{Err: errors.New("failed")}
	c.controlSocket(&f)
	if f.ControlSocket.Err == nil || f.ControlSocket.Socket.Path != "" {
		t.Fatal("failed refresh retained the old socket")
	}
	f.RspamdOptions = antispam.CommandResult{Stdout: `{"control_socket":"` + sock + `","control_socket":"` + sock + `"}`}
	c.controlSocket(&f)
	if f.ControlSocket.Err == nil {
		t.Fatal("duplicate control socket settings accepted")
	}
}

func TestRedisEndpointSelection(t *testing.T) {
	password := rand.Text()
	encoded, err := json.Marshal(password)
	if err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		full, redis, want string
		password          bool
	}{
		"before install":          {`{"worker":[{"normal":{}}]}`, `{"servers":"/r.sock"}`, "/r.sock", false},
		"keyed worker":            {`{"worker":{"fuzzy":{"servers":"/r.sock"}}}`, `{}`, "/r.sock", false},
		"typed worker":            {`{"worker":[{"type":"fuzzy","servers":"/r.sock"}]}`, `{}`, "/r.sock", false},
		"typed name collision":    {`{"worker":[{"type":"normal","fuzzy":{"servers":"/other.sock"}}]}`, `{"servers":"/r.sock"}`, "/r.sock", false},
		"specific inherited auth": {fuzzyWorkerDump(""), `{"fuzzy":{"servers":"/fuzzy.sock"},"password":` + string(encoded) + `}`, "/fuzzy.sock", true},
		"fuzzy override":          {fuzzyWorkerDump(""), `{"servers":"/other.sock","fuzzy":{"servers":"/fuzzy.sock"}}`, "/fuzzy.sock", false},
		"storage alias":           {fuzzyWorkerDump(""), `{"servers":"/other.sock","fuzzy_storage":{"servers":"/fuzzy.sock"}}`, "/fuzzy.sock", false},
		"inherited auth":          {fuzzyWorkerDump(`,"servers":"/fuzzy.sock"`), `{"servers":"/other.sock","password":` + string(encoded) + `}`, "/fuzzy.sock", true},
		"singular server":         {fuzzyWorkerDump(`,"server":"/fuzzy.sock"`), `{"servers":"/other.sock"}`, "/fuzzy.sock", false},
		"array server":            {fuzzyWorkerDump(""), `{"servers":["/fuzzy.sock"]}`, "/fuzzy.sock", false},
		"default port":            {fuzzyWorkerDump(""), `{"servers":"192.0.2.1"}`, "192.0.2.1:6379", false},
		"read precedence":         {fuzzyWorkerDump(""), `{"servers":"/unused.sock","read_servers":"/fuzzy.sock","write_servers":"/fuzzy.sock"}`, "/fuzzy.sock", false},
	} {
		t.Run(name, func(t *testing.T) {
			endpoint, _, secret, err := redisEndpoint(antispam.LearningDumps{Redis: []byte(tc.redis)}, []byte(tc.full))
			if err != nil || endpoint != tc.want || (secret.Reveal() == password) != tc.password {
				t.Fatalf("wrong backend selection: endpoint=%q err=%v", endpoint, err)
			}
		})
	}
}

func TestRedisEndpointRejectsAmbiguity(t *testing.T) {
	for _, full := range []string{
		`null`, `{}`, `{"worker":null}`, `{"worker":[null]}`, `{"worker":[{"fuzzy":null}]}`,
		`{"worker":[{"fuzzy":7}]}`, `{"worker":[{"fuzzy":{}},{"fuzzy":{}}]}`,
		`{"worker":[{"type":""}]}`, `{"worker":[{"type":"\u0000"}]}`,
		`{"worker":[{"fuzzy":{},"fuzzy":{}}]}`, `{"worker":[],"worker":[]}`,
	} {
		if _, _, _, err := redisEndpoint(antispam.LearningDumps{Redis: []byte(`{"servers":"/r.sock"}`)}, []byte(full)); err == nil {
			t.Error("ambiguous worker used the global Redis backend")
		}
	}
	for _, config := range []string{
		`{"servers":"/r.sock","password":null}`,
		`{"servers":"/r.sock","fuzzy":null}`,
		`{"servers":"/r.sock","fuzzy":{}}`,
		`{"servers":"/r.sock","sentinels":"192.0.2.1:26379"}`,
		`{"servers":"/r.sock","username":"service"}`,
		`{"servers":"/r.sock","ssl":true}`,
		`{"servers":"/a.sock","servers":"/b.sock"}`,
		`{"fuzzy":{"servers":"/a.sock","servers":"/b.sock"}}`,
	} {
		if _, _, _, err := redisEndpoint(antispam.LearningDumps{Redis: []byte(config)}, []byte(fuzzyWorkerDump(""))); err == nil {
			t.Error("unsupported Redis configuration was silently ignored")
		}
	}
}

func TestRedisUnknownGroupMembership(t *testing.T) {
	c, d := learningCollector(t, &fakeRun{})
	sock := serve(t, d, pong)
	f := antispam.HostFacts{
		LearningDumps: antispam.LearningDumps{Redis: []byte(`{"servers":"` + sock + `"}`)},
		RspamdConfig:  antispam.CommandResult{Stdout: fuzzyWorkerDump("")},
	}
	c.readGroup = func() ([]byte, error) { return nil, errors.New("unreadable") }
	if got := c.redis(context.Background(), f); got.Err == nil {
		t.Fatal("unknown Redis group membership returned no error")
	}
}
