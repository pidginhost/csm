package webserver

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

func TestInstallSocketSettings(t *testing.T) {
	for _, tc := range []struct {
		name, addr, group, wantError string
	}{
		{name: "valid", addr: config.ChallengeSocketExample, group: "proxy"},
		{name: "normalized", addr: " UNIX:/run/csm/challenge.sock ", group: " proxy "},
		{name: "empty path", addr: "unix:", group: "proxy", wantError: "absolute"},
		{name: "relative path", addr: "unix:challenge.sock", group: "proxy", wantError: "absolute"},
		{name: "empty group", addr: config.ChallengeSocketExample, wantError: "challenge.listen_group"},
		{name: "blank group", addr: config.ChallengeSocketExample, group: " \t ", wantError: "challenge.listen_group"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := &fakeHandler{kind: "apache", body: "url={{ .ChallengePublicURL }}\n"}
			i := newTestInstaller(t, h)
			cfg := &config.Config{}
			cfg.Challenge.ListenAddr = tc.addr
			cfg.Challenge.ListenGroup = tc.group
			cfg.Challenge.PublicURL = "https://challenge.example.com/challenge"
			rc := RenderConfigFromConfig(cfg)
			rc.ChallengeMapPath = i.Config.ChallengeMapPath
			rc.ChallengeNginxMapPath = i.Config.ChallengeNginxMapPath
			i.Config = rc

			res, err := i.Install()
			if tc.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantError) {
					t.Fatalf("Install error = %v, want %q", err, tc.wantError)
				}
				if res.Status != "fail" || res.Message != err.Error() {
					t.Fatalf("result = %+v, want fail with the validation error", res)
				}
				for _, path := range []string{h.path, rc.ChallengeMapPath, rc.ChallengeNginxMapPath} {
					if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
						t.Errorf("invalid socket settings created %s: %v", path, statErr)
					}
				}
				if h.validates.Load() != 0 || h.reloads.Load() != 0 {
					t.Fatal("invalid socket settings changed the webserver")
				}
				return
			}
			if err != nil || res.Status != "ok" {
				t.Fatalf("Install = %+v, %v, want success", res, err)
			}
			if h.validates.Load() != 1 || h.reloads.Load() != 1 {
				t.Fatalf("validate/reload counts = %d/%d, want 1/1", h.validates.Load(), h.reloads.Load())
			}
			body, err := os.ReadFile(h.path)
			if err != nil || !strings.Contains(string(body), "url="+cfg.Challenge.PublicURL) {
				t.Fatalf("installed snippet = %q, %v, want the public redirect URL", body, err)
			}
		})
	}
}

func TestInstallRejectsUnsafeSocketPath(t *testing.T) {
	pinInstallerHost(t)
	for _, addr := range []string{"unix:/run/csm//challenge.sock", "unix:/" + strings.Repeat("d", 95) + "/c"} {
		h := &fakeHandler{kind: "apache", body: "body\n"}
		i := newTestInstaller(t, h)
		i.Config.ChallengeListenAddr = addr
		i.Config.ChallengeListenGroup = "nginx"
		i.Config.ChallengePublicURL = "https://challenge.example.com/challenge"
		if _, err := i.Install(); err == nil {
			t.Fatalf("%q: install accepted a path the server refuses", addr)
		}
		if h.validates.Load() != 0 || h.reloads.Load() != 0 {
			t.Fatalf("%q: refused install touched the webserver", addr)
		}
	}
}
