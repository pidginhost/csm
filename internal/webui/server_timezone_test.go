package webui

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

func withTimeZoneSources(t *testing.T, env, zoneFile, localtimeLink string) {
	t.Helper()
	oldEnv, oldRead, oldLink := timeZoneEnv, readTimeZoneFile, readLocaltimeLink
	t.Cleanup(func() { timeZoneEnv, readTimeZoneFile, readLocaltimeLink = oldEnv, oldRead, oldLink })
	timeZoneEnv = func() string { return env }
	readTimeZoneFile = func() ([]byte, error) {
		if zoneFile == "" {
			return nil, os.ErrNotExist
		}
		return []byte(zoneFile + "\n"), nil
	}
	readLocaltimeLink = func() (string, error) {
		if localtimeLink == "" {
			return "", errors.New("not a link")
		}
		return localtimeLink, nil
	}
}

// The browser can only show "server time" if it knows the server's zone by
// name; Go reports the local zone as "Local".
func TestServerTimeZoneName(t *testing.T) {
	cases := []struct {
		name, env, file, link, want string
	}{
		{"TZ variable", "Europe/Bucharest", "", "", "Europe/Bucharest"},
		{"TZ with colon", ":America/Chicago", "", "", "America/Chicago"},
		{"etc timezone", "", "Asia/Tokyo", "", "Asia/Tokyo"},
		{"localtime link", "", "", "/usr/share/zoneinfo/America/New_York", "America/New_York"},
		{"relative link", "", "", "../usr/share/zoneinfo/Europe/Paris", "Europe/Paris"},
		{"invalid names are ignored", "Not/AZone", "also bad", "/usr/share/zoneinfo/Nope/Nope", ""},
		{"nothing known", "", "", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withTimeZoneSources(t, tc.env, tc.file, tc.link)
			if got := serverTimeZoneName(); got != tc.want {
				t.Fatalf("serverTimeZoneName() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestLayoutTellsTheBrowserTheServerTimeZone(t *testing.T) {
	withTimeZoneSources(t, "Europe/Bucharest", "", "")
	uiDir, err := filepath.Abs("../../ui")
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{StatePath: t.TempDir()}
	cfg.WebUI.UIDir = uiDir
	cfg.WebUI.Tokens = []config.WebUIToken{{Name: "ops", Token: "tok", Scope: "admin"}}
	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	s, err := New(cfg, st)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	s.handleHardening(w, httptest.NewRequest(http.MethodGet, "/hardening", nil))
	body := w.Body.String()
	if !strings.Contains(body, `data-csm-server-tz="Europe/Bucharest"`) {
		t.Fatalf("layout does not carry the server zone name:\n%s", body[:min(len(body), 600)])
	}
	if !strings.Contains(body, `data-csm-server-offset="`) {
		t.Fatal("layout does not carry the server UTC offset fallback")
	}
}
