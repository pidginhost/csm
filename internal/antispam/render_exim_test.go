package antispam

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The golden files are the hook text verified on a cPanel 11.138 / Exim
// 4.100.1 scratch host (spike 1a). Change them only with new host evidence.
func golden(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name)) // #nosec G304 -- fixed test fixture names
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func defaults(dryRun bool) Settings {
	return Settings{DryRun: dryRun, Socket: DefaultSocket, RejectScore: DefaultRejectScore, TagScore: DefaultTagScore}
}

func TestRenderEximMatchesVerifiedGoldens(t *testing.T) {
	for _, tc := range []struct {
		mode   string
		dryRun bool
	}{{"enforce", false}, {"dryrun", true}} {
		t.Run(tc.mode, func(t *testing.T) {
			h, err := RenderExim(defaults(tc.dryRun))
			if err != nil {
				t.Fatal(err)
			}
			for name, got := range map[string]string{"rcpt": h.RCPT, "scan": h.Scan, "post": h.Post} {
				if want := golden(t, name+"_"+tc.mode+".golden"); got != want {
					t.Errorf("%s %s differs from golden:\n--- got ---\n%s--- want ---\n%s", name, tc.mode, got, want)
				}
			}
		})
	}
}

func TestRenderEximConfigBlock(t *testing.T) {
	h, err := RenderExim(defaults(false))
	if err != nil {
		t.Fatal(err)
	}
	want := "# CSM-ANTISPAM BEGIN\nspamd_address = /run/rspamd/csm-normal.sock variant=rspamd tmo=30s\n# CSM-ANTISPAM END\n"
	if h.Config != want {
		t.Errorf("config block = %q, want %q", h.Config, want)
	}
}

func TestRenderEximUsesConfiguredThresholds(t *testing.T) {
	s := defaults(false)
	s.RejectScore, s.TagScore = 20, 8
	h, err := RenderExim(s)
	if err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{h.Scan, h.Post} {
		if !strings.Contains(text, ">={$acl_m_csm_score}{200}") || !strings.Contains(text, ">={$acl_m_csm_score}{80}") {
			t.Errorf("thresholds 200/80 missing:\n%s", text)
		}
		if strings.Contains(text, "{150}") || strings.Contains(text, "{60}") {
			t.Errorf("default thresholds leaked:\n%s", text)
		}
	}
}

func TestRenderEximRejectsInvalidSettings(t *testing.T) {
	for _, s := range []Settings{
		{Socket: "/run/x.sock variant=x", RejectScore: 15, TagScore: 6},
		{Socket: DefaultSocket, RejectScore: 6, TagScore: 15},
	} {
		if _, err := RenderExim(s); err == nil {
			t.Errorf("RenderExim(%+v) = nil error", s)
		}
	}
}
