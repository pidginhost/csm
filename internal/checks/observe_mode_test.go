package checks

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/platform"
)

func TestObserveModeWAFReportsWithoutUpdatingHost(t *testing.T) {
	for _, mode := range []string{config.ModeObserve, config.ModeEnforce} {
		t.Run(mode, func(t *testing.T) {
			platform.ResetForTest()
			t.Cleanup(platform.ResetForTest)
			platform.SetOverrides(platform.Overrides{Panel: ptrPanel(platform.PanelCPanel), WebServer: ptrWebServer(platform.WSApache), ApacheConfigDir: "/etc/apache2"})
			dest := vpTestOperator
			fs := setupVPTestFS(t, vpTestSrcV1, &dest)
			fs.files["/etc/apache2/conf.d/modsec2.conf"] = "SecRuleEngine DetectionOnly\n"
			vendorDir := wafVendorDir(t, t.TempDir(), "vendor", 60*24*time.Hour)
			mock := osFS.(*mockOS)
			mock.readDir = func(path string) ([]os.DirEntry, error) {
				if path == vendorDir {
					return os.ReadDir(path)
				}
				return nil, os.ErrNotExist
			}
			enginePath := filepath.Join(t.TempDir(), "engine.conf")
			if err := os.WriteFile(enginePath, []byte("SecRuleEngine DetectionOnly\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			mock.open = func(path string) (*os.File, error) {
				if path == "/etc/apache2/conf.d/modsec2.conf" {
					return os.Open(enginePath)
				}
				return nil, os.ErrNotExist
			}
			updates := 0
			withMockCmd(t, &mockCmd{run: func(name string, args ...string) ([]byte, error) {
				if name != "whmapi1" || len(args) == 0 {
					return nil, os.ErrNotExist
				}
				switch args[0] {
				case "modsec_get_configs":
					return []byte(`{"metadata":{"result":1},"data":{"configs":[{"active":1,"vendor_id":"vendor"}]}}`), nil
				case "modsec_get_vendors":
					if len(args) == 1 {
						return []byte("vendor_id: vendor\n"), nil
					}
					return []byte(fmt.Sprintf(`{"metadata":{"result":1},"data":{"vendors":[{"vendor_id":"vendor","path":%q}]}}`, vendorDir)), nil
				case "modsec_update_vendor":
					updates++
					return []byte("result: 1\n"), nil
				}
				return nil, os.ErrNotExist
			}})
			findings := CheckWAFStatus(context.Background(), &config.Config{Mode: mode}, nil)
			seen := map[string]int{}
			for _, f := range findings {
				seen[f.Check]++
			}
			if seen["waf_detection_only"] != 1 || seen["waf_rules_stale"] != 1 {
				t.Fatalf("detection lost: %+v", findings)
			}
			want := 0
			if mode == config.ModeEnforce {
				want = 1
			}
			if fs.writes != want || updates != want {
				t.Fatalf("host writes/vendor updates = %d/%d, want %d/%d", fs.writes, updates, want, want)
			}
			if mode == config.ModeObserve && fs.files[vpTestDest] != dest {
				t.Fatal("operator WAF config changed")
			}
		})
	}
}

// The AF_ALG mitigation re-applies itself by unloading kernel modules, which
// is a host change. Observe mode stops it at the call site rather than through
// a config conflict: enforcement is a no-op until an operator opts in with
// `csm harden --copy-fail`, so demanding every observe host also set
// auto_response.disable_enforce_af_alg would make the posture two settings
// instead of one, keyed on an inverted name.
func TestObserveModeSkipsAFAlgEnforcement(t *testing.T) {
	calls := 0
	orig := enforceAFAlgBlockedFn
	t.Cleanup(func() { enforceAFAlgBlockedFn = orig })
	enforceAFAlgBlockedFn = func() (EnforceResult, error) {
		calls++
		return EnforceResult{Action: EnforceActionNoop}, nil
	}

	if findings := CheckAFAlgEnforcement(context.Background(), &config.Config{Mode: config.ModeObserve}, nil); findings != nil {
		t.Fatalf("observe mode emitted enforcement findings: %+v", findings)
	}
	if calls != 0 {
		t.Fatalf("observe mode ran AF_ALG enforcement %d times", calls)
	}

	CheckAFAlgEnforcement(context.Background(), &config.Config{Mode: config.ModeEnforce}, nil)
	if calls != 1 {
		t.Fatalf("enforce mode ran AF_ALG enforcement %d times, want 1", calls)
	}
}
