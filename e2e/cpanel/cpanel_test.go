//go:build linux && integration

package cpanel

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/health"
	"github.com/pidginhost/csm/internal/platform"
)

func run(t *testing.T, name string, args ...string) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s failed: %v\n%s", name, err, output)
	}
	return output
}

func TestCandidateCPanelPlatform(t *testing.T) {
	info := platform.DetectFresh()
	if !info.IsCPanel() || !info.IsRHELFamily() || platform.DetectMTA() != platform.MTAExim {
		t.Fatalf("wrong integration platform: %+v", info)
	}
	for _, path := range []string{info.ApacheCompatibleConfigDir(), info.MailLogPath()} {
		if path == "" {
			t.Fatal("platform returned an empty path")
		}
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("platform path %s unavailable: %v", path, err)
		}
	}
	run(t, "systemctl", "is-active", "--quiet", "exim.service", "dovecot.service")
	run(t, "exim", "-bV")
	run(t, "doveconf", "-n")
}

func TestCandidateWHMPlugin(t *testing.T) {
	const cgi = "/usr/local/cpanel/whostmgr/docroot/cgi/addon_csm.cgi"
	info, err := os.Stat(cgi)
	if err != nil || info.Mode().Perm()&0111 == 0 {
		t.Fatalf("WHM CGI unavailable: %v", err)
	}
	app, err := os.ReadFile("/var/cpanel/apps/csm.conf")
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"name=csm", "service=whostmgr", "url=/cgi/addon_csm.cgi"} {
		if !strings.Contains(string(app), field+"\n") {
			t.Fatalf("WHM registration missing %q", field)
		}
	}
	var registered struct {
		Metadata struct {
			Result int `json:"result"`
		} `json:"metadata"`
		Data struct {
			WHM []struct {
				Name        string   `json:"name"`
				URL         string   `json:"url"`
				DisplayName string   `json:"displayname"`
				ACLs        []string `json:"acls"`
			} `json:"whostmgr"`
		} `json:"data"`
	}
	if err = json.Unmarshal(run(t, "/usr/local/cpanel/bin/whmapi1", "--output=json", "get_appconfig_application_list"), &registered); err != nil {
		t.Fatal(err)
	}
	if registered.Metadata.Result != 1 {
		t.Fatal("WHM could not list registered applications")
	}
	matched := 0
	for _, app := range registered.Data.WHM {
		if app.Name == "csm" {
			matched++
			if app.URL != "/cgi/addon_csm.cgi" || app.DisplayName != "CSM Security Monitor" || !slices.Contains(app.ACLs, "all") {
				t.Fatalf("incorrect registered CSM app: %+v", app)
			}
		}
	}
	if matched != 1 {
		t.Fatalf("WHM lists %d CSM registrations, want 1", matched)
	}
	output := run(t, cgi)
	cfg, err := config.Load("/etc/csm/csm.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(output), "Status: 302 Found") || !strings.Contains(string(output), "Location: https://"+cfg.Hostname+":") || !strings.Contains(string(output), "/dashboard") {
		t.Fatalf("WHM redirect incorrect: %s", output)
	}
}

func TestCandidateServiceAndMailWatcher(t *testing.T) {
	for property, want := range map[string]string{"Type": "notify", "ProtectSystem": "strict", "Result": "success"} {
		if got := strings.TrimSpace(string(run(t, "systemctl", "show", "csm.service", "--property="+property, "--value"))); got != want {
			t.Fatalf("%s=%q want=%q", property, got, want)
		}
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(run(t, "systemctl", "show", "csm.service", "--property=MainPID", "--value"))))
	if err != nil || pid <= 1 {
		t.Fatalf("daemon PID=%d error=%v", pid, err)
	}
	var snapshot health.Snapshot
	if err := json.Unmarshal(run(t, "/opt/csm/csm", "status", "--json"), &snapshot); err != nil {
		t.Fatal(err)
	}
	if !snapshot.StoreHealthy || snapshot.StartedAt.IsZero() || !snapshot.Watchers["maillog"] {
		t.Fatalf("candidate daemon or mail watcher unhealthy: %+v", snapshot)
	}
	t.Logf("candidate version=%s, daemon PID=%d, attached mail watcher, healthy state", snapshot.Version, pid)
}
