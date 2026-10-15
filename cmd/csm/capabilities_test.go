package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/health"
)

// The phpanel agent runs `csm capabilities` before rendering newer config
// keys, so it has to answer without a daemon or a readable config.
func TestCapabilitiesCommandPrintsOnePerLine(t *testing.T) {
	var out bytes.Buffer
	if err := writeCapabilities(&out, nil); err != nil {
		t.Fatal(err)
	}
	got := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
	if want := health.Capabilities(); !slices.Equal(got, want) {
		t.Fatalf("lines = %q, want %q", got, want)
	}
}

func TestCapabilitiesCommandJSON(t *testing.T) {
	var out bytes.Buffer
	if err := writeCapabilities(&out, []string{"--config", "/missing/csm.yaml", "--json"}); err != nil {
		t.Fatal(err)
	}
	var got []string
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("output is not a JSON array: %v: %s", err, out.String())
	}
	if want := health.Capabilities(); !slices.Equal(got, want) {
		t.Fatalf("capabilities = %q, want %q", got, want)
	}
}

func TestCapabilitiesCommandRejectsUnknownFlag(t *testing.T) {
	var out bytes.Buffer
	if err := writeCapabilities(&out, []string{"--yaml"}); err == nil {
		t.Fatal("unknown flag must fail")
	}
	if out.Len() != 0 {
		t.Fatalf("nothing may be printed on a usage error, got %q", out.String())
	}
}

func TestCapabilitiesCommandRejectsMissingOptionValues(t *testing.T) {
	for _, flag := range []string{"--config", "--config-dir"} {
		for _, args := range [][]string{{flag}, {flag, ""}, {flag, "--json"}} {
			var out bytes.Buffer
			if err := writeCapabilities(&out, args); err == nil || out.Len() != 0 {
				t.Errorf("args %q: err = %v, output bytes = %d; want usage error without output", args, err, out.Len())
			}
		}
	}
}

func TestCapabilitiesMainIgnoresInvalidConfig(t *testing.T) {
	const childEnv = "CSM_TEST_CAPABILITIES_CONFIG"
	if path := os.Getenv(childEnv); path != "" {
		os.Args = []string{"csm", "capabilities", "--json", "--config", path, "--config-dir", path + ".missing"}
		main()
		os.Exit(0)
	}
	path := filepath.Join(t.TempDir(), "csm.yaml")
	if err := os.WriteFile(path, []byte("hostname: [invalid\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, "-test.run=^"+t.Name()+"$")
	cmd.Env = append(os.Environ(), childEnv+"="+path)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("capabilities with invalid config failed: %v: %s", err, out)
	}
	var caps []string
	if err := json.Unmarshal(out, &caps); err != nil || !slices.Contains(caps, "confd.rehash.fragment.v1") {
		t.Fatalf("capabilities did not return build features: %v", err)
	}
}
