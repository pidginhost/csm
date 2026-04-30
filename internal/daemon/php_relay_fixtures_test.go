package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/emailspool"
	"gopkg.in/yaml.v3"
)

type expectFile struct {
	Fixture     string   `yaml:"fixture"`
	MustFire    []string `yaml:"must_fire"`
	MustNotFire []string `yaml:"must_not_fire"`
	Notes       string   `yaml:"notes"`
}

func TestFixtureExpectations(t *testing.T) {
	dir := "testdata/php_relay"
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".H") {
			continue
		}
		name := e.Name()
		t.Run(name, func(t *testing.T) {
			expectPath := filepath.Join(dir, name+".expect.yaml")
			if _, err := os.Stat(expectPath); err != nil {
				// .H without sibling .expect.yaml: derive from base.
				expectPath = filepath.Join(dir, strings.TrimSuffix(name, ".H")+".expect.yaml")
			}
			expBytes, err := os.ReadFile(expectPath)
			if err != nil {
				t.Skipf("no .expect.yaml for %s", name)
			}
			var exp expectFile
			if uerr := yaml.Unmarshal(expBytes, &exp); uerr != nil {
				t.Fatal(uerr)
			}

			cfg := defaultPHPRelayCfg()
			cfg.EmailProtection.PHPRelay.HeaderScoreVolumeMin = 1 // tight; one event triggers
			psw := newPerScriptWindow()
			pip := newPerIPWindow(64)
			pacct := newPerAccountWindow(5000)
			eng := newEvaluator(psw, pip, pacct, cfg, nil)

			udir := t.TempDir()
			if mkerr := os.MkdirAll(filepath.Join(udir, "exampleuser"), 0o755); mkerr != nil {
				t.Fatal(mkerr)
			}
			ud, uderr := os.ReadFile(filepath.Join(dir, "userdata_account_with_domains.yaml"))
			if uderr != nil {
				t.Fatal(uderr)
			}
			if werr := os.WriteFile(filepath.Join(udir, "exampleuser", "main"), ud, 0o644); werr != nil {
				t.Fatal(werr)
			}
			domains := newUserDomainsResolverWithRoot(udir, time.Hour)
			pol := newTestPolicies(t)
			eng.SetPolicies(pol)

			h, err := emailspool.ParseHeaders(filepath.Join(dir, name))
			if err != nil {
				t.Fatal(err)
			}
			if h.XPHPScript == "" {
				// Short-circuit fixture (e.g., legit_mailchimp_forwarder).
				assertFire(t, exp, nil)
				return
			}
			auth, _ := domains.Domains(h.EnvelopeUser)
			sig := computeSignals(h, auth, pol)
			psw.getOrCreate(sig.ScriptKey).append(scriptEvent{
				At:               time.Now(),
				MsgID:            "fixture",
				FromMismatch:     sig.FromMismatch,
				AdditionalSignal: sig.AdditionalSignal,
				SourceIP:         sig.SourceIP,
			})
			findings := eng.evaluatePaths(sig.ScriptKey, sig.SourceIP, h.EnvelopeUser, time.Now())
			assertFire(t, exp, findings)
		})
	}
}

func assertFire(t *testing.T, exp expectFile, findings []alert.Finding) {
	t.Helper()
	fired := make(map[string]bool)
	for _, f := range findings {
		fired["path"+pathToNum(f.Path)] = true
	}
	for _, expected := range exp.MustFire {
		if !fired[expected] {
			t.Errorf("must_fire: %s did not fire (got %+v)", expected, findings)
		}
	}
	for _, forbid := range exp.MustNotFire {
		if fired[forbid] {
			t.Errorf("must_not_fire: %s fired (got %+v)", forbid, findings)
		}
	}
}

func pathToNum(p string) string {
	switch p {
	case "header":
		return "1"
	case "volume":
		return "2"
	case "volume_account":
		return "2b"
	case "fanout":
		return "4"
	case "baseline":
		return "5"
	case "reputation":
		return "3"
	}
	return p
}
