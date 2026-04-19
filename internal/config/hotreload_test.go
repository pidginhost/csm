package config

import (
	"reflect"
	"sync"
	"testing"
)

func TestActiveRoundTrip(t *testing.T) {
	t.Cleanup(func() { SetActive(nil) })

	if Active() != nil {
		SetActive(nil)
	}

	cfg := &Config{Hostname: "probe"}
	SetActive(cfg)
	if got := Active(); got != cfg {
		t.Errorf("Active: got %p, want %p", got, cfg)
	}
	SetActive(nil)
	if got := Active(); got != nil {
		t.Errorf("Active after nil SetActive: got %+v, want nil", got)
	}
}

func TestActiveIsConcurrentSafe(t *testing.T) {
	t.Cleanup(func() { SetActive(nil) })

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				cfg := &Config{Hostname: "w"}
				SetActive(cfg)
				_ = Active()
			}
		}()
	}
	wg.Wait()
}

func TestDiffNoChange(t *testing.T) {
	a := &Config{Hostname: "h1"}
	b := &Config{Hostname: "h1"}
	if got := Diff(a, b); len(got) != 0 {
		t.Errorf("empty diff expected, got %+v", got)
	}
}

func TestDiffRestartField(t *testing.T) {
	// Hostname has no hotreload tag -> treated as restart.
	a := &Config{Hostname: "h1"}
	b := &Config{Hostname: "h2"}
	changes := Diff(a, b)
	if len(changes) != 1 {
		t.Fatalf("want 1 change, got %+v", changes)
	}
	if changes[0].Field != "hostname" {
		t.Errorf("yaml name: got %q want hostname", changes[0].Field)
	}
	if changes[0].Tag == TagSafe {
		t.Errorf("untagged field must not be classified safe")
	}
	if !RestartRequired(changes) {
		t.Error("RestartRequired should be true for an untagged change")
	}
}

func TestDiffSafeField(t *testing.T) {
	// Thresholds is tagged hotreload:"safe". Changing a nested key
	// inside it bubbles up to the parent as a single safe change.
	a := &Config{}
	a.Thresholds.MailQueueWarn = 100
	b := &Config{}
	b.Thresholds.MailQueueWarn = 200

	changes := Diff(a, b)
	if len(changes) != 1 {
		t.Fatalf("want 1 change, got %+v", changes)
	}
	if changes[0].Field != "thresholds" {
		t.Errorf("field: got %q want thresholds", changes[0].Field)
	}
	if changes[0].Tag != TagSafe {
		t.Errorf("tag: got %q want %q", changes[0].Tag, TagSafe)
	}
	if RestartRequired(changes) {
		t.Error("RestartRequired should be false when only safe fields change")
	}
}

// TestDiffAllSafeFieldsClassifiedSafe nails down which top-level
// fields are hot-reloadable today. If a future refactor accidentally
// drops a `hotreload:"safe"` tag, this test fails immediately rather
// than the field silently regressing to restart-required and
// operators discovering it only when their next SIGHUP throws a
// warning. Update the expected list when intentionally adding a new
// safe field.
func TestDiffAllSafeFieldsClassifiedSafe(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Config)
	}{
		{"thresholds", func(c *Config) { c.Thresholds.MailQueueWarn++ }},
		{"alerts", func(c *Config) { c.Alerts.MaxPerHour++ }},
		{"suppressions", func(c *Config) { c.Suppressions.TrustedCountries = append(c.Suppressions.TrustedCountries, "RO") }},
		{"auto_response", func(c *Config) { c.AutoResponse.NetBlockThreshold++ }},
		{"reputation", func(c *Config) { c.Reputation.Whitelist = append(c.Reputation.Whitelist, "10.0.0.1") }},
		{"email_protection", func(c *Config) { c.EmailProtection.RateWindowMin++ }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := &Config{}
			b := &Config{}
			tc.mutate(b)
			changes := Diff(a, b)
			if len(changes) != 1 {
				t.Fatalf("want 1 change, got %+v", changes)
			}
			if changes[0].Tag != TagSafe {
				t.Errorf("%s should be classified safe, got tag %q", tc.name, changes[0].Tag)
			}
			if RestartRequired(changes) {
				t.Errorf("%s should not require restart", tc.name)
			}
		})
	}
}

// TestDiffFieldTagOverridesParent covers the "field-level override"
// rule the recursive Diff honours: WebUI is tagged restart, but
// MetricsToken inside has an explicit `hotreload:"safe"` tag, so a
// change to MetricsToken alone is reported as safe (webui.metrics_token)
// and does NOT require a restart.
func TestDiffFieldTagOverridesParent(t *testing.T) {
	a := &Config{}
	a.WebUI.MetricsToken = "old"
	b := &Config{}
	b.WebUI.MetricsToken = "new"

	changes := Diff(a, b)
	if len(changes) != 1 {
		t.Fatalf("want 1 change, got %+v", changes)
	}
	if changes[0].Field != "webui.metrics_token" {
		t.Errorf("field path: got %q want webui.metrics_token", changes[0].Field)
	}
	if changes[0].Tag != TagSafe {
		t.Errorf("tag: got %q want %q (field-level safe must override parent restart)",
			changes[0].Tag, TagSafe)
	}
	if RestartRequired(changes) {
		t.Error("RestartRequired should be false when only a safe-tagged leaf changed")
	}
}

// TestDiffFieldOverrideSplitsClassification covers the mixed case:
// an edit touches BOTH webui.metrics_token (safe) and webui.listen
// (inherits parent restart). The recursive Diff reports them as two
// separate Changes with different tags, and RestartRequired is true
// because one of them is not safe.
func TestDiffFieldOverrideSplitsClassification(t *testing.T) {
	a := &Config{}
	a.WebUI.Listen = "0.0.0.0:9443"
	a.WebUI.MetricsToken = "old"
	b := &Config{}
	b.WebUI.Listen = "0.0.0.0:9444"
	b.WebUI.MetricsToken = "new"

	changes := Diff(a, b)
	if len(changes) != 2 {
		t.Fatalf("want 2 changes (mixed classification), got %+v", changes)
	}
	byField := map[string]string{}
	for _, c := range changes {
		byField[c.Field] = c.Tag
	}
	if byField["webui.metrics_token"] != TagSafe {
		t.Errorf("webui.metrics_token tag: got %q want %q", byField["webui.metrics_token"], TagSafe)
	}
	if byField["webui.listen"] != TagRestart {
		t.Errorf("webui.listen tag: got %q want %q", byField["webui.listen"], TagRestart)
	}
	if !RestartRequired(changes) {
		t.Error("RestartRequired should be true when any change is not safe")
	}
}

func TestDiffMixedTouchesRestart(t *testing.T) {
	a := &Config{Hostname: "h1"}
	a.Thresholds.MailQueueWarn = 100
	b := &Config{Hostname: "h2"}
	b.Thresholds.MailQueueWarn = 200

	changes := Diff(a, b)
	if len(changes) != 2 {
		t.Fatalf("want 2 changes, got %+v", changes)
	}
	if !RestartRequired(changes) {
		t.Error("RestartRequired should be true when any change requires restart")
	}
}

func TestDiffNilReturnsNothing(t *testing.T) {
	if got := Diff(nil, &Config{}); got != nil {
		t.Errorf("nil old: got %+v", got)
	}
	if got := Diff(&Config{}, nil); got != nil {
		t.Errorf("nil new: got %+v", got)
	}
	if got := Diff(nil, nil); got != nil {
		t.Errorf("both nil: got %+v", got)
	}
}

func TestDiffIgnoresConfigFile(t *testing.T) {
	// ConfigFile is the in-memory path of the loaded file and must
	// not register as a change between two reloads of the same
	// configuration.
	a := &Config{ConfigFile: "/opt/csm/csm.yaml"}
	b := &Config{ConfigFile: "/tmp/csm.yaml"}
	if got := Diff(a, b); len(got) != 0 {
		t.Errorf("ConfigFile change must be ignored: got %+v", got)
	}
}

// TestEveryTopLevelFieldIsTagged enforces the explicit-tag policy
// on Config. Any top-level field added in the future must carry a
// `hotreload:"safe"` or `hotreload:"restart"` struct tag, unless it
// is one of the two grandfathered internal fields
// (ConfigFile, Integrity) that Diff ignores.
//
// The default for untagged fields in Diff is restart-required, so a
// new field would still be treated correctly at runtime -- but
// relying on the default means "I thought this field hot-reloaded"
// versus "it never could" arguments can happen at incident time.
// The explicit tag closes that conversation.
func TestEveryTopLevelFieldIsTagged(t *testing.T) {
	t.Parallel()

	typ := reflect.TypeOf(Config{})
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		if !f.IsExported() {
			continue
		}
		switch f.Name {
		case "ConfigFile", "Integrity":
			continue
		}
		tag := f.Tag.Get("hotreload")
		switch tag {
		case TagSafe, TagRestart:
			// explicit classification, good
		case "":
			t.Errorf("Config.%s has no hotreload tag -- add `hotreload:%q` or `hotreload:%q`",
				f.Name, TagSafe, TagRestart)
		default:
			t.Errorf("Config.%s has unknown hotreload tag %q -- expected %q or %q",
				f.Name, tag, TagSafe, TagRestart)
		}
	}
}

func TestDiffIgnoresIntegrity(t *testing.T) {
	// Integrity is daemon-managed; every successful reload re-signs
	// integrity.config_hash, so it always differs between consecutive
	// reloads. Treating it as a diff would reject every reload.
	a := &Config{}
	a.Integrity.ConfigHash = "sha256:old"
	b := &Config{}
	b.Integrity.ConfigHash = "sha256:new"
	if got := Diff(a, b); len(got) != 0 {
		t.Errorf("Integrity change must be ignored: got %+v", got)
	}
}
