package config

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/verdict"
)

// packagedDifference is a key whose packaged value differs from the value a
// config that omits it gets. Both values are pinned, so a change to either
// side is made on purpose.
type packagedDifference struct {
	builtIn, packaged string
	why               string
	// effect, when set, reads the value the key resolves to: the packaged
	// key only spells out the built-in default, so both must resolve alike.
	effect func(*testing.T, *Config) any
}

var packagedDefaultDifferences = map[string]packagedDifference{
	// Values the operator replaces at install.
	"hostname":             {`""`, `"SET_HOSTNAME_HERE"`, "placeholder", nil},
	"alerts.email.enabled": {"false", "true", "installs alert by email to the address they set", nil},
	"alerts.email.from":    {`""`, `"csm@SET_HOSTNAME_HERE"`, "placeholder", nil},
	"alerts.email.smtp":    {`""`, `"localhost:25"`, "installs relay through the local MTA", nil},
	"alerts.email.to":      {"[]", `["SET_EMAIL_HERE"]`, "placeholder", nil},
	"alerts.webhook.type":  {`""`, `"slack"`, "sample for the disabled webhook", nil},
	"webui.enabled":        {"false", "true", "installs serve the Web UI", nil},
	"webui.ui_dir":         {`""`, `"/opt/csm/ui"`, "packages install the UI there", nil},

	// Packaged policy: stricter or more cautious than the built-in fallback.
	"alerts.max_per_hour":                              {"30", "10", "packaged alert limit", nil},
	"firewall.ipv6":                                    {"false", "true", "IPv6 would bypass the firewall", nil},
	"thresholds.http_distributed_min_ips":              {"0", "10", "distributed HTTP detection is opt-in when omitted", nil},
	"incidents.spray_suppression.dry_run":              {"false", "true", "credential-spray suppression runs as a dry run; omitted, it is off", nil},
	"incidents.spray_suppression.distinct_mailboxes":   {"0", "10", "spray suppression is off when omitted; 10 is its fallback", nil},
	"incidents.spray_suppression.max_tracked_ips":      {"0", "10000", "spray suppression is off when omitted; 10000 is its fallback", nil},
	"incidents.spray_suppression.severity_escalate_at": {"0", "50", "spray suppression is off when omitted; 5x distinct_mailboxes is its fallback", nil},
	"incidents.spray_suppression.per_check":            {"[]", `["email_auth_failure_realtime","pam_bruteforce","credential_stuffing"]`, "spray suppression is off when omitted", nil},

	// The packaged key spells out the default the code applies.
	"auto_response.dry_run":                                     {"null", "true", "", func(_ *testing.T, c *Config) any { return c.AutoResponseDryRunEnabled() }},
	"auto_response.virtual_patch_exposed_files":                 {`""`, `"off"`, "", func(_ *testing.T, c *Config) any { return c.VirtualPatchMode() }},
	"bpf_enforcement.dry_run":                                   {"null", "true", "", bpfDryRunEffect},
	"detection.direct_smtp_egress.dry_run":                      {"null", "true", "", func(_ *testing.T, c *Config) any { return c.DirectSMTPEgressDryRunEnabled() }},
	"detection.vulnerable_plugin_scanning":                      {"null", "true", "", func(_ *testing.T, c *Config) any { return c.VulnerablePluginScanningEnabled() }},
	"firewall.dos_exempt_known_mail_providers":                  {"null", "true", "", func(_ *testing.T, c *Config) any { return c.Firewall.ExemptKnownMailProviders() }},
	"incidents.auto_close.enabled":                              {"null", "true", "", func(_ *testing.T, c *Config) any { return c.IncidentsAutoCloseEnabled() }},
	"incidents.auto_close.by_kind":                              {"{}", `{"credential_spray":"24h","mailbox_bruteforce":"24h","mailbox_takeover":"24h","web_account_compromise":"168h","web_attack":"24h"}`, "", func(_ *testing.T, c *Config) any { return c.IncidentsAutoCloseThresholds() }},
	"reputation.bot_ranges.auto_update":                         {"null", "true", "", func(_ *testing.T, c *Config) any { return c.BotRangesAutoUpdate() }},
	"reputation.bot_verify_enabled":                             {"null", "true", "", func(_ *testing.T, c *Config) any { return c.BotVerifyEnabled() }},
	"updates.check_enabled":                                     {"null", "true", "", func(_ *testing.T, c *Config) any { return c.UpdatesCheckEnabled() }},
	"auto_response.verdict_callback.require_response_signature": {"null", "true", "the verdict client requires signatures when omitted", verdictSignatureEffect},
	"thresholds.multi_ip_login_threshold":                       {"0", "3", "the cPanel login check falls back to 3", nil},
	"thresholds.multi_ip_login_window_min":                      {"0", "60", "the cPanel login check falls back to 60", nil},

	// Omitted, these keys change behaviour.
	"backdoor_ports":                 {"[]", "[4444,5555,55553,55555,31337]", "omitted, no listening port is flagged as a backdoor", nil},
	"firewall.smtp_allow_users":      {"[]", `["cpanel","mailman"]`, "omitted, smtp_block lets only root and mailnull send", nil},
	"suppressions.upcp_window_start": {`""`, `"00:30"`, "omitted, password changes during the cPanel update stay Critical", nil},
	"suppressions.upcp_window_end":   {`""`, `"02:00"`, "omitted, password changes during the cPanel update stay Critical", nil},
}

// TestPackagedDefaultsMatchBuiltInDefaults compares every key of the packaged
// config with the value a config that omits it gets. A difference not listed
// above needs an explicit policy decision before either default is changed.
func TestPackagedDefaultsMatchBuiltInDefaults(t *testing.T) {
	data, err := os.ReadFile("../../build/packaging/csm.yaml.default")
	if err != nil {
		t.Fatal(err)
	}
	packaged, err := LoadBytes(data)
	if err != nil {
		t.Fatal(err)
	}
	builtIn, err := LoadBytes([]byte("{}\n"))
	if err != nil {
		t.Fatal(err)
	}
	found := map[string][2]string{}
	diffConfigValues("", reflect.ValueOf(builtIn).Elem(), reflect.ValueOf(packaged).Elem(), found)

	for key, got := range found {
		want, ok := packagedDefaultDifferences[key]
		if !ok {
			t.Errorf("%s: built-in %q, packaged %q: unlisted difference", key, got[0], got[1])
			continue
		}
		if got != [2]string{want.builtIn, want.packaged} {
			t.Errorf("%s: built-in %q, packaged %q; listed as %q and %q (%s)", key, got[0], got[1], want.builtIn, want.packaged, want.why)
		}
	}
	for key, want := range packagedDefaultDifferences {
		if _, ok := found[key]; !ok {
			t.Errorf("%s: no longer differs; remove it from the list", key)
		}
		if want.effect != nil {
			a, b := want.effect(t, builtIn), want.effect(t, packaged)
			if !reflect.DeepEqual(a, b) {
				t.Errorf("%s: resolves to %v when omitted, %v as packaged", key, a, b)
			}
		}
	}
}

func bpfDryRunEffect(_ *testing.T, cfg *Config) any {
	// The other dry-run guards otherwise mask this setting's fallback.
	probe := *cfg
	probe.AutoResponse.DryRun = new(false)
	probe.Detection.DirectSMTPEgress.DryRun = new(false)
	return probe.BPFEnforcementDryRunEnabled()
}

// verdictSignatureEffect exercises the private accessor through the client.
// Only a missing signature is evidence of the setting; transport or decoding
// failures must not make both sides appear equivalent.
func verdictSignatureEffect(t *testing.T, cfg *Config) any {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"verdict":"block"}`))
	}))
	defer server.Close()
	client := verdict.New(verdict.Config{
		URL:                      server.URL,
		HMACSecret:               rand.Text(),
		RequireResponseSignature: cfg.AutoResponse.VerdictCallback.RequireResponseSignature,
	})
	response, err := client.Ask(t.Context(), verdict.Request{IP: "192.0.2.1"})
	if err != nil {
		if class := verdict.ClassOf(err); class != verdict.ClassSignature {
			t.Fatalf("verdict signature probe failed: %s", class)
		}
		return true
	}
	if response.Verdict != "block" {
		t.Fatalf("verdict signature probe returned %q, want block", response.Verdict)
	}
	return false
}

// diffConfigValues records YAML leaf paths. Scalar collections stay together
// so list order and map membership are pinned. Structured collections recurse
// so ignored fields and pointer identities cannot affect their comparison.
func diffConfigValues(path string, a, b reflect.Value, found map[string][2]string) {
	originalA, originalB := a, b
	for a.IsValid() && a.Kind() == reflect.Pointer {
		a = a.Elem()
	}
	for b.IsValid() && b.Kind() == reflect.Pointer {
		b = b.Elem()
	}
	if !a.IsValid() && !b.IsValid() {
		// A nil entry still occupies a map key or sequence position.
		if originalA.IsValid() != originalB.IsValid() {
			values := [2]string{"<absent>", "<absent>"}
			if originalA.IsValid() {
				values[0] = configValueString(originalA)
			}
			if originalB.IsValid() {
				values[1] = configValueString(originalB)
			}
			found[path] = values
		}
		return
	}
	typ := b
	if a.IsValid() {
		typ = a
	}
	switch typ.Kind() {
	case reflect.Struct:
		before := len(found)
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Type().Field(i)
			name, options, _ := strings.Cut(f.Tag.Get("yaml"), ",")
			if (!f.IsExported() && !f.Anonymous) || name == "-" {
				continue
			}
			av, bv := reflect.Value{}, reflect.Value{}
			if a.IsValid() {
				av = a.Field(i)
			}
			if b.IsValid() {
				bv = b.Field(i)
			}
			if slices.Contains(strings.Split(options, ","), "inline") {
				if f.Type.Kind() == reflect.Map {
					diffConfigMap(path, av, bv, found)
				} else {
					diffConfigValues(path, av, bv, found)
				}
				continue
			}
			if name == "" {
				name = strings.ToLower(f.Name)
			}
			diffConfigValues(configChildPath(path, name), av, bv, found)
		}
		// Even a struct with no YAML leaves differs from a nil pointer.
		if len(found) == before && a.IsValid() != b.IsValid() {
			values := [2]string{"null", "null"}
			if a.IsValid() {
				values[0] = "{}"
			}
			if b.IsValid() {
				values[1] = "{}"
			}
			found[path] = values
		}
		return
	case reflect.Map:
		if configContainsStruct(typ.Type().Elem()) {
			diffConfigMap(path, a, b, found)
			return
		}
	case reflect.Slice, reflect.Array:
		if configContainsStruct(typ.Type().Elem()) {
			alen, blen := 0, 0
			if a.IsValid() {
				alen = a.Len()
			}
			if b.IsValid() {
				blen = b.Len()
			}
			for i := 0; i < max(alen, blen); i++ {
				av, bv := reflect.Value{}, reflect.Value{}
				if i < alen {
					av = a.Index(i)
				}
				if i < blen {
					bv = b.Index(i)
				}
				diffConfigValues(fmt.Sprintf("%s[%d]", path, i), av, bv, found)
			}
			return
		}
	}
	av, bv := configValueString(a), configValueString(b)
	if av != bv {
		found[path] = [2]string{av, bv}
	}
}

func configContainsStruct(typ reflect.Type) bool {
	switch typ.Kind() {
	case reflect.Struct:
		return true
	case reflect.Pointer, reflect.Slice, reflect.Array, reflect.Map:
		return configContainsStruct(typ.Elem())
	default:
		return false
	}
}

func diffConfigMap(path string, a, b reflect.Value, found map[string][2]string) {
	keys := map[string]reflect.Value{}
	for _, v := range []reflect.Value{a, b} {
		if v.IsValid() {
			for _, key := range v.MapKeys() {
				keys[key.String()] = key
			}
		}
	}
	for name, key := range keys {
		av, bv := reflect.Value{}, reflect.Value{}
		if a.IsValid() {
			av = a.MapIndex(key)
		}
		if b.IsValid() {
			bv = b.MapIndex(key)
		}
		diffConfigValues(configChildPath(path, name), av, bv, found)
	}
}

func configChildPath(path, name string) string {
	if name == "" || strings.ContainsAny(name, ".[]\"") {
		return fmt.Sprintf("%s[%q]", path, name)
	}
	if path == "" {
		return name
	}
	return path + "." + name
}

// JSON preserves collection boundaries and quotes strings, unlike fmt.Sprint.
// Empty and nil collections are intentionally equivalent at every leaf.
func configValueString(v reflect.Value) string {
	if !v.IsValid() {
		return "null"
	}
	if v.Kind() == reflect.Slice && v.IsNil() {
		v = reflect.MakeSlice(v.Type(), 0, 0)
	}
	if v.Kind() == reflect.Map && v.IsNil() {
		v = reflect.MakeMap(v.Type())
	}
	data, err := json.Marshal(v.Interface())
	if err != nil {
		panic(fmt.Sprintf("cannot pin config value: %v", err))
	}
	return string(data)
}
