package config

import (
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
)

// packagedDifference is a key whose packaged value differs from the value a
// config that omits it gets. Both values are pinned, so a change to either
// side is made on purpose.
type packagedDifference struct {
	builtIn, packaged string
	why               string
	// effect, when set, reads the value the key resolves to: the packaged
	// key only spells out the built-in default, so both must resolve alike.
	effect func(*Config) any
}

var packagedDefaultDifferences = map[string]packagedDifference{
	// Values the operator replaces at install.
	"hostname":             {"", "SET_HOSTNAME_HERE", "placeholder", nil},
	"alerts.email.enabled": {"false", "true", "installs alert by email to the address they set", nil},
	"alerts.email.from":    {"", "csm@SET_HOSTNAME_HERE", "placeholder", nil},
	"alerts.email.smtp":    {"", "localhost:25", "installs relay through the local MTA", nil},
	"alerts.email.to":      {"[]", "[SET_EMAIL_HERE]", "placeholder", nil},
	"alerts.webhook.type":  {"", "slack", "sample for the disabled webhook", nil},
	"webui.enabled":        {"false", "true", "installs serve the Web UI", nil},
	"webui.ui_dir":         {"", "/opt/csm/ui", "packages install the UI there", nil},

	// Packaged policy: stricter or more cautious than the built-in fallback.
	"alerts.max_per_hour":                              {"30", "10", "packaged alert limit", nil},
	"firewall.ipv6":                                    {"false", "true", "IPv6 would bypass the firewall", nil},
	"thresholds.http_distributed_min_ips":              {"0", "10", "distributed HTTP detection is opt-in when omitted", nil},
	"incidents.spray_suppression.dry_run":              {"false", "true", "credential-spray suppression runs as a dry run; omitted, it is off", nil},
	"incidents.spray_suppression.distinct_mailboxes":   {"0", "10", "spray suppression is off when omitted; 10 is its fallback", nil},
	"incidents.spray_suppression.max_tracked_ips":      {"0", "10000", "spray suppression is off when omitted; 10000 is its fallback", nil},
	"incidents.spray_suppression.severity_escalate_at": {"0", "50", "spray suppression is off when omitted; 5x distinct_mailboxes is its fallback", nil},
	"incidents.spray_suppression.per_check":            {"[]", "[email_auth_failure_realtime pam_bruteforce credential_stuffing]", "spray suppression is off when omitted", nil},

	// The packaged key spells out the default the code applies.
	"auto_response.dry_run":                                     {"<nil>", "true", "", func(c *Config) any { return c.AutoResponseDryRunEnabled() }},
	"auto_response.virtual_patch_exposed_files":                 {"", "off", "", func(c *Config) any { return c.VirtualPatchMode() }},
	"bpf_enforcement.dry_run":                                   {"<nil>", "true", "", func(c *Config) any { return c.BPFEnforcementDryRunEnabled() }},
	"detection.direct_smtp_egress.dry_run":                      {"<nil>", "true", "", func(c *Config) any { return c.DirectSMTPEgressDryRunEnabled() }},
	"detection.vulnerable_plugin_scanning":                      {"<nil>", "true", "", func(c *Config) any { return c.VulnerablePluginScanningEnabled() }},
	"firewall.dos_exempt_known_mail_providers":                  {"<nil>", "true", "", func(c *Config) any { return c.Firewall.ExemptKnownMailProviders() }},
	"incidents.auto_close.enabled":                              {"<nil>", "true", "", func(c *Config) any { return c.IncidentsAutoCloseEnabled() }},
	"incidents.auto_close.by_kind":                              {"map[]", "map[credential_spray:24h mailbox_bruteforce:24h mailbox_takeover:24h web_account_compromise:168h web_attack:24h]", "", func(c *Config) any { return c.IncidentsAutoCloseThresholds() }},
	"reputation.bot_ranges.auto_update":                         {"<nil>", "true", "", func(c *Config) any { return c.BotRangesAutoUpdate() }},
	"reputation.bot_verify_enabled":                             {"<nil>", "true", "", func(c *Config) any { return c.BotVerifyEnabled() }},
	"updates.check_enabled":                                     {"<nil>", "true", "", func(c *Config) any { return c.UpdatesCheckEnabled() }},
	"auto_response.verdict_callback.require_response_signature": {"<nil>", "true", "the verdict client requires signatures when omitted", nil},
	"thresholds.multi_ip_login_threshold":                       {"0", "3", "the cPanel login check falls back to 3", nil},
	"thresholds.multi_ip_login_window_min":                      {"0", "60", "the cPanel login check falls back to 60", nil},

	// Omitted, these keys change behaviour.
	"backdoor_ports":                 {"[]", "[4444 5555 55553 55555 31337]", "omitted, no listening port is flagged as a backdoor", nil},
	"firewall.smtp_allow_users":      {"[]", "[cpanel mailman]", "omitted, smtp_block lets only root and mailnull send", nil},
	"suppressions.upcp_window_start": {"", "00:30", "omitted, password changes during the cPanel update stay Critical", nil},
	"suppressions.upcp_window_end":   {"", "02:00", "omitted, password changes during the cPanel update stay Critical", nil},
}

// TestPackagedDefaultsMatchBuiltInDefaults compares every key of the packaged
// config with the value a config that omits it gets. A difference not listed
// above is drift: change the default or the packaged file, or list it.
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
		if want.effect != nil && !reflect.DeepEqual(want.effect(builtIn), want.effect(packaged)) {
			t.Errorf("%s: resolves to %v when omitted, %v as packaged", key, want.effect(builtIn), want.effect(packaged))
		}
	}
}

// diffConfigValues records, by YAML path, every leaf where a and b differ.
// Empty and nil collections are equal; pointers compare by what they hold.
func diffConfigValues(path string, a, b reflect.Value, found map[string][2]string) {
	switch a.Kind() {
	case reflect.Pointer:
		if !a.IsNil() && !b.IsNil() {
			diffConfigValues(path, a.Elem(), b.Elem(), found)
		} else if a.IsNil() != b.IsNil() {
			found[path] = [2]string{pointerString(a), pointerString(b)}
		}
	case reflect.Struct:
		for i := 0; i < a.NumField(); i++ {
			f := a.Type().Field(i)
			name, _, _ := strings.Cut(f.Tag.Get("yaml"), ",")
			if !f.IsExported() || name == "-" {
				continue
			}
			if name == "" {
				name = f.Name
			}
			diffConfigValues(strings.TrimPrefix(path+"."+name, "."), a.Field(i), b.Field(i), found)
		}
	case reflect.Slice, reflect.Map:
		if (a.Len() != 0 || b.Len() != 0) && !reflect.DeepEqual(a.Interface(), b.Interface()) {
			found[path] = [2]string{fmt.Sprint(a.Interface()), fmt.Sprint(b.Interface())}
		}
	default:
		if !reflect.DeepEqual(a.Interface(), b.Interface()) {
			found[path] = [2]string{fmt.Sprint(a.Interface()), fmt.Sprint(b.Interface())}
		}
	}
}

func pointerString(v reflect.Value) string {
	if v.IsNil() {
		return "<nil>"
	}
	return fmt.Sprint(v.Elem().Interface())
}
