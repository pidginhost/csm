package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/control"
	"github.com/pidginhost/csm/internal/health"
)

// A configured ceiling below the default warns and tells the operator to
// remove the key; a defaulted ceiling, or a configured one at the default,
// stays ok. It warns, never fails, whether admission previews or executes,
// so an upgrade over a config that carries the old shipped value passes.
func TestDoctorWarnsOnAConfiguredCeilingBelowTheDefault(t *testing.T) {
	at := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	for _, executing := range []bool{false, true} {
		for _, tc := range []struct {
			limit  uint32
			source string
			want   string
		}{
			{50, config.CeilingConfigured, "warn"},
			{config.DefaultAdmissionCeiling - 1, config.CeilingConfigured, "warn"},
			{config.DefaultAdmissionCeiling, config.CeilingConfigured, "ok"},
			{5000, config.CeilingConfigured, "ok"},
			{config.DefaultAdmissionCeiling, config.CeilingDefault, "ok"},
			// A ledger that has not applied a reload yet can still hold a
			// lower ceiling after the key was removed: no key to remove.
			{50, config.CeilingDefault, "ok"},
		} {
			a := &health.AdmissionStatus{CheckedAt: at,
				Ledger: &admission.LedgerStatus{Ceiling: admission.CeilingStatus{Limit: tc.limit}},
				Owner:  &health.AdmissionOwner{Executing: executing, CeilingSource: tc.source},
			}
			var row DoctorCheck
			for _, c := range ownerDoctorChecks(a) {
				if c.Name == "admission ceiling" {
					row = c
				}
			}
			if row.Status != tc.want {
				t.Errorf("executing=%v %d (%s): status %q, want %q: %+v", executing, tc.limit, tc.source, row.Status, tc.want, row)
				continue
			}
			if tc.want == "ok" {
				if row.Fix != "" {
					t.Errorf("executing=%v %d (%s): ok row carries a fix: %+v", executing, tc.limit, tc.source, row)
				}
				continue
			}
			if !strings.Contains(row.Message, "below the default of 1000") || !strings.Contains(row.Fix, "remove auto_response.max_blocks_per_hour") {
				t.Errorf("executing=%v %d: warning %+v does not say it is below the default and to remove the key", executing, tc.limit, row)
			}
		}
	}
}

// A config an earlier release accepted keeps its meaning and never fails
// doctor. The scan budget stays what the key says, or 50 without it;
// admission takes 1000 for an omitted or zero key, the configured value
// otherwise and the largest ceiling for one above it; a drop-in overrides
// the main file. The report warns about a low configured ceiling, keeps
// the messages for a ceiling of 1 and for a clamped one, and its overall
// status is never a failure, previewing or executing.
func TestDoctorLegacyCeilingConfigCompatibility(t *testing.T) {
	for _, tc := range []struct {
		name, main, dropIn string
		legacy             int
		limit              uint32
		source, status     string
		says               string
	}{
		{"omitted", "", "", 50, 1000, config.CeilingDefault, "ok", "1000 automatic responses per hour (default)"},
		{"zero", "max_blocks_per_hour: 0", "", 50, 1000, config.CeilingDefault, "ok", "1000 automatic responses per hour (default)"},
		{"old shipped value", "max_blocks_per_hour: 50", "", 50, 50, config.CeilingConfigured, "warn", "below the default of 1000"},
		{"one", "max_blocks_per_hour: 1", "", 1, 1, config.CeilingConfigured, "warn", "a ceiling of 1 runs only the reserved lane"},
		{"at the default", "max_blocks_per_hour: 1000", "", 1000, 1000, config.CeilingConfigured, "ok", "1000 automatic responses per hour (configured)"},
		{"former default kept", "max_blocks_per_hour: 2000", "", 2000, 2000, config.CeilingConfigured, "ok", "2000 automatic responses per hour (configured)"},
		{"above the largest", "max_blocks_per_hour: 30000", "", 30000, admission.MaxCeiling, config.CeilingClamped, "warn", "exceeds the largest ceiling"},
		{"drop-in sets it", "", "max_blocks_per_hour: 50", 50, 50, config.CeilingConfigured, "warn", "below the default of 1000"},
		{"drop-in clears it", "max_blocks_per_hour: 50", "max_blocks_per_hour: 0", 50, 1000, config.CeilingDefault, "ok", "1000 automatic responses per hour (default)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			confDir := filepath.Join(dir, "conf.d")
			if err := os.MkdirAll(confDir, 0o700); err != nil {
				t.Fatal(err)
			}
			section := func(key string) string {
				if key == "" {
					return "hostname: host.example.com\n"
				}
				return "hostname: host.example.com\nauto_response:\n  " + key + "\n"
			}
			main := filepath.Join(dir, "csm.yaml")
			if err := os.WriteFile(main, []byte(section(tc.main)), 0o600); err != nil {
				t.Fatal(err)
			}
			if tc.dropIn != "" {
				if err := os.WriteFile(filepath.Join(confDir, "10-ceiling.yaml"), []byte("auto_response:\n  "+tc.dropIn+"\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			cfg, err := config.LoadWithDir(main, confDir)
			if err != nil {
				t.Fatalf("a config earlier releases accepted does not load: %v", err)
			}
			for _, r := range config.Validate(cfg) {
				if r.Level == "error" && strings.HasPrefix(r.Field, "auto_response") {
					t.Fatalf("validation refuses the config: %+v", r)
				}
			}
			limit, source := cfg.AdmissionCeiling()
			if cfg.AutoResponse.MaxBlocksPerHour != tc.legacy || limit != tc.limit || source != tc.source {
				t.Fatalf("scan budget %d, admission ceiling %d (%s); want %d, %d (%s)", cfg.AutoResponse.MaxBlocksPerHour, limit, source, tc.legacy, tc.limit, tc.source)
			}
			for _, executing := range []bool{false, true} {
				ledger := &admission.LedgerStatus{Storage: admission.StorageStatus{RecoveryRoom: admission.RecoveryReserveBytes}}
				ledger.Ceiling.Limit = limit
				report := doctorReportForSnapshot(t, admissionSnapshot(&health.AdmissionStatus{
					CheckedAt: time.Now(), Ledger: ledger, Ingress: &admission.IngressHealth{Admitting: true},
					Owner: &health.AdmissionOwner{Executing: executing, Settled: executing, CeilingSource: source},
				}))
				row, ok := doctorCheckNamed(report, "admission ceiling")
				if !ok || row.Status != tc.status || !strings.Contains(row.Message, tc.says) {
					t.Fatalf("executing=%t: admission ceiling = %+v (%v), want %s saying %q", executing, row, ok, tc.status, tc.says)
				}
				if report.OverallStatus == "fail" {
					t.Fatalf("executing=%t: doctor fails on an accepted config: %+v", executing, report.Checks)
				}
			}
		})
	}
}

// A negative temporary block limit was accepted by earlier releases, so it
// must still pass plain doctor: validation adds one warning and no error,
// and the report warns without failing.
func TestDoctorAcceptsLegacyNegativeTemporaryLimit(t *testing.T) {
	errorsOf := func(cfg *config.Config) (fields []string) {
		for _, r := range config.Validate(cfg) {
			if r.Level == "error" {
				fields = append(fields, r.Field)
			}
		}
		return fields
	}
	load := func(value string) *config.Config {
		loaded, err := config.LoadBytes([]byte("firewall:\n  deny_temp_ip_limit: " + value + "\n"))
		if err != nil {
			t.Fatalf("limit %s does not load: %v", value, err)
		}
		cfg := validDoctorConfig()
		cfg.Firewall = loaded.Firewall
		return cfg
	}
	cfg, baseline := load("-1"), load("0")
	if got, want := errorsOf(cfg), errorsOf(baseline); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("a negative limit adds validation errors: %v, baseline %v", got, want)
	}
	payload, err := json.Marshal(control.StatusResult{Version: "test", Snapshot: admissionSnapshot(nil)})
	if err != nil {
		t.Fatal(err)
	}
	report := buildDoctorReport(func() (*config.Config, error) { return cfg, nil }, func() ([]byte, error) { return payload, nil }, integrityOK)
	row, ok := doctorCheckNamed(report, "config: firewall.deny_temp_ip_limit")
	if !ok || row.Status != "warn" || !strings.Contains(row.Message, "negative") {
		t.Fatalf("doctor row for the negative limit = %+v (%v), want a warning", row, ok)
	}
	if report.OverallStatus == "fail" {
		t.Fatalf("doctor fails on a limit earlier releases accepted: %+v", report.Checks)
	}
	// The one warning is all the negative value adds to the report.
	clean := buildDoctorReport(func() (*config.Config, error) { return baseline, nil }, func() ([]byte, error) { return payload, nil }, integrityOK)
	statuses := func(r DoctorReport) map[string]string {
		out := map[string]string{}
		for _, c := range r.Checks {
			if c.Name != "config: firewall.deny_temp_ip_limit" {
				out[c.Name] = c.Status
			}
		}
		return out
	}
	if got, want := statuses(report), statuses(clean); !reflect.DeepEqual(got, want) {
		t.Fatalf("a negative limit changed other rows: %v, with a limit of 0 %v", got, want)
	}
}
