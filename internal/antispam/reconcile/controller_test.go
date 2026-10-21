package reconcile

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"unicode"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/antispam"
	"github.com/pidginhost/csm/internal/eximlock"
)

func stockControllerFacts() antispam.HostFacts {
	f := goodFeedFacts()
	f.Controller = antispam.ControllerConfig{
		Present:      true,
		Listeners:    []antispam.ControllerListener{{Raw: "localhost:11334", HostPort: "localhost:11334"}},
		TrustEntries: []string{"127.0.0.1", "::1"},
		PasswordSet:  true,
	}
	return f
}

func passWithFacts(f antispam.HostFacts, action antispam.Action) Outcome {
	h := &fakeHost{assessment: antispam.Assessment{Action: action}}
	r := h.reconciler()
	r.Collect = func(context.Context, string) antispam.HostFacts { return f }
	return r.Pass(context.Background(), desired(true))
}

func controllerFindings(out Outcome) []alert.Finding {
	var got []alert.Finding
	for _, f := range out.Findings {
		if f.Check == CheckControllerOpen {
			got = append(got, f)
		}
	}
	return got
}

func TestPassReportsControllerOpen(t *testing.T) {
	out := passWithFacts(stockControllerFacts(), antispam.Keep)
	got := controllerFindings(out)
	if len(got) != 1 {
		t.Fatalf("controller findings = %+v, want one", got)
	}
	f := got[0]
	if f.Severity != alert.Warning || f.DedupKey != "localhost:11334" ||
		!strings.Contains(f.Message+f.Details, "localhost:11334") ||
		!strings.Contains(f.Details, "trusted address reachable by local processes") {
		t.Fatalf("finding = %+v", f)
	}
	if !slices.Contains(out.Checks, CheckControllerOpen) {
		t.Fatalf("Checks = %v, want %s settled", out.Checks, CheckControllerOpen)
	}
}

func TestPassClearsControllerOpen(t *testing.T) {
	f := stockControllerFacts()
	f.Controller.TrustEntries = nil
	out := passWithFacts(f, antispam.Keep)
	if got := controllerFindings(out); len(got) != 0 {
		t.Fatalf("controller findings = %+v, want none", got)
	}
	if !slices.Contains(out.Checks, CheckControllerOpen) {
		t.Fatalf("Checks = %v, want %s settled so old findings clear", out.Checks, CheckControllerOpen)
	}
}

func TestPassControllerDumpErrorKeepsPreviousState(t *testing.T) {
	f := goodFeedFacts()
	f.ControllerErr = errors.New("rspamadm configdump failed")
	out := passWithFacts(f, antispam.Keep)
	if slices.Contains(out.Checks, CheckControllerOpen) {
		t.Fatalf("Checks = %v: an unreadable controller must not clear earlier findings", out.Checks)
	}
	if got := controllerFindings(out); len(got) != 0 {
		t.Fatalf("controller findings = %+v, want none", got)
	}
}

func TestPassControllerSettledWhenBusy(t *testing.T) {
	h := &fakeHost{
		assessment: antispam.Assessment{Action: antispam.Install},
		result:     antispam.Result{Operation: antispam.OpApply, Busy: true, FailedStep: "lock", Rollback: antispam.RollbackNone},
	}
	r := h.reconciler()
	r.Collect = func(context.Context, string) antispam.HostFacts { return stockControllerFacts() }
	out := r.Pass(context.Background(), desired(true))
	if !slices.Contains(out.Checks, CheckControllerOpen) || len(controllerFindings(out)) != 1 {
		t.Fatalf("busy pass: Checks = %v, findings = %+v", out.Checks, out.Findings)
	}
}

// Every pass that collected the controller carries the stats endpoint, so
// the web UI follows the host without reading it itself.
func TestPassCarriesStatsEndpoint(t *testing.T) {
	trusted := antispam.StatsEndpoint{Address: "127.0.0.1:11334", Version: "4.2.2"}
	untrusted := stockControllerFacts()
	untrusted.Controller.TrustEntries = nil
	_, noListener := antispam.StatsEndpointFor(untrusted)
	if noListener == "" {
		t.Fatal("no reason for a controller without a readable listener")
	}
	busy := func(f antispam.HostFacts) Outcome {
		h := &fakeHost{
			assessment: antispam.Assessment{Action: antispam.Install},
			result:     antispam.Result{Operation: antispam.OpApply, Busy: true, FailedStep: "lock", Rollback: antispam.RollbackNone},
		}
		r := h.reconciler()
		r.Collect = func(context.Context, string) antispam.HostFacts { return f }
		return r.Pass(context.Background(), desired(true))
	}
	observe := func(f antispam.HostFacts) Outcome {
		h := &fakeHost{assessment: antispam.Assessment{Action: antispam.Keep}}
		r := h.reconciler()
		r.Collect = func(context.Context, string) antispam.HostFacts { return f }
		d := desired(true)
		d.Observe = true
		return r.Pass(context.Background(), d)
	}
	for name, tc := range map[string]struct {
		out        Outcome
		want       antispam.StatsEndpoint
		wantReason string
	}{
		"keep":        {passWithFacts(stockControllerFacts(), antispam.Keep), trusted, ""},
		"install":     {passWithFacts(stockControllerFacts(), antispam.Install), trusted, ""},
		"busy":        {busy(stockControllerFacts()), trusted, ""},
		"observe":     {observe(stockControllerFacts()), trusted, ""},
		"no listener": {passWithFacts(untrusted, antispam.Keep), antispam.StatsEndpoint{Version: "4.2.2"}, noListener},
	} {
		if len(tc.out.Checks) == 0 || tc.out.Stats != tc.want || tc.out.StatsReason != tc.wantReason {
			t.Errorf("%s: checks %v stats %+v reason %q, want %+v %q", name, tc.out.Checks, tc.out.Stats, tc.out.StatsReason, tc.want, tc.wantReason)
		}
	}
	// A disabled pass reads only CSM's own files, not the controller.
	h := &fakeHost{assessment: antispam.Assessment{Action: antispam.Keep}}
	if out := h.reconciler().Pass(context.Background(), desired(false)); out.Stats != (antispam.StatsEndpoint{}) || out.StatsReason != "" {
		t.Fatalf("disabled pass: stats %+v reason %q", out.Stats, out.StatsReason)
	}
}

func TestPassControllerClearedWhenDisabled(t *testing.T) {
	h := &fakeHost{assessment: antispam.Assessment{Action: antispam.Keep}}
	out := h.reconciler().Pass(context.Background(), desired(false))
	if !slices.Contains(out.Checks, CheckControllerOpen) || len(controllerFindings(out)) != 0 {
		t.Fatalf("disabled pass: Checks = %v, findings = %+v; want the check settled with no findings", out.Checks, out.Findings)
	}
}

func TestControllerFindingNeverCarriesPassword(t *testing.T) {
	password, enablePassword := rand.Text(), rand.Text()
	dump := fmt.Sprintf(`{"worker":{"controller":{"bind_socket":"localhost:11334","secure_ip":["127.0.0.1"],"password":%q,"enable_password":%q}}}`, password, enablePassword)
	f := stockControllerFacts()
	var err error
	f.Controller, err = antispam.ParseControllerConfig([]byte(dump))
	if err != nil {
		t.Fatal("could not parse controller fixture")
	}
	// The full dump also remains in the collected host facts.
	f.RspamdConfig.Stdout = dump
	out := passWithFacts(f, antispam.Keep)
	if len(controllerFindings(out)) != 1 {
		t.Fatal("expected one controller finding")
	}
	for _, finding := range out.Findings {
		encoded, err := json.Marshal(finding)
		if err != nil {
			t.Fatal("could not encode finding")
		}
		if strings.Contains(string(encoded), password) || strings.Contains(string(encoded), enablePassword) {
			t.Fatal("finding carries a controller password")
		}
	}
}

func TestControllerFindingEscapesControlCharacters(t *testing.T) {
	controls := "\x00\t\r\n\x1b[2J\x7f\u0085\u2028\u202e"
	p := antispam.Problem{Code: antispam.CodeControllerOpen, Severity: antispam.Warning, Key: "localhost:11334" + controls, Detail: "reason" + controls}
	cf := controllerFinding(p, testNow)
	for _, s := range []string{cf.Message, cf.Details, cf.DedupKey} {
		for _, c := range s {
			if unicode.IsControl(c) || c > unicode.MaxASCII {
				t.Fatal("finding keeps a control or non-ASCII character")
			}
		}
	}
	if cf.DedupKey == "localhost:11334" || !strings.Contains(cf.Message, cf.DedupKey) {
		t.Fatal("escaping lost the listener identity")
	}
}

func TestPassControllerClearedWhenDisabledInvalidationFails(t *testing.T) {
	for _, failure := range []error{eximlock.ErrBusy, errors.New("read-only state directory")} {
		t.Run(failure.Error(), func(t *testing.T) {
			h := &fakeHost{}
			r := h.reconciler()
			r.Invalidate = func(context.Context) error { return failure }
			out := r.Pass(context.Background(), desired(false))
			if !slices.Equal(out.Checks, []string{CheckControllerOpen}) || len(controllerFindings(out)) != 0 {
				t.Fatalf("disabled pass left controller warnings unsettled: %+v", out)
			}
			if h.installed != 0 || len(h.collected) != 0 || len(h.requests) != 0 {
				t.Fatal("failed invalidation must still prevent host reads and worker requests")
			}
		})
	}
}

func TestPassControllerObserveAndBusyLifecycle(t *testing.T) {
	for _, observe := range []bool{false, true} {
		for _, state := range []string{"open", "closed", "unreadable", "disabled"} {
			t.Run(fmt.Sprintf("observe=%t/%s", observe, state), func(t *testing.T) {
				f := stockControllerFacts()
				f.Controller.Listeners = append(f.Controller.Listeners, antispam.ControllerListener{Raw: "[::1]:11334", HostPort: "[::1]:11334"})
				switch state {
				case "closed":
					f.Controller.TrustEntries = nil
				case "unreadable", "disabled":
					f.ControllerErr = errors.New("controller dump unavailable")
				}
				action, operation := antispam.Install, antispam.OpApply
				if state == "disabled" {
					action, operation = antispam.Uninstall, antispam.OpRemove
				}
				h := &fakeHost{
					assessment: antispam.Assessment{Action: action},
					result:     antispam.Result{Operation: operation, Busy: true, FailedStep: "lock", Rollback: antispam.RollbackNone},
				}
				r := h.reconciler()
				r.Collect = func(context.Context, string) antispam.HostFacts { return f }
				r.Installed = func() antispam.HostFacts { return f }
				d := desired(state != "disabled")
				d.Observe = observe
				out := r.Pass(context.Background(), d)
				if settled := slices.Contains(out.Checks, CheckControllerOpen); settled != (state != "unreadable") {
					t.Fatalf("settled=%t for %s", settled, state)
				}
				got := controllerFindings(out)
				if state == "open" {
					if len(got) != 2 || got[0].DedupKey != "localhost:11334" || got[1].DedupKey != "[::1]:11334" {
						t.Fatalf("want one finding per listener, got %+v", got)
					}
				} else if len(got) != 0 {
					t.Fatalf("unexpected controller findings: %+v", got)
				}
				if observe && len(h.requests) != 0 || !observe && (len(h.requests) != 1 || out.Retry != BusyRetry) {
					t.Fatalf("requests=%d retry=%s", len(h.requests), out.Retry)
				}
			})
		}
	}
}

func TestControllerFindingExplainsUnixProtection(t *testing.T) {
	f := stockControllerFacts()
	f.Controller.Listeners = []antispam.ControllerListener{{Raw: "/run/rspamd/controller.sock mode=0600", Unix: true, Path: "/run/rspamd/controller.sock"}}
	got := controllerFindings(passWithFacts(f, antispam.Keep))
	if len(got) != 1 {
		t.Fatalf("want one finding for unavailable socket facts, got %d", len(got))
	}
	for _, want := range []string{"owner", "parent directories", "ACL"} {
		if !strings.Contains(got[0].Details, want) {
			t.Errorf("socket guidance is missing %q", want)
		}
	}
}

func TestPassReportsUnverifiableController(t *testing.T) {
	f := goodFeedFacts()
	f.ControllerUnverifiable = errors.New("configdump worker controller: bind_socket systemd endpoint is unresolved")
	out := passWithFacts(f, antispam.Keep)
	got := controllerFindings(out)
	if len(got) != 1 || got[0].DedupKey != "controller" || !strings.Contains(got[0].Details, "controller configuration CSM cannot verify") {
		t.Fatalf("controller findings = %+v, want one cannot-verify warning", got)
	}
	if !slices.Contains(out.Checks, CheckControllerOpen) {
		t.Fatalf("Checks = %v, want the check settled with the warning", out.Checks)
	}
}
