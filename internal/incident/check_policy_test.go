package incident_test

import (
	"encoding/json"
	"fmt"
	"go/parser"
	"go/token"
	"io"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/incident"
	"github.com/pidginhost/csm/internal/processctx"
)

type incidentCheckPolicy struct {
	Kind      string   `json:"kind"`
	Selectors []string `json:"selectors"`
	Reason    string   `json:"reason"`
	Checks    []string `json:"checks"`
}

// Columns: no attributes; source; source/mailbox/tenant; tenant;
// source/ephemeral process; source/tenant. These are policy expectations,
// independent of the production selector tables and classifier branches.
var incidentKindExpectations = map[string][6]incident.Kind{
	"attributes": {
		incident.KindWebAccountCompromise, incident.KindWebAccountCompromise, incident.KindMailboxTakeover,
		incident.KindWebAccountCompromise, incident.KindPostExploitProcess, incident.KindWebAccountCompromise,
	},
	"host": {
		incident.KindHostIntegrityRisk, incident.KindHostIntegrityRisk, incident.KindHostIntegrityRisk,
		incident.KindHostIntegrityRisk, incident.KindHostIntegrityRisk, incident.KindHostIntegrityRisk,
	},
	"mail_attack": {
		incident.KindWebAccountCompromise, incident.KindMailboxBruteforce, incident.KindMailboxBruteforce,
		incident.KindWebAccountCompromise, incident.KindMailboxBruteforce, incident.KindMailboxBruteforce,
	},
	"web_attack": {
		incident.KindWebAccountCompromise, incident.KindWebAttack, incident.KindWebAttack,
		incident.KindWebAccountCompromise, incident.KindWebAttack, incident.KindWebAttack,
	},
	"mail_takeover": {
		incident.KindMailboxTakeover, incident.KindMailboxTakeover, incident.KindMailboxTakeover,
		incident.KindMailboxTakeover, incident.KindMailboxTakeover, incident.KindMailboxTakeover,
	},
	"remote_reputation": {
		incident.KindWebAccountCompromise, incident.KindWebAttack, incident.KindMailboxTakeover,
		incident.KindWebAccountCompromise, incident.KindPostExploitProcess, incident.KindWebAccountCompromise,
	},
}

func readIncidentCheckPolicy(t *testing.T) []incidentCheckPolicy {
	t.Helper()
	f, err := os.Open("testdata/check-policy.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	decoder := json.NewDecoder(f)
	decoder.DisallowUnknownFields()
	var policy []incidentCheckPolicy
	if err := decoder.Decode(&policy); err != nil {
		t.Fatal(err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		t.Fatalf("unexpected data after check policy: %v", err)
	}
	return policy
}

func TestIncidentCheckPolicyIsComplete(t *testing.T) {
	registered := registeredIncidentChecks()
	for _, problem := range validateIncidentCheckPolicy(readIncidentCheckPolicy(t), registered, readIncidentSelectors(t, registered)) {
		t.Error(problem)
	}
}

func validateIncidentCheckPolicy(policy []incidentCheckPolicy, registered map[string]bool, actual incidentSelectors) []string {
	var problems []string
	report := func(format string, args ...any) { problems = append(problems, fmt.Sprintf(format, args...)) }
	seen := make(map[string]bool)
	wanted := make(incidentSelectors)
	for i, group := range policy {
		if _, ok := incidentKindExpectations[group.Kind]; !ok {
			report("group %d: unknown or missing kind role %q", i, group.Kind)
		}
		if strings.TrimSpace(group.Reason) == "" || len(group.Checks) == 0 || group.Selectors == nil {
			report("group %d needs a reason, checks and explicit selectors (use [] for none)", i)
		}
		selected := make(map[string]bool)
		for _, selector := range group.Selectors {
			if selected[selector] {
				report("group %d repeats selector %s", i, selector)
			}
			selected[selector] = true
			if _, ok := actual[selector]; !ok {
				report("group %d names missing selector %s", i, selector)
			}
			if wanted[selector] == nil {
				wanted[selector] = make(map[string]bool)
			}
		}
		for _, check := range group.Checks {
			if !registered[check] {
				report("policy names unregistered check %s", check)
			}
			if seen[check] {
				report("policy repeats check %s", check)
			}
			seen[check] = true
			for _, selector := range group.Selectors {
				wanted[selector][check] = true
			}
		}
	}
	for check := range registered {
		if !seen[check] {
			report("registered check %s needs an explicit incident policy", check)
		}
	}
	for selector, members := range actual {
		expected, ok := wanted[selector]
		if !ok {
			report("selector %s needs an explicit membership contract", selector)
		}
		for check := range members {
			if !expected[check] {
				report("selector %s has unexpected member %s", selector, check)
			}
		}
	}
	for selector, members := range wanted {
		for check := range members {
			if !actual[selector][check] {
				report("selector %s is missing eligible check %s", selector, check)
			}
		}
	}
	slices.Sort(problems)
	return problems
}

func TestRegisteredCheckKindPolicy(t *testing.T) {
	scenarios := []struct {
		name    string
		finding alert.Finding
	}{
		{"plain", alert.Finding{}},
		{"source", alert.Finding{SourceIP: "192.0.2.1"}},
		{"source_mailbox_tenant", alert.Finding{SourceIP: "192.0.2.1", Mailbox: "user@example.com", TenantID: "tenant"}},
		{"tenant", alert.Finding{TenantID: "tenant"}},
		{"source_process", alert.Finding{SourceIP: "192.0.2.1", Process: &processctx.ProcessContext{Exe: "/tmp/payload", PID: 123}}},
		{"source_tenant", alert.Finding{SourceIP: "192.0.2.1", TenantID: "tenant"}},
	}
	for _, group := range readIncidentCheckPolicy(t) {
		want, ok := incidentKindExpectations[group.Kind]
		if !ok {
			t.Fatalf("unknown kind role %q", group.Kind)
		}
		for _, check := range group.Checks {
			t.Run(check, func(t *testing.T) {
				for i, scenario := range scenarios {
					f := scenario.finding
					f.Check = check
					if got := incident.ClassifyKind(f); got != want[i] {
						t.Errorf("%s: kind = %s, want %s", scenario.name, got, want[i])
					}
				}
				f := scenarios[2].finding
				f.Check = check
				if got, want := incident.KeyFor(f).IsEmpty(), slices.Contains(group.Selectors, "excludedFromIncidents"); got != want {
					t.Errorf("attributed finding excluded = %v, want %v", got, want)
				}
			})
		}
	}
}

func TestIncidentPolicyGuardRejectsDrift(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func([]incidentCheckPolicy, map[string]bool, incidentSelectors) []incidentCheckPolicy
		want   string
	}{
		{"new detector", func(p []incidentCheckPolicy, r map[string]bool, _ incidentSelectors) []incidentCheckPolicy {
			r["new_detector"] = true
			return p
		}, "new_detector needs an explicit incident policy"},
		{"missing eligible member", func(p []incidentCheckPolicy, _ map[string]bool, s incidentSelectors) []incidentCheckPolicy {
			delete(s["hostIntegrityChecks"], "integrity")
			return p
		}, "missing eligible check integrity"},
		{"unregistered member", func(p []incidentCheckPolicy, _ map[string]bool, s incidentSelectors) []incidentCheckPolicy {
			s["hostIntegrityChecks"]["typo"] = true
			return p
		}, "unexpected member typo"},
		{"new empty table", func(p []incidentCheckPolicy, _ map[string]bool, s incidentSelectors) []incidentCheckPolicy {
			s["newChecks"] = map[string]bool{}
			return p
		}, "newChecks needs an explicit membership contract"},
		{"removed table", func(p []incidentCheckPolicy, _ map[string]bool, s incidentSelectors) []incidentCheckPolicy {
			delete(s, "hostIntegrityChecks")
			return p
		}, "names missing selector hostIntegrityChecks"},
		{"omitted policy", func(_ []incidentCheckPolicy, _ map[string]bool, _ incidentSelectors) []incidentCheckPolicy {
			return nil
		}, "integrity needs an explicit incident policy"},
		{"duplicate detector", func(p []incidentCheckPolicy, _ map[string]bool, _ incidentSelectors) []incidentCheckPolicy {
			p[0].Checks = append(p[0].Checks, "integrity")
			return p
		}, "repeats check integrity"},
		{"unregistered policy", func(p []incidentCheckPolicy, _ map[string]bool, _ incidentSelectors) []incidentCheckPolicy {
			p[0].Checks = append(p[0].Checks, "typo")
			return p
		}, "unregistered check typo"},
		{"missing reason", func(p []incidentCheckPolicy, _ map[string]bool, _ incidentSelectors) []incidentCheckPolicy {
			p[0].Reason = ""
			return p
		}, "needs a reason"},
		{"implicit selectors", func(p []incidentCheckPolicy, _ map[string]bool, _ incidentSelectors) []incidentCheckPolicy {
			p[0].Selectors = nil
			return p
		}, "explicit selectors"},
		{"unknown role", func(p []incidentCheckPolicy, _ map[string]bool, _ incidentSelectors) []incidentCheckPolicy {
			p[0].Kind = "unknown"
			return p
		}, "unknown or missing kind role"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			policy := []incidentCheckPolicy{{Kind: "host", Selectors: []string{"hostIntegrityChecks"}, Reason: "Binary/config tamper affects the host.", Checks: []string{"integrity"}}}
			registered := map[string]bool{"integrity": true}
			selectors := incidentSelectors{"hostIntegrityChecks": {"integrity": true}}
			if problems := validateIncidentCheckPolicy(policy, registered, selectors); len(problems) != 0 {
				t.Fatalf("valid control rejected: %v", problems)
			}
			policy = tc.change(policy, registered, selectors)
			if problems := strings.Join(validateIncidentCheckPolicy(policy, registered, selectors), "\n"); !strings.Contains(problems, tc.want) {
				t.Fatalf("guard returned %q, want %q", problems, tc.want)
			}
		})
	}
}

func TestIncidentSelectorInventory(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "selectors.go", `package incident
var renamedSet = map[string]bool{"integrity": true}
var newChecks = map[string]struct{}{}
func kindCheck(check string, unrelated int) bool {
  switch unrelated { case 1: }
  if strings.HasPrefix(check, "http_") { return true }
  switch strings.ToLower(strings.TrimSpace(check)) {
  case "webshell": return true
  }
  return false
}`, 0)
	if err != nil {
		t.Fatal(err)
	}
	got := make(incidentSelectors)
	if err := inventoryIncidentSelectors(file, map[string]bool{"http_probe": true, "integrity": true, "webshell": true}, got); err != nil {
		t.Fatal(err)
	}
	want := incidentSelectors{
		"renamedSet": {"integrity": true},
		"newChecks":  {},
		"kindCheck":  {"http_probe": true, "webshell": true},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("inventory = %v, want %v", got, want)
	}
}

func TestCompoundPolicyMembersEscalateIncidents(t *testing.T) {
	sets := make(map[string][]string)
	for _, group := range readIncidentCheckPolicy(t) {
		for _, selector := range group.Selectors {
			sets[selector] = append(sets[selector], group.Checks...)
		}
	}
	for _, pair := range []struct {
		left, right string
		tenant      string
		want        incident.Kind
	}{
		{"compoundPostExploitWebChecks", "compoundPostExploitNetworkChecks", "tenant", incident.KindPostExploitProcess},
		{"compoundHostPrivescUID0Checks", "compoundHostPrivescSUIDChecks", "", incident.KindHostTakeover},
		{"compoundHostPrivescUID0Checks", "compoundHostPrivescBadASNChecks", "", incident.KindHostTakeover},
		{"compoundHostPrivescSUIDChecks", "compoundHostPrivescBadASNChecks", "", incident.KindHostTakeover},
	} {
		if len(sets[pair.left]) == 0 || len(sets[pair.right]) == 0 {
			t.Fatalf("compound leg missing: %s + %s", pair.left, pair.right)
		}
		for _, left := range sets[pair.left] {
			for _, right := range sets[pair.right] {
				for _, sequence := range [][2]string{{left, right}, {right, left}} {
					t.Run(strings.Join(sequence[:], "+"), func(t *testing.T) {
						c := incident.NewCorrelator(incident.CorrelatorConfig{OpenThreshold: 3})
						firstID, created, err := c.OnFinding(alert.Finding{Check: sequence[0], Severity: alert.Critical, TenantID: pair.tenant})
						if err != nil || !created || firstID == "" {
							t.Fatalf("first leg: id=%q created=%v err=%v", firstID, created, err)
						}
						if before, ok := c.Get(firstID); !ok || before.Kind == pair.want {
							t.Fatalf("one leg must not produce compound kind: %+v", before)
						}
						mergedID, created, err := c.OnFinding(alert.Finding{Check: sequence[1], Severity: alert.Critical, TenantID: pair.tenant})
						if err != nil || created || mergedID != firstID {
							t.Fatalf("second leg: id=%q created=%v err=%v", mergedID, created, err)
						}
						if after, ok := c.Get(firstID); !ok || after.Kind != pair.want {
							t.Fatalf("compound incident = %+v, want %s", after, pair.want)
						}
					})
				}
			}
		}
	}
}
