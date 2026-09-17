//go:build linux

package firewall

import (
	"errors"
	"testing"

	"github.com/google/nftables"
)

func TestRulesetBaselineFollowsOnlySuccessfulApply(t *testing.T) {
	conn, captured := nftConnCapturingRules(t)
	live := "rules A"
	var captureErr error
	e := &Engine{
		conn: conn, cfg: &FirewallConfig{}, statePath: t.TempDir(),
		listTables: func() ([]*nftables.Table, error) { return nil, nil },
		readRuleset: func() (string, error) {
			if len(*captured) == 0 {
				t.Error("baseline read before kernel transaction committed")
			}
			if captureErr != nil {
				return "", captureErr
			}
			return live, nil
		},
	}
	if err := e.Apply(); err != nil {
		t.Fatal(err)
	}
	live = "rules B"
	current, applied, err := e.RulesetSnapshot()
	if err != nil || current != live || applied != "rules A" {
		t.Fatalf("external edit: current=%q applied=%q err=%v", current, applied, err)
	}
	e.listTables = func() ([]*nftables.Table, error) { return nil, errors.New("list failed") }
	if err := e.Apply(); err == nil {
		t.Fatal("failed table listing accepted")
	}
	if _, applied, _ := e.RulesetSnapshot(); applied != "rules A" {
		t.Fatal("failed Apply replaced the baseline")
	}
	e.listTables = func() ([]*nftables.Table, error) { return nil, nil }
	if err := e.Apply(); err != nil {
		t.Fatal(err)
	}
	if _, applied, _ := e.RulesetSnapshot(); applied != live {
		t.Fatal("successful Apply did not replace the baseline")
	}
	captureErr = errors.New("nft unavailable")
	if err := e.Apply(); err != nil {
		t.Fatalf("monitor failure must not undo the applied firewall: %v", err)
	}
	captureErr = nil
	live = "rules C"
	if _, applied, err := e.RulesetSnapshot(); err != nil || applied != "" {
		t.Fatalf("late read blessed unverified rules: applied=%q err=%v", applied, err)
	}
}
