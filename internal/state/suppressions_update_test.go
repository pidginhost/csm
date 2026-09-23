package state

import (
	"errors"
	"fmt"
	"sync"
	"testing"
)

func TestUpdateSuppressionsKeepsConcurrentChanges(t *testing.T) {
	s := openTestStore(t)
	const n = 50
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			err := s.UpdateSuppressions(func(rules []SuppressionRule) ([]SuppressionRule, error) {
				return append(rules, SuppressionRule{ID: fmt.Sprint(i), Check: "webshell"}), nil
			})
			if err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	if got := len(s.LoadSuppressions()); got != n {
		t.Fatalf("%d of %d rules kept", got, n)
	}
}

func TestUpdateSuppressionsErrorLeavesRulesUnchanged(t *testing.T) {
	s := openTestStore(t)
	if err := s.SaveSuppressions([]SuppressionRule{{ID: "keep", Check: "webshell"}}); err != nil {
		t.Fatal(err)
	}
	refused := errors.New("refused")
	err := s.UpdateSuppressions(func([]SuppressionRule) ([]SuppressionRule, error) {
		return nil, refused
	})
	if !errors.Is(err, refused) {
		t.Fatalf("err = %v, want the callback's error", err)
	}
	rules := s.LoadSuppressions()
	if len(rules) != 1 || rules[0].ID != "keep" {
		t.Fatalf("rules = %+v, want the original rule", rules)
	}
}
