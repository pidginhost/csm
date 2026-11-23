package rollback

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/integrity"
	"github.com/pidginhost/csm/internal/store"
)

// A failed helper must retain recovery state and never trigger a restart.
// Once the helper succeeds, both operator revert and startup recovery restore
// the exact snapshot before clearing the pending record and restarting.
func TestRollbackUsesConfigWriter(t *testing.T) {
	for _, startup := range []bool{false, true} {
		name := "operator"
		if startup {
			name = "startup"
		}
		t.Run(name, func(t *testing.T) {
			m, db, path, restarts := newTestManager(t)
			prev := []byte("hostname: previous\n")
			prev = append(prev, []byte("integrity:\n  config_hash: "+integrity.HashConfigStableBytes(prev)+"\n")...)
			if err := db.SaveFirewallRollback(store.FirewallRollback{PrevYAML: prev, ExpiresAt: time.Now().Add(-time.Minute)}); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			failure := errors.New("helper denied")
			calls := 0
			integrity.SetConfigWriter(func(c integrity.SignedConfig) error {
				calls++
				if c.Path != path || !bytes.Equal(c.Bytes, prev) || c.Fragments != nil {
					t.Fatal("rollback snapshot changed")
				}
				if failure != nil {
					return failure
				}
				return integrity.WriteSignedConfig(c)
			})
			t.Cleanup(func() { integrity.SetConfigWriter(nil) })
			revert := func() error {
				if startup {
					_, err := m.RecoverOnStartup(context.Background())
					return err
				}
				return m.Revert(context.Background())
			}
			if err := revert(); !errors.Is(err, failure) {
				t.Fatalf("error = %v", err)
			}
			if got, err := os.ReadFile(path); err != nil || !bytes.Equal(got, before) {
				t.Fatal("failed helper changed config")
			}
			if _, pending := db.GetFirewallRollback(); !pending || restarts.Load() != 0 || calls != 1 {
				t.Fatal("failed helper lost recovery or restarted")
			}
			failure = nil
			if err := revert(); err != nil {
				t.Fatal(err)
			}
			if got, err := os.ReadFile(path); err != nil || !bytes.Equal(got, prev) {
				t.Fatal("successful helper did not restore snapshot")
			}
			if _, pending := db.GetFirewallRollback(); pending || restarts.Load() != 1 || calls != 2 {
				t.Fatal("successful helper did not finish recovery")
			}
		})
	}
}
