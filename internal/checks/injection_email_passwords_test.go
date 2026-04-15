package checks

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/store"
)

// withTestStore opens a fresh bbolt store and registers it as the global,
// restoring the previous global on cleanup. Returns the *store.DB so tests
// can pre-populate state if needed.
func withTestStore(t *testing.T) *store.DB {
	t.Helper()
	db, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	prev := store.Global()
	store.SetGlobal(db)
	t.Cleanup(func() {
		store.SetGlobal(prev)
		_ = db.Close()
	})
	return db
}

// --- CheckEmailPasswords -----------------------------------------------

func TestCheckEmailPasswordsNilStoreReturnsNil(t *testing.T) {
	prev := store.Global()
	store.SetGlobal(nil)
	t.Cleanup(func() { store.SetGlobal(prev) })

	cfg := &config.Config{}
	cfg.EmailProtection.PasswordCheckIntervalMin = 60

	if findings := CheckEmailPasswords(context.Background(), cfg, nil); findings != nil {
		t.Errorf("expected nil findings with nil store, got %d", len(findings))
	}
}

func TestCheckEmailPasswordsNoShadowFilesEarlyReturn(t *testing.T) {
	withTestStore(t)
	withMockOS(t, &mockOS{
		glob: func(string) ([]string, error) { return nil, nil },
	})

	cfg := &config.Config{}
	cfg.EmailProtection.PasswordCheckIntervalMin = 60

	findings := CheckEmailPasswords(context.Background(), cfg, nil)
	if findings != nil {
		t.Errorf("no shadow files should yield nil, got %d", len(findings))
	}
}

func TestCheckEmailPasswordsThrottleSkipsIfRecentRefresh(t *testing.T) {
	db := withTestStore(t)
	// Mark a refresh as having just happened.
	_ = db.SetEmailPWLastRefresh(time.Now())

	withMockOS(t, &mockOS{
		glob: func(string) ([]string, error) {
			return []string{"/home/alice/etc/example.com/shadow"}, nil
		},
	})

	cfg := &config.Config{}
	cfg.EmailProtection.PasswordCheckIntervalMin = 60

	findings := CheckEmailPasswords(context.Background(), cfg, nil)
	if findings != nil {
		t.Errorf("throttle should skip and return nil, got %d findings", len(findings))
	}
}

func TestCheckEmailPasswordsForceAllOverridesThrottle(t *testing.T) {
	db := withTestStore(t)
	_ = db.SetEmailPWLastRefresh(time.Now()) // recent refresh

	prev := ForceAll
	ForceAll = true
	t.Cleanup(func() { ForceAll = prev })

	// Provide a discoverable shadow file that's empty (no entries).
	withMockOS(t, &mockOS{
		glob: func(p string) ([]string, error) {
			if strings.Contains(p, "shadow") {
				return []string{"/home/alice/etc/example.com/shadow"}, nil
			}
			return nil, nil
		},
		open: func(name string) (*os.File, error) {
			tmp := t.TempDir() + "/shadow"
			_ = os.WriteFile(tmp, []byte(""), 0644)
			return os.Open(tmp)
		},
	})

	cfg := &config.Config{}
	cfg.EmailProtection.PasswordCheckIntervalMin = 60

	// ForceAll bypasses throttle. With no entries we just verify the
	// function ran (no panic, returned nil).
	_ = CheckEmailPasswords(context.Background(), cfg, nil)
}

func TestCheckEmailPasswordsHeuristicMatchEmitsCritical(t *testing.T) {
	withTestStore(t)

	// Set up: shadow file with one mailbox whose hash matches a heuristic
	// candidate. The mock cmd accepts the doveadm call when candidate
	// matches what we expect generateCandidates to produce for our entry.
	shadowContent := "alice@example.com:{CRYPT}$6$salt$hashpattern\n"

	withMockOS(t, &mockOS{
		glob: func(p string) ([]string, error) {
			if strings.Contains(p, "shadow") {
				return []string{"/home/alice/etc/example.com/shadow"}, nil
			}
			return nil, nil
		},
		open: func(name string) (*os.File, error) {
			tmp := t.TempDir() + "/shadow"
			_ = os.WriteFile(tmp, []byte(shadowContent), 0644)
			return os.Open(tmp)
		},
	})
	withMockCmd(t, &mockCmd{
		run: func(name string, args ...string) ([]byte, error) {
			if name == "doveadm" {
				// Accept any password as valid (simulates a hash that
				// matches every candidate). Real doveadm would only
				// match specific ones.
				return nil, nil
			}
			return nil, fmt.Errorf("unexpected: %s", name)
		},
	})
	// Mock HIBP to claim "found in 0 breaches" so the test doesn't hit
	// pwnedpasswords.com.
	withTestHIBP(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintln(w, "0:0")
	})

	cfg := &config.Config{}
	cfg.EmailProtection.PasswordCheckIntervalMin = 60

	findings := CheckEmailPasswords(context.Background(), cfg, nil)
	hasWeak := false
	for _, f := range findings {
		if f.Check == "email_weak_password" && f.Severity == alert.Critical {
			hasWeak = true
			if !strings.Contains(f.Message, "alice@example.com") {
				t.Errorf("finding message should mention mailbox: %q", f.Message)
			}
			break
		}
	}
	if !hasWeak {
		t.Errorf("expected email_weak_password critical finding when doveadm matches, got: %+v", findings)
	}
}

func TestCheckEmailPasswordsSkipsUnchangedHash(t *testing.T) {
	db := withTestStore(t)
	// Pre-record a fingerprint for the mailbox we'll discover.
	hash := "{CRYPT}$6$salt$preexisting"
	fp := hashFingerprint(hash)
	_ = db.SetMetaString("email:pwaudit:alice:user@example.com", fp)

	// Shadow file format puts just the local-part on the LHS;
	// readShadowFile combines it with the domain (extracted from the
	// /home/{account}/etc/{domain}/shadow path) to form fullMailbox.
	shadowContent := "user:" + hash + "\n"
	withMockOS(t, &mockOS{
		glob: func(p string) ([]string, error) {
			if strings.Contains(p, "shadow") {
				return []string{"/home/alice/etc/example.com/shadow"}, nil
			}
			return nil, nil
		},
		open: func(name string) (*os.File, error) {
			tmp := t.TempDir() + "/shadow"
			_ = os.WriteFile(tmp, []byte(shadowContent), 0644)
			return os.Open(tmp)
		},
	})
	doveadmCalls := 0
	withMockCmd(t, &mockCmd{
		run: func(name string, args ...string) ([]byte, error) {
			if name == "doveadm" {
				doveadmCalls++
			}
			return nil, fmt.Errorf("should not have been called")
		},
	})

	cfg := &config.Config{}
	cfg.EmailProtection.PasswordCheckIntervalMin = 60

	_ = CheckEmailPasswords(context.Background(), cfg, nil)
	if doveadmCalls != 0 {
		t.Errorf("expected 0 doveadm calls when hash unchanged, got %d", doveadmCalls)
	}
}
