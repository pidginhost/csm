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
	previousRefresh := time.Now().Add(-time.Minute)
	if err := db.SetEmailPWLastRefresh(previousRefresh); err != nil {
		t.Fatal(err)
	}

	prev := ForceAll
	ForceAll = true
	t.Cleanup(func() { ForceAll = prev })

	// An empty but readable shadow must still refresh the completed audit.
	opens := 0
	withMockOS(t, &mockOS{
		glob: func(p string) ([]string, error) {
			if strings.Contains(p, "shadow") {
				return []string{"/home/alice/etc/example.com/shadow"}, nil
			}
			return nil, nil
		},
		open: func(name string) (*os.File, error) {
			opens++
			tmp := t.TempDir() + "/shadow"
			_ = os.WriteFile(tmp, []byte(""), 0644)
			return os.Open(tmp)
		},
	})

	cfg := &config.Config{}
	cfg.EmailProtection.PasswordCheckIntervalMin = 60

	findings := CheckEmailPasswords(context.Background(), cfg, nil)
	if len(findings) != 0 || opens != 1 || !db.GetEmailPWLastRefresh().After(previousRefresh) {
		t.Fatalf("forced audit did not read and refresh: findings=%v, opens=%d", findings, opens)
	}
}

func TestCheckEmailPasswordsHeuristicMatchEmitsCritical(t *testing.T) {
	withTestStore(t)

	shadowContent := "alice:{PLAIN}alice2026\n"

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
	// Mock HIBP to claim "found in 0 breaches" so the test doesn't hit
	// pwnedpasswords.com.
	withTestHIBP(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintln(w, "0:0")
	})

	cfg := &config.Config{}
	cfg.EmailProtection.PasswordCheckIntervalMin = 60

	findings := CheckEmailPasswords(context.Background(), cfg, nil)
	if len(findings) != 1 || findings[0].Check != "email_weak_password" || findings[0].Severity != alert.Critical || findings[0].Mailbox != "alice@example.com" {
		t.Fatalf("expected exactly one critical finding for alice@example.com: %+v", findings)
	}
}

func TestCheckEmailPasswordsSkipsUnchangedHash(t *testing.T) {
	db := withTestStore(t)
	// Pre-record a fingerprint for the mailbox we'll discover.
	hash := "{PLAIN}example"
	fp := "v2:" + hashFingerprint(hash)
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

	cfg := &config.Config{}
	cfg.EmailProtection.PasswordCheckIntervalMin = 60

	findings := CheckEmailPasswords(context.Background(), cfg, nil)
	if len(findings) != 0 || db.GetMetaString("email:pwaudit:alice:user@example.com") != fp || db.GetEmailPWLastRefresh().IsZero() {
		t.Fatalf("unchanged, previously audited hash was checked again: %+v", findings)
	}
}

func TestCheckEmailPasswordsDoesNotRecordAuditWhenContextCanceledAfterRead(t *testing.T) {
	db := withTestStore(t)

	ctx, cancel := context.WithCancel(context.Background())
	shadowContent := "user:{CRYPT}$6$salt$hash\n"
	withMockOS(t, &mockOS{
		glob: func(p string) ([]string, error) {
			if strings.Contains(p, "shadow") {
				return []string{"/home/alice/etc/example.com/shadow"}, nil
			}
			return nil, nil
		},
		open: func(name string) (*os.File, error) {
			tmp := t.TempDir() + "/shadow"
			if err := os.WriteFile(tmp, []byte(shadowContent), 0644); err != nil {
				t.Fatal(err)
			}
			f, err := os.Open(tmp)
			cancel()
			return f, err
		},
	})

	cfg := &config.Config{}
	cfg.EmailProtection.PasswordCheckIntervalMin = 60

	findings := CheckEmailPasswords(ctx, cfg, nil)
	if len(findings) != 0 {
		t.Errorf("canceled scan should not emit findings, got %v", findings)
	}
	if db.GetMetaString("email:pwaudit:alice:user@example.com") != "" {
		t.Error("canceled scan recorded mailbox fingerprint")
	}
	if got := db.GetEmailPWLastRefresh(); !got.IsZero() {
		t.Errorf("canceled scan recorded refresh timestamp: %s", got)
	}
}
