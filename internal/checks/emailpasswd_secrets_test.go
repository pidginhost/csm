package checks

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

func TestPasswordVerificationKeepsSecretsOutOfCommands(t *testing.T) {
	const password = "fixture-secret-123"
	const storedHash = "{PLAIN}" + password
	commands := 0
	withMockCmd(t, &mockCmd{runContext: func(_ context.Context, _ string, args ...string) ([]byte, error) {
		commands++
		for _, arg := range args {
			if strings.Contains(arg, password) || strings.Contains(arg, storedHash) {
				t.Error("password verification exposed a secret in a process argument")
			}
		}
		return nil, nil
	}})
	v := mustEmailPasswordVerifier(t, storedHash)
	if matched, err := v.matches(context.Background(), password); err != nil || !matched {
		t.Fatal("valid fixture password was not verified")
	}
	if commands != 0 {
		t.Fatalf("in-process verification launched %d commands", commands)
	}
}

func TestEmailPasswordFindingsDoNotContainMatchedPassword(t *testing.T) {
	withTestStore(t)
	withWeakPasswords(t, []string{"fixture-secret-123"})
	const password = "fixture-secret-123"
	const storedHash = "{PLAIN}" + password
	path := t.TempDir() + "/shadow"
	if err := os.WriteFile(path, []byte("mailbox:"+storedHash+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	withMockOS(t, &mockOS{
		glob: func(string) ([]string, error) {
			return []string{"/home/alice/etc/example.test/shadow"}, nil
		},
		open: func(string) (*os.File, error) { return os.Open(path) },
	})
	withMockCmd(t, &mockCmd{runContext: func(_ context.Context, _ string, args ...string) ([]byte, error) {
		if args[len(args)-1] == password {
			return nil, nil
		}
		return nil, os.ErrPermission
	}})
	withTestHIBP(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	findings := CheckEmailPasswords(context.Background(), &config.Config{}, nil)
	if len(findings) != 1 || findings[0].Check != "email_weak_password" || findings[0].Severity != alert.Critical {
		t.Fatalf("confirmed weak password did not produce one critical finding: %+v", findings)
	}
	encoded, err := json.Marshal(findings)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), password) || strings.Contains(string(encoded), storedHash) {
		t.Fatal("finding payload exposed the matched password or stored hash")
	}
}

func mustEmailPasswordVerifier(t *testing.T, stored string) *emailPasswordVerifier {
	t.Helper()
	v, err := parseEmailPasswordHash(stored)
	if err != nil {
		t.Fatal(err)
	}
	return v
}
