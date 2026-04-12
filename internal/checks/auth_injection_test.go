package checks

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

func TestCheckUID0AccountsNormal(t *testing.T) {
	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			if name == "/etc/passwd" {
				return []byte("root:x:0:0:root:/root:/bin/bash\nnobody:x:65534:65534::/:/usr/sbin/nologin\nalice:x:1000:1000::/home/alice:/bin/bash\n"), nil
			}
			return nil, os.ErrNotExist
		},
	})

	findings := CheckUID0Accounts(context.Background(), &config.Config{}, nil)
	if len(findings) != 0 {
		t.Errorf("normal passwd should produce 0 findings, got %d: %v", len(findings), findings)
	}
}

func TestCheckUID0AccountsExtraRoot(t *testing.T) {
	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			if name == "/etc/passwd" {
				return []byte("root:x:0:0:root:/root:/bin/bash\nhacker:x:0:0::/tmp:/bin/bash\n"), nil
			}
			return nil, os.ErrNotExist
		},
	})

	findings := CheckUID0Accounts(context.Background(), &config.Config{}, nil)
	if len(findings) == 0 {
		t.Fatal("expected finding for extra UID 0 account")
	}
}

func TestCheckUID0AccountsMissingPasswd(t *testing.T) {
	withMockOS(t, &mockOS{})

	findings := CheckUID0Accounts(context.Background(), &config.Config{}, nil)
	if len(findings) != 0 {
		t.Errorf("missing passwd should produce 0, got %d", len(findings))
	}
}

func TestCheckShadowChangesNoFile(t *testing.T) {
	withMockOS(t, &mockOS{})

	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	findings := CheckShadowChanges(context.Background(), &config.Config{}, store)
	if len(findings) != 0 {
		t.Errorf("missing shadow should produce 0, got %d", len(findings))
	}
}

func TestCheckHealthAllCommandsFound(t *testing.T) {
	withMockCmd(t, &mockCmd{
		lookPath: func(name string) (string, error) {
			return "/usr/bin/" + name, nil
		},
	})

	findings := CheckHealth(context.Background(), &config.Config{}, nil)
	// May still produce findings for state dir writability on dev machines.
	// Verify no command-not-found findings.
	for _, f := range findings {
		if strings.Contains(f.Message, "command not found") {
			t.Errorf("unexpected missing command: %s", f.Message)
		}
	}
}

func TestCheckHealthMissingCommand(t *testing.T) {
	withMockCmd(t, &mockCmd{
		lookPath: func(name string) (string, error) {
			return "", os.ErrNotExist
		},
	})

	findings := CheckHealth(context.Background(), &config.Config{}, nil)
	if len(findings) == 0 {
		t.Error("missing commands should produce findings")
	}
}
