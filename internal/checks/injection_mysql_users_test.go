package checks

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/state"
)

// CheckMySQLUsers behavior:
//   - mysql command fails / returns nil → no findings
//   - empty output → no findings (no non-standard superusers)
//   - first call with output → no finding (just establishes baseline hash)
//   - second call with SAME output → no finding (hash unchanged)
//   - second call with DIFFERENT output → emits "superuser accounts changed"

func TestCheckMySQLUsersMySQLCommandFailsReturnsNil(t *testing.T) {
	withMockCmd(t, &mockCmd{
		run: func(name string, args ...string) ([]byte, error) {
			if name == "mysql" {
				return nil, errors.New("mysql: command not found")
			}
			return nil, nil
		},
	})
	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()

	if findings := CheckMySQLUsers(context.Background(), nil, st); findings != nil {
		t.Errorf("expected nil when mysql fails, got %d findings", len(findings))
	}
}

func TestCheckMySQLUsersEmptyOutputReturnsNil(t *testing.T) {
	withMockCmd(t, &mockCmd{
		run: func(name string, args ...string) ([]byte, error) {
			return []byte(""), nil
		},
	})
	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()

	if findings := CheckMySQLUsers(context.Background(), nil, st); findings != nil {
		t.Errorf("expected nil for empty output (no non-standard superusers), got %d", len(findings))
	}
}

func TestCheckMySQLUsersFirstRunEstablishesBaselineNoFinding(t *testing.T) {
	withMockCmd(t, &mockCmd{
		run: func(name string, args ...string) ([]byte, error) {
			// One non-standard superuser present.
			return []byte("admin_user\tlocalhost\n"), nil
		},
	})
	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()

	findings := CheckMySQLUsers(context.Background(), nil, st)
	if len(findings) != 0 {
		t.Errorf("first run should establish baseline without a finding, got %d", len(findings))
	}
}

func TestCheckMySQLUsersUnchangedHashNoFinding(t *testing.T) {
	withMockCmd(t, &mockCmd{
		run: func(name string, args ...string) ([]byte, error) {
			return []byte("admin_user\tlocalhost\n"), nil
		},
	})
	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()

	// First run establishes baseline.
	_ = CheckMySQLUsers(context.Background(), nil, st)

	// Second run with same output → no finding.
	findings := CheckMySQLUsers(context.Background(), nil, st)
	if len(findings) != 0 {
		t.Errorf("unchanged superusers should not produce findings, got %d: %+v",
			len(findings), findings)
	}
}

func TestCheckMySQLUsersChangedHashEmitsHighFinding(t *testing.T) {
	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()

	// First run with one user — establishes baseline.
	withMockCmd(t, &mockCmd{
		run: func(name string, args ...string) ([]byte, error) {
			return []byte("admin_user\tlocalhost\n"), nil
		},
	})
	_ = CheckMySQLUsers(context.Background(), nil, st)

	// Second run with different output (an attacker added a new superuser).
	withMockCmd(t, &mockCmd{
		run: func(name string, args ...string) ([]byte, error) {
			return []byte("admin_user\tlocalhost\nbackdoor\t%\n"), nil
		},
	})
	findings := CheckMySQLUsers(context.Background(), nil, st)

	hasChange := false
	for _, f := range findings {
		if f.Check == "mysql_superuser" && f.Severity == alert.High &&
			strings.Contains(f.Message, "changed") {
			hasChange = true
			if !strings.Contains(f.Details, "backdoor") {
				t.Errorf("finding details should include the new superuser; got %q", f.Details)
			}
			break
		}
	}
	if !hasChange {
		t.Errorf("expected high-severity 'superuser accounts changed' finding, got %+v", findings)
	}
}
