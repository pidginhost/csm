package checks

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

// shadowFakeInfo returns a fake FileInfo with a caller-controlled ModTime
// so CheckShadowChanges sees successive calls as "shadow was modified".
type shadowFakeInfo struct {
	name string
	mt   time.Time
}

func (f shadowFakeInfo) Name() string       { return f.name }
func (f shadowFakeInfo) Size() int64        { return 100 }
func (f shadowFakeInfo) Mode() os.FileMode  { return 0600 }
func (f shadowFakeInfo) ModTime() time.Time { return f.mt }
func (f shadowFakeInfo) IsDir() bool        { return false }
func (f shadowFakeInfo) Sys() any           { return nil }

// shadowMockOS returns a mockOS that serves a fixed /etc/shadow content
// plus a controllable mtime via stat.
func shadowMockOS(content string, mt time.Time) *mockOS {
	return &mockOS{
		stat: func(name string) (os.FileInfo, error) {
			if name == "/etc/shadow" {
				return shadowFakeInfo{name: "shadow", mt: mt}, nil
			}
			return nil, os.ErrNotExist
		},
		readFile: func(name string) ([]byte, error) {
			if name == "/etc/shadow" {
				return []byte(content), nil
			}
			return nil, os.ErrNotExist
		},
	}
}

// mkShadow builds an /etc/shadow with `n` users plus root having the
// given suffix on its hash (use "" for unchanged root).
func mkShadow(rootHashSuffix string, users ...string) string {
	var sb strings.Builder
	sb.WriteString("root:$6$salt$rootbase" + rootHashSuffix + ":19000:0:99999:7:::\n")
	for _, u := range users {
		sb.WriteString(u + ":$6$salt$hash:19000:0:99999:7:::\n")
	}
	return sb.String()
}

func TestCheckShadowChangesRootPasswordChangeEmitsCritical(t *testing.T) {
	initial := mkShadow("", "alice")
	base := time.Now()
	withMockOS(t, shadowMockOS(initial, base))

	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	_ = CheckShadowChanges(context.Background(), &config.Config{}, st)

	// Root hash changed, nothing else. Expect root_password_change.
	withMockOS(t, shadowMockOS(mkShadow("_rotated", "alice"), base.Add(1*time.Minute)))
	got := CheckShadowChanges(context.Background(), &config.Config{}, st)

	hasRoot := false
	for _, f := range got {
		if f.Check == "root_password_change" && f.Severity == alert.Critical {
			hasRoot = true
		}
	}
	if !hasRoot {
		t.Errorf("expected root_password_change critical finding, got %+v", got)
	}
}

func TestCheckShadowChangesBulkChangeEmitsHigh(t *testing.T) {
	initial := mkShadow("", "alice", "bob", "carol", "dave", "eve", "frank")
	base := time.Now()
	withMockOS(t, shadowMockOS(initial, base))

	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	_ = CheckShadowChanges(context.Background(), &config.Config{}, st)

	// All six user hashes changed. userCount will be 6 (>=5) → bulk.
	changed := "root:$6$salt$rootbase:19000:0:99999:7:::\n" +
		"alice:$6$salt$H1:19000:0:99999:7:::\n" +
		"bob:$6$salt$H2:19000:0:99999:7:::\n" +
		"carol:$6$salt$H3:19000:0:99999:7:::\n" +
		"dave:$6$salt$H4:19000:0:99999:7:::\n" +
		"eve:$6$salt$H5:19000:0:99999:7:::\n" +
		"frank:$6$salt$H6:19000:0:99999:7:::\n"
	withMockOS(t, shadowMockOS(changed, base.Add(1*time.Minute)))

	got := CheckShadowChanges(context.Background(), &config.Config{}, st)
	hasBulk := false
	for _, f := range got {
		if f.Check == "bulk_password_change" && f.Severity == alert.High {
			hasBulk = true
		}
	}
	if !hasBulk {
		t.Errorf("expected bulk_password_change high finding, got %+v", got)
	}
}

func TestCheckShadowChangesMissingShadowFileReturnsNil(t *testing.T) {
	withMockOS(t, &mockOS{
		stat: func(string) (os.FileInfo, error) { return nil, os.ErrNotExist },
	})
	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()

	got := CheckShadowChanges(context.Background(), &config.Config{}, st)
	if got != nil {
		t.Errorf("missing /etc/shadow should yield nil, got %d findings", len(got))
	}
}

func TestCheckShadowChangesFirstRunStoresBaselineNoFindings(t *testing.T) {
	withMockOS(t, shadowMockOS(mkShadow("", "alice"), time.Now()))

	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()

	got := CheckShadowChanges(context.Background(), &config.Config{}, st)
	if len(got) != 0 {
		t.Errorf("first run should only baseline, got %d findings", len(got))
	}
}

func TestCheckShadowChangesUPCPWindowDowngradesToWarning(t *testing.T) {
	initial := mkShadow("", "alice")
	base := time.Now()
	withMockOS(t, shadowMockOS(initial, base))

	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	_ = CheckShadowChanges(context.Background(), &config.Config{}, st)

	// Single user changed (not root, not bulk). Inside upcp window the
	// severity must be Warning instead of Critical.
	changed := mkShadow("", "alice") + "newuser:$6$salt$h:19000:0:99999:7:::\n"
	withMockOS(t, shadowMockOS(changed, base.Add(1*time.Minute)))

	// Set the upcp window to cover the current minute.
	now := time.Now()
	cfg := &config.Config{}
	cfg.Suppressions.UPCPWindowStart = "00:00"
	cfg.Suppressions.UPCPWindowEnd = "23:59"
	_ = now

	got := CheckShadowChanges(context.Background(), cfg, st)
	hasWarning := false
	for _, f := range got {
		if f.Check == "shadow_change" && f.Severity == alert.Warning {
			hasWarning = true
		}
	}
	if !hasWarning {
		t.Errorf("expected shadow_change warning during upcp window, got %+v", got)
	}
}
