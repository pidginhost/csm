package checks

import (
	"context"
	"os"
	"testing"
	"time"
)

// statWithMtime lets the mockOS Stat callback return a specific ModTime
// without touching the real filesystem. Separate from injection_batch_test.go's
// fakeFileInfo, which hardcodes ModTime to time.Now() and is unsuitable for
// mtime-ranking assertions.
type statWithMtime struct {
	name    string
	modTime time.Time
}

func (s statWithMtime) Name() string       { return s.name }
func (s statWithMtime) Size() int64        { return 0 }
func (s statWithMtime) Mode() os.FileMode  { return 0o644 }
func (s statWithMtime) ModTime() time.Time { return s.modTime }
func (s statWithMtime) IsDir() bool        { return false }
func (s statWithMtime) Sys() any           { return nil }

// mtimesByPath builds a stat callback that returns the configured ModTime
// for known paths and ErrNotExist for everything else.
func mtimesByPath(times map[string]time.Time) func(string) (os.FileInfo, error) {
	return func(name string) (os.FileInfo, error) {
		t, ok := times[name]
		if !ok {
			return nil, os.ErrNotExist
		}
		return statWithMtime{name: name, modTime: t}, nil
	}
}

func TestRankPathsByMtimeDesc_EmptyInput(t *testing.T) {
	withMockOS(t, &mockOS{})
	got := rankPathsByMtimeDesc(context.Background(), nil, 0)
	if len(got) != 0 {
		t.Errorf("len(got) = %d, want 0", len(got))
	}
}

func TestRankPathsByMtimeDesc_OrdersMostRecentFirst(t *testing.T) {
	now := time.Now()
	times := map[string]time.Time{
		"/a": now.Add(-30 * time.Minute),
		"/b": now.Add(-1 * time.Minute),
		"/c": now.Add(-10 * time.Minute),
	}
	withMockOS(t, &mockOS{stat: mtimesByPath(times)})

	got := rankPathsByMtimeDesc(context.Background(), []string{"/a", "/b", "/c"}, 0)

	want := []string{"/b", "/c", "/a"}
	if len(got) != len(want) {
		t.Fatalf("len(got) = %d, want %d (got=%v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got[%d] = %q, want %q (full=%v)", i, got[i], want[i], got)
		}
	}
}

// Late-alphabet equity: under lex-order plus a downstream cap, account
// "zzz-customer" would be the first to drop. With mtime-desc ranking it
// rises to the top when its files were modified most recently. This is
// the same fairness invariant the May 2026 scanDomlogs fix added for
// per-domain access logs; it must also hold for any /home/* scanner.
func TestRankPathsByMtimeDesc_LateAlphabetWinsUnderCap(t *testing.T) {
	now := time.Now()
	paths := []string{
		"/home/aaa-customer/wp-config.php",
		"/home/bbb-customer/wp-config.php",
		"/home/yyy-customer/wp-config.php",
		"/home/zzz-customer/wp-config.php",
	}
	times := map[string]time.Time{
		paths[0]: now.Add(-7 * 24 * time.Hour),
		paths[1]: now.Add(-3 * 24 * time.Hour),
		paths[2]: now.Add(-1 * time.Hour),
		paths[3]: now.Add(-1 * time.Minute),
	}
	withMockOS(t, &mockOS{stat: mtimesByPath(times)})

	got := rankPathsByMtimeDesc(context.Background(), paths, 2)

	if len(got) != 2 {
		t.Fatalf("len(got) = %d, want 2 (got=%v)", len(got), got)
	}
	if got[0] != paths[3] {
		t.Errorf("got[0] = %q, want %q (lex order would have dropped this)", got[0], paths[3])
	}
	if got[1] != paths[2] {
		t.Errorf("got[1] = %q, want %q", got[1], paths[2])
	}
}

func TestRankPathsByMtimeDesc_EqualMtimeTiebreaksByPath(t *testing.T) {
	t0 := time.Date(2026, 5, 22, 12, 0, 0, 0, time.UTC)
	times := map[string]time.Time{
		"/home/zeta/x":  t0,
		"/home/alpha/x": t0,
		"/home/mid/x":   t0,
	}
	withMockOS(t, &mockOS{stat: mtimesByPath(times)})

	got := rankPathsByMtimeDesc(context.Background(), []string{"/home/zeta/x", "/home/alpha/x", "/home/mid/x"}, 0)

	want := []string{"/home/alpha/x", "/home/mid/x", "/home/zeta/x"}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestRankPathsByMtimeDesc_CapZeroKeepsAll(t *testing.T) {
	now := time.Now()
	times := map[string]time.Time{
		"/a": now, "/b": now.Add(-time.Minute), "/c": now.Add(-2 * time.Minute), "/d": now.Add(-3 * time.Minute),
	}
	withMockOS(t, &mockOS{stat: mtimesByPath(times)})

	got := rankPathsByMtimeDesc(context.Background(), []string{"/a", "/b", "/c", "/d"}, 0)
	if len(got) != 4 {
		t.Errorf("len(got) = %d, want 4 (cap=0 must be unbounded)", len(got))
	}

	got = rankPathsByMtimeDesc(context.Background(), []string{"/a", "/b", "/c", "/d"}, -1)
	if len(got) != 4 {
		t.Errorf("len(got) = %d, want 4 (negative cap must be unbounded)", len(got))
	}
}

// Stat failures must not drop paths -- the helper exists to close a
// hidden-input bug class, so silently dropping discovered paths would
// reintroduce it. The contract is "rank what we can, send the rest to
// the tail."
func TestRankPathsByMtimeDesc_StatFailuresRankLast(t *testing.T) {
	now := time.Now()
	times := map[string]time.Time{
		"/exists":      now,
		"/also-exists": now.Add(-time.Minute),
	}
	withMockOS(t, &mockOS{stat: mtimesByPath(times)})

	got := rankPathsByMtimeDesc(context.Background(),
		[]string{"/exists", "/missing-a", "/also-exists", "/missing-b"}, 0)

	if len(got) != 4 {
		t.Fatalf("len(got) = %d, want 4 (stat failures must rank last, not drop) got=%v", len(got), got)
	}
	if got[0] != "/exists" || got[1] != "/also-exists" {
		t.Errorf("got[0..1] = %v, want [/exists /also-exists]", got[:2])
	}
	if got[2] != "/missing-a" || got[3] != "/missing-b" {
		t.Errorf("got[2..3] = %v, want stat-failed paths sorted by path asc", got[2:])
	}
}

// Cap chops the stat-failed tail first.
func TestRankPathsByMtimeDesc_CapChopsStatFailedTailFirst(t *testing.T) {
	now := time.Now()
	times := map[string]time.Time{
		"/recent": now,
	}
	withMockOS(t, &mockOS{stat: mtimesByPath(times)})

	got := rankPathsByMtimeDesc(context.Background(),
		[]string{"/recent", "/gone-1", "/gone-2"}, 1)

	if len(got) != 1 {
		t.Fatalf("len(got) = %d, want 1", len(got))
	}
	if got[0] != "/recent" {
		t.Errorf("got[0] = %q, want /recent (cap must keep ranked paths, drop the stat-failed tail)", got[0])
	}
}

func TestRankPathsByMtimeDesc_CanceledCtxReturnsNil(t *testing.T) {
	withMockOS(t, &mockOS{stat: mtimesByPath(map[string]time.Time{"/a": time.Now()})})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got := rankPathsByMtimeDesc(ctx, []string{"/a", "/b"}, 0)
	if got != nil {
		t.Errorf("got = %v, want nil for canceled ctx", got)
	}
}

func TestRankPathsByMtimeDesc_NilCtxDefaultsToBackground(t *testing.T) {
	times := map[string]time.Time{"/a": time.Now(), "/b": time.Now().Add(-time.Minute)}
	withMockOS(t, &mockOS{stat: mtimesByPath(times)})
	got := rankPathsByMtimeDesc(nil, []string{"/a", "/b"}, 0) //nolint:staticcheck // SA1012: nil ctx is a documented fallback for this helper
	if len(got) != 2 {
		t.Errorf("len(got) = %d, want 2", len(got))
	}
}
