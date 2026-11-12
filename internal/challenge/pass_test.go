package challenge

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/store"
)

type fakePassStore struct {
	mu      sync.Mutex
	puts    map[string]time.Time
	known   map[string]time.Time
	reads   int
	readErr error
}

func TestPassMaintenancePrunesStoreWithoutRestart(t *testing.T) {
	l := NewIPList(filepath.Join(t.TempDir(), "challenge_ips.txt"))
	db, openErr := store.Open(t.TempDir())
	if openErr != nil {
		t.Fatal(openErr)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := l.SetPassStore(db); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	for ip, at := range map[string]time.Time{
		"203.0.113.70": now.Add(-PassMemory - time.Hour),
		"203.0.113.71": now.Add(-time.Hour),
	} {
		if err := db.PutChallengePass(ip, at); err != nil {
			t.Fatal(err)
		}
		l.passes[ip] = at
	}
	l.ExpiredEntries()
	got, err := db.ChallengePasses(time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || !got["203.0.113.71"].Equal(now.Add(-time.Hour)) {
		t.Fatalf("persisted passes did not expire during runtime: %v", got)
	}
	if len(l.passes) != 1 {
		t.Fatalf("in-memory passes did not expire: %v", l.passes)
	}
}

func (f *fakePassStore) ChallengePasses(time.Time) (map[string]time.Time, error) {
	f.reads++
	return f.known, f.readErr
}

func (f *fakePassStore) PutChallengePass(ip string, at time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.puts == nil {
		f.puts = make(map[string]time.Time)
	}
	f.puts[ip] = at
	return nil
}

func newPassList(t *testing.T) (*IPList, *fakePassStore) {
	t.Helper()
	l := NewIPList(filepath.Join(t.TempDir(), "challenge_ips.txt"))
	store := &fakePassStore{}
	if err := l.SetPassStore(store); err != nil {
		t.Fatal(err)
	}
	return l, store
}

func TestMarkPassedRecordsOnlyAListedAddress(t *testing.T) {
	l, store := newPassList(t)
	const ip = "203.0.113.70"
	if l.MarkPassed(ip) {
		t.Fatal("an address that was never challenged counted as a pass")
	}
	l.Add(ip, "test", time.Hour)
	if !l.MarkPassed(ip) {
		t.Fatal("a challenged address was not marked passed")
	}
	if l.Contains(ip) {
		t.Fatal("a passed address stayed on the challenge list")
	}
	if l.MarkPassed(ip) {
		t.Fatal("one pass was counted twice")
	}
	passes, _ := l.Passes()
	if _, ok := passes[ip]; !ok {
		t.Fatal("the pass is not remembered")
	}
	if _, ok := store.puts[ip]; !ok {
		t.Fatal("the pass was not persisted")
	}
}

// A visitor who passed is challenged again on evidence that predates the
// pass; when they do not come back, the timeout must not block them.
func TestTimeoutSoonAfterAPassDoesNotEscalate(t *testing.T) {
	l, _ := newPassList(t)
	const ip = "203.0.113.71"
	l.Add(ip, "test", time.Hour)
	l.MarkPassed(ip)
	l.Add(ip, "routed again", -time.Second)
	if got := l.ExpiredEntries(); len(got) != 0 {
		t.Fatalf("timeout after a recent pass escalated: %+v", got)
	}
	if l.Contains(ip) {
		t.Fatal("the timed-out entry stayed on the list")
	}
}

func TestTimeoutLongAfterAPassEscalates(t *testing.T) {
	l, _ := newPassList(t)
	const ip = "203.0.113.72"
	l.Add(ip, "test", time.Hour)
	l.MarkPassed(ip)
	l.mu.Lock()
	l.passes[ip] = time.Now().Add(-passEscalationGrace - time.Minute)
	l.mu.Unlock()
	l.Add(ip, "routed again", -time.Second)
	if got := l.ExpiredEntries(); len(got) != 1 || got[0].IP != ip {
		t.Fatalf("timeout long after a pass did not escalate: %+v", got)
	}
}

// Passes come back from the store at startup, so a restart cannot revive the
// evidence a visitor already answered.
func TestSetPassStoreRestoresRememberedPasses(t *testing.T) {
	l := NewIPList(filepath.Join(t.TempDir(), "challenge_ips.txt"))
	now := time.Now()
	err := l.SetPassStore(&fakePassStore{known: map[string]time.Time{
		"203.0.113.73": now.Add(-time.Hour),
		"203.0.113.74": now.Add(-PassMemory - time.Hour),
	}})
	if err != nil {
		t.Fatal(err)
	}
	passes, _ := l.Passes()
	if _, ok := passes["203.0.113.73"]; !ok {
		t.Fatal("a recent pass was not restored")
	}
	if _, ok := passes["203.0.113.74"]; ok {
		t.Fatal("a pass older than the pass memory was restored")
	}
	l.Add("203.0.113.73", "routed again", -time.Second)
	if got := l.ExpiredEntries(); len(got) != 0 {
		t.Fatalf("timeout after a restored pass escalated: %+v", got)
	}
}

func solvePoW(nonce string, difficulty int) string {
	prefix := strings.Repeat("0", difficulty)
	for c := 0; ; c++ {
		s := strconv.FormatInt(int64(c), 16)
		h := sha256.Sum256([]byte(nonce + s))
		if strings.HasPrefix(hex.EncodeToString(h[:]), prefix) {
			return s
		}
	}
}

func TestSolvedChallengeIsCountedAsAPass(t *testing.T) {
	s, list := newServerForTest(t)
	if err := list.SetPassStore(&fakePassStore{}); err != nil {
		t.Fatal(err)
	}
	const ip = "203.0.113.75"
	list.Add(ip, "test", time.Hour)

	nonce := "0123abcd"
	form := url.Values{
		"nonce":    {nonce},
		"token":    {s.makeToken(ip, nonce)},
		"solution": {solvePoW(nonce, s.cfg.Challenge.Difficulty)},
	}
	req := httptest.NewRequest(http.MethodPost, "/challenge/verify", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "[::ffff:" + ip + "]:50000"
	before := challengePassedCounter().With(passMethodPoW).Value()
	rr := httptest.NewRecorder()
	s.handleVerify(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body.String())
	}
	passes, _ := list.Passes()
	if _, ok := passes[ip]; !ok {
		t.Fatal("solved challenge was not remembered as a pass")
	}
	list.Add(ip, "new evidence", time.Hour)
	get := httptest.NewRequest(http.MethodGet, "/challenge", nil)
	get.RemoteAddr = req.RemoteAddr
	page := httptest.NewRecorder()
	s.handleChallenge(page, get)
	if page.Code != http.StatusOK || !list.Contains(ip) || strings.Contains(page.Body.String(), "Verified - redirecting") {
		t.Fatalf("a solver without its cookie bypassed the next challenge: status=%d pending=%v", page.Code, list.Contains(ip))
	}
	if got := challengePassedCounter().With(passMethodPoW).Value() - before; got != 1 {
		t.Fatalf("csm_challenge_passed_total{method=pow} delta = %v, want 1", got)
	}
}

func TestPassMemoryKeepsNewestCompletion(t *testing.T) {
	l, _ := newPassList(t)
	const ip = "203.0.113.70"
	now := time.Now()
	l.Add(ip, "first", time.Hour)
	l.remove(ip, now)
	l.Add(ip, "second", time.Hour)
	l.remove(ip, now.Add(-time.Minute))
	passes, _ := l.Passes()
	if got := passes[ip]; !got.Equal(now) {
		t.Fatalf("pass regressed to %v", got)
	}
}

func TestPassMaintenanceRetriesFailuresAndLimitsSweeps(t *testing.T) {
	l, ps := newPassList(t)
	ps.readErr = errors.New("store unavailable")
	before := ps.reads
	l.ExpiredEntries()
	if ps.reads != before+1 {
		t.Fatal("runtime maintenance did not try the store")
	}
	ps.readErr = nil
	l.ExpiredEntries()
	if ps.reads != before+2 {
		t.Fatal("failed cleanup was not retried")
	}
	l.ExpiredEntries()
	if ps.reads != before+2 {
		t.Fatal("successful cleanup repeated on every tick")
	}
	l.lastPassPrune = time.Now().Add(-2 * time.Hour)
	l.ExpiredEntries()
	if ps.reads != before+3 {
		t.Fatal("cleanup never ran again after its interval")
	}
}
