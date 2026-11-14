package checks

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/firewall"
)

// A failed tracker read must preserve queued work and must not forget which
// blocks have already contributed a strike.
func TestRecordAdmissionBlocksReadFailurePreservesState(t *testing.T) {
	cfg := pendingTestConfig(t)
	cfg.AutoResponse.PermBlock = true
	applyBlockTestSetup(t, &outcomeStubBlocker{})
	at := time.Now().UTC()
	b := AdmissionBlock{IP: "203.0.113.64", BlockedAt: at, ExpiresAt: at.Add(time.Hour)}
	before := &blockState{Pending: []pendingIP{{IP: "203.0.113.65", QueuedAt: at}}, BlocksThisHour: 7}
	if err := writeBlockState(cfg.StatePath, before); err != nil {
		t.Fatal(err)
	}
	previous := osFS
	t.Cleanup(func() { osFS = previous })
	osFS = &retryQueueReadFailure{OS: realOS{}, path: filepath.Join(cfg.StatePath, blockStateFile), calls: 1, fail: true}
	if got := RecordAdmissionBlocks(cfg, []AdmissionBlock{b}); len(got) != 0 {
		t.Errorf("unreadable tracker emitted %d notices", len(got))
	}
	osFS = previous
	after, err := readBlockState(cfg.StatePath)
	if err != nil || !reflect.DeepEqual(after, before) {
		t.Fatalf("unreadable tracker replaced existing state: %+v, %v", after, err)
	}
	if got := len(loadPermBlockTracker(cfg.StatePath).IPs[b.IP]); got != 0 {
		t.Fatalf("unreadable tracker recorded %d strikes", got)
	}
}

// No side effect may precede the durable duplicate marker. An interrupted
// write can otherwise count the same block again when the outbox replays.
func TestRecordAdmissionBlocksPersistsBeforeStrikes(t *testing.T) {
	for _, phase := range []string{"write error", "crash before write", "crash after write"} {
		t.Run(phase, func(t *testing.T) {
			cfg := pendingTestConfig(t)
			cfg.AutoResponse.PermBlock = true
			applyBlockTestSetup(t, &outcomeStubBlocker{})
			at := time.Now().UTC()
			b := AdmissionBlock{IP: "203.0.113.66", BlockedAt: at, ExpiresAt: at.Add(time.Hour)}
			previous := persistAutoBlockState
			t.Cleanup(func() { persistAutoBlockState = previous })
			interrupted := new(int)
			persistAutoBlockState = func(path string, state *blockState) error {
				if phase == "write error" {
					return os.ErrPermission
				}
				if phase == "crash after write" {
					if err := previous(path, state); err != nil {
						t.Fatal(err)
					}
				}
				panic(interrupted)
			}
			func() {
				defer func() {
					if p := recover(); p != nil && p != interrupted {
						panic(p)
					}
				}()
				if got := RecordAdmissionBlocks(cfg, []AdmissionBlock{b}); len(got) != 0 {
					t.Errorf("failed persistence emitted %d notices", len(got))
				}
				if phase != "write error" {
					t.Fatal("crash hook was not reached")
				}
			}()
			if got := len(loadPermBlockTracker(cfg.StatePath).IPs[b.IP]); got != 0 {
				t.Errorf("interrupted persistence recorded %d strikes", got)
			}
			persistAutoBlockState = previous
			want := 1
			if phase == "crash after write" {
				want = 0 // Best effort: the marker survives, the side effects do not.
			}
			for i := range 2 {
				got := RecordAdmissionBlocks(cfg, []AdmissionBlock{b})
				if len(got) != want*(1-i) {
					t.Errorf("replay %d emitted %d notices", i, len(got))
				}
				if strikes := len(loadPermBlockTracker(cfg.StatePath).IPs[b.IP]); strikes != want {
					t.Errorf("replay %d recorded %d strikes, want %d", i, strikes, want)
				}
			}
		})
	}
}

// A block admission applied is recorded where a legacy block is: a tracker
// row (which netblock escalation counts), a permanent-block strike and the
// Critical auto_block finding naming its cause. A repeated delivery changes
// nothing.
func TestRecordAdmissionBlocks(t *testing.T) {
	cfg := pendingTestConfig(t)
	cfg.AutoResponse.PermBlock = true
	blocker := &outcomeStubBlocker{outcome: firewall.BlockOutcomeLive}
	applyBlockTestSetup(t, blocker)
	at := time.Now().Add(-time.Minute).UTC().Truncate(time.Second)
	b := AdmissionBlock{IP: "203.0.113.61", Reason: "CSM auto-block: ssh_brute", Check: "ssh_brute", FindingID: "0123456789abcdef", BlockedAt: at, ExpiresAt: at.Add(24 * time.Hour)}
	findings := RecordAdmissionBlocks(cfg, []AdmissionBlock{b})
	if len(findings) != 1 {
		t.Fatalf("findings = %+v, want one", findings)
	}
	f := findings[0]
	if f.Check != "auto_block" || f.Severity != alert.Critical || f.SourceIP != b.IP || f.Message != "AUTO-BLOCK: 203.0.113.61 blocked (expires in 24h0m0s)" ||
		!strings.Contains(f.Details, b.Reason) || f.Cause == nil || *f.Cause != (alert.Cause{FindingID: b.FindingID, Check: b.Check}) {
		t.Fatalf("finding = %+v", f)
	}
	state := loadBlockState(cfg.StatePath)
	if len(state.IPs) != 1 {
		t.Fatalf("tracker = %+v, want one row", state.IPs)
	}
	row := state.IPs[0]
	if row.IP != b.IP || row.FindingID != b.FindingID || row.Reason != b.Reason || !row.BlockedAt.Equal(at) || !row.ExpiresAt.Equal(b.ExpiresAt) || !countsTowardNetblock(row) {
		t.Fatalf("tracker row = %+v", row)
	}
	if strikes := loadPermBlockTracker(cfg.StatePath).IPs[b.IP]; len(strikes) != 1 {
		t.Fatalf("strikes = %v, want one", strikes)
	}
	if again := RecordAdmissionBlocks(cfg, []AdmissionBlock{b}); len(again) != 0 {
		t.Fatalf("repeated delivery emitted %+v", again)
	}
	if state := loadBlockState(cfg.StatePath); len(state.IPs) != 1 || len(loadPermBlockTracker(cfg.StatePath).IPs[b.IP]) != 1 {
		t.Fatalf("repeated delivery changed the tracker or strikes: %+v", state.IPs)
	}
	if len(blocker.calls) != 0 {
		t.Fatalf("recording called the engine: %+v", blocker.calls)
	}
}

// A strike that reaches the permanent-block count promotes nothing: the
// block is admission's, and a permanent block is not an admission
// response. The strike still counts toward a later legacy block.
func TestRecordAdmissionBlocksPromotesNothing(t *testing.T) {
	cfg := pendingTestConfig(t)
	cfg.AutoResponse.PermBlock = true
	cfg.AutoResponse.PermBlockCount = 2
	cfg.AutoResponse.PermBlockInterval = "24h"
	blocker := &outcomeStubBlocker{outcome: firewall.BlockOutcomeLive}
	applyBlockTestSetup(t, blocker)
	at := time.Now().Add(-time.Minute).UTC()
	first := AdmissionBlock{IP: "203.0.113.62", Reason: "CSM auto-block: ssh_brute", Check: "ssh_brute", BlockedAt: at, ExpiresAt: at.Add(time.Hour)}
	second := first
	second.ExpiresAt = at.Add(2 * time.Hour)
	findings := RecordAdmissionBlocks(cfg, []AdmissionBlock{first, second})
	if len(findings) != 2 || len(blocker.calls) != 0 || len(blocker.promoted) != 0 {
		t.Fatalf("findings %+v, engine calls %+v, promoted %v; want two notices and no promotion", findings, blocker.calls, blocker.promoted)
	}
	for _, f := range findings {
		if strings.Contains(f.Message, "PERMBLOCK") {
			t.Fatalf("promotion notice %q", f.Message)
		}
	}
	if strikes := loadPermBlockTracker(cfg.StatePath).IPs[first.IP]; len(strikes) != 2 {
		t.Fatalf("strikes = %v, want two", strikes)
	}
}

// The notice carries the Cloudflare coverage warning a legacy block gets,
// and no strike is counted with permanent blocking off or for a listed C2
// server, as for a legacy block.
func TestRecordAdmissionBlocksWarnsAndSkipsStrikesAsLegacy(t *testing.T) {
	at := time.Now().Add(-time.Minute).UTC()
	for _, tc := range []struct {
		name      string
		permBlock bool
		c2        bool
		cf        bool
		strikes   int
	}{
		{"cloudflare", true, false, true, 1},
		{"permblock off", false, false, false, 0},
		{"listed c2", true, true, false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := pendingTestConfig(t)
			cfg.AutoResponse.PermBlock = tc.permBlock
			b := AdmissionBlock{IP: "203.0.113.63", Reason: "CSM auto-block: ssh_brute", Check: "ssh_brute", BlockedAt: at, ExpiresAt: at.Add(time.Hour)}
			if tc.c2 {
				cfg.C2Blocklist = []string{b.IP}
			}
			blocker := &outcomeStubBlocker{outcome: firewall.BlockOutcomeLive, cfCovers: tc.cf}
			applyBlockTestSetup(t, blocker)
			findings := RecordAdmissionBlocks(cfg, []AdmissionBlock{b})
			if len(findings) != 1 {
				t.Fatalf("findings = %+v", findings)
			}
			if warned := strings.Contains(findings[0].Details, firewall.CloudflareCoverageWarning); warned != tc.cf {
				t.Fatalf("details %q, Cloudflare warning %v, want %v", findings[0].Details, warned, tc.cf)
			}
			if got := len(loadPermBlockTracker(cfg.StatePath).IPs[b.IP]); got != tc.strikes {
				t.Fatalf("strikes = %d, want %d", got, tc.strikes)
			}
		})
	}
}
