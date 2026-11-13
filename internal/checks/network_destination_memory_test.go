package checks

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

// Use the public scan boundary so these tests compile before the producer
// starts keeping observations. The raw value is the on-disk contract.
func c2MemorySeed(t *testing.T, st *state.Store, at time.Time) {
	t.Helper()
	raw, err := json.Marshal(struct {
		Boot string           `json:"boot"`
		Seen map[string]int64 `json:"seen"`
	}{testBootID, map[string]int64{"12345": at.UnixNano()}})
	if err != nil {
		t.Fatal(err)
	}
	st.SetRaw("_c2_sockets_seen", string(raw))
}

func c2MemoryScan(t *testing.T, st *state.Store) alert.Finding {
	t.Helper()
	got := c2Findings(CheckOutboundConnections(context.Background(), &config.Config{C2Blocklist: []string{"203.0.113.9", "203.0.113.10"}}, st))
	if len(got) != 1 || got[0].Observation.ObservedAt.IsZero() {
		t.Fatalf("findings = %+v, want one socket observation", got)
	}
	return got[0]
}

func c2MemoryMint(t *testing.T, f alert.Finding) admission.Evidence {
	t.Helper()
	id, in, err := AdmissionEvidence(f)
	if err != nil {
		t.Fatal(err)
	}
	reg, err := admission.NewRegistry(AdmissionPolicy)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range producerTable {
		if row.Spec.ID != id {
			continue
		}
		p, err := reg.Register(row.Spec)
		if err != nil {
			t.Fatal(err)
		}
		e, err := p.Mint(in)
		if err != nil {
			t.Fatal(err)
		}
		return e
	}
	t.Fatal("connection producer missing")
	return admission.Evidence{}
}

// A saved time is immutable, including when wall time moves around it.
func TestC2MemoryClockSteps(t *testing.T) {
	outboundOS(t, c2Row, testBootID)
	for _, delta := range []time.Duration{-3 * time.Hour, 3 * time.Hour} {
		t.Run(delta.String(), func(t *testing.T) {
			st, err := state.Open(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			at := time.Now().Add(delta).Round(0).UTC()
			c2MemorySeed(t, st, at)
			f := c2MemoryScan(t, st)
			if !f.Observation.ObservedAt.Equal(at) {
				t.Fatalf("saved time %v rebased to %v", at, f.Observation.ObservedAt)
			}
			e := c2MemoryMint(t, f)
			_, err = admission.Assess(e.Target(), []admission.Evidence{e}, time.Now())
			want := admission.ReasonStale
			if delta > 0 {
				want = admission.ReasonInvalid
			}
			var refusal *admission.Error
			if !errors.As(err, &refusal) || refusal.Reason != want {
				t.Fatalf("assessment = %v, want %s", err, want)
			}
			if again := c2MemoryMint(t, c2MemoryScan(t, st)); !e.SameExceptFinding(again) {
				t.Fatal("clock movement refreshed a saved observation")
			}
		})
	}
}

// Lost memory may mint a conflicting record, never replace the old one.
// No Flush or Close is allowed between the scan and reopening this store.
func TestC2MemoryUnflushedRestart(t *testing.T) {
	outboundOS(t, c2Row, testBootID)
	dir := t.TempDir()
	st, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	st.SetRaw("_c2_memory_test_sentinel", "unchanged")
	if err = st.Flush(); err != nil {
		t.Fatal(err)
	}
	c2MemorySeed(t, st, time.Now().Add(-time.Hour))
	before := c2MemoryMint(t, c2MemoryScan(t, st))
	reopened, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := reopened.GetRaw("_c2_sockets_seen"); ok {
		t.Fatal("crash fixture unexpectedly saved the first-seen value")
	}
	after := c2MemoryMint(t, c2MemoryScan(t, reopened))
	if before.ID() != after.ID() || before.SameExceptFinding(after) || !after.ObservedAt().After(before.ObservedAt()) {
		t.Fatal("lost first-seen time must conflict under the original ID")
	}
	if !errors.Is(before.Conflict(after), admission.ErrEvidenceConflict) {
		t.Fatal("lost time did not produce the immutable-record refusal")
	}
}

// An inode reused between samples is not proof of another lifetime. An
// absent scan instead forgets its time, which can conflict with old evidence.
func TestC2MemoryInodeReuse(t *testing.T) {
	sock := outboundOS(t, c2Row, testBootID)
	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	c2MemorySeed(t, st, time.Now().Add(-time.Hour))
	first := c2MemoryMint(t, c2MemoryScan(t, st))
	sock.table = strings.Replace(c2Row, ":C350", ":C351", 1)
	reused := c2MemoryMint(t, c2MemoryScan(t, st))
	if first.ID() != reused.ID() || !first.SameExceptFinding(reused) {
		t.Fatal("unseen reuse for the same destination became independent evidence")
	}
	sock.table = strings.Replace(sock.table, "097100CB", "0A7100CB", 1)
	other := c2MemoryMint(t, c2MemoryScan(t, st))
	if first.ID() == other.ID() || !first.ObservedAt().Equal(other.ObservedAt()) || other.Target().Prefix().String() != "203.0.113.10/32" {
		t.Fatal("new destination lost target binding or refreshed the sampled inode")
	}
	sock.table = ""
	if got := c2Findings(CheckOutboundConnections(context.Background(), &config.Config{C2Blocklist: []string{"203.0.113.9"}}, st)); len(got) != 0 {
		t.Fatalf("absent socket still reported: %+v", got)
	}
	sock.table = c2Row
	afterGap := c2MemoryMint(t, c2MemoryScan(t, st))
	if afterGap.ID() != first.ID() || first.SameExceptFinding(afterGap) || !afterGap.ObservedAt().After(first.ObservedAt()) {
		t.Fatal("reuse after an absent scan must not replace retained evidence")
	}
}

// Memory scales with this scan's sockets and shrinks again. The synthetic
// workload is not a production limit and must not introduce one.
func TestC2MemoryCardinalityAndOwnership(t *testing.T) {
	const n = 4096
	var rows strings.Builder
	for i := 0; i < n; i++ {
		fmt.Fprintf(&rows, "%d: 010200C0:%04X 097100CB:01BB 01 00000000:00000000 00:00000000 00000000 1001 0 %d\n", i, 20000+i, 12345+i)
	}
	sock := outboundOS(t, rows.String(), testBootID)
	dir := t.TempDir()
	st, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	st.SetRaw("_c2_memory_test_sentinel", "unchanged")
	cfg := &config.Config{C2Blocklist: []string{"203.0.113.9"}}
	got := c2Findings(CheckOutboundConnections(context.Background(), cfg, st))
	if len(got) != n {
		t.Fatalf("findings = %d, want %d", len(got), n)
	}
	raw, ok := st.GetRaw("_c2_sockets_seen")
	if !ok || len(raw) <= 65536 || len(raw) > 64*n+256 {
		t.Fatalf("raw bytes = %d, present = %v; want a complete linear-sized value", len(raw), ok)
	}
	var saved struct {
		Boot string           `json:"boot"`
		Seen map[string]int64 `json:"seen"`
	}
	if err = json.Unmarshal([]byte(raw), &saved); err != nil || saved.Boot != testBootID || len(saved.Seen) != n {
		t.Fatalf("saved socket count = %d, boot = %q, err = %v", len(saved.Seen), saved.Boot, err)
	}
	for i, f := range got {
		inode := strconv.Itoa(12345 + i)
		if f.Observation.Cursor != inode || saved.Seen[inode] != f.Observation.ObservedAt.UnixNano() {
			t.Fatalf("socket %s missing or truncated", inode)
		}
	}
	withMockOS(t, &mockOS{readFile: func(string) ([]byte, error) { return nil, errors.New("unreadable socket table") }})
	if failed := c2Findings(CheckOutboundConnections(context.Background(), cfg, st)); len(failed) != 0 {
		t.Fatal("failed read reported a connection")
	}
	if kept, present := st.GetRaw("_c2_sockets_seen"); !present || kept != raw {
		t.Fatal("failed read erased socket memory")
	}
	sock.install(t)
	if err = st.Flush(); err != nil {
		t.Fatal(err)
	}
	st, err = state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if reopened, present := st.GetRaw("_c2_sockets_seen"); !present || reopened != raw {
		t.Fatal("large first-seen value changed across a restart")
	}
	sock.table = c2Row
	c2MemoryScan(t, st)
	small, ok := st.GetRaw("_c2_sockets_seen")
	saved.Seen = nil
	if !ok || json.Unmarshal([]byte(small), &saved) != nil || len(saved.Seen) != 1 || saved.Seen["12345"] != got[0].Observation.ObservedAt.UnixNano() {
		t.Fatal("smaller scan retained old sockets or refreshed the surviving one")
	}
	sock.table = ""
	if empty := c2Findings(CheckOutboundConnections(context.Background(), cfg, st)); len(empty) != 0 {
		t.Fatal("empty table reported a connection")
	}
	if _, ok := st.GetRaw("_c2_sockets_seen"); ok {
		t.Fatal("empty scan retained first-seen memory")
	}
	if sentinel, ok := st.GetRaw("_c2_memory_test_sentinel"); !ok || sentinel != "unchanged" {
		t.Fatal("C2 scan changed another owner's housekeeping value")
	}
}

// Listener changes do not create a new lifetime for a socket still present.
func TestC2MemoryKeepsTimeAcrossListenerChanges(t *testing.T) {
	cfg := &config.Config{C2Blocklist: []string{"203.0.113.9"}}
	for _, seeded := range []bool{false, true} {
		t.Run(strconv.FormatBool(seeded), func(t *testing.T) {
			dir := t.TempDir()
			st, err := state.Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			at := time.Now().Add(-time.Hour).Round(0).UTC()
			if seeded {
				c2MemorySeed(t, st, at)
			}
			sock := outboundOS(t, c2Row+"2: 00000000:C350 00000000:0000 0A 00000000:00000000 00:00000000 00000000 1001 0 100\n", testBootID)
			before := time.Now()
			got := c2Findings(CheckOutboundConnections(context.Background(), cfg, st))
			after := time.Now()
			if len(got) != 1 || got[0].Observation != (alert.Observation{}) || got[0].Attribution.Valid() {
				t.Fatalf("listening socket findings = %+v, want one unstamped alert", got)
			}
			raw, ok := st.GetRaw("_c2_sockets_seen")
			var saved c2SocketsSeen
			if !ok || json.Unmarshal([]byte(raw), &saved) != nil || saved.Boot != testBootID || len(saved.Seen) != 1 {
				t.Fatalf("listening socket memory = %q, want this boot and one socket", raw)
			}
			first := time.Unix(0, saved.Seen["12345"]).UTC()
			if seeded && !first.Equal(at) || !seeded && (first.Before(before) || first.After(after)) {
				t.Fatalf("first seen = %v, want the original sighting", first)
			}
			if err = st.Flush(); err != nil {
				t.Fatal(err)
			}
			st, err = state.Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			sock.table = c2Row
			if f := c2MemoryScan(t, st); !f.Observation.ObservedAt.Equal(first) {
				t.Fatalf("listener disappearance refreshed %v to %v", first, f.Observation.ObservedAt)
			}
		})
	}
}

// A slow process lookup must not let an older scan overwrite newer memory.
func TestC2MemoryOverlappingProcessLookups(t *testing.T) {
	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{C2Blocklist: []string{"203.0.113.9"}}
	lookupStarted := make(chan struct{})
	releaseLookup := make(chan struct{})
	var calls atomic.Int32
	withMockOS(t, &mockOS{
		readFile: func(path string) ([]byte, error) {
			if path == "/proc/net/tcp" {
				return []byte(procTCPHeader + c2Row), nil
			}
			if path == "/proc/sys/kernel/random/boot_id" {
				return []byte(testBootID), nil
			}
			return nil, errors.New("not found")
		},
		glob: func(pattern string) ([]string, error) {
			if pattern == "/proc/*/fd/*" && calls.Add(1) == 1 {
				close(lookupStarted)
				<-releaseLookup
			}
			return nil, nil
		},
	})
	firstDone := make(chan []alert.Finding, 1)
	go func() { firstDone <- CheckOutboundConnections(context.Background(), cfg, st) }()
	<-lookupStarted
	second := c2Findings(CheckOutboundConnections(context.Background(), cfg, st))
	close(releaseLookup)
	first := c2Findings(<-firstDone)
	if len(first) != 1 || len(second) != 1 || first[0].Observation != second[0].Observation {
		t.Fatalf("overlapping scans disagree: first %+v, second %+v", first, second)
	}
	if last := c2MemoryScan(t, st); last.Observation != first[0].Observation {
		t.Fatal("overlapping scans changed the saved observation")
	}
}
