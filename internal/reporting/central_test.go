package reporting

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestParseActionDefaultsToChallenge(t *testing.T) {
	if ParseAction("off") != ActionOff {
		t.Fatal("off")
	}
	if ParseAction("block_if_local_corroborated") != ActionBlockIfLocalCorroborated {
		t.Fatal("block")
	}
	if ParseAction("challenge") != ActionChallenge || ParseAction("bogus") != ActionChallenge {
		t.Fatal("default must be challenge")
	}
}

func TestDecideFirebreakAlwaysIgnores(t *testing.T) {
	in := DecisionInput{Found: true, Score: 100, Protected: true, LocallyCorroborated: true}
	if d := Decide(in, ActionBlockIfLocalCorroborated, 50); d != DecisionIgnore {
		t.Fatalf("protected IP got %v, want Ignore", d)
	}
}

func TestDecideNotFoundIgnores(t *testing.T) {
	if d := Decide(DecisionInput{Found: false, Score: 90}, ActionChallenge, 50); d != DecisionIgnore {
		t.Fatalf("got %v, want Ignore", d)
	}
}

func TestDecideOffIgnores(t *testing.T) {
	if d := Decide(DecisionInput{Found: true, Score: 90}, ActionOff, 50); d != DecisionIgnore {
		t.Fatalf("got %v, want Ignore", d)
	}
}

func TestDecideChallengeByDefault(t *testing.T) {
	// Present, high score, but action is challenge -> challenge, never block.
	if d := Decide(DecisionInput{Found: true, Score: 95, LocallyCorroborated: true}, ActionChallenge, 50); d != DecisionChallenge {
		t.Fatalf("got %v, want Challenge", d)
	}
}

func TestDecideBlockNeedsLocalCorroborationAndThreshold(t *testing.T) {
	// block_if_local_corroborated:
	// - no local corroboration -> challenge
	if d := Decide(DecisionInput{Found: true, Score: 95, LocallyCorroborated: false}, ActionBlockIfLocalCorroborated, 50); d != DecisionChallenge {
		t.Fatalf("no local corroboration got %v, want Challenge", d)
	}
	// - corroborated but below threshold -> challenge
	if d := Decide(DecisionInput{Found: true, Score: 40, LocallyCorroborated: true}, ActionBlockIfLocalCorroborated, 50); d != DecisionChallenge {
		t.Fatalf("below threshold got %v, want Challenge", d)
	}
	// - corroborated and at/above threshold -> block
	if d := Decide(DecisionInput{Found: true, Score: 50, LocallyCorroborated: true}, ActionBlockIfLocalCorroborated, 50); d != DecisionBlock {
		t.Fatalf("corroborated+threshold got %v, want Block", d)
	}
}

func TestCentralStoreRefreshAndLookup(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	snapBytes, _ := MarshalScoredSnapshot(sampleSnapshot())
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeSigned(w, priv, snapBytes, "snapshot")
	}))
	defer srv.Close()

	cs := NewCentralStore(NewPuller(srv.Client(), srv.URL+"/decisions", hex.EncodeToString(pub)))
	if _, ok := cs.Lookup("203.0.113.5"); ok {
		t.Fatal("empty store should not find IP")
	}
	if err := cs.Refresh(context.Background()); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if cs.Version() != 7 {
		t.Fatalf("version = %d, want 7", cs.Version())
	}
	if _, ok := cs.Lookup("203.0.113.5"); !ok {
		t.Fatal("IP not found after refresh")
	}
}

func TestCentralStoreRejectsVersionRegression(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	v8b, _ := MarshalScoredSnapshot(ScoredSnapshot{Version: 8, Entries: []ScoredEntry{
		{IP: "203.0.113.5", Score: 80, Classes: []Class{ClassBruteforce}, LastSeen: setTS},
	}})
	v5b, _ := MarshalScoredSnapshot(ScoredSnapshot{Version: 5, Entries: []ScoredEntry{
		{IP: "203.0.113.9", Score: 70, Classes: []Class{ClassBruteforce}, LastSeen: setTS},
	}})
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		if calls == 1 {
			writeSigned(w, priv, v8b, "snapshot")
			return
		}
		writeSigned(w, priv, v5b, "snapshot") // rolled back / hostile
	}))
	defer srv.Close()

	cs := NewCentralStore(NewPuller(srv.Client(), srv.URL+"/decisions", hex.EncodeToString(pub)))
	if err := cs.Refresh(context.Background()); err != nil {
		t.Fatalf("initial refresh: %v", err)
	}
	if err := cs.Refresh(context.Background()); err != ErrSetVersionGap {
		t.Fatalf("regression refresh err = %v, want ErrSetVersionGap", err)
	}
	if cs.Version() != 8 {
		t.Fatalf("version = %d, want 8 (regression rejected)", cs.Version())
	}
	if _, ok := cs.Lookup("203.0.113.9"); ok {
		t.Fatal("rolled-back entry was applied")
	}
}

func TestCentralStoreRefreshVersionGapFallsBackToFullPull(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	baseBytes, _ := MarshalScoredSnapshot(sampleSnapshot())
	fullBytes, _ := MarshalScoredSnapshot(ScoredSnapshot{Version: 8, Entries: []ScoredEntry{
		{IP: "203.0.113.9", Score: 88, Classes: []Class{ClassBruteforce}, LastSeen: setTS},
	}})
	gapDiffBytes, _ := MarshalScoredDiff(ScoredDiff{
		FromVersion: 99,
		ToVersion:   100,
		Added: []ScoredEntry{
			{IP: "203.0.113.10", Score: 90, Classes: []Class{ClassBruteforce}, LastSeen: setTS},
		},
	})

	var sinceSeen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sinceSeen = append(sinceSeen, r.URL.Query().Get("since"))
		switch len(sinceSeen) {
		case 1:
			writeSigned(w, priv, baseBytes, "snapshot")
		case 2:
			writeSigned(w, priv, gapDiffBytes, "diff")
		default:
			writeSigned(w, priv, fullBytes, "snapshot")
		}
	}))
	defer srv.Close()

	cs := NewCentralStore(NewPuller(srv.Client(), srv.URL+"/decisions", hex.EncodeToString(pub)))
	if err := cs.Refresh(context.Background()); err != nil {
		t.Fatalf("initial refresh: %v", err)
	}
	if err := cs.Refresh(context.Background()); err != nil {
		t.Fatalf("gap fallback refresh: %v", err)
	}

	if want := []string{"", "7", ""}; len(sinceSeen) != len(want) {
		t.Fatalf("since sequence = %v, want %v", sinceSeen, want)
	} else {
		for i := range want {
			if sinceSeen[i] != want[i] {
				t.Fatalf("since sequence = %v, want %v", sinceSeen, want)
			}
		}
	}
	if cs.Version() != 8 {
		t.Fatalf("version = %d, want 8", cs.Version())
	}
	if _, ok := cs.Lookup("203.0.113.9"); !ok {
		t.Fatal("fallback snapshot IP not found")
	}
}

func TestCentralStoreRefreshRejectsSnapshotRollback(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	baseBytes, _ := MarshalScoredSnapshot(sampleSnapshot())
	oldBytes, _ := MarshalScoredSnapshot(ScoredSnapshot{Version: 6, Entries: []ScoredEntry{
		{IP: "203.0.113.8", Score: 60, Classes: []Class{ClassBruteforce}, LastSeen: setTS},
	}})

	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		if calls == 1 {
			writeSigned(w, priv, baseBytes, "snapshot")
			return
		}
		writeSigned(w, priv, oldBytes, "snapshot")
	}))
	defer srv.Close()

	cs := NewCentralStore(NewPuller(srv.Client(), srv.URL+"/decisions", hex.EncodeToString(pub)))
	if err := cs.Refresh(context.Background()); err != nil {
		t.Fatalf("initial refresh: %v", err)
	}
	if err := cs.Refresh(context.Background()); err != ErrSetVersionGap {
		t.Fatalf("rollback refresh err = %v, want ErrSetVersionGap", err)
	}
	if cs.Version() != 7 {
		t.Fatalf("version = %d, want cached version 7", cs.Version())
	}
	if _, ok := cs.Lookup("203.0.113.8"); ok {
		t.Fatal("rolled-back snapshot replaced the cached set")
	}
}
