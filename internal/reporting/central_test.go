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
