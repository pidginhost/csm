package antispam

import (
	"strings"
	"testing"
)

// An engine that found its ledger out of step with storage turns learning
// off like any other state mismatch (spec 10: core-only reconcile).
func TestResolveLearningLearnerMismatch(t *testing.T) {
	f := safeLearningFacts()
	f.LearnerMismatch = true
	s, gate, problems := ResolveLearning(Settings{Learning: true, Roundcube: true}, f)
	if s.Learning || gate != (LearningGate{}) {
		t.Fatalf("learning stayed on: settings %+v gate %+v", s, gate)
	}
	onlyLearningReason(t, problems, ReasonStateMismatch)
}

func TestLearnerEndpoint(t *testing.T) {
	f := safeLearningFacts()
	socket, uid, ok := LearnerEndpoint(f)
	if !ok || socket != privateController || uid != testRspamdUID {
		t.Fatalf("endpoint %q uid %d ok %v", socket, uid, ok)
	}
	f.ControllerHost.RspamdUID = -1
	if _, _, ok := LearnerEndpoint(f); ok {
		t.Fatal("endpoint without a known rspamd user")
	}
}

func TestHashGenerationIdentifiesKeys(t *testing.T) {
	a := LearningKeys{Fuzzy: NewSecret(strings.Repeat("8e", 32)), Shingles: NewSecret(strings.Repeat("9f", 32)), Prefix: "csmfz_x"}
	b := a
	if HashGeneration(a) != HashGeneration(b) || len(HashGeneration(a)) != 64 {
		t.Fatalf("generation %q", HashGeneration(a))
	}
	b.Shingles = NewSecret(strings.Repeat("7d", 32))
	if HashGeneration(a) == HashGeneration(b) {
		t.Fatal("different shingle keys share a generation")
	}
	if strings.Contains(HashGeneration(a), "8e8e") || strings.Contains(HashGeneration(a), "9f9f") {
		t.Fatal("generation exposes key material")
	}
}
