package daemon

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/pidginhost/csm/internal/reporting"
)

func TestClassSetParsesKnownSkipsUnknown(t *testing.T) {
	got := classSet([]string{"bruteforce", "php_relay", "not_a_class", "credential_stuffing"})
	if len(got) != 3 {
		t.Fatalf("classes = %v, want 3 known", got)
	}
	if !got[reporting.ClassBruteforce] || !got[reporting.ClassPHPRelay] || !got[reporting.ClassCredentialStuffing] {
		t.Fatalf("missing expected classes: %v", got)
	}
	if got[reporting.Class("not_a_class")] {
		t.Fatal("unknown class accepted")
	}
}

func TestBuildReportTargetsEd25519(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	t.Setenv("CSM_NODE_KEY", hex.EncodeToString(priv))
	got := buildReportTargets([]reportTargetConfig{{
		Name: "central", URL: "https://abuse.example/report", Transport: "ed25519",
		NodeID: "n1", KeyID: "k1", KeyEnv: "CSM_NODE_KEY",
	}})
	if len(got) != 1 {
		t.Fatalf("targets = %d, want 1", len(got))
	}
	if got[0].Transport != reporting.TransportEd25519 || len(got[0].Ed25519Key) != ed25519.PrivateKeySize {
		t.Fatalf("ed25519 target not built: %+v", got[0])
	}
}

func TestBuildReportTargetsHMACWithBearer(t *testing.T) {
	t.Setenv("CSM_REPORT_HMAC", "shared-secret")
	t.Setenv("CSM_REPORT_TOKEN", "bearer-tok")
	got := buildReportTargets([]reportTargetConfig{{
		Name: "priv", URL: "https://collector.internal/report", Transport: "hmac",
		NodeID: "n1", KeyID: "k1", KeyEnv: "CSM_REPORT_HMAC", TokenEnv: "CSM_REPORT_TOKEN",
	}})
	if len(got) != 1 {
		t.Fatalf("targets = %d, want 1", len(got))
	}
	if got[0].Transport != reporting.TransportHMAC || string(got[0].HMACSecret) != "shared-secret" || got[0].BearerToken != "bearer-tok" {
		t.Fatalf("hmac target not built: %+v", got[0])
	}
}

func TestBuildReportTargetsSkipsInvalid(t *testing.T) {
	t.Setenv("BAD_KEY", "not-hex")
	t.Setenv("EMPTY", "")
	cases := []reportTargetConfig{
		{Name: "", URL: "https://x/report", Transport: "ed25519", NodeID: "n1", KeyID: "k1", KeyEnv: "BAD_KEY"}, // missing name
		{Name: "badhex", URL: "https://x/report", Transport: "ed25519", NodeID: "n1", KeyID: "k1", KeyEnv: "BAD_KEY"},
		{Name: "emptyhmac", URL: "https://x/report", Transport: "hmac", NodeID: "n1", KeyID: "k1", KeyEnv: "EMPTY"},
		{Name: "unknowntransport", URL: "https://x/report", Transport: "rot13", NodeID: "n1", KeyID: "k1", KeyEnv: "EMPTY"},
		{Name: "nourl", URL: "", Transport: "hmac", NodeID: "n1", KeyID: "k1", KeyEnv: "EMPTY"},
	}
	if got := buildReportTargets(cases); len(got) != 0 {
		t.Fatalf("expected all invalid targets skipped, got %d: %+v", len(got), got)
	}
}
