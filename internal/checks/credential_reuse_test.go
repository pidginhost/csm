package checks

import (
	"strings"
	"testing"
)

func TestHashFingerprintGroupsIdenticalNeverLeaksHash(t *testing.T) {
	raw := "$P$Bxxxxxxxxxxxxxxxxxxxxxxxxxxx" // synthetic phpass-shaped hash
	fp1 := credentialHashFingerprint(raw)
	fp2 := credentialHashFingerprint(raw)
	if fp1 == "" || fp1 != fp2 {
		t.Fatalf("identical hashes must map to the same non-empty fingerprint: %q vs %q", fp1, fp2)
	}
	if credentialHashFingerprint("") != "" {
		t.Error("empty hash must yield empty fingerprint")
	}
	if credentialHashFingerprint("other") == fp1 {
		t.Error("distinct hashes must not collide")
	}
	// The fingerprint must not reveal the raw hash.
	if strings.Contains(fp1, raw) || strings.Contains(fp1, "$P$") {
		t.Errorf("fingerprint leaks the raw hash: %q", fp1)
	}
}

func TestBuildCredentialReuseFindings(t *testing.T) {
	byHash := map[string]map[string]struct{}{
		"fp:reused":  {"alice": {}, "bob": {}, "carol": {}},
		"fp:single":  {"dave": {}},
		"fp:reused2": {"erin": {}, "frank": {}},
	}
	out := buildCredentialReuseFindings(byHash, credentialReuseMinAccounts)
	if len(out) != 2 {
		t.Fatalf("findings = %d, want 2 (only fingerprints on >=2 accounts)", len(out))
	}
	// Deterministic order by fingerprint: fp:reused before fp:reused2.
	if !strings.Contains(out[0].Message, "alice, bob, carol") {
		t.Errorf("first finding accounts wrong: %q", out[0].Message)
	}
	if out[0].Check != "credential_reuse" {
		t.Errorf("check = %q", out[0].Check)
	}
	// No finding may contain a raw fingerprint key or the word hash value.
	for _, f := range out {
		if strings.Contains(f.Message, "fp:") || strings.Contains(f.Details, "fp:") {
			t.Errorf("finding leaks fingerprint key: %q / %q", f.Message, f.Details)
		}
	}
}

func TestBuildCredentialReuseFindingsEmpty(t *testing.T) {
	if out := buildCredentialReuseFindings(nil, 2); len(out) != 0 {
		t.Errorf("nil input -> %d findings, want 0", len(out))
	}
	single := map[string]map[string]struct{}{"fp:x": {"alice": {}}}
	if out := buildCredentialReuseFindings(single, 2); len(out) != 0 {
		t.Errorf("single-account hash must not flag: %d", len(out))
	}
}
