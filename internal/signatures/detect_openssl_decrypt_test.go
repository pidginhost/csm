package signatures

import (
	"os"
	"path/filepath"
	"testing"
)

// eval(openssl_decrypt(...)) is the loader form used by a real cross-account
// compromise (2026-07-23). The eval-decoder chain rule recognized gzinflate,
// base64_decode, str_rot13 and friends but not openssl_decrypt, so an eval
// that directly wrapped openssl_decrypt slipped through.
func TestPHPEvalDecodeChainMatchesOpensslDecrypt(t *testing.T) {
	rules, err := os.ReadFile(filepath.Join("..", "..", "configs", "malware.yml"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "malware.yml"), rules, 0o644); err != nil {
		t.Fatal(err)
	}
	s := NewScanner(dir)

	target := filepath.Join(t.TempDir(), "loader.php")
	sample := []byte("<?php eval(openssl_decrypt(base64_decode($p), 'aes-256-cbc', $k, 0, $iv)); ?>")
	if err := os.WriteFile(target, sample, 0o644); err != nil {
		t.Fatal(err)
	}

	found := false
	for _, m := range s.ScanFile(target, 1<<20) {
		if m.RuleName == "php_eval_decode_chain" {
			found = true
		}
	}
	if !found {
		t.Error("php_eval_decode_chain did not match eval(openssl_decrypt(...))")
	}
}
