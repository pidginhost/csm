package checks

import (
	"os"
	"path/filepath"
	"testing"
)

func TestVerifyUID0AccountResolvedWhenGone(t *testing.T) {
	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			if name == "/etc/passwd" {
				return []byte("root:x:0:0:root:/root:/bin/bash\nalice:x:1001:1001::/home/alice:/bin/bash\n"), nil
			}
			return nil, os.ErrNotExist
		},
	})
	res := VerifyFinding("uid0_account", "Unauthorized UID 0 account: evil", "evil:x:0:0::/root:/bin/bash")
	if !res.Checked || !res.Resolved {
		t.Fatalf("removed uid0 account should verify resolved, got %+v", res)
	}
}

func TestVerifyUID0AccountResolvedWhenUIDChanged(t *testing.T) {
	withMockOS(t, &mockOS{
		readFile: func(string) ([]byte, error) {
			return []byte("evil:x:1002:1002::/home/evil:/bin/bash\n"), nil
		},
	})
	res := VerifyFinding("uid0_account", "Unauthorized UID 0 account: evil", "")
	if !res.Checked || !res.Resolved {
		t.Fatalf("uid demoted from 0 should verify resolved, got %+v", res)
	}
}

func TestVerifyUID0AccountUnresolvedWhenStillUID0(t *testing.T) {
	withMockOS(t, &mockOS{
		readFile: func(string) ([]byte, error) {
			return []byte("evil:x:0:0::/root:/bin/bash\n"), nil
		},
	})
	res := VerifyFinding("uid0_account", "Unauthorized UID 0 account: evil", "")
	if !res.Checked || res.Resolved {
		t.Fatalf("still-uid0 account should verify unresolved, got %+v", res)
	}
}

func TestVerifyUID0AccountPasswdUnreadableNotVerifiable(t *testing.T) {
	withMockOS(t, &mockOS{
		readFile: func(string) ([]byte, error) { return nil, os.ErrPermission },
	})
	res := VerifyFinding("uid0_account", "Unauthorized UID 0 account: evil", "")
	if res.Checked || res.Resolved {
		t.Fatalf("unreadable /etc/passwd must not verify resolved, got %+v", res)
	}
}

func TestVerifyUID0AccountNoUserNotVerifiable(t *testing.T) {
	res := VerifyFinding("uid0_account", "some unrelated message", "")
	if res.Checked {
		t.Errorf("message without an account should not be auto-verifiable, got %+v", res)
	}
}

func TestVerifySuidClearedResolvedWhenGone(t *testing.T) {
	tmp := t.TempDir()
	withQuarantineAllowedRoots(t, tmp)
	res := VerifyFinding("suid_binary", "SUID binary in unusual location: "+filepath.Join(tmp, "gone"), "", filepath.Join(tmp, "gone"))
	if !res.Checked || !res.Resolved {
		t.Fatalf("removed suid binary should verify resolved, got %+v", res)
	}
}

func TestVerifySuidClearedResolvedWhenBitCleared(t *testing.T) {
	tmp := t.TempDir()
	withQuarantineAllowedRoots(t, tmp)
	bin := filepath.Join(tmp, "tool")
	if err := os.WriteFile(bin, []byte("x"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(bin, 0755); err != nil { // no setuid bit
		t.Fatal(err)
	}
	res := VerifyFinding("suid_binary", "SUID binary in unusual location: "+bin, "", bin)
	if !res.Checked || !res.Resolved {
		t.Fatalf("suid-cleared binary should verify resolved, got %+v", res)
	}
}

func TestVerifySuidClearedUnresolvedWhenStillSetuid(t *testing.T) {
	tmp := t.TempDir()
	withQuarantineAllowedRoots(t, tmp)
	bin := filepath.Join(tmp, "tool")
	if err := os.WriteFile(bin, []byte("x"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(bin, 0755|os.ModeSetuid); err != nil {
		t.Fatal(err)
	}
	res := VerifyFinding("suid_binary", "SUID binary in unusual location: "+bin, "", bin)
	if !res.Checked || res.Resolved {
		t.Fatalf("still-setuid binary should verify unresolved, got %+v", res)
	}
}
