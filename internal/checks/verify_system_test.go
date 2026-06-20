package checks

import (
	"os"
	"path/filepath"
	"testing"
)

func TestClassifyUID0LineMatchesDetectorRules(t *testing.T) {
	tests := []struct {
		name        string
		line        string
		wantUser    string
		wantFinding bool
	}{
		{name: "root allowed", line: "root:x:0:0:root:/root:/bin/bash", wantUser: "root"},
		{name: "sync allowed", line: "sync:x:0:0:sync:/sbin:/bin/sync", wantUser: "sync"},
		{name: "shutdown allowed", line: "shutdown:x:0:0:shutdown:/sbin:/sbin/shutdown", wantUser: "shutdown"},
		{name: "halt allowed", line: "halt:x:0:0:halt:/sbin:/sbin/halt", wantUser: "halt"},
		{name: "operator allowed", line: "operator:x:0:0:operator:/root:/sbin/nologin", wantUser: "operator"},
		{name: "unauthorized uid0", line: "evil:x:0:0::/root:/bin/bash", wantUser: "evil", wantFinding: true},
		{name: "uid must match exactly", line: "evil:x:00:0::/root:/bin/bash", wantUser: "evil"},
		{name: "malformed short line ignored", line: "evil:x:0"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotUser, gotFinding := classifyUID0Line(tt.line)
			if gotUser != tt.wantUser || gotFinding != tt.wantFinding {
				t.Fatalf("classifyUID0Line(%q) = (%q, %v), want (%q, %v)", tt.line, gotUser, gotFinding, tt.wantUser, tt.wantFinding)
			}
		})
	}
}

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

func TestVerifyUID0AccountUnresolvedWhenDuplicateStillUID0(t *testing.T) {
	withMockOS(t, &mockOS{
		readFile: func(string) ([]byte, error) {
			return []byte("evil:x:1002:1002::/home/evil:/bin/bash\nevil:x:0:0::/root:/bin/bash\n"), nil
		},
	})
	res := VerifyFinding("uid0_account", "Unauthorized UID 0 account: evil", "")
	if !res.Checked || res.Resolved {
		t.Fatalf("duplicate account with a remaining uid0 entry should verify unresolved, got %+v", res)
	}
}

func TestVerifyUID0AccountUsesExactAccountName(t *testing.T) {
	withMockOS(t, &mockOS{
		readFile: func(string) ([]byte, error) {
			return []byte("evil:x:1002:1002::/home/evil:/bin/bash\nevil :x:0:0::/root:/bin/bash\n"), nil
		},
	})
	res := VerifyFinding("uid0_account", "Unauthorized UID 0 account: evil ", "")
	if !res.Checked || res.Resolved {
		t.Fatalf("account name should match passwd exactly, got %+v", res)
	}
}

func TestVerifyUID0AccountRejectsUnmatchableAccountName(t *testing.T) {
	withMockOS(t, &mockOS{
		readFile: func(string) ([]byte, error) {
			return []byte("evil:x:0:0::/root:/bin/bash\n"), nil
		},
	})
	res := VerifyFinding("uid0_account", "Unauthorized UID 0 account: evil:shadow", "")
	if res.Checked || res.Resolved {
		t.Fatalf("account name containing passwd delimiters should not auto-verify, got %+v", res)
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
	withQuarantineAllowedRoots(t, "/home")
	bin := "/home/alice/tool"
	withMockOS(t, &mockOS{
		lstat: func(name string) (os.FileInfo, error) {
			switch name {
			case "/home", "/home/alice":
				return suidFileInfo{name: filepath.Base(name), mode: os.ModeDir | 0755}, nil
			case bin:
				return suidFileInfo{name: "tool", mode: 0755 | os.ModeSetuid}, nil
			default:
				return nil, os.ErrNotExist
			}
		},
	})
	res := VerifyFinding("suid_binary", "SUID binary in unusual location: "+bin, "", bin)
	if !res.Checked || res.Resolved {
		t.Fatalf("still-setuid binary should verify unresolved, got %+v", res)
	}
}

func TestVerifySuidClearedPreservesStructuredPathWhitespace(t *testing.T) {
	withQuarantineAllowedRoots(t, "/home")
	trimmed := "/home/alice/tool"
	flagged := trimmed + " "
	withMockOS(t, &mockOS{
		lstat: func(name string) (os.FileInfo, error) {
			switch name {
			case "/home", "/home/alice":
				return suidFileInfo{name: filepath.Base(name), mode: os.ModeDir | 0755}, nil
			case trimmed:
				return suidFileInfo{name: "tool", mode: 0755}, nil
			case flagged:
				return suidFileInfo{name: "tool ", mode: 0755 | os.ModeSetuid}, nil
			default:
				return nil, os.ErrNotExist
			}
		},
	})
	res := VerifyFinding("suid_binary", "SUID binary in unusual location: "+flagged, "", flagged)
	if !res.Checked || res.Resolved {
		t.Fatalf("suid path should be verified exactly, got %+v", res)
	}
}

func TestVerifySuidClearedNonRegularNotVerifiable(t *testing.T) {
	tmp := t.TempDir()
	withQuarantineAllowedRoots(t, tmp)
	dir := filepath.Join(tmp, "dir")
	if err := os.Mkdir(dir, 0755); err != nil {
		t.Fatal(err)
	}
	res := VerifyFinding("suid_binary", "SUID binary in unusual location: "+dir, "", dir)
	if res.Checked || res.Resolved {
		t.Fatalf("non-regular suid path should not auto-verify, got %+v", res)
	}
}

func TestVerifySuidClearedStatErrorNotVerifiable(t *testing.T) {
	withQuarantineAllowedRoots(t, "/home")
	target := "/home/alice/tool"
	withMockOS(t, &mockOS{
		lstat: func(name string) (os.FileInfo, error) {
			switch name {
			case "/home", "/home/alice":
				return suidFileInfo{name: filepath.Base(name), mode: os.ModeDir | 0755}, nil
			case target:
				return nil, os.ErrPermission
			default:
				return nil, os.ErrNotExist
			}
		},
	})
	res := VerifyFinding("suid_binary", "SUID binary in unusual location: "+target, "", target)
	if res.Checked || res.Resolved {
		t.Fatalf("suid stat error should not auto-verify, got %+v", res)
	}
}

func TestVerifySuidClearedSymlinkLeafNotVerifiable(t *testing.T) {
	tmp := t.TempDir()
	withQuarantineAllowedRoots(t, tmp)
	target := filepath.Join(tmp, "target")
	if err := os.WriteFile(target, []byte("x"), 0755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(tmp, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	res := VerifyFinding("suid_binary", "SUID binary in unusual location: "+link, "", link)
	if res.Checked || res.Resolved {
		t.Fatalf("suid symlink leaf should not auto-verify, got %+v", res)
	}
}
