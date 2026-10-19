package learnwatch

import (
	"bytes"
	"path/filepath"
	"slices"
	"testing"
)

type fakeSource struct {
	users  []string
	passwd string
	big    []byte
}

func (f fakeSource) CPanelUsers() ([]string, error) { return f.users, nil }
func (f fakeSource) Passwd() ([]byte, error) {
	if f.big != nil {
		return f.big, nil
	}
	return []byte(f.passwd), nil
}

const passwd = "root:x:0:0:root:/root:/bin/bash\n" +
	"tenant1:x:1001:1001::/home/tenant1:/bin/bash\n" +
	"tenant2:x:1002:1002::/home2/tenant2:/bin/bash\n" +
	"tenant3:x:0:1003::/home/tenant3:/bin/bash\n" +
	"tenant4:x:1004:1004::home/tenant4:/bin/bash\n" +
	"tenant5:x:1005:1005::/:/bin/bash\n" +
	"tenant6:x:1006:1006::/home/../etc:/bin/bash\n"

func accountsOf(t *testing.T, users ...string) ([]Account, []Skip) {
	t.Helper()
	got, skips, err := Accounts(fakeSource{users: users, passwd: passwd})
	if err != nil {
		t.Fatal(err)
	}
	return got, skips
}

func TestAccountsIncludesHome2(t *testing.T) {
	got, skips := accountsOf(t, "tenant1", "tenant2")
	want := []Account{
		{Name: "tenant1", UID: 1001, GID: 1001, Home: "/home/tenant1"},
		{Name: "tenant2", UID: 1002, GID: 1002, Home: "/home2/tenant2"},
	}
	if !slices.Equal(got, want) || len(skips) != 0 {
		t.Fatalf("accounts %+v, skips %+v", got, skips)
	}
}

func TestAccountsSkipsMissingPasswd(t *testing.T) {
	got, skips := accountsOf(t, "tenant1", "ghost")
	if len(got) != 1 || got[0].Name != "tenant1" {
		t.Fatalf("accounts %+v", got)
	}
	if !slices.Equal(skips, []Skip{{Name: "ghost", Reason: SkipNoPasswd}}) {
		t.Fatalf("skips %+v", skips)
	}
}

func TestAccountsSkipsRootAndRelativeHome(t *testing.T) {
	got, skips := accountsOf(t, "tenant3", "tenant4", "tenant5", "tenant6")
	if len(got) != 0 {
		t.Fatalf("accounts %+v", got)
	}
	want := []Skip{
		{Name: "tenant3", Reason: SkipRootUID},
		{Name: "tenant4", Reason: SkipBadHome},
		{Name: "tenant5", Reason: SkipBadHome},
		{Name: "tenant6", Reason: SkipBadHome},
	}
	if !slices.Equal(skips, want) {
		t.Fatalf("skips %+v", skips)
	}
}

func TestAccountsIgnoresInvalidNames(t *testing.T) {
	got, skips := accountsOf(t, "../x", "root", "", "tenant1")
	if len(got) != 1 || got[0].Name != "tenant1" || len(skips) != 0 {
		t.Fatalf("accounts %+v, skips %+v", got, skips)
	}
}

func TestAccountsBoundsPasswd(t *testing.T) {
	big := bytes.Repeat([]byte("x"), MaxPasswdBytes+1)
	if _, _, err := Accounts(fakeSource{users: []string{"tenant1"}, big: big}); err == nil {
		t.Fatal("oversized passwd accepted")
	}
}

func FuzzParsePasswd(f *testing.F) {
	f.Add([]byte(passwd), "tenant1")
	f.Add([]byte("a:b:c"), "a")
	f.Fuzz(func(t *testing.T, data []byte, name string) {
		got, _, err := Accounts(fakeSource{users: []string{name}, passwd: string(data)})
		if err != nil {
			return
		}
		for _, a := range got {
			if a.Name != name || a.UID <= 0 || a.GID < 0 || !filepathIsCleanAbs(a.Home) {
				t.Fatalf("bad account %+v", a)
			}
		}
	})
}

func filepathIsCleanAbs(p string) bool {
	return len(p) > 1 && p[0] == '/' && filepath.Clean(p) == p
}
