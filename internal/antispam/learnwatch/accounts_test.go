package learnwatch

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"testing"
)

type fakeSource struct {
	users               []string
	passwd              string
	big                 []byte
	usersErr, passwdErr error
}

func (f fakeSource) CPanelUsers() ([]string, error) { return f.users, f.usersErr }
func (f fakeSource) Passwd() ([]byte, error) {
	if f.big != nil {
		return f.big, f.passwdErr
	}
	return []byte(f.passwd), f.passwdErr
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

func TestAccountsRejectsInvalidIDs(t *testing.T) {
	for _, id := range []string{"-1", "4294967295", "4294967296", "9223372036854775807"} {
		for _, field := range []string{"uid", "gid"} {
			t.Run(field+"/"+id, func(t *testing.T) {
				uid, gid := "1001", "1001"
				if field == "uid" {
					uid = id
				} else {
					gid = id
				}
				data := fmt.Sprintf("tenant1:x:%s:%s::/home/tenant1:/bin/bash\n", uid, gid)
				got, skips, err := Accounts(fakeSource{users: []string{"tenant1"}, passwd: data})
				if err != nil || len(got) != 0 || !slices.Equal(skips, []Skip{{Name: "tenant1", Reason: SkipNoPasswd}}) {
					t.Fatalf("accounts %+v, skips %+v, error %v", got, skips, err)
				}
			})
		}
	}
}

func TestAccountsAcceptsValidIDBounds(t *testing.T) {
	maxID := int64(4294967294)
	if strconv.IntSize == 32 {
		maxID = 2147483647
	}
	for _, ids := range [][2]int{{1, 0}, {int(maxID), int(maxID)}} {
		data := fmt.Sprintf("tenant1:x:%d:%d::/home/tenant1:/bin/bash\n", ids[0], ids[1])
		got, skips, err := Accounts(fakeSource{users: []string{"tenant1"}, passwd: data})
		want := []Account{{Name: "tenant1", UID: ids[0], GID: ids[1], Home: "/home/tenant1"}}
		if err != nil || !slices.Equal(got, want) || len(skips) != 0 {
			t.Fatalf("accounts %+v, skips %+v, error %v", got, skips, err)
		}
	}
}

func TestAccountsRejectsNULHome(t *testing.T) {
	got, skips, err := Accounts(fakeSource{
		users:  []string{"tenant1"},
		passwd: "tenant1:x:1001:1001::/home/tenant1\x00other:/bin/bash\n",
	})
	if err != nil || len(got) != 0 || !slices.Equal(skips, []Skip{{Name: "tenant1", Reason: SkipBadHome}}) {
		t.Fatalf("accounts %+v, skips %+v, error %v", got, skips, err)
	}
}

func TestAccountsUsesFirstValidPasswdEntry(t *testing.T) {
	for _, prefix := range []string{
		"tenant1:x:invalid:1001::/wrong:/bin/bash\n",
		"tenant1:x:1001:4294967296::/wrong:/bin/bash\n",
		"tenant1:x:4294967296:1001::/wrong:/bin/bash\n",
	} {
		data := prefix + "tenant1:x:1001:1002::/home2/tenant1:/bin/bash\n" +
			"tenant1:x:1003:1004::/other:/bin/bash\n"
		got, skips, err := Accounts(fakeSource{users: []string{"tenant1"}, passwd: data})
		want := []Account{{Name: "tenant1", UID: 1001, GID: 1002, Home: "/home2/tenant1"}}
		if err != nil || !slices.Equal(got, want) || len(skips) != 0 {
			t.Fatalf("accounts %+v, skips %+v, error %v", got, skips, err)
		}
	}
}

func TestAccountsSourceErrors(t *testing.T) {
	wantErr := errors.New("source unavailable")
	for _, src := range []fakeSource{
		{users: []string{"tenant1"}, usersErr: wantErr, passwd: passwd},
		{users: []string{"tenant1"}, passwd: passwd, passwdErr: wantErr},
	} {
		got, skips, err := Accounts(src)
		if !errors.Is(err, wantErr) || len(got) != 0 || len(skips) != 0 {
			t.Fatalf("accounts %+v, skips %+v, error %v", got, skips, err)
		}
	}
}

func TestLiveSourceErrors(t *testing.T) {
	absent := filepath.Join(t.TempDir(), "absent")
	src := LiveSource{UsersDir: absent, PasswdPath: absent}
	if names, err := src.CPanelUsers(); !errors.Is(err, os.ErrNotExist) || len(names) != 0 {
		t.Fatalf("names %v, error %v", names, err)
	}
	if data, err := src.Passwd(); !errors.Is(err, os.ErrNotExist) || len(data) != 0 {
		t.Fatalf("read %d bytes, error %v", len(data), err)
	}
	src.PasswdPath = t.TempDir()
	if data, err := src.Passwd(); err == nil || len(data) != 0 {
		t.Fatalf("read directory as passwd: %d bytes, error %v", len(data), err)
	}
}

func TestLiveSourceOnlyListsRegularRecords(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "tenant1"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "tenant2"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "tenant1"), filepath.Join(dir, "tenant3")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "missing"), filepath.Join(dir, "tenant4")); err != nil {
		t.Fatal(err)
	}
	names, err := (LiveSource{UsersDir: dir}).CPanelUsers()
	if err != nil || !slices.Equal(names, []string{"tenant1"}) {
		t.Fatalf("names %v, error %v", names, err)
	}
}

func TestLiveSourcePasswdBound(t *testing.T) {
	path := filepath.Join(t.TempDir(), "passwd")
	for _, size := range []int{MaxPasswdBytes, MaxPasswdBytes + 1, MaxPasswdBytes + 2} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			data := bytes.Repeat([]byte{'x'}, size)
			copy(data, passwd)
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			src := LiveSource{PasswdPath: path}
			got, err := src.Passwd()
			if err != nil || !bytes.Equal(got, data[:min(size, MaxPasswdBytes+1)]) {
				t.Fatalf("read %d bytes, error %v", len(got), err)
			}
			accounts, skips, err := Accounts(fakeSource{users: []string{"tenant1"}, big: got})
			if size > MaxPasswdBytes {
				if err == nil || len(accounts) != 0 || len(skips) != 0 {
					t.Fatalf("oversized passwd: accounts %+v, skips %+v, error %v", accounts, skips, err)
				}
			} else if err != nil || !slices.Equal(accounts, []Account{{Name: "tenant1", UID: 1001, GID: 1001, Home: "/home/tenant1"}}) || len(skips) != 0 {
				t.Fatalf("at bound: accounts %+v, skips %+v, error %v", accounts, skips, err)
			}
		})
	}
}
