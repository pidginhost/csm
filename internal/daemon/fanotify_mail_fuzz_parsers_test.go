//go:build linux

package daemon

import (
	"strings"
	"testing"
)

func FuzzAccountMailDirectory(f *testing.F) {
	for _, account := range []string{"alice", "Alice", "mail", "alice-old", "0", ""} {
		f.Add(account)
	}
	f.Fuzz(func(t *testing.T, account string) {
		if len(account) > 255 || account == "" || account == "." || account == ".." || strings.ContainsAny(account, "/\x00") {
			return
		}
		for _, dir := range sensitivePHPDirs {
			if "/"+account+"/" == dir {
				return
			}
		}
		fm := &FileMonitor{accountRootPatterns: []string{"/home/*"}}
		for _, root := range []string{"/home/", "/home2/", "/home3/"} {
			for _, path := range []string{
				root + account + "/mail/probe.php",
				root + "/" + account + "//mail/probe.php",
			} {
				if got := fm.sensitivePHPDir(path); got != accountMailDir {
					t.Fatalf("sensitivePHPDir(%q) = %q, want account mail store", path, got)
				}
			}
			path := root + account + "/public_html/mail/probe.php"
			if got := fm.sensitivePHPDir(path); got != "" {
				t.Fatalf("sensitivePHPDir(%q) = %q for nested application directory", path, got)
			}
		}
	})
}
