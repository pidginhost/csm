//go:build linux

package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

func TestDropperDiscardedLanguagePackDirectoryGroup(t *testing.T) {
	for _, tc := range []struct {
		name          string
		payloadSize   int
		filteredBurst bool
	}{
		{"500 KB pack", 500_000, false},
		{"500 KB filtered burst", 500_000, true},
		{"incomplete snapshots", dropperDigestMax + 1, false},
		{"incomplete snapshots filtered burst", dropperDigestMax + 1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			pack := filepath.Join(root, "wp-content/upgrade/wordpress-7.1-ro_ro")
			r := newWPInstallRun(t, root)
			body := "<?php return ['messages'=>['Settings'=>'" + strings.Repeat("x", tc.payloadSize) + "']];"
			names := []string{"ro_RO.l10n.php", "admin-ro_RO.l10n.php", "admin-network-ro_RO.l10n.php", "continents-cities-ro_RO.l10n.php"}
			ignored := make(map[string]bool)
			if tc.filteredBurst {
				for _, prefix := range []string{"a", "b", "c", "d"} {
					file := prefix + "-ignored.l10n.php"
					names = append(names, file)
					ignored[filepath.Join(pack, file)] = true
				}
			}
			for _, file := range names {
				path := filepath.Join(pack, file)
				writeWPInstallFile(t, path, body)
				c := r.observe(t, path, nil)
				if !c.Parent.known() {
					t.Fatal("fixture must retain parent identity")
				}
				if tc.payloadSize > dropperDigestMax && (c.DigestKnown || c.WPInstallData) {
					t.Fatal("oversized fixture unexpectedly has complete content proof")
				}
			}
			shell := filepath.Join(pack, "shell.php")
			writeWPInstallFile(t, shell, testDropperPHP)
			c := r.observe(t, shell, nil)
			c.ContentSuspicious = true
			if !r.fm.dropper.tr.Refresh(*c) {
				t.Fatal("refresh lost suspect candidate")
			}
			if err := os.RemoveAll(pack); err != nil {
				t.Fatal(err)
			}
			probeAt := time.Now().Add(r.ttl + time.Second)
			prober := r.fm.newDropperFSProbe()
			r.fm.dropper.probeStep(probeAt, prober, probeAt)
			r.fm.dropper.ignorePath = func(path string) bool { return ignored[path] }
			flushAt := probeAt.Add(dropperGraceWindow)
			r.fm.dropper.probeStep(flushAt, prober, flushAt)
			if len(*r.alerts) != 2 {
				t.Fatalf("alerts = %+v, want one directory Warning and one suspect Critical", *r.alerts)
			}
			var grouped, suspect bool
			for _, a := range *r.alerts {
				switch a.path {
				case pack:
					grouped = true
					if a.sev != alert.Warning || !strings.HasPrefix(a.msg, "4 ") || strings.Contains(a.details, "ignored") || strings.Contains(a.details, "shell.php") {
						t.Errorf("invalid directory finding: %+v", a)
					}
					for _, file := range names[:4] {
						if !strings.Contains(a.details, file) {
							t.Errorf("directory finding omitted %s", file)
						}
					}
				case shell:
					suspect = true
					if a.sev != alert.Critical {
						t.Errorf("suspect severity = %v, want Critical", a.sev)
					}
				default:
					t.Errorf("unexpected finding: %+v", a)
				}
			}
			if !grouped || !suspect {
				t.Fatal("missing directory or suspect finding")
			}
		})
	}
}
