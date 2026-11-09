//go:build linux

package main

import (
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"testing"
)

func TestDeployShieldConfigKeepsExistingSymlink(t *testing.T) {
	for _, dangling := range []bool{false, true} {
		name := "live"
		if dangling {
			name = "dangling"
		}
		t.Run(name, func(t *testing.T) {
			inst, conf := setupShieldConfigTest(t)
			target := conf + ".target"
			const edited = "<?php return array('blocked_paths' => array('/custom/'));\n"
			if !dangling {
				if err := os.WriteFile(target, []byte(edited), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Symlink(target, conf); err != nil {
				t.Fatal(err)
			}
			inst.deployShieldConfig()
			if got, err := os.Readlink(conf); err != nil || got != target {
				t.Fatalf("config symlink changed: %q, %v", got, err)
			}
			data, err := os.ReadFile(target)
			if dangling {
				if !os.IsNotExist(err) {
					t.Fatalf("dangling symlink target created: %v", err)
				}
			} else if err != nil || string(data) != edited {
				t.Fatalf("operator config changed: %v", err)
			}
		})
	}
}

func TestUninstallStillRemovesShieldConfig(t *testing.T) {
	var events []string
	inst := uninstallRecorder(&events, func() error { return nil })
	inst.operations.removeCommandLink = func(string, string) error { return nil }
	if err := inst.Uninstall(false); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(events, "remove "+phpShieldConfPath) {
		t.Fatal("uninstall kept the Shield config")
	}
}

func TestDeployShieldConfigKeepsFileCreatedDuringConfigLoad(t *testing.T) {
	for _, symlink := range []bool{false, true} {
		name := "regular"
		if symlink {
			name = "symlink"
		}
		t.Run(name, func(t *testing.T) {
			inst, conf := setupShieldConfigTest(t)
			inst.ConfigPath = filepath.Join(t.TempDir(), "config.fifo")
			if err := syscall.Mkfifo(inst.ConfigPath, 0600); err != nil {
				t.Fatal(err)
			}
			const edited = "<?php return array('allowed_ips' => array());\n"
			created := make(chan error, 1)
			go func() {
				// Opening the writer waits until the installer has checked the
				// destination and started reading its configuration.
				f, err := os.OpenFile(inst.ConfigPath, os.O_WRONLY, 0600)
				if err != nil {
					created <- err
					return
				}
				defer func() { _ = f.Close() }()
				target := conf
				if symlink {
					target += ".target"
				}
				if err = os.WriteFile(target, []byte(edited), 0600); err == nil && symlink {
					err = os.Symlink(target, conf)
				}
				if err == nil {
					_, err = f.WriteString("hostname: example.com\n")
				}
				created <- err
			}()
			inst.deployShieldConfig()
			if err := <-created; err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(conf)
			if err != nil {
				t.Fatal(err)
			}
			if string(data) != edited {
				t.Fatal("concurrently created Shield config was overwritten")
			}
			if symlink {
				if target, err := os.Readlink(conf); err != nil || target != conf+".target" {
					t.Fatalf("config symlink changed: %q, %v", target, err)
				}
			}
		})
	}
}
