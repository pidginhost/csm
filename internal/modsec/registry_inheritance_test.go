package modsec

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRegistryIncompleteDefaultsRemainBlocking(t *testing.T) {
	for _, failure := range []string{"read", "parse", "truncated"} {
		t.Run(failure, func(t *testing.T) {
			root := t.TempDir()
			setup := filepath.Join(root, "pack", "setup.conf")
			writeRule(t, setup, `SecDefaultAction "phase:2,deny"`)
			writeRule(t, filepath.Join(root, "pack", "rules", "rules.conf"), `SecRule ARGS "x" "id:5001,phase:2,block"
SecRule ARGS "x" "id:5002,phase:2,pass"
SecRule ARGS "x" "id:5003,phase:2,drop"
SecRule ARGS "x" "id:5004,phase:2,log"
`)
			writeRule(t, filepath.Join(root, "other", "rules.conf"), `SecRule ARGS "x" "id:5005,phase:2,block"`)
			// A readable pass default must not mask another setup file
			// in the same scope whose action could not be determined.
			writeRule(t, filepath.Join(root, "pack", "a_setup.conf"), `SecDefaultAction "phase:2,pass"`)
			switch failure {
			case "read":
				interceptRuleReads(t, setup, func(f *os.File) io.Reader {
					return ruleReadFunc(func([]byte) (int, error) { return 0, errors.New("setup read failed") })
				})
			case "truncated":
				writeRule(t, setup, `SecDefaultAction "phase:2,deny`)
			default:
				writeRule(t, setup, strings.Repeat("#", maxModsecLineBytes+1)+"\n"+`SecDefaultAction "phase:2,deny"`)
			}
			reg, err := BuildRegistry([]string{root})
			if err == nil {
				t.Fatal("incomplete setup was not reported")
			}
			if action, known := reg.Action(5001); !known || !IsBlockingAction(action) {
				t.Errorf("incomplete defaults weakened block: action=%q known=%v", action, known)
			}
			wantRegistryActions(t, reg, map[int]string{5002: "pass", 5003: "drop", 5005: "pass"})
			if action, known := reg.Action(5004); known {
				t.Errorf("metadata-only rule must remain absent, got %q", action)
			}
			fingerprint, present := RuleTreeFingerprint([]string{root})
			if !present || reg.Fingerprint() != fingerprint {
				t.Fatal("parser and fingerprint disagree about the incomplete tree")
			}
			if (fingerprint == "") != (failure == "read") {
				t.Fatalf("only read failures should prevent caching, got %q", fingerprint)
			}
		})
	}
}

func TestRegistryLinkedDirectoriesKeepDefaultsAndFingerprint(t *testing.T) {
	for _, linked := range []string{"root", "rules", "pack"} {
		t.Run(linked, func(t *testing.T) {
			root := t.TempDir()
			pack := filepath.Join(root, "pack")
			physical := pack
			if linked == "pack" || linked == "root" {
				physical = t.TempDir()
				if err := os.Symlink(physical, pack); err != nil {
					t.Fatal(err)
				}
			}
			setup := filepath.Join(physical, "setup.conf")
			writeRule(t, setup, `SecDefaultAction "phase:2,deny"`)
			rules := filepath.Join(physical, "rules")
			if linked == "rules" {
				target := t.TempDir()
				if err := os.Symlink(target, rules); err != nil {
					t.Fatal(err)
				}
			}
			writeRule(t, filepath.Join(rules, "rules.conf"), `SecRule ARGS "x" "id:5101,phase:2,block"`)
			writeRule(t, filepath.Join(rules, "nested", "setup.conf"), `SecDefaultAction "phase:2,pass"`)
			writeRule(t, filepath.Join(rules, "nested", "rules.conf"), `SecRule ARGS "x" "id:5102,phase:2,block"`)
			if linked == "root" {
				root = pack
			}
			reg, err := BuildRegistry([]string{root})
			if err != nil {
				t.Fatal(err)
			}
			wantRegistryActions(t, reg, map[int]string{5101: "deny", 5102: "pass"})
			before, _ := RuleTreeFingerprint([]string{root})
			if before == "" || before != reg.Fingerprint() {
				t.Fatal("linked tree fingerprint does not describe parsed content")
			}
			writeRule(t, setup, `SecDefaultAction "phase:2,pass"`)
			after, _ := RuleTreeFingerprint([]string{root})
			if before == after {
				t.Error("linked setup change did not invalidate the registry")
			}
			reg, err = BuildRegistry([]string{root})
			if err != nil {
				t.Fatal(err)
			}
			wantRegistryActions(t, reg, map[int]string{5101: "pass", 5102: "pass"})
		})
	}
}

func TestRegistryDirectoryCycleReportsIncompleteTree(t *testing.T) {
	root := t.TempDir()
	writeRule(t, filepath.Join(root, "rules.conf"), `SecRule ARGS "x" "id:5201,deny"`)
	if err := os.Symlink(root, filepath.Join(root, "loop")); err != nil {
		t.Fatal(err)
	}
	reg, err := BuildRegistry([]string{root})
	if err == nil || reg.Fingerprint() != "" {
		t.Fatal("directory cycle must report an uncached incomplete tree")
	}
	wantRegistryActions(t, reg, map[int]string{5201: "deny"})
	if fingerprint, present := RuleTreeFingerprint([]string{root}); fingerprint != "" || !present {
		t.Fatalf("cycle fingerprint=%q present=%v", fingerprint, present)
	}
}

func TestRegistryDirectoryAliasesKeepTheirOwnScope(t *testing.T) {
	root := t.TempDir()
	target := t.TempDir()
	writeRule(t, filepath.Join(target, "rules.conf"), `SecRule ARGS "x" "id:5202,phase:2,block"`)
	for _, pack := range []string{"a", "b"} {
		action := "deny"
		if pack == "b" {
			action = "pass"
		}
		writeRule(t, filepath.Join(root, pack, "setup.conf"), `SecDefaultAction "phase:2,`+action+`"`)
		if err := os.Symlink(target, filepath.Join(root, pack, "rules")); err != nil {
			t.Fatal(err)
		}
	}
	reg, err := BuildRegistry([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	// Both aliases must be visited: the later definition inherits b's pass.
	wantRegistryActions(t, reg, map[int]string{5202: "pass"})
	reg, err = BuildRegistry([]string{filepath.Join(root, "a"), filepath.Join(root, "b")})
	if err != nil {
		t.Fatal(err)
	}
	// Separate roots keep their established first-directory precedence.
	wantRegistryActions(t, reg, map[int]string{5202: "deny"})
}

func TestRegistryExplicitDisruptionWinsOverBlock(t *testing.T) {
	for _, action := range []string{"deny", "drop", "redirect:'https://example.com/'", "proxy:'http://example.com/'", "pause:100"} {
		t.Run(action, func(t *testing.T) {
			root := t.TempDir()
			writeRule(t, filepath.Join(root, "rules.conf"), fmt.Sprintf(`SecDefaultAction "phase:2,pass"
SecRule ARGS "x" "id:5301,phase:2,block,%s,log,msg:'pass,phase:1',logdata:'drop,phase:4'"
`, action))
			reg, err := BuildRegistry([]string{root})
			if err != nil {
				t.Fatal(err)
			}
			want, _, _ := strings.Cut(action, ":")
			wantRegistryActions(t, reg, map[int]string{5301: want})
		})
	}
}

func TestRegistryOperatorCannotSupplyActions(t *testing.T) {
	for _, action := range []string{"deny", "drop"} {
		t.Run(action, func(t *testing.T) {
			root := t.TempDir()
			writeRule(t, filepath.Join(root, "rules.conf"), fmt.Sprintf(`SecDefaultAction "phase:2,pass"
SecRule ARGS "@rx ,id:5401,phase:2,block" "id:5401,phase:1,%s"
`, action))
			reg, err := BuildRegistry([]string{root})
			if err != nil {
				t.Fatal(err)
			}
			wantRegistryActions(t, reg, map[int]string{5401: action})
		})
	}
}

func TestRegistryActionEscapesCannotHideDenies(t *testing.T) {
	root := t.TempDir()
	writeRule(t, filepath.Join(root, "rules.conf"), `SecDefaultAction "phase:2,pass"
SecDefaultAction "phase:1,deny"
SecRule ARGS "x" "id:5501,phase:2,block,msg:'It\\'s a match',deny"
SecRule ARGS "x" "id:5502,phase:2,block,logdata:'It\\'s a match',drop"
SecRule ARGS "x" "id:5503,phase:1,block,msg:'It\\'s text,phase:2'"
`)
	writeRule(t, filepath.Join(root, "nested", "rules.conf"), `SecDefaultAction "redirect:'https://example.com/it\\'s',phase:1"
SecRule ARGS "x" "id:5504,phase:1,block"
`)
	reg, err := BuildRegistry([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	wantRegistryActions(t, reg, map[int]string{5501: "deny", 5502: "drop", 5503: "deny", 5504: "redirect"})
}
