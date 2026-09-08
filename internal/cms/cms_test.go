package cms

import (
	"go/ast"
	"go/constant"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// expectedKinds is an independent expectation. It must not be generated
// from All(): deleting a descriptor would otherwise delete its own test.
var expectedKinds = []Kind{"wordpress", "joomla", "drupal", "opencart", "magento"}

// expectedOwners pins each adapter owner name independently of the table.
var expectedOwners = map[Kind]string{
	"wordpress": "db_content",
	"joomla":    "db_content_joomla",
	"drupal":    "db_content_drupal",
	"opencart":  "db_content_opencart",
	"magento":   "db_content_magento",
}

func TestCMSKindsAndDescriptors(t *testing.T) {
	got := All()
	if len(got) != len(expectedKinds) {
		t.Fatalf("All() returned %d descriptors, want %d", len(got), len(expectedKinds))
	}
	for i, d := range got {
		if d.Kind != expectedKinds[i] {
			t.Errorf("descriptor %d kind = %q, want %q", i, d.Kind, expectedKinds[i])
		}
		if want := expectedOwners[d.Kind]; d.DBContentCheck != want {
			t.Errorf("%s: DBContentCheck = %q, want %q", d.Kind, d.DBContentCheck, want)
		}
	}
	if err := validateDescriptors(got); err != nil {
		t.Fatal(err)
	}
}

func TestValidateDescriptorsRejects(t *testing.T) {
	base := All
	cases := map[string]func([]Descriptor) []Descriptor{
		"missing descriptor": func(ds []Descriptor) []Descriptor { return ds[:len(ds)-1] },
		"duplicate kind": func(ds []Descriptor) []Descriptor {
			dup := ds[0]
			dup.DBContentCheck = "db_content_other"
			dup.PathConstants = []string{"other_root"}
			return append(ds, dup)
		},
		"duplicate owner": func(ds []Descriptor) []Descriptor {
			ds[1].DBContentCheck = ds[0].DBContentCheck
			return ds
		},
		"empty owner": func(ds []Descriptor) []Descriptor {
			ds[2].DBContentCheck = ""
			return ds
		},
		"no constants": func(ds []Descriptor) []Descriptor {
			ds[3].PathConstants = nil
			return ds
		},
		"empty constant": func(ds []Descriptor) []Descriptor {
			ds[3].PathConstants = append(ds[3].PathConstants, "")
			return ds
		},
		"upper-case constant": func(ds []Descriptor) []Descriptor {
			ds[3].PathConstants = append(ds[3].PathConstants, "DIR_UPPER")
			return ds
		},
		"constant shared across kinds": func(ds []Descriptor) []Descriptor {
			ds[4].PathConstants = append(ds[4].PathConstants, ds[0].PathConstants[0])
			return ds
		},
		"constant repeated within kind": func(ds []Descriptor) []Descriptor {
			ds[4].PathConstants = append(ds[4].PathConstants, ds[4].PathConstants[0])
			return ds
		},
		"undeclared kind": func(ds []Descriptor) []Descriptor {
			return append(ds, Descriptor{Kind: "prestashop", DBContentCheck: "db_content_prestashop", PathConstants: []string{"dir_ps"}})
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			ds := mutate(base())
			if name == "missing descriptor" || name == "undeclared kind" {
				// These are caught by the declared-constant comparison, not
				// by the shape validator alone.
				if err := compareDeclaredKinds(declaredKindValues(t), ds); err == nil {
					t.Fatal("expected declared-kind mismatch")
				}
				return
			}
			if err := validateDescriptors(ds); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

// declaredKindValues type-checks every production file in this package and
// returns the value of each constant whose type is Kind, counting
// duplicates so an alias with the same value is visible.
func declaredKindValues(t *testing.T) map[string]int {
	t.Helper()
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	var files []*ast.File
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, perr := parser.ParseFile(fset, filepath.Join(".", name), nil, 0)
		if perr != nil {
			t.Fatal(perr)
		}
		files = append(files, f)
	}
	conf := types.Config{Importer: importer.Default()}
	info := types.Info{Defs: make(map[*ast.Ident]types.Object)}
	pkg, err := conf.Check("cms", fset, files, &info)
	if err != nil {
		t.Fatal(err)
	}
	kindObj := pkg.Scope().Lookup("Kind")
	if kindObj == nil {
		t.Fatal("type Kind not declared")
	}
	out := map[string]int{}
	// Package scope omits local and blank-identifier declarations. Defs
	// retains both, including inferred aliases of a supported kind.
	for _, obj := range info.Defs {
		c, ok := obj.(*types.Const)
		if !ok || !types.Identical(c.Type(), kindObj.Type()) {
			continue
		}
		out[constant.StringVal(c.Val())]++
	}
	return out
}

// compareDeclaredKinds requires every typed Kind constant to describe
// exactly one descriptor and every descriptor kind to have exactly one
// constant.
func compareDeclaredKinds(declared map[string]int, ds []Descriptor) error {
	described := map[string]int{}
	for _, d := range ds {
		described[string(d.Kind)]++
	}
	for k, n := range declared {
		if described[k] != 1 {
			return &kindMismatch{kind: k, constants: n, descriptors: described[k]}
		}
	}
	for k, n := range described {
		if declared[k] != 1 {
			return &kindMismatch{kind: k, constants: declared[k], descriptors: n}
		}
	}
	return nil
}

type kindMismatch struct {
	kind                   string
	constants, descriptors int
}

func (m *kindMismatch) Error() string {
	return "kind " + m.kind + ": declared " + itoa(m.constants) + " typed constant(s), " + itoa(m.descriptors) + " descriptor(s); want exactly one of each"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func TestDeclaredKindConstantsMatchDescriptors(t *testing.T) {
	declared := declaredKindValues(t)
	if len(declared) != len(expectedKinds) {
		t.Fatalf("declared typed Kind constants %v, want %d", declared, len(expectedKinds))
	}
	if err := compareDeclaredKinds(declared, All()); err != nil {
		t.Fatal(err)
	}
}

func TestDeclaredKindValuesIncludesEveryDeclaration(t *testing.T) {
	for name, source := range map[string]string{
		"explicit":     `const Extra Kind = "future"`,
		"inferred":     `const Extra = Kind("future")`,
		"type alias":   `type Alias = Kind; const Extra Alias = "future"`,
		"local":        `func f() { const Extra Kind = "future" }`,
		"local alias":  `func f() { const Extra = WordPress }`,
		"blank":        `const _ Kind = "future"`,
		"implicit":     "const (\nExtra Kind = \"future\"\nAlias\n)",
		"local shadow": `func f() { const WordPress Kind = "future" }`,
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			files := map[string]string{
				"cms.go":   "package cms\ntype Kind string\nconst WordPress Kind = \"wordpress\"\n",
				"extra.go": "package cms\n" + source + "\n",
			}
			for filename, contents := range files {
				if err := os.WriteFile(filepath.Join(dir, filename), []byte(contents), 0600); err != nil {
					t.Fatal(err)
				}
			}
			t.Chdir(dir)
			want := map[string]int{"wordpress": 1, "future": 1}
			switch name {
			case "local alias":
				want = map[string]int{"wordpress": 2}
			case "implicit":
				want["future"] = 2
			}
			got := declaredKindValues(t)
			if !maps.Equal(got, want) {
				t.Fatalf("declared kinds = %v, want %v", got, want)
			}
			if err := compareDeclaredKinds(got, []Descriptor{{Kind: WordPress}}); err == nil {
				t.Fatal("extra typed Kind declaration passed the descriptor guard")
			}
		})
	}
}

func TestCMSAccessors(t *testing.T) {
	for _, k := range expectedKinds {
		if got, ok := Parse(string(k)); !ok || got != k {
			t.Errorf("Parse(%q) = %q, %v", k, got, ok)
		}
		if d, ok := Lookup(k); !ok || d.Kind != k {
			t.Errorf("Lookup(%q) = %+v, %v", k, d, ok)
		}
	}
	for _, s := range []string{"", "Joomla", " joomla", "joomla ", "joomla!", "wp", "WORDPRESS", "prestashop"} {
		if k, ok := Parse(s); ok || k != "" {
			t.Errorf("Parse(%q) = %q, %v; want zero, false", s, k, ok)
		}
	}
	if d, ok := Lookup(Kind("prestashop")); ok || d.Kind != "" || d.DBContentCheck != "" || d.PathConstants != nil {
		t.Errorf("Lookup(unknown) = %+v, %v; want zero descriptor, false", d, ok)
	}

	first := All()
	first[0].Kind = "mutated"
	first[0].DBContentCheck = "mutated"
	first[0].PathConstants[0] = "mutated"
	first[1].PathConstants = append(first[1].PathConstants, "appended")
	again := All()
	if again[0].Kind == "mutated" || again[0].DBContentCheck == "mutated" || again[0].PathConstants[0] == "mutated" {
		t.Fatal("All() exposes shared policy memory")
	}
	if len(again[1].PathConstants) != len(expectedJoomlaConstants()) {
		t.Fatal("All() slice growth leaked into policy")
	}
	viaLookup, _ := Lookup(WordPress)
	viaLookup.PathConstants[0] = "mutated"
	fresh, _ := Lookup(WordPress)
	if fresh.PathConstants[0] == "mutated" {
		t.Fatal("Lookup() exposes shared policy memory")
	}
	if _, ok := Lookup(Kind("mutated")); ok {
		t.Fatal("mutating a returned Kind changed the table")
	}
}

func expectedJoomlaConstants() []string {
	return []string{"jpath_root", "jpath_base", "jpath_site", "jpath_administrator", "jpath_api",
		"jpath_cache", "jpath_cli", "jpath_component", "jpath_component_administrator",
		"jpath_component_site", "jpath_configuration", "jpath_installation",
		"jpath_libraries", "jpath_manifests", "jpath_plugins", "jpath_public", "jpath_themes"}
}
