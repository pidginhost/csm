package checks

import (
	"os"
	"strings"
	"testing"
)

// deployVirtualPatches shares modsec2.user.conf with operator-maintained
// rules (Host-scoped ctl:ruleRemoveById exclusions and the like), so CSM
// may only ever rewrite its own marker-delimited section. These tests pin
// the on-disk format: the marker lines are a contract with files already
// deployed in production, so they are spelled out literally here.
const (
	vpTestBegin = "# BEGIN CSM Custom ModSecurity Rules (managed by CSM - do not edit inside this block)"
	vpTestEnd   = "# END CSM Custom ModSecurity Rules"

	vpTestSrcPath = "/opt/csm/configs/csm_modsec_custom.conf"
	vpTestDestDir = "/etc/apache2/conf.d/modsec"
	vpTestDest    = "/etc/apache2/conf.d/modsec/modsec2.user.conf"
)

// The real rules file starts with this header line; pre-delimiter CSM
// versions appended it verbatim, which is exactly the legacy layout the
// migration path has to recognize.
const (
	vpTestSrcV1 = "# CSM Custom ModSecurity Rules\n" +
		"SecRule REQUEST_URI \"/xmlrpc\\.php$\" \"id:900100,phase:1,deny\"\n"
	vpTestSrcV2 = "# CSM Custom ModSecurity Rules\n" +
		"SecRule REQUEST_URI \"/wp-json/wp/v2/users\" \"id:900200,phase:1,deny\"\n"
	vpTestOperator = "# Host-scoped CWAF exclusion, operator-maintained\n" +
		"SecRule REQUEST_HEADERS:Host \"@streq shop.example.com\" " +
		"\"id:100001,phase:1,pass,ctl:ruleRemoveById=214930\"\n"
)

// vpTestFS is an in-memory filesystem for deployVirtualPatches: the source
// rules file plus (optionally) the first destination path, whose parent
// directory always exists. Writes land back in the map so tests can assert
// on the final file bytes and on how many writes happened.
type vpTestFS struct {
	files  map[string]string
	writes int
	perms  []os.FileMode
}

func setupVPTestFS(t *testing.T, srcContent string, destContent *string) *vpTestFS {
	t.Helper()
	fs := &vpTestFS{files: map[string]string{vpTestSrcPath: srcContent}}
	if destContent != nil {
		fs.files[vpTestDest] = *destContent
	}
	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			if content, ok := fs.files[name]; ok {
				return []byte(content), nil
			}
			return nil, os.ErrNotExist
		},
		stat: func(name string) (os.FileInfo, error) {
			if name == vpTestDestDir {
				return nil, nil
			}
			return nil, os.ErrNotExist
		},
		writeFile: func(name string, data []byte, perm os.FileMode) error {
			fs.files[name] = string(data)
			fs.writes++
			fs.perms = append(fs.perms, perm)
			return nil
		},
	})
	return fs
}

func vpTestSection(src string) string {
	return vpTestBegin + "\n" + src + vpTestEnd + "\n"
}

// Cycle-2 regression: operator rules followed by a legacy CSM block (old
// marker, no END delimiter, block runs to EOF). CSM must upgrade its block
// in place and must not wipe the operator rules that precede it.
func TestDeployVirtualPatches_MigratesLegacyBlockPreservingOperatorRules(t *testing.T) {
	dest := vpTestOperator + "\n\n" + vpTestSrcV1
	fs := setupVPTestFS(t, vpTestSrcV2, &dest)

	deployVirtualPatches()

	got := fs.files[vpTestDest]
	if !strings.HasPrefix(got, vpTestOperator) {
		t.Fatalf("operator rules wiped; file now:\n%s", got)
	}
	if !strings.Contains(got, vpTestBegin) || !strings.Contains(got, vpTestEnd) {
		t.Errorf("missing section delimiters; file now:\n%s", got)
	}
	if !strings.Contains(got, "id:900200") {
		t.Errorf("new CSM rules not deployed; file now:\n%s", got)
	}
	if strings.Contains(got, "id:900100") {
		t.Errorf("legacy CSM rules not removed; file now:\n%s", got)
	}
	if fs.writes != 1 {
		t.Errorf("writes = %d, want 1", fs.writes)
	}
}

// Once the delimited section is in place and matches the source rules,
// further cycles must not touch the file at all.
func TestDeployVirtualPatches_UpToDateSectionLeavesFileUntouched(t *testing.T) {
	dest := vpTestOperator
	fs := setupVPTestFS(t, vpTestSrcV2, &dest)

	deployVirtualPatches()
	if fs.writes != 1 {
		t.Fatalf("setup deploy: writes = %d, want 1", fs.writes)
	}
	afterFirst := fs.files[vpTestDest]

	deployVirtualPatches()

	if fs.writes != 1 {
		t.Errorf("up-to-date cycle wrote the file: writes = %d, want 1", fs.writes)
	}
	if fs.files[vpTestDest] != afterFirst {
		t.Errorf("file changed on up-to-date cycle:\n%s", fs.files[vpTestDest])
	}
}

// A missing destination file gets exactly the delimited section.
func TestDeployVirtualPatches_FreshFileGetsDelimitedSection(t *testing.T) {
	fs := setupVPTestFS(t, vpTestSrcV2, nil)

	deployVirtualPatches()

	want := vpTestSection(vpTestSrcV2)
	if got := fs.files[vpTestDest]; got != want {
		t.Errorf("fresh file = %q, want %q", got, want)
	}
	if len(fs.perms) != 1 || fs.perms[0] != 0o644 {
		t.Errorf("perms = %v, want [0644]", fs.perms)
	}
}

// A destination holding only operator rules (no CSM marker anywhere) gets
// the section appended; the pre-existing bytes stay byte-for-byte intact.
func TestDeployVirtualPatches_AppendsToOperatorFilePreservingBytes(t *testing.T) {
	dest := vpTestOperator
	fs := setupVPTestFS(t, vpTestSrcV2, &dest)

	deployVirtualPatches()

	want := vpTestOperator + "\n" + vpTestSection(vpTestSrcV2)
	if got := fs.files[vpTestDest]; got != want {
		t.Errorf("appended file = %q, want %q", got, want)
	}
}

// The exported wrapper is consumed by the installer and the daemon startup
// config deploy. These tests pin its contract: changed=false means the file
// already carries the wanted section and the caller must not write.
func TestMergeModSecUserConfSection_FreshThenUpToDate(t *testing.T) {
	src := []byte(vpTestSrcV2)

	fresh, changed := MergeModSecUserConfSection(nil, src)
	if !changed {
		t.Fatal("fresh file: changed = false, want true")
	}
	if string(fresh) != vpTestSection(vpTestSrcV2) {
		t.Errorf("fresh = %q, want %q", fresh, vpTestSection(vpTestSrcV2))
	}

	if merged, changed := MergeModSecUserConfSection(fresh, src); changed {
		t.Errorf("up-to-date file: changed = true, merged = %q", merged)
	}
}

func TestMergeModSecUserConfSection_PreservesBytesOutsideSection(t *testing.T) {
	after := "\n# CSM overrides - managed by CSM rule management\n" +
		"Include /etc/apache2/conf.d/modsec/modsec2.csm-overrides.conf\n"
	existing := []byte(vpTestOperator + "\n" + vpTestSection(vpTestSrcV1) + after)

	merged, changed := MergeModSecUserConfSection(existing, []byte(vpTestSrcV2))

	if !changed {
		t.Fatal("changed = false, want true")
	}
	want := vpTestOperator + "\n" + vpTestSection(vpTestSrcV2) + after
	if string(merged) != want {
		t.Errorf("merged = %q, want %q", merged, want)
	}
}

func TestMergeModSecUserConfSection_MigratesLegacyAppend(t *testing.T) {
	existing := []byte(vpTestOperator + "\n\n" + vpTestSrcV1)

	merged, changed := MergeModSecUserConfSection(existing, []byte(vpTestSrcV2))

	if !changed {
		t.Fatal("changed = false, want true")
	}
	if !strings.HasPrefix(string(merged), vpTestOperator) {
		t.Errorf("operator rules wiped; merged:\n%s", merged)
	}
	if strings.Contains(string(merged), "id:900100") {
		t.Errorf("legacy CSM rules not removed; merged:\n%s", merged)
	}
	if !strings.Contains(string(merged), "id:900200") {
		t.Errorf("new CSM rules missing; merged:\n%s", merged)
	}
}

func TestMergeModSecUserConfSection_PreservesOverridesIncludeOnLegacyMigration(t *testing.T) {
	after := "\n# CSM overrides - managed by CSM rule management\n" +
		"Include /etc/apache2/conf.d/modsec/modsec2.csm-overrides.conf\n"
	existing := []byte(vpTestOperator + "\n\n" + vpTestSrcV1 + after)

	merged, changed := MergeModSecUserConfSection(existing, []byte(vpTestSrcV2))

	if !changed {
		t.Fatal("changed = false, want true")
	}
	want := vpTestOperator + "\n\n" + vpTestSection(vpTestSrcV2) + after
	if string(merged) != want {
		t.Errorf("merged = %q, want %q", merged, want)
	}
}

func TestMergeModSecUserConfSection_RepairsMalformedDelimitedBlockFromBegin(t *testing.T) {
	after := "\n# CSM overrides - managed by CSM rule management\n" +
		"Include /etc/apache2/conf.d/modsec/modsec2.csm-overrides.conf\n"
	existing := []byte(vpTestOperator + "\n" + vpTestBegin + "\n" + vpTestSrcV1 + after)

	merged, changed := MergeModSecUserConfSection(existing, []byte(vpTestSrcV2))

	if !changed {
		t.Fatal("changed = false, want true")
	}
	want := vpTestOperator + "\n" + vpTestSection(vpTestSrcV2) + after
	if string(merged) != want {
		t.Errorf("merged = %q, want %q", merged, want)
	}
	if strings.Count(string(merged), vpTestBegin) != 1 {
		t.Errorf("begin markers = %d, want 1; merged:\n%s", strings.Count(string(merged), vpTestBegin), merged)
	}
}

func TestMergeModSecUserConfSection_IgnoresMarkerTextInsideOperatorLine(t *testing.T) {
	existing := []byte("# Operator note mentions " + vpTestBegin + "\n" + vpTestOperator)

	merged, changed := MergeModSecUserConfSection(existing, []byte(vpTestSrcV2))

	if !changed {
		t.Fatal("changed = false, want true")
	}
	want := string(existing) + "\n" + vpTestSection(vpTestSrcV2)
	if string(merged) != want {
		t.Errorf("merged = %q, want %q", merged, want)
	}
}

// When the source rules change, only the bytes between the markers move;
// operator content both before and after the section is preserved exactly.
func TestDeployVirtualPatches_ReplacesDelimitedSectionInPlace(t *testing.T) {
	after := "\n# CSM overrides - managed by CSM rule management\n" +
		"Include /etc/apache2/conf.d/modsec/modsec2.csm-overrides.conf\n"
	dest := vpTestOperator + "\n" + vpTestSection(vpTestSrcV1) + after
	fs := setupVPTestFS(t, vpTestSrcV2, &dest)

	deployVirtualPatches()

	want := vpTestOperator + "\n" + vpTestSection(vpTestSrcV2) + after
	if got := fs.files[vpTestDest]; got != want {
		t.Errorf("replaced file = %q, want %q", got, want)
	}
	if fs.writes != 1 {
		t.Errorf("writes = %d, want 1", fs.writes)
	}
}
