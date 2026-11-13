package checks

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestStampProofDiscoveryRejectsNonTests(t *testing.T) {
	root := t.TempDir()
	for name, source := range map[string]string{
		"internal/proof_test.go": `package fixture
import "testing"
func TestProof(t *testing.T) {}
func Testhelper(t *testing.T) {}
func TestNoArgument() {}
func TestWrongArgument(t *testing.B) {}
func TestTwoArguments(t, other *testing.T) {}
func TestResult(t *testing.T) bool { return true }
func TestGeneric[T any](t *testing.T) {}
func TestMain(m *testing.M) {}
func TestDeclaration(t *testing.T)
func (receiver) TestMethod(t *testing.T) {}
`,
		"cmd/proof_test.go": `package fixture
import check "testing"
func TestAlias(t *check.T) {}
`,
		"internal/dot/proof_test.go": `package fixture
import . "testing"
func TestDot(t *T) {}
`,
		"internal/other/proof_test.go": `package fixture
import testing "example.com/other"
func TestOtherPackage(t *testing.T) {}
`,
		"internal/testdata/broken_test.go":  "not Go source",
		"internal/proof.go":                 "package fixture; import \"testing\"; func TestProduction(t *testing.T) {}",
		"internal/testdata/proof_test.go":   "package fixture; import \"testing\"; func TestFixture(t *testing.T) {}",
		"internal/_ignored/proof_test.go":   "package fixture; import \"testing\"; func TestIgnoredDir(t *testing.T) {}",
		"internal/.ignored/proof_test.go":   "package fixture; import \"testing\"; func TestHiddenDir(t *testing.T) {}",
		"internal/_ignored_test.go":         "package fixture; import \"testing\"; func TestIgnoredFile(t *testing.T) {}",
		"internal/.ignored_test.go":         "package fixture; import \"testing\"; func TestHiddenFile(t *testing.T) {}",
		"internal/vendor/pkg/proof_test.go": "package fixture; import \"testing\"; func TestDependency(t *testing.T) {}",
	} {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want := map[string]bool{"TestProof": true, "TestAlias": true, "TestDot": true}
	if got := testFunctionNames(t, root); !reflect.DeepEqual(got, want) {
		t.Fatalf("proof tests = %v, want %v", got, want)
	}
}
