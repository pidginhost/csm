package scripts

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func queueRunnerWrite(t *testing.T, root, name, body string, mode os.FileMode) {
	t.Helper()
	path := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
}

func TestProductionRunnerEnforcesQueueInventory(t *testing.T) {
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	toolDir := t.TempDir()
	for _, name := range []string{"queuegate", "testgate"} {
		command := exec.Command(goBinary, "build", "-o", filepath.Join(toolDir, name), "./"+name)
		if output, buildErr := command.CombinedOutput(); buildErr != nil {
			t.Fatalf("build %s: %v\n%s", name, buildErr, output)
		}
	}
	runner, err := os.ReadFile("production-tests.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"portable", "kernel"} {
		for _, scenario := range []string{"pass", "capacity changed", "new allocation", "missing owner test", "skipped owner test"} {
			t.Run(mode+"/"+scenario, func(t *testing.T) {
				root := queueRunnerFixture(t, toolDir, string(runner), mode, scenario)
				command := exec.Command("bash", filepath.Join(root, "scripts", "production-tests.sh"), mode)
				command.Env = append(os.Environ(),
					"PATH="+filepath.Join(root, "bin")+":"+os.Getenv("PATH"),
					"CSM_QUEUE_FIXTURE_GO="+goBinary,
					"CSM_QUEUE_FIXTURE_TOOLS="+toolDir,
					"CSM_QUEUE_FIXTURE_SCENARIO="+scenario,
					"GOWORK=off")
				output, runErr := command.CombinedOutput()
				artifacts := filepath.Join(root, "production-results", mode)
				if scenario == "pass" {
					if runErr != nil {
						t.Fatalf("valid owner evidence rejected: %v\n%s", runErr, output)
					}
					var requirements []struct{ Package, Name string }
					data, readErr := os.ReadFile(filepath.Join(artifacts, "queue-required.json"))
					if readErr != nil {
						t.Fatalf("runner did not retain combined requirements: %v", readErr)
					}
					if decodeErr := json.Unmarshal(data, &requirements); decodeErr != nil {
						t.Fatal(decodeErr)
					}
					var names []string
					for _, required := range requirements {
						if required.Package != "github.com/pidginhost/csm/internal/example" {
							t.Fatalf("unexpected evidence package: %+v", required)
						}
						names = append(names, required.Name)
					}
					want := []string{"TestBaseline", "TestLifecycle", "TestPublication"}
					if mode == "kernel" {
						want = []string{"TestBaseline", "TestKernelOwner"}
					}
					if !slices.Equal(names, want) {
						t.Fatalf("baseline and owner requirements = %v, want %v", names, want)
					}
					queueRunnerPassedEvents(t, filepath.Join(artifacts, "tests.jsonl"), want)
					return
				}
				if runErr == nil {
					t.Fatalf("runner accepted %s\n%s", scenario, output)
				}
				var wantError string
				switch scenario {
				case "capacity changed":
					wantError = "allocation changed"
				case "new allocation":
					wantError = "unclassified allocation"
				case "missing owner test":
					wantError = "required test did not pass"
					if mode == "kernel" {
						wantError = "required test was not selected"
					}
				case "skipped owner test":
					wantError = "required test did not pass"
				}
				if !strings.Contains(string(output), wantError) {
					t.Fatalf("runner failed outside intended gate (%s): %v\n%s", wantError, runErr, output)
				}
				if scenario == "capacity changed" || scenario == "new allocation" {
					events, readErr := os.ReadFile(filepath.Join(artifacts, "tests.jsonl"))
					if readErr != nil || len(events) != 0 {
						t.Fatalf("invalid allocation reached test execution: events=%d err=%v", len(events), readErr)
					}
				}
			})
		}
	}
}

func queueRunnerPassedEvents(t *testing.T, name string, want []string) {
	t.Helper()
	data, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	passed := make(map[string]int)
	for line := range strings.SplitSeq(string(data), "\n") {
		if line == "" {
			continue
		}
		var event struct{ Action, Package, Test string }
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatal(err)
		}
		if event.Action == "pass" && event.Package == "github.com/pidginhost/csm/internal/example" {
			passed[event.Test]++
		}
	}
	if passed[""] != 1 || len(passed) != len(want)+1 {
		t.Fatalf("unexpected package/test completion events: %v", passed)
	}
	for _, test := range want {
		if passed[test] != 1 {
			t.Fatalf("required test %s did not actually pass exactly once: %v", test, passed)
		}
	}
}

func queueRunnerFixture(t *testing.T, toolsDir, runner, mode, scenario string) string {
	t.Helper()
	root := t.TempDir()
	write := func(name, contents string) { queueRunnerWrite(t, root, name, contents, 0o600) }
	write("go.mod", "module github.com/pidginhost/csm\n\ngo 1.26.0\n\nrequire github.com/VirusTotal/yara-x/go v1.20.0\n")
	write("build/Dockerfile.builder", "RUN git clone --branch v1.20.0 fixture\n")
	write("configs/.fixture", "fixture\n")
	write("scripts/production-tests.sh", runner)
	queueRunnerWrite(t, root, "bin/go", `#!/bin/bash
set -eu
if [[ "$1" == run && ( "$2" == ./scripts/queuegate || "$2" == ./scripts/testgate ) ]]; then
  tool=${2##*/}
  shift 2
  exec "$CSM_QUEUE_FIXTURE_TOOLS/$tool" "$@"
fi
exec "$CSM_QUEUE_FIXTURE_GO" "$@"
`, 0o700)
	queueRunnerWrite(t, root, "bin/pkg-config", "#!/bin/sh\nif [ \"$1\" = --modversion ]; then echo 1.20.0; fi\n", 0o700)
	queueRunnerWrite(t, root, "bin/git", "#!/bin/sh\necho 0000000000000000000000000000000000000000\n", 0o700)
	source := "package example\nconst bound = 4\nfunc pending() chan int { return make(chan int, bound) }\n"
	write("internal/example/source.go", source)
	commonTests := `package example
import ("os"; "testing")
func TestBaseline(t *testing.T) { if cap(pending()) != bound { t.Fatal("capacity") } }
func TestPublication(t *testing.T) { if cap(pending()) != 4 { t.Fatal("capacity") }; skipOwner(t) }
func TestLifecycle(t *testing.T) {
 q:=pending(); q<-7; close(q)
 if value,ok:=<-q; !ok || value!=7 {t.Fatal("lost buffered work")}
 if _,ok:=<-q; ok {t.Fatal("queue did not finish")}
}
func skipOwner(t *testing.T) { if os.Getenv("CSM_QUEUE_FIXTURE_SCENARIO")=="skipped owner test" { t.Skip("negative control: required evidence cannot skip") } }
`
	kernelTests := `//go:build kernelintegration

package example
import "testing"
func TestKernelOwner(t *testing.T) { if cap(pending()) != 4 { t.Fatal("capacity") }; skipOwner(t) }
`
	if scenario == "missing owner test" {
		if mode == "portable" {
			commonTests = strings.ReplaceAll(commonTests, "TestPublication", "TestUnrelated")
		} else {
			kernelTests = strings.ReplaceAll(kernelTests, "TestKernelOwner", "TestUnrelatedKernel")
		}
	}
	write("internal/example/source_test.go", commonTests)
	write("internal/example/source_kernel_test.go", kernelTests)
	command := exec.Command(filepath.Join(toolsDir, "queuegate"), "-root", root, "-scan")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("fixture scan: %v\n%s", err, output)
	}
	var allocations []map[string]any
	if decodeErr := json.Unmarshal(output, &allocations); decodeErr != nil || len(allocations) != 1 {
		t.Fatalf("fixture allocations: %s err=%v", output, decodeErr)
	}
	allocations[0]["class"], allocations[0]["queue"], allocations[0]["rationale"] = "work", "fixture", "Buffered fixture work with required publication and lifecycle evidence."
	evidence := func(name, mode string) map[string]string {
		return map[string]string{"package": "github.com/pidginhost/csm/internal/example", "name": name, "mode": mode}
	}
	manifest := map[string]any{
		"version": 1, "allocations": allocations,
		"owners": []any{map[string]any{
			"id": "fixture", "rows": []string{"fixture.work"}, "bounds": "Four waiting items.",
			"publication": []any{evidence("TestPublication", "portable"), evidence("TestKernelOwner", "kernel")},
			"lifecycle":   []any{evidence("TestLifecycle", "portable"), evidence("TestKernelOwner", "kernel")},
		}},
	}
	encoded, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	write("scripts/queue-inventory.json", string(encoded))
	baseline := `[{"Package":"github.com/pidginhost/csm/internal/example","Name":"TestBaseline"}]`
	write("scripts/production-required.json", baseline)
	write("scripts/kernel-required.json", baseline)
	switch scenario {
	case "capacity changed":
		write("internal/example/source.go", strings.ReplaceAll(source, "bound = 4", "bound = 8"))
	case "new allocation":
		write("internal/example/source.go", source+"func additional() chan int { return make(chan int, 1) }\n")
	}
	return root
}
