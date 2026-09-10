package main

import (
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"
)

func queueFixture(files map[string]string) fs.FS {
	fixture := fstest.MapFS{}
	for path, source := range files {
		fixture[path] = &fstest.MapFile{Data: []byte(source)}
	}
	return fixture
}

func TestScanTracksAllBuildVariantsAndNamedChannels(t *testing.T) {
	files := queueFixture(map[string]string{
		"internal/example/source_linux.go": `//go:build linux && journal
package example
type pending chan string
type alias = pending
const limit = 4
func start() { queue := make(alias, limit); _ = queue }
`,
		"internal/example/source_other.go": `//go:build !linux
package example
func fallback() { var result = make(chan int, 7); _ = result }
`,
		"internal/example/source_test.go": `package example
func fixture() { _ = make(chan bool, 99) }
`,
		"internal/example/testdata/probe.go": `package probe
func sample() { _ = make(chan bool, 99) }
`,
	})
	got, err := scanSources(files)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("allocations=%+v want both production variants only", got)
	}
	if got[0].ID != "internal/example/source_linux.go::start::queue::channel::1" || got[0].Capacity != "4" || got[1].Capacity != "7" {
		t.Fatalf("named channel identity or capacity missing: %+v", got)
	}
}

func TestScanResolvesCrossFileAndImportedChannelTypes(t *testing.T) {
	got, err := scanSources(queueFixture(map[string]string{
		"internal/types/types.go":   `package types; type Pending[T any] chan T`,
		"internal/example/types.go": `package example; type values []int; type messages = chan int`,
		"internal/example/source.go": `package example
import kinds "github.com/pidginhost/csm/internal/types"
func start() { _ = make(values, 8); local := make(messages, 3); foreign := make(kinds.Pending[int], 6); _, _ = local, foreign }
`,
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Capacity != "6" || got[1].Capacity != "3" {
		t.Fatalf("cross-file or imported channel alias disappeared: %+v", got)
	}
}

func TestScanResolvesWrapperImportsAndShadowing(t *testing.T) {
	for _, tc := range []struct {
		name, source string
		want         int
	}{
		{"renamed", `package example; import q "github.com/pidginhost/csm/internal/queuehealth"; func start() { out := q.NewChannel[int](8, 60); _ = out }`, 1},
		{"dot", `package example; import . "github.com/pidginhost/csm/internal/queuehealth"; func start() { out := NewChannel[int](8, 60); _ = out }`, 1},
		{"unrelated import", `package example; import queuehealth "example.test/other"; func start() { out := queuehealth.NewChannel[int](8, 60); _ = out }`, 0},
		{"local shadow", `package example; import queuehealth "github.com/pidginhost/csm/internal/queuehealth"; func start(queuehealth struct{NewChannel func(int) int}) { out := queuehealth.NewChannel(8); _ = out }`, 0},
		{"dot shadow", `package example; import . "github.com/pidginhost/csm/internal/queuehealth"; func start(NewChannel func(int) int) { out := NewChannel(8); _ = out }`, 0},
		{"fake local name", `package example; func start(queuehealth struct{NewChannel func(int) int}) { out := queuehealth.NewChannel(8); _ = out }`, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := scanSources(queueFixture(map[string]string{"internal/example/source.go": tc.source}))
			if err != nil || len(got) != tc.want {
				t.Fatalf("wrapper import resolution: allocations=%+v err=%v want=%d", got, err, tc.want)
			}
			if tc.want == 1 && (got[0].Kind != "accounted_channel" || got[0].Capacity != "8") {
				t.Fatalf("wrapper capacity/ownership missing: %+v", got)
			}
		})
	}
}

func TestScanRejectsUnresolvedAndIndirectAllocations(t *testing.T) {
	for _, tc := range []struct{ name, source, reason string }{
		{"missing type", `package example; func start() { _ = make(missing, 3) }`, "unresolved make type"},
		{"cyclic type", `package example; type A = B; type B = A; func start() { _ = make(A, 3) }`, "cyclic make type"},
		{"generic constraint", `package example; func start[T interface{ ~chan int }]() { _ = make(T, 3) }`, "unresolved make type"},
		{"wrapper value", `package example; import q "github.com/pidginhost/csm/internal/queuehealth"; var allocate = q.NewChannel[int]; func start() { _ = allocate(3, 60) }`, "indirect channel constructor"},
		{"dot wrapper value", `package example; import . "github.com/pidginhost/csm/internal/queuehealth"; var allocate = NewChannel[int]`, "indirect channel constructor"},
		{"reflect", `package example; import r "reflect"; func start(t r.Type) { _ = r.MakeChan(t, 3) }`, "reflective channel allocation"},
		{"dot reflect", `package example; import . "reflect"; func start(t Type) { _ = MakeChan(t, 3) }`, "reflective channel allocation"},
		{"dot reflect alias", `package example; import . "reflect"; var allocate = MakeChan`, "indirect channel constructor"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := scanSources(queueFixture(map[string]string{"internal/example/source.go": tc.source}))
			if err == nil || !strings.Contains(err.Error(), tc.reason) {
				t.Fatalf("unsupported channel construction did not fail closed: err=%v want=%q", err, tc.reason)
			}
		})
	}
}

func TestScanTracksCapacityDefinitionsAndLocalDefaults(t *testing.T) {
	for _, limit := range []string{"4", "8"} {
		got, err := scanSources(queueFixture(map[string]string{
			"internal/example/cap.go": `package example; const limit = ` + limit,
			"internal/example/source.go": `package example
func start(options struct{Capacity int}) {
 if options.Capacity <= 0 { options.Capacity = limit }
 queue := make(chan int, options.Capacity)
 _ = queue
}
`,
		}))
		if err != nil || len(got) != 1 {
			t.Fatalf("configured allocation missing: %+v %v", got, err)
		}
		if got[0].Capacity != "options.Capacity" || len(got[0].Defaults) != 1 || got[0].Defaults[0] != "options.Capacity = "+limit {
			t.Fatalf("capacity default definition did not follow constant change: %+v", got)
		}
	}
}

func TestScanResolvesStandardLibraryNamedSlices(t *testing.T) {
	got, err := scanSources(queueFixture(map[string]string{
		"internal/example/source.go": `package example; import "net"; func start(){ _ = make(net.IP, 16); _ = make(net.HardwareAddr, 6); _ = make(chan net.IP, 4) }`,
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Source != "make(chan net.IP, 4)" {
		t.Fatalf("named slices classified as queues: %+v", got)
	}
}

func TestScanAssignsDistinctPackageAllocationIdentities(t *testing.T) {
	got, err := scanSources(queueFixture(map[string]string{"internal/example/source.go": `package example; var _ = make(chan int, 1); var _ = make(chan int, 2)`}))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].ID == got[1].ID {
		t.Fatalf("package allocations collapsed: %+v", got)
	}
}

func TestScanTracksConvertedAndMultiNameConstants(t *testing.T) {
	for _, limit := range []string{"4", "8"} {
		got, err := scanSources(queueFixture(map[string]string{"internal/example/source.go": `package example; const first, second = ` + limit + `, first; func start(){ _ = make(chan int, int(second)) }`}))
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 || got[0].Capacity != "int("+limit+")" {
			t.Fatalf("converted capacity did not follow definition: %+v", got)
		}
	}
}

func TestScanRejectsUnsupportedCapacityConstantForms(t *testing.T) {
	for _, source := range []string{
		`package example; const (first = 4; second); func start(){ _ = make(chan int, second) }`,
		`package example; const limit = iota+4; func start(){ _ = make(chan int, limit) }`,
	} {
		_, err := scanSources(queueFixture(map[string]string{"internal/example/source.go": source}))
		if err == nil || !strings.Contains(err.Error(), "capacity constant") {
			t.Fatalf("unsupported constant was silently accepted: %v", err)
		}
	}
}

func TestScanPreservesCapacityExpressionGrouping(t *testing.T) {
	var capacities []string
	for _, source := range []string{
		`package example; const a=1+2; const b=3; const limit=a*b; func start(){ _=make(chan int,limit) }`,
		`package example; const a=1; const b=2*3; const limit=a+b; func start(){ _=make(chan int,limit) }`,
	} {
		got, err := scanSources(queueFixture(map[string]string{"internal/example/source.go": source}))
		if err != nil || len(got) != 1 {
			t.Fatalf("scan=%+v err=%v", got, err)
		}
		capacities = append(capacities, got[0].Capacity)
	}
	if capacities[0] == capacities[1] {
		t.Fatalf("capacities 9 and 7 have identical descriptors: %q", capacities)
	}
}

func TestScanCombinesSharedCapacityBuildVariants(t *testing.T) {
	files := map[string]string{
		"internal/example/limit_linux.go": "//go:build linux\npackage example; const limit=4; type pending chan int",
		"internal/example/limit_other.go": "//go:build !linux\npackage example; const limit=8; type pending chan int",
		"internal/example/source.go":      `package example; func start(){ _=make(pending,limit) }`,
	}
	got, err := scanSources(queueFixture(files))
	if err != nil || len(got) != 1 || got[0].Capacity != "4 | 8" {
		t.Fatalf("variant capacities=%+v err=%v", got, err)
	}
	files["internal/example/limit_other.go"] = "//go:build !linux\npackage example; const limit=8; type pending []int"
	if _, err := scanSources(queueFixture(files)); err == nil || !strings.Contains(err.Error(), "ambiguous make type") {
		t.Fatalf("ambiguous channel variant accepted: %v", err)
	}
}

func TestScanResolvesDeclaredImportPackageNames(t *testing.T) {
	got, err := scanSources(queueFixture(map[string]string{
		"internal/queuehealth/channel.go": `package accounting; func NewChannel[T any](n int, age int) chan T { return nil }`,
		"internal/example/source.go":      `package example; import "github.com/pidginhost/csm/internal/queuehealth"; func start(){ _=accounting.NewChannel[int](4,60) }`,
	}))
	if err != nil || len(got) != 1 || got[0].Kind != "accounted_channel" {
		t.Fatalf("declared package name lost constructor: %+v %v", got, err)
	}
}

func TestScanRejectsAmbiguousCrossFileMakeShadowing(t *testing.T) {
	_, err := scanSources(queueFixture(map[string]string{
		"internal/example/shadow_linux.go": "//go:build linux\npackage example; func make(values ...int) int { return 0 }",
		"internal/example/source_other.go": "//go:build !linux\npackage example; func start(){ _=make(chan int,4) }",
	}))
	if err == nil || !strings.Contains(err.Error(), "ambiguous make shadowing") {
		t.Fatalf("build-variant queue disappeared behind inactive shadow: %v", err)
	}
}
