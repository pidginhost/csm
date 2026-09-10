package main

import (
	"fmt"
	"strings"
	"testing"
)

func TestScanRejectsImportedMixedPackageVariants(t *testing.T) {
	_, err := scanSources(queueFixture(map[string]string{
		"internal/variant/type_linux.go":   "//go:build linux\npackage first; type Pending []int",
		"internal/variant/type_windows.go": "//go:build windows\npackage second; type Pending chan int",
		"internal/example/source.go":       `package example; import v "github.com/pidginhost/csm/internal/variant"; func start(){ _=make(v.Pending,4) }`,
	}))
	if err == nil || !strings.Contains(err.Error(), "ambiguous make type") {
		t.Fatalf("imported channel variant omitted: %v", err)
	}
}

func TestCapacityChangesInvalidateReviewedManifest(t *testing.T) {
	for _, tc := range []struct{ name, source string }{
		{"local var", `package example; func start(){ var limit=%d; _=make(chan int,limit) }`},
		{"compound local var", `package example; func start(){ var limit=%d; _=make(chan int,limit+1) }`},
		{"local alias", `package example; func start(){ limit:=%d; size:=limit; _=make(chan int,size) }`},
		{"typed local var", `package example; const size=%d; func start(){ var limit int=size; _=make(chan int,limit) }`},
		{"array length", `package example; const limit=%d; func start(){ _=make(chan int,len([limit]byte{})) }`},
		{"slice bound", `package example; const limit=%d; func start(){ _=make(chan int,len("0123456789"[:limit])) }`},
		{"array default", `package example; const size=%d; func start(){ var limit=len([size]byte{}); _=make(chan int,limit) }`},
		{"keyed array", `package example; const limit=%d; func start(){ _=make(chan int,len([... ]byte{limit:1})) }`},
		{"full slice bound", `package example; const limit=%d; func start(){ var input [10]byte; _=make(chan int,cap(input[:0:limit])) }`},
		{"array pointer", `package example; const limit=%d; func start(){ _=make(chan int,cap(new([limit]byte))) }`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := func(limit int) map[string]string {
				return map[string]string{"internal/example/source.go": fmt.Sprintf(tc.source, limit)}
			}
			before := queueFixture(fixture(4))
			sites, err := scanSources(before)
			if err != nil || len(sites) != 1 {
				t.Fatalf("baseline allocation=%+v err=%v", sites, err)
			}
			manifest := queueManifest{Version: 1, Allocations: []allocationDecision{{allocation: sites[0], Class: "lifecycle", Rationale: "Reviewed completion signal capacity."}}}
			if _, validationErr := validateManifest(before, manifest); validationErr != nil {
				t.Fatal(validationErr)
			}
			_, err = validateManifest(queueFixture(fixture(8)), manifest)
			if err == nil || !strings.Contains(err.Error(), "allocation changed") {
				t.Fatalf("changed capacity input 4 -> 8 accepted: %v; baseline=%+v", err, sites[0])
			}
		})
	}
}

func TestScanRejectsUnresolvedCapacityLiteralAndClosure(t *testing.T) {
	for _, source := range []string{
		`package example; type values [4]int; func start(){ _=make(chan int,len(values{})) }`,
		`package example; const limit=4; func start(){ _=make(chan int,func() int{return limit}()) }`,
	} {
		_, err := scanSources(queueFixture(map[string]string{"internal/example/source.go": source}))
		if err == nil || !strings.Contains(err.Error(), "unsupported capacity") {
			t.Fatalf("unresolved expression accepted: %v", err)
		}
	}
}

func TestScanKeepsRuntimeBatchLengthSymbolic(t *testing.T) {
	got, err := scanSources(queueFixture(map[string]string{"internal/example/source.go": `package example
 type job struct{value int}
 func start(input []int){
  pending:=make([]job,0,len(input))
  for _,value:=range input{pending=append(pending,job{value:value})}
  _=make(chan job,len(pending))
 }`}))
	if err != nil || len(got) != 1 {
		t.Fatalf("runtime batch scan=%+v err=%v", got, err)
	}
	if got[0].Capacity != "len(pending)" || len(got[0].Defaults) != 0 {
		t.Fatalf("batch contents treated as scalar capacity definitions: %+v", got[0])
	}
}

func TestScanRejectsEmptyMakeInCapacity(t *testing.T) {
	_, err := scanSources(queueFixture(map[string]string{"internal/example/source.go": `package example; func start(){ _=make(chan int,len(make())) }`}))
	if err == nil || !strings.Contains(err.Error(), "make has no type") {
		t.Fatalf("malformed nested make was not rejected: %v", err)
	}
}

func TestScanRejectsUnsupportedCapacityInsideSelector(t *testing.T) {
	for _, expression := range []string{
		`(limits{Max: bound}).Max`,
		`(func() limits { return limits{Max: bound} }()).Max`,
	} {
		source := `package example; type limits struct{Max int}; const bound=4; func start(){ _=make(chan int,` + expression + `) }`
		_, err := scanSources(queueFixture(map[string]string{"internal/example/source.go": source}))
		if err == nil || !strings.Contains(err.Error(), "unsupported capacity") {
			t.Fatalf("selector hid unsupported capacity %s: %v", expression, err)
		}
	}
}
